## REGISTER ENDPOINT

* Get `email`, `password`, `firstName`, `lastName`, `displayName` from body
* Normalize `email`
* Hash the `password`
* **try**
    * Add new user using transaction - **BEGIN**
        * Find the existing active user by email
        * If the existing active user by email is found, log `EMAIL_ALREADY_EXISTS` and return a generic registration response
        * Create a new user
        * Get the new user's primary email
        * Create a new email verification token for attaching in verification mail
        * Return the user and token id
    * If new user is not created, log proper error and return a generic registration response
    * Add verification email to queue
    * If email not added to queue, return success with `"account created but failed sending email"` message
    * Return success and queued email message    
* **catch** any error
    * Log `EMAIL_ALREADY_EXISTS` for error code `P2002` and return generic registration response
    * Throw any other error

## HELPERS
#### normalizeEmail:
* transform to lowercase

#### hashPassword:
* hashes the password. For password hashing we are using Argon2, a modern and secure password-hashing algorithm, typically used in a NestJS backend.
* It is designed to be resistant to GPU-based cracking attacks (like brute-force attacks using graphics cards or ASICs) by requiring a significant amount of memory (memoryCost) and computational time (timeCost).
* The specific variant used here, argon2id, is a hybrid version that combines Argon2i (resistant to side-channel attacks) and Argon2d (resistant to GPU cracking). It is widely considered the gold standard for password hashing in web applications.
* **Breakdown of the Configuration:**
  * Each property controls a specific resource parameter used during the hashing and verification process:
    * **`memoryCost: 65536 (64 MB)`**
    What it does: Specifies the amount of RAM (in kibibytes, so 65,536 KiB = 64 MB) that the algorithm must use.
    Why it matters: Attackers trying to crack millions of hashes simultaneously on a GPU will quickly run out of VRAM. High memory requirements bottleneck their hardware, making mass-cracking economically and computationally unfeasible.
    * **`timeCost: 3`**
    What it does: Represents the number of iterations (or passes) over the memory.
    Why it matters: It dictates how many cycles the algorithm runs. A value of 3 means the server takes a bit longer to compute the hash (a fraction of a second), which slows down legitimate logins slightly but heavily penalizes an attacker trying billions of guesses.
    * **`parallelism: 4`**
    What it does: Defines the degree of parallelism (the number of independent threads/lanes used).
    Why it matters: It allows the hashing process to utilize multiple CPU cores efficiently without significantly altering the security profile.
    * **`type: argon2.argon2id`**
    What it does: Selects the Argon2id flavor, ensuring optimal defense against both side-channel and GPU-accelerated brute-force attacks.
    * **`as const`**
    TypeScript Note: This makes the properties readonly and infers literal types (e.g., exactly 65536 instead of just number), ensuring strict type-safety across your NestJS services.

#### findActiveUserByEmail:
* destructure args
* Using same transaction, find active user by email
* its common function, so in response, send back all information used by multiple endpoints

#### createNewUser:
* destructure args
* create a new user, and its primary email record
* in response, send back the created user with emails

#### createNewToken:
* destructure args
* generate raw token using 32 randomBytes, and using base64url on that. Eg: `return randomBytes(32).toString('base64url');`
* hash the raw token by passing the raw token through the SHA-256 cryptographic hash function, and returns a fixed-length 64-character hexadecimal string. 
Eg: `return createHash('sha256').update(rawToken).digest('hex')`
* create new record in userToken table
* return token record info and rawToken as on first instance, we will share rawtoken with the user

#### enqueueMail
It enqueues a verification email.
* destructure args
* call emailService enqueue function with the data which ultimately adds the email job object to the email queue

---

## LOGIN ENDPOINT

The whole point of this flow: **every way of failing must look identical to the caller** — same error message, and roughly the same amount of time taken. If a wrong email answered faster than a wrong password, anyone could discover which emails have accounts just by timing the responses.

* Get `email`, `password` from body, and build the `context` (ip address, user agent, device id) from the request
* Normalize `email`
* Find the active user by that email (plain query, no transaction — we are only reading)
* Take `now`
* Work out if the account is locked: it has a `passwordLockedUntil` **and** that time is still in the future
* **Decide which hash to compare against BEFORE comparing** — this is the important bit
    * If there is no user, **or** the user has no `passwordHash`, **or** the account is locked → use the **dummy hash**
    * Otherwise → use the user's real `passwordHash`
    * Either way exactly **one** argon2 comparison runs, so all paths cost the same wall-clock time
* Run `verifyPassword(password, hashToVerify)` and keep the result
* **Now handle the failures, in this order.** All four throw the *same* `401` with the same generic message:
    * **No user found** → record a non-counting failure with reason `USER_NOT_FOUND`
    * **User exists but has no password** (e.g. an OAuth-only account) → record a non-counting failure with reason `NO_PASSWORD_CREDENTIAL`
    * **Account is locked** → record a non-counting failure with reason `ACCOUNT_LOCKED`
        * "Non-counting" means: do not bump the lockout counter. There is either no account to count against, or it is already locked, so counting again achieves nothing
    * **Password was wrong**
        * First, if the user has a `passwordLockedUntil` set at all, reset the failure state
            * Why: the lock has clearly expired (we would have exited at the locked check otherwise). If we skip this, the counter is still sitting at 5, so the very next failure makes it 6, which is `>= 5`, and the account re-locks instantly. The user would be stuck at one attempt per lock window, forever
        * Then record the failed login (this one **does** count)
* **Success path**
    * Reset the password failure state, so the next run of bad attempts starts from zero
    * Upgrade the password hash if the cost parameters have changed
    * Build the authentication result: `userId`, `authMethod: PASSWORD`, `emailVerified` (from the email row we looked up), `mustChangePassword`
    * Ask `SessionService.createSession` for a new session + tokens
    * Return the user summary and the issued session

> Note on responsibility: login **authenticates the person**. It does not decide what they are allowed to do. Everything it returns is about identity and the freshness of that identity.

### LOGIN HELPERS

#### dummyPasswordHash:
* A real argon2id hash of 32 random bytes, computed **once** when the service is constructed (it is stored as a promise and awaited whenever needed)
* Because it is a genuine hash with the same cost settings, verifying against it takes the same time as verifying a real one
* This is what makes "user not found" indistinguishable from "wrong password" on the clock

#### recordNonCountingLoginFailure:
* Writes a `LOGIN_FAILED` audit event with the ip, user agent, device id and a `reason`
* `userId` is optional — for `USER_NOT_FOUND` there is no user to attach it to
* Deliberately does **not** touch `passwordFailedAttempts`

#### recordFailedLogin:
* Read `maxFailedAttempts` and `lockDurationSeconds` from config
* In a transaction:
    * Increment `passwordFailedAttempts` by 1 and read the new value back
        * Using `{ increment: 1 }` makes this atomic at the row level, so two failures landing at the same moment cannot lose one of the counts
    * If the new count is `>= maxFailedAttempts`, set `passwordLockedUntil = now + lockDurationSeconds`
    * Write a `LOGIN_FAILED` audit event carrying the reason, the attempt count, and whether this attempt caused the lock

#### resetPasswordFailureState:
* Set `passwordFailedAttempts = 0` and `passwordLockedUntil = null` for that user
* Called on a successful login, and also when an expired lock is found on a failed one

#### upgradePasswordHashIfNeeded:
* Login is the **only** moment we ever hold the plaintext password, so it is the only chance to re-hash it with stronger settings
* If `passwordNeedsRehash(currentHash)` is false, do nothing
* Otherwise hash the password again with the current settings and save it
* It deliberately does **not** update `passwordChangedAt` — the user did not change their password, we only re-encoded it
* Wrapped in try/catch and only logs a warning on failure: a hash upgrade going wrong must never turn a good login into an error

---

## RESEND VERIFICATION EMAIL ENDPOINT

Same idea as login: the response never reveals whether the email exists or what state it is in. It always returns the same generic verification response.

* Normalize the email
* Look up the mail details (`id`, `userId`, `isVerified`) for that address
* If nothing is found → return the generic verification response
* If the email is already verified → log `EMAIL_ALREADY_VERIFIED` and return the generic verification response
* Create a new verification token, with retry
    * If the result comes back as `allowed: false`, the cooldown is still running → log `COOLDOWN_ACTIVE` and return the generic response
* Enqueue the verification email with the new token id and raw token
    * If enqueueing fails → log `VERIFICATION_EMAIL_ENQUEUE_FAILED` and still return the generic response
* Return the generic verification response

### RESEND HELPERS

#### getMailDetails:
* Straight lookup of the `userEmail` row by address, selecting `id`, `userId`, `isVerified`
* Note it does **not** filter on user status or `deletedAt` — unlike `findActiveUserByEmail`, which does. This path only ever leads to sending a verification mail, never to issuing credentials

#### isVerificationCooldownActive:
* Find the most recently created token for that user + token type + email id (ordered by `createdAt` descending), selecting only `createdAt`
* If there is no such token → not on cooldown, return `false` (and log that none was found)
* Work out `cooldownEndsAt = createdAt + cooldownTime` (config value, in seconds)
* If `now` is still before that → log `COOLDOWN` and return `true`
* Otherwise return `false`

#### expireVerificationTokenByMail:
* `updateMany` setting `expiresAt = now` on every token matching that user + type + email id
* Effect: any verification link already sitting in the user's inbox stops working the moment a new one is issued, so only the newest link is ever live

#### createVerificationTokenWithRetry:
* Runs the whole thing inside `withSerializableRetry` (Serializable isolation, retried on Postgres serialization failures)
* Inside the transaction:
    * Check the cooldown → if active, return `{ allowed: false, token: null }`
    * Expire all existing verification tokens for that email
    * Create a fresh token
    * Return `{ allowed: true, token, rawToken }`
* Serializable matters here because the cooldown check and the token creation must see a consistent picture — otherwise two simultaneous resend requests could both pass the cooldown check and both send a mail

---

## VERIFY EMAIL ENDPOINT

* Get the `rawToken` from the query params
* Hash it (SHA-256), because only the hash is stored in the database
* In **one** transaction:
    * Find and validate the token
    * Atomically consume it (mark it used)
    * Mark the user's email as verified
    * Write an `EMAIL_VERIFIED` audit event
    * Return the success message
* Everything is in a single transaction so a token can never be consumed without the email actually being verified, and vice versa

### VERIFY HELPERS

#### findAndValidateToken:
* Look up the token row by its hash
* Reject with `400 Invalid verification token` if the row is missing, or its type is not `EMAIL_VERIFICATION`
* Reject with `400` if `usedAt` is already set → "already been used"
* Reject with `400` if `expiresAt` is set and is in the past → "has expired"
* Validate the `metaData`: it must be a non-null, non-array object with a string `userEmailId`
    * Anything else → `400 Invalid verification token`
* Return `{ tokenId, userId, userEmailId }`

#### consumeToken:
* `update` the token row `where { id: tokenId, usedAt: null }`, setting `usedAt = now`
* The `usedAt: null` in the **where clause** is what makes this single-use: if two requests arrive with the same token, only one can match
* Catch Prisma error `P2025` (record not found — i.e. someone else consumed it first) and turn it into `400 Verification token has already been used`
* Any other error is rethrown

#### updateUserEmail:
* Update the email row: `isVerified = true`, `verifiedAt = now`
* Catch `P2025` and turn it into `400 Associated email record not found`

---

## SESSION SERVICE

A **session** is the long-lived record that someone is logged in on a device. Sitting under it are **refresh tokens** — short-lived, single-use, and rotated every time they are exchanged. The access token (JWT) is separate and stateless.

Three ideas run through this whole service:

1. **The database only ever stores hashes of tokens.** The raw token exists once, in the response. If our database leaks, the tokens in it are useless.
2. **A refresh token is single-use.** Using one mints its replacement. Using one *twice* is treated as evidence of theft.
3. **Revocation goes through exactly one function** (`revokeSessions`), so the meaning of "revoked" cannot drift between logout, eviction, expiry and theft detection.

### createSession
Called by login once the password has been accepted.

* Read `maxActivePerUser` and `absoluteTtlSeconds` from config
* Take `now`, and compute `sessionExpiresAt = now + absoluteTtl`
* Run a **unit of work** (transaction + after-commit effects):
    * Find the user's currently usable sessions: `revokedAt: null` **and** `expiresAt > now`, ordered by `lastUsedAt` ascending (oldest use first)
        * The `expiresAt > now` part matters: a session past its absolute expiry is already dead even if nothing has swept it yet, so it must not take up a slot
    * Work out how many to evict: `evictCount = activeSessions.length - maxSessions + 1`
        * The `+ 1` is making room for the session we are about to create
    * If `evictCount > 0`:
        * Revoke that many sessions from the front of the list (the least recently used) with reason `SESSION_LIMIT`
        * If anything was actually revoked, write one `SESSION_REVOKED` audit event listing the evicted ids
        * **Why evict instead of refusing the login:** the password was correct. A user who is blocked has no way to free a slot, because logging out elsewhere would itself need a session they cannot get
    * Create the session row: `userId`, `expiresAt`, normalized ip, user agent, device id, `deviceName: null`, `authMethod`. Select back `id` and `tokenFamilyId`
    * Create the first refresh token for it
    * Write a `LOGIN_SUCCESS` audit event
    * Return the session id, token family id, refresh token and its expiry
* **After** the transaction commits, generate the access token
    * Why after: it needs the session id, and if signing failed inside the transaction it would roll back a perfectly good session
* Return the issued session: session id, token family id, access token, `expiresIn`, refresh token and its expiry

> **The cap is soft, on purpose.** Two logins racing can both read the same count and both insert, leaving the user one over the limit. The promise is "we normally keep at most N and evict the least recently used", not "N can never be exceeded". A hard cap would mean Serializable isolation on the login path, which is not worth it.

### rotateRefreshToken
Exchanges a refresh token for a new pair, rotating the refresh token.

**The structural trick here:** every decision happens inside one transaction that **returns an outcome object** instead of throwing. The rejection paths perform writes (the lazy expiry sweep, the family revocation), and a thrown exception would roll those writes back — leaving a stolen token alive. The `401` is raised only after the transaction has committed.

* Read `refreshReuseGraceSeconds` from config, take `now`, hash the raw token
* In a unit of work:
    * Read the stored refresh token by hash, pulling in its session and the session's user (status, `mustChangePassword`)
    * **Reject** `TOKEN_NOT_FOUND` if no row — no writes, and no hint to the caller that it was unknown
    * **Reject** `SESSION_REVOKED` if the session is already revoked — nothing left to revoke, and this is not a theft signal
    * If the session is past `expiresAt`:
        * Revoke it with reason `EXPIRED` — this is the **lazy sweep**, so expired sessions get marked without needing a background job
        * **Reject** `SESSION_EXPIRED` (and note this write must survive, which is why we return rather than throw)
    * **Reject** `USER_NOT_ACTIVE` if the user's status is not `ACTIVE`
        * Re-checked on every refresh, otherwise a suspended user keeps renewing for the remaining lifetime of their session
    * **Reject** `TOKEN_REVOKED` if the token itself is revoked
    * **Reject** `TOKEN_EXPIRED` if the token is past its own `expiresAt` (this is the idle timeout — shorter than the session's absolute lifetime)
    * Start `graceReplay = false`
    * **If the token has already been used (`usedAt` is set):**
        * If that use is **outside** the grace window → revoke the whole token family and **reject** `TOKEN_REUSE`
        * If it is **inside** the window → treat it as a benign double-submit, set `graceReplay = true`
    * **If the token has not been used:**
        * `updateMany where { id, usedAt: null }` setting `usedAt = now`
            * This is the single-use guarantee: whoever flips `usedAt` away from null wins. Under Read Committed the loser's update waits for the winner to commit, re-checks the where clause, and matches zero rows
        * If `count === 0` we lost the race → re-read the row to see the winner's `usedAt`
            * If there is no `usedAt`, or it is outside the grace window → revoke the family and **reject** `TOKEN_REUSE`
            * Otherwise set `graceReplay = true`
    * Create the replacement refresh token
    * Update the session: `lastUsedAt`, `lastRefreshedAt`, ip, user agent
    * Read the user's primary email **fresh** for its `isVerified` flag
        * Why not trust the old token's claim: verifying an email would otherwise not take effect until the session ended
    * Write a `TOKEN_REFRESH` audit event, recording whether this was a grace replay
    * Return a `ROTATED` outcome with everything the access token needs
* After the transaction: if the outcome is `REJECTED`, throw `401` with **one generic message** for every reason
    * Telling the caller whether a token was unknown, expired or reused is free reconnaissance for someone probing a stolen token. The real reason lives in the audit log only
* Otherwise generate the access token and return the new pair

#### The grace window, explained
Reuse inside the grace window is **tolerated**, and that is a deliberate decision, not an oversight.

* Real clients double-submit all the time: two requests `401` together and both try to refresh, or a response is dropped and the client retries
* Inside the window, a thief's replay is genuinely indistinguishable from that
* Outside it, reuse means two parties hold the same token, so we assume theft
* Narrowing the window buys better detection at the cost of more false logouts

A grace replay mints a **second child of the same parent** rather than re-issuing the first child — we only ever stored the first child's hash, so the original raw token is unrecoverable by design. Both children are valid and tied to the session; the client keeps whichever response arrives last.

### revokeSession
Revokes one session and every refresh token under it.

* Take `now`, and in a unit of work:
    * Look up the session's `userId` and `authMethod`
    * If it does not exist → return quietly
    * Revoke it with reason `LOGOUT`
    * If nothing was actually revoked (it was already revoked) → return **without** writing an audit event
        * A logout that did not happen should not be recorded as one
    * Write a `LOGOUT` audit event
* **Idempotent by design:** logging out twice, or a retried request, must succeed rather than return an error

### revokeSessionByRefreshToken
The logout path for a client holding only the refresh cookie — which is the normal case, since the access token has very likely expired by the time someone clicks "log out".

* Hash the raw token and look up the refresh token row, selecting just `sessionId`
* If there is no row → return quietly
* Call `revokeSession` with that id
* Resolving and then revoking in two separate steps is safe precisely because revocation is idempotent

### revokeAllSessions
* Take `now`, and in a unit of work:
    * Revoke every session for that user with reason `LOGOUT_ALL`
    * If anything was revoked, write **one** `LOGOUT_ALL` audit event carrying the count and the initiating session id
        * One event, not one per session, because this is a single user action
* Return how many were revoked

### revokeSessions
**The** revocation function. Every path that ends a session — logout, logout-all, eviction at the cap, the lazy expiry sweep, theft detection, a password change — goes through here.

* Find the matching sessions that are **still active** (`revokedAt: null`), selecting only their ids
    * Reading the ids first means we know the exact set we are revoking. We need that for the denylist, and it keeps the token update off sessions that were revoked earlier
* If the list is empty → return `[]` (so callers can tell nothing happened)
* `updateMany` those ids: `revokedAt = now`, `revocationReason = reason`
* Retire all their refresh tokens
* Queue `denylist.revoke(sessionIds)` to run **after commit**
    * A revoked session's access token stays valid until it expires; the denylist closes that gap
    * Queued after commit so a rollback can never leave a live session sitting on the denylist
* Return the ids actually revoked
* Auditing stays with the **caller**, because each path records a different event type

### reissueRefreshToken
Swaps every refresh token of one session for a single fresh one. Used after a credential change: the session survives, but any refresh token issued before the change — including one that may have leaked — stops working.

* Retire all refresh tokens for that session
* Create one new one and return it

> Old tokens are **retired (revoked)** rather than marked used. If the response carrying the new cookie is lost, the client's next refresh presents a *revoked* token and gets a plain `401`. A *used* token would instead trip reuse detection once the grace window passed, and raise a false theft alarm.

### SESSION HELPERS

#### createRefreshToken:
* Read `refreshTtlSeconds` from config
* Generate a raw token (32 random bytes, base64url)
* Compute the expiry as `min(now + refreshTtl, sessionExpiresAt)`
    * **Clamped to the session on purpose:** a refresh token must never outlive the session it belongs to, or the absolute session lifetime is not actually absolute
* Store the row with only the **hash** of the token
* Return the raw token and its expiry — this is the one and only moment the raw value exists
* Shared by login, rotation and reissue, so the clamping and the hashing cannot drift apart between them

#### retireRefreshTokens:
* `updateMany` every not-yet-revoked refresh token for the given sessions, setting `revokedAt = now`
* Shared by revocation and reissue, since both need to retire every live token of a session

#### isWithinGrace:
* Returns `now - usedAt <= graceSeconds * 1000`

#### revokeTokenFamily:
* Called when a used token is replayed outside the grace window, which means two parties hold it. We assume theft
* Revoke **every session sharing that token family** (not just this one) with reason `TOKEN_REUSE`
    * The family links a session to its descendants, so a thief who already rotated cannot keep their branch alive
* Write a `TOKEN_REUSE_DETECTED` audit event recording the family id, the presented token's id, when it had been used, and how many sessions this killed

---

## PASSWORD SERVICE

This service owns the **password credential lifecycle** — changing it now, resetting it later.

It is **not** an authentication mechanism. Nothing here produces an authentication result, because whoever calls change-password is already authenticated. Authentication answers *"who is this?"*; this service manages the proof itself.

### changePassword

* Get `userId`, `sessionId`, `currentPassword`, `newPassword`, `context`; take `now`
* Load the session by id, pulling in the user's `status`, `deletedAt` and `passwordHash`
* **Re-validate the session against the database.** Throw `401 SESSION_REVOKED` if any of these hold:
    * the session does not exist
    * its `userId` does not match the caller
    * it has been revoked
    * it has passed `expiresAt`
    * the user is not `ACTIVE`
    * the user is soft-deleted
    * **Why re-check when the guard already verified the token:** the guard is stateless, so a session revoked a few minutes ago still carries a perfectly valid access token. A credential change must not run on one
* If the user has no `passwordHash` → `403 NO_PASSWORD_CREDENTIAL`
    * An account created through an external provider has no password to change. Setting a *first* password is a different flow with its own verification
* Verify `currentPassword` against the stored hash. If it does not match → `403 INVALID_CURRENT_PASSWORD`
    * **This is re-authentication.** A valid access token proves possession of a credential, not that the owner is at the keyboard right now, so a credential change demands fresh proof
    * **403, not 401, deliberately:** clients treat `401` as "my session died, go refresh", which is wrong here. The session is fine; the input is not
    * **Not counted toward the lockout counter:** that counter exists to stop unauthenticated guessing. Counting here would let anything able to send requests as this user (an XSS, say) lock the real owner out of their own account
* If the new password equals the current one → `400 PASSWORD_UNCHANGED`
* Hash the new password **outside** the transaction
    * argon2 is deliberately CPU-bound and slow; never hold a transaction open across it
* Run one unit of work — the credential, the other sessions, and this session's refresh token all change together or not at all:
    * Update the user: new `passwordHash`, `passwordChangedAt = now`, `mustChangePassword = false`, `passwordFailedAttempts = 0`, `passwordLockedUntil = null`
    * Revoke **every other** session for this user (`id: { not: sessionId }`) with reason `PASSWORD_CHANGED`
        * Anyone holding a stolen refresh token on another device loses it
        * The caller's own session is kept, so they are not logged out of the tab they just used
        * Denylisting happens after commit, queued by `revokeSessions` itself
    * Reissue the refresh token for the surviving session — it keeps working, but any refresh token issued before the change is retired
    * Write a `PASSWORD_CHANGED` audit event including how many other sessions were revoked
    * Return the new refresh token, its expiry, and the revoked count
* The controller then writes the new refresh token into the cookie — the client **must** receive it, or its next refresh will fail

---

## TOKEN SERVICE

Stateless JWT minting and verification. It touches no database at all.

### generateAccessToken
* Sign a JWT with these claims:
    * `sid` — session id (this is what ties a stateless token back to a revocable session)
    * `fam` — token family id
    * `ev` — email verified
    * `mcp` — must change password
    * `amr` — authentication methods, as an array
    * `jti` — a random UUID, so an individual token can be identified
    * `sub` — the user id (set via the `subject` option)
* Signing options: `HS256`, plus the configured secret, issuer, audience and TTL
* `keyid` is set from config, which enables key rotation without a code change
* Return the token and its `expiresIn`

### verifyAccessToken
* Verify with the same secret, algorithm, issuer and audience
* `clockTolerance: 5` allows five seconds of clock skew between machines

---

## SHARED BUILDING BLOCKS

#### runUnitOfWork:
A transaction **plus the side effects that must wait for it to commit**.

* Some effects cannot be rolled back — a Redis write, an email, a published event. Run inside the transaction, they would survive a rollback and act on a change that never actually happened
* So code inside the transaction calls `afterCommit(effect)` to queue them instead
* How it works:
    * Collect queued effects in an array
    * Run the work inside `prisma.$transaction`
    * Once it commits, run the effects in order
    * If the transaction fails, the effects are simply discarded
* A nice side benefit: inner code never has to return data out of the transaction purely so a caller can perform the effect later
* Effects run after the commit is final, so they should handle their own failures — one that throws will surface as an error even though the data change already landed

#### withSerializableRetry:
* Runs the function in a **Serializable** transaction
* Retries on Postgres serialization failures (Prisma error `P2034`), up to `maxRetries` (default 3), logging a warning on each retry
* Any other error is rethrown immediately
* **Important limitation:** this only converts lost races into retries. Single-use guarantees must still come from the queries themselves, e.g. `update where { usedAt: null }`

#### buildAuthContext:
* Builds the `AuthContext` (ip address, user agent, device id) from the request
* Normalizes the ip, and trims + length-clamps the user agent and device id
* Sanitizing every client-controlled value here, at the boundary, means no downstream writer has to remember to

#### SessionDenylistService:
Closes the revocation gap left by stateless access tokens.

* The problem: a revoked session's access token stays valid until it expires, because the JWT guard only checks a signature and touches no database
* The fix: record revoked session ids in Redis so the guard can reject them straight away
* The TTL on each entry equals the **access token** lifetime — nothing needs to outlive a revocation by longer than that. So storage is proportional to *revocations in the last few minutes*, not to the number of sessions
* **Fails open** on Redis errors: this narrows an already-short window rather than being a primary control, so a cache blip must not take authentication down with it. Errors are logged loudly, because a silent denylist is worse than no denylist
* Completely inert when disabled in config — no connection is opened and no Redis call is made
* `revoke(ids)` writes the entries in a pipeline, and must be called **after** the database transaction commits
* `isRevoked(id)` is a single `EXISTS`, since it runs on every authenticated request

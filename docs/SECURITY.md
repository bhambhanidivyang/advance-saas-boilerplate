# Security measures

This file lists every attack the authentication system defends against, how it defends, where the defence lives, and what tests it. It also lists the practices behind those defences and the gaps that remain.

Status meanings:

| Status | Meaning |
|------|------|
| **Enforced** | Implemented, and covered by a test or verified live |
| **Partial** | Implemented, but a known variant of the attack still gets through |
| **Planned** | Designed and agreed, not built yet |
| **Gap** | Known weakness with no fix scheduled yet |

For how the flows work end to end, see [AUTHENTICATION.md](AUTHENTICATION.md).

---

## 1. Account discovery and identity attacks

### Email enumeration

**Attack:** an attacker learns which emails have accounts by comparing responses, then targets those accounts with phishing or password guessing.

**Defence:**
- Login returns the same 401 status and body for an unknown email, an account with no password, a locked account and a wrong password. All four use the constant `GENERIC_LOGIN_RESPONSE`.
- Registration returns the same generic success whether the email is new or already registered, including when a race hits the database unique constraint (`P2002`).
- Resending the verification email returns the same message whether or not the address exists or is already verified.

**Where:** `auth.service.ts` (`login`, `register`, `resendVerifyEmail`), `constants/auth.constants.ts`
**Status:** Enforced for login. **Partial** for registration and resend (see timing below).
**Tested by:** the login parity unit test (compares status and body), and the e2e parity journey.

### Timing attacks

**Attack:** responses look identical, but response *time* differs. Checking a real argon2 hash takes about 100 ms, and returning early for an unknown email takes about 2 ms. Timing reveals which emails exist.

**Defence:** login decides *which* hash to check before checking. Every path runs exactly one argon2 verification: against the real hash when the account can log in, or otherwise against a dummy hash made at startup with the same cost settings. Registration hashes the password *before* looking up the email, so the expensive step happens on both paths.

**Where:** `auth.service.ts` (`dummyPasswordHash`, `login`, `register`)
**Status:** Enforced for login. **Partial** for registration and resend: a new account also writes rows and queues an email, while an existing one does neither. That difference is a few milliseconds, and statistical sampling could detect it.
**Tested by:** a table-driven test asserting exactly one verification on each of the five login branches.

### Pre-account hijacking

**Attack:** the attacker registers a password account with the victim's email and never verifies it. Later the victim signs in with Google, the system links Google to that account because the emails match, and the attacker's password still works. Both people now share the account.

**Defence:** `IdentityService` resolves a Google identity by the provider's permanent `sub`, never by email, and only uses an email Google reports as verified. When it links to an account whose own email was **never** verified, one transaction does all of: link the identity, mark the email verified (Google has just proved ownership), remove the password, revoke every session with reason `SECURITY`, and expire pending verification tokens. The squatter's password and sessions are gone; the real owner can set a password through reset.

Linking happens automatically only when both sides confirmed the address. Every link writes an `IDENTITY_LINKED` event recording `newUser`, `emailWasUnverified`, `passwordRemoved` and `revokedSessions`, so an incident responder can see exactly what was done.

**Where:** `auth/identity/identity.service.ts`
**Status:** Enforced.
**Tested by:** unit tests per branch, real-Postgres tests of the whole transaction, and an end-to-end journey: register with a password, sign in, then sign in with Google on the same address — the password then returns 401 and its session can no longer refresh.

### Deleted or suspended accounts signing in

**Attack:** an account that was suspended or deleted keeps signing in, or keeps refreshing an existing session.

**Defence:** the login lookup requires `status = ACTIVE` and `deletedAt IS NULL`, checked separately so one column can't stand in for the other. Every refresh checks the user's status again. Change password checks the session and user against the database again, not only the token.

**Status:** Enforced. **Tested by:** the suspended-user rotation test and the change-password session recheck tests.

---

## 2. Password attacks

### Online brute force against one account

**Attack:** trying many passwords against one account.

**Defence:** five wrong passwords lock the account for one hour. The database increments the counter atomically, so parallel attempts can't lose a count. When a lock has expired, the counter is cleared before the next attempt is judged. Without that, a user would be stuck at one attempt per hour forever.

**Status:** Enforced. **Tested by:** the expired-lock reset test.

### Lockout used to lock out someone else

**Attack:** an attacker deliberately fails logins to lock out the real user, or keeps them locked.

**Defence:** only a real wrong-password guess counts toward the lockout. An unknown email, an account without a password, attempts on an already-locked account, and a wrong *current* password during change password are all recorded in the audit log but not counted. Change password never counts, because anything able to send requests as the user (an XSS, for example) could otherwise lock out the owner.

**Status:** Enforced. **Tested by:** the tests for failures that don't count.

### Credential stuffing and password spraying

**Attack:** trying leaked email/password pairs across many accounts, or one common password against many accounts, so no single account reaches its lockout limit.

**Defence:** rate limits per IP, stored in Redis: 60 requests per minute overall, and 5 per minute on `login`, `refresh`, `logout`, `logout-all` and `change-password`.

**Status:** **Partial.** The limits are per IP, so an attacker spread across many IPs isn't slowed much. `register`, `resend-verification-email` and `verify-email` only have the general 60/min limit; see the gaps section.

### Weak and breached passwords

**Attack:** users choose passwords attackers try first.

**Defence:** one shared policy decorator (`MeetsPasswordPolicy`), used by registration and change password:
- 8 to 128 characters, with complexity rules
- a blocklist of common passwords
- a breach check against Have I Been Pwned, using k-anonymity: only the first 5 characters of the SHA-1 hash leave the server. If the service is down, the check allows the password rather than blocking sign-up.

The policy applies only when a password is **set**, never when it is checked. Enforcing it at login would lock out anyone whose password is older than a policy change.

**Where:** `common/decorators/meets-password-policy.decorator.ts`, `is-not-breached.decorator.ts`, `is-not-common-password.decorator.ts`
**Status:** Enforced. **Tested by:** the e2e policy rejection journey.

### Account takeover by token substitution

**Attack:** an attacker runs their own application, gets the victim to sign in there with Google, and replays that ID token to us. If we only checked the signature, the token would look perfectly valid — it *is* a genuine Google token for that person, just issued to somebody else's app. This is the confused-deputy problem.

**Defence:** `verifyIdToken` is always given our configured client IDs as `audience`, so a token whose `aud` is another application is refused. Identity is taken from `sub`, never from the email, so a changed or reassigned Google address cannot redirect a sign-in to another account.

**Where:** `auth/google/google-token-verifier.ts`
**Status:** Enforced. **Tested by:** a unit test that pins the `audience` argument; removing the option makes it fail.

### Offline cracking of stolen hashes

**Attack:** after a database leak, the attacker guesses passwords offline against the hashes.

**Defence:** argon2id with fixed settings: 64 MiB of memory, 3 iterations, parallelism 4. The memory cost makes GPU cracking expensive. When the settings are raised, each user's hash is upgraded at their next successful login, the only moment the plaintext is available. The upgrade doesn't change `passwordChangedAt`, and if it fails the login still succeeds.

**Where:** `utils/password-hash.util.ts`
**Status:** Enforced. **Tested by:** the upgrade-on-login and upgrade-failure tests.

### Long-password denial of service

**Attack:** sending a huge password so every hash takes a lot of CPU.

**Defence:** passwords are capped at 128 characters on every DTO that accepts one: login, registration and change password. Validation rejects longer input before argon2 runs.

**Status:** Enforced.

---

## 3. Token and session attacks

### Replay of a Google ID token

**Attack:** a Google ID token is a bearer credential, valid for about an hour. If one leaks — through request logs, frontend error reporting, a third-party script on the sign-in page, or a proxy — an attacker replays it and receives a full session for that account.

**Defence:** each sign-in is bound to a single-use nonce. `POST /auth/google/nonce` issues 32 random bytes and stores only their SHA-256 with a five-minute expiry. The client passes it to Google, which puts it in the signed token, and we claim it with a conditional update that matches only unused, unexpired rows. A replay finds the nonce already spent. A nonce that is present is always verified, so stripping the claim does not bypass the check.

The Google ID token and the nonce are also removed from request logs by the redaction list.

**Where:** `auth/google/google-nonce.service.ts`, `google-authenticator.service.ts`
**Status:** **Partial.** The server half is enforced and tested. `AUTH_GOOGLE_NONCE_REQUIRED` stays off until a frontend sends the nonce, so a token without one is currently accepted; startup validation makes it mandatory in production.
**Tested by:** unit, real-Postgres concurrency, and an end-to-end replay of one token.

### Replay of a refresh token

**Attack:** a stolen refresh token is used again after the real client has already used it.

**Defence:** each refresh token works once. It is marked used with a conditional update (`WHERE usedAt IS NULL`), and the database's count of changed rows decides the winner, so two requests can't both use the same token. If a used token appears again after the grace window, the whole token family is revoked, so both the thief and the victim are signed out, and a `TOKEN_REUSE_DETECTED` event is recorded.

**Status:** Enforced. **Tested by:** the real-Postgres reuse test, which backdates `usedAt` in the database because fake timers can't move the database clock.

### False theft alarms

**Attack:** not an attack, but a failure mode. Real clients send the same token twice (two tabs refreshing together, a retry after a dropped response). A strict system would treat this as theft and sign the user out.

**Defence:** a 15-second grace window. A token reused within 15 seconds is treated as a duplicate request: a second new token is issued and nothing is revoked. The tradeoff is deliberate: a thief replaying within those 15 seconds looks like a normal retry.

**Status:** Enforced. **Tested by:** a real-Postgres test that fires two refreshes at exactly the same time and asserts both succeed with no theft alarm.

### Refresh token theft through XSS

**Attack:** injected JavaScript reads the refresh token.

**Defence:** the refresh token only ever travels in an `httpOnly` cookie, which JavaScript can't read. It is scoped to `Path=/auth`, is `Secure` in production, and never appears in a response body. The access token lasts 10 minutes and is meant to be kept in memory only.

**Status:** Enforced. **Tested by:** assertions in the unit and e2e tests that no response body contains the refresh token.

### Cross-site request forgery (CSRF)

**Attack:** a malicious site makes the browser send a request to our API with the user's cookie attached.

**Defence:** `SameSite=Lax` stops browsers from sending the cookie on cross-site POSTs. CORS allows one configured origin, so a forged request can't read the response. Routes that use a Bearer token are immune, because browsers never attach it automatically. Setting `SameSite=None` is only allowed together with `Secure`, and startup validation enforces that.

**Status:** **Partial.** This is enough while the frontend and the API share a site. A frontend on a different site needs double-submit CSRF tokens.

### Session fixation

**Attack:** the attacker gets the victim to sign in with a session ID the attacker already knows.

**Defence:** the server creates the session ID and all tokens at login, from random values. The client never supplies an identifier that gets reused, and each login creates a new session.

**Status:** Enforced (by design).

### A stolen token outliving a password change

**Attack:** the user changes their password because they suspect a compromise, but the attacker's session keeps working.

**Defence:** change password asks for the current password again, then in one transaction: stores the new hash, revokes every other session, and replaces this session's refresh token. The user stays signed in only where they made the change.

**Status:** Enforced. **Tested by:** the e2e journey across two devices.

### Access tokens still working after revocation

**Attack:** after logout or revocation, the 10-minute access token keeps working.

**Defence:** an optional Redis denylist of revoked session IDs, checked once per request. If Redis is down, the check is skipped rather than blocking all traffic.

**Status:** **Optional.** It ships disabled. With it off, a revoked session's access token works for up to 10 minutes. Both settings have been verified live.

### Sessions that never end

**Attack:** a stolen session stays useful forever.

**Defence:** two limits. An absolute limit is set at login and never extended. A shorter refresh-token lifetime works as an idle timeout and never goes past the absolute limit. Expired sessions are marked expired, and their tokens retired, the next time they are used.

**Status:** Enforced. **Tested by:** the clamp test, which uses a deliberately inverted configuration.

### Too many sessions per user

**Attack:** creating sessions until storage or the per-user limit runs out.

**Defence:** a per-user cap. When a new login goes over it, the least recently used session is revoked with reason `SESSION_LIMIT`. Refusing the new login instead would let anyone who knows the password lock out the owner. Two exactly simultaneous logins can end up one over the cap; this is accepted and documented.

**Status:** Enforced. **Tested by:** the cap tests, including one that checks evicted sessions are only denylisted if the login commits.

### Database leak exposing usable tokens

**Attack:** someone who reads the database uses the tokens stored there.

**Defence:** refresh tokens and email verification tokens are 256-bit random values, stored only as SHA-256 hashes. Because the values are random rather than chosen by people, a fast hash is enough; a slow hash like argon2 isn't needed.

**Status:** Enforced.

---

## 4. Protocol and token-format attacks

### JWT algorithm confusion and `alg: none`

**Attack:** forging a token by changing its header to `alg: none` or to a different algorithm the server might accept.

**Defence:** verification only accepts `HS256`. Issuer and audience are checked too, with a 5-second tolerance for clock drift. A `kid` header lets keys be rotated through configuration.

**Status:** Enforced. **Tested by:** tests using a forged `alg: none` token and a token signed with a different secret.

### Using a token somewhere it wasn't issued for

**Attack:** using a token issued for another service or environment.

**Defence:** issuer and audience must match. The access-token secret must be at least 32 characters, which startup validation checks.

**Status:** Enforced. The issuer, audience and key ID in `.env` are still placeholders; see the pre-production list.

### Unprotected routes

**Attack:** calling a route that someone forgot to protect.

**Defence:** a global guard protects every route by default. A route is only public if it is explicitly marked `@Public()`, so a missing decorator makes a route *more* restricted, not less. Rate limiting runs before signature checks, so floods are cut off before any crypto work. A third global guard blocks every route except change password and logout-all while `mustChangePassword` is set. It reads the `mcp` claim in the token, so no database lookup is needed.

**Status:** Enforced. **Tested by:** the guard specs and e2e 401/403 checks.

---

## 5. Input and infrastructure attacks

### Request size attacks

**Attack:** huge request bodies or headers that use up memory or break database writes.

**Defence:**
- JSON bodies are capped at 256 KB. This parser is registered before Nest's default one, which then skips JSON. URL-encoded bodies keep Express's 100 KB default.
- Client headers written to the database are cut to fit their columns: device ID to 255 characters, user agent to 1000.
- Every string field in a DTO has a maximum length.

**Where:** `app.setup.ts`, `utils/auth.util.ts`
**Status:** Enforced. **Tested by:** the length-cap tests.

### Over-posting (mass assignment)

**Attack:** sending extra fields, such as `status` or `passwordHash`, hoping they get written to the database.

**Defence:** the global `ValidationPipe` uses `whitelist` and `forbidNonWhitelisted`, so a request with any field the DTO doesn't declare is rejected with a 400.

**Status:** Enforced.

### SQL injection

**Attack:** crafted input that changes a database query.

**Defence:** all database access goes through Prisma's parameterised queries. The application code has no SQL built from strings.

**Status:** Enforced (by design).

### Spoofed client IP

**Attack:** faking `X-Forwarded-For` to dodge per-IP rate limits or to put false IPs in the audit log.

**Defence:** how many proxies to trust is set explicitly in configuration. Every IP is checked with `net.isIP` and stored as null if it's malformed.

**Status:** Enforced. **Tested by:** the table-driven IP tests.

### Malformed input breaking security writes

**Attack:** a found-and-fixed bug. An invalid `X-Forwarded-For` value reached a Postgres `inet` column, aborted the transaction, and threw away the failed-attempt count along with it. Sending that header let an attacker guess passwords without ever triggering the lockout.

**Defence:** IPs are cleaned where the request context is built, and again inside the audit writer.

**Status:** Fixed. **Tested by:** a test that sends the malformed value directly.

### Browser-level attacks

**Attack:** clickjacking, MIME sniffing, downgrading to HTTP, referrer leaks.

**Defence:** Helmet's default headers: HSTS, Content-Security-Policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, Referrer-Policy and the cross-origin policies. Production refuses to start unless the refresh cookie is `Secure`.

**Status:** Enforced.

### Unbounded growth of expired credentials

**Attack:** not an attack so much as a slow failure. Expired refresh tokens, verification tokens and sign-in nonces accumulate until the tables dominate the database.

**Defence:** a BullMQ repeatable job deletes rows past their retention: refresh tokens 30 days after expiry, user tokens 7 days, nonces 1 day. Deletes run in bounded batches (1000 rows per statement, 50 per run) so no statement holds locks for long and a backlog is worked down over several runs. Each run logs its counts.

**The rule it follows: delete on expiry, never on use.** Reuse detection recognises a replayed refresh token by finding its used row; removing rows because they were used would turn theft into an ordinary 401 with no family revocation and no alert. Sessions are deliberately never deleted, because `AuthEvent.sessionId` is `onDelete: SetNull` and removing them would strip session ids from historical audit rows.

**Where:** `maintenance/cleanup.service.ts`
**Status:** Enforced. **Tested by:** 11 unit tests, including mutation checks that deleting by `usedAt` or ignoring retention fails.

### Email bombing and duplicate emails

**Attack:** using the resend endpoint to flood someone's inbox. A related failure: a queue retry sending the same email twice.

**Defence:** a cooldown per address when resending. The check runs at `Serializable` isolation with retry, so two simultaneous resends can't both get through. Each email job has an idempotency key based on the token ID, so a retry can't send it twice.

**Status:** **Partial.** Each address is protected, but one IP can still trigger emails to 60 *different* addresses per minute.

---

## 6. Information leakage

### Internal details in error responses

**Attack:** reading stack traces, SQL or Prisma errors in responses to learn how the system is built.

**Defence:** one global exception filter builds every error response from an allowed list of fields: status, message, an optional code and the request ID. It never passes through the exception's own payload. Unexpected errors become a generic 500, and the full stack trace is logged on the server.

**Status:** Enforced. **Tested by:** a test that plants a hash and a query in an exception and checks neither reaches the response.

### Secrets in logs

**Attack:** reading credentials from log storage.

**Defence:** the structured logger removes 17 fields: the authorization and cookie headers, passwords, raw tokens, access and refresh tokens, hashes, API keys, client secrets, and the Google ID token and nonce.

**Status:** **Partial.** See the query-string gap below.

---

## 7. Practices behind the defences

- **Fail closed by default, fail open on purpose.** Route protection is opt-out, so mistakes make things stricter. The denylist and the breach check fail open, because being unavailable must not take down sign-in. Each choice depends on which failure is safer and easier to notice.
- **One way to fail.** Every login failure goes through one constant and one status code. Parity tests check that the responses match exactly, not just that they are "similar".
- **Record everything, punish only real guesses.** All failures are written to the audit log. Only a real wrong password counts toward lockout.
- **Store hashes of secrets, never the secrets.** Passwords are hashed with argon2id; tokens with SHA-256.
- **Correctness comes from atomic database operations.** Single-use tokens and counters rely on conditional updates and atomic increments, not on locks in application code.
- **A side effect only runs after its transaction commits.** Redis writes are queued with `afterCommit`, so a rollback can't leave a revocation that never happened.
- **Clean input at the boundary.** Client-supplied values are validated once, where the request context is built.
- **Ask for the password again before changing credentials.** A valid token proves the client holds a credential, not that the user is present right now.
- **Test seams instead of mocked stacks.** The one class that talks to Google is its own injectable, so end-to-end tests replace it alone and run guards, validation, identity resolution, sessions, cookies and the database for real.
- **Configuration is a contract.** 58 environment rules are checked at startup, including combinations of settings. The app won't start with an unsafe configuration.
- **Tests are checked to see that they fail.** Important guarantees were verified by putting the bug back and confirming the right test fails.
- **Real concurrency is tested on a real database.** Race conditions are reproduced by making transactions overlap in Postgres, not by mocking.
- **Tests boot the deployed setup.** E2E tests use the same `configureApp()` as production.

---

## 8. Known gaps

| Gap | Risk | Fix |
|------|------|------|
| Email verification token sent in the query string (`POST /auth/verify-email?rawToken=…`) | Request logs record the URL, and redaction only covers `req.body`, so raw tokens end up in logs. Risk is low: a logged token has already been used by that request. | Accept the token in the request body; the frontend reads it from the link and POSTs it |
| `register`, `resend-verification-email`, `verify-email` only have the general 60/min limit | Registration spam; emails sent to many different addresses | Apply the `auth` rate-limit profile to these routes |
| Timing difference between new and existing emails at registration and resend | Statistical enumeration | Move the email queueing and row writes off the request path, or pad the response time |
| Per-IP limits only | Spraying from many IPs | Per-account and global anomaly limits |
| Access-token tail with the denylist off | Up to 10 minutes of access after revocation | Enable the denylist in production |
| No double-submit CSRF token | CSRF if the frontend moves to a different site | Add it before any cross-site deployment |
| No MFA | A single stolen password gives full access | Roadmap, after organizations and policy |
| `AUTH_GOOGLE_NONCE_REQUIRED` is off in development | A Google ID token with no nonce is accepted, so a leaked token is replayable within its hour | Turn it on with the frontend that sends the nonce; production already refuses to start without it |


## 9. Before production

- Replace the placeholder JWT secret, issuer, audience and key ID.
- Swap the two session lifetimes in `.env` so the absolute one is the longer (currently `SESSION_ABSOLUTE_TTL_SECONDS` is shorter than `SESSION_REFRESH_TTL_SECONDS`), and add the startup validation rule that enforces it.
- Set how many proxies to trust to the real number in front of the service.
- Decide whether the denylist is on.


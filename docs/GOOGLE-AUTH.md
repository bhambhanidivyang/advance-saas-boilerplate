# Google sign-in: implementation log

How Google sign-in was added to this codebase, step by step, with the reasoning behind each decision. Written as the work happens, so it records what was chosen **and** what was rejected.

Related: [AUTHENTICATION.md](AUTHENTICATION.md) for the password flows, [SECURITY.md](SECURITY.md) for the threat register, [REFACTOR-PRE-GOOGLE.md](REFACTOR-PRE-GOOGLE.md) for the refactor that made this possible.

| Step | What | Status |
|------|------|------|
| G0 | Google Cloud OAuth client | Done |
| G1 | Configuration and the capability flag | Done |
| G2 | Audit event migration | Done |
| G3 | `GoogleTokenVerifier` | Done |
| G4 | `IdentityService`: find, link or create | Done |
| G5 | `GoogleAuthenticatorService` | Done |
| G6 | Endpoint, DTO and `requests.http` | Done |
| G7 | Integration and end-to-end tests | Done |
| G8 | Nonce binding against token replay | Backend done; awaiting frontend for the browser half |

---

## The five decisions this is built on

### 1. The ID-token flow, not the redirect flow

The frontend obtains a signed ID token from Google and POSTs it to our API. We verify it and issue our own session.

The alternative, used by most NestJS tutorials through Passport's `google-oauth20` strategy, redirects the browser to Google and handles a callback. It was rejected because:

- It exists to obtain **access tokens for calling Google APIs**, which this application never does. All we need from Google is proof of identity, and the ID token is exactly that.
- It requires storing and rotating a client secret. The ID-token flow needs none.
- The callback has to hand a session back to a single-page app through a redirect, which is more moving parts and more ways to leak a token in a URL.
- Native mobile sign-in also produces ID tokens, so one endpoint serves web and mobile.

Choose the redirect (authorization code) flow only if this application ever needs to act on a user's behalf in Google Drive, Calendar or Gmail.

### 2. Verify the ID token completely

`google-auth-library`'s `verifyIdToken` checks the signature against Google's published keys, the issuer, and expiry. Two things are our responsibility:

- **`aud` must equal our client ID.** This is the check that matters most. Without it, a token Google issued to *any* application is accepted: an attacker runs their own app, the victim signs into it with Google, and the attacker replays that token here to take over the victim's account. This is the confused-deputy problem, and the audience claim is what prevents it.
- **Identify users by `sub`, never by email.** `sub` is permanent. Email addresses change, and Workspace administrators can reassign one to a different person.

An email from Google is only usable when `email_verified` is `true`.

### 3. Finding, linking or creating the account

1. Look up `AuthIdentity` by `(GOOGLE, sub)`. A hit means a returning user: check the account is active and sign them in. Email is not consulted.
2. No identity, and `email_verified` is not true → reject. We never link or create on an unconfirmed address.
3. Look up `UserEmail` by the normalised address:
   - **No match** → create user, verified primary email and identity in one transaction. `passwordHash` stays null.
   - **Match, our email is verified** → link. Both sides confirmed the same address, which is the standard condition for automatic linking.
   - **Match, our email is unverified** → the **pre-account-hijacking** case, handled below.
4. Two simultaneous first sign-ins both miss step 1 and both insert, so one hits a unique constraint (`P2002`). Catch it and repeat step 1 once. Same principle as refresh-token rotation: the database decides the winner.

**Pre-account hijacking.** An attacker registers with the victim's email and never verifies it. The victim later signs in with Google. If we simply linked the accounts, the attacker's password would still work on the victim's account. So when linking to an account whose email was never verified, one unit of work: link the identity, mark the email verified (Google just proved ownership), **remove the password**, revoke every session with reason `SECURITY`, and expire pending verification tokens. The real owner can set a password later through reset.

Removing the password is a credential operation, so it belongs to `PasswordService`, taking the caller's unit of work.

### 4. What a Google sign-in returns

- `authMethod: GOOGLE`, `emailVerified: true`.
- **`mustChangePassword: false`, always.** That flag is about a password. On a Google session it would block every route, and change-password would answer `NO_PASSWORD_CREDENTIAL`, leaving the user permanently stuck.
- **A password lockout does not block Google sign-in.** The lockout stops password guessing; this is a different proof.
- `createSession` already writes `LOGIN_SUCCESS` with `authMethod = GOOGLE`, so there is no separate "Google login" event.

### 5. Google is an application capability

The first concrete piece of the capability layer: what this deployment *can* offer, as distinct from what an organisation allows. It is configuration, not a per-request database lookup. Organisation-level policy stays deferred until the organisations phase.

---

## G0: Google Cloud setup

An OAuth client of type **Web application** in a development-only project:

| Setting | Value | Why |
|------|------|------|
| Authorised JavaScript origin | `http://localhost:3001` | Matches `FRONTEND_URL`. Google exempts localhost from its HTTPS requirement. |
| Authorised redirect URI | `https://developers.google.com/oauthplayground` | Development only, so tokens can be obtained without a frontend |
| Publishing status | Testing, with the developer added as a test user | Only listed test users can sign in |
| Scopes | `openid`, `email`, `profile` | Non-sensitive, so no Google review is required |

The client secret is **not** stored in this project. It exists only so the OAuth Playground can complete its code exchange; our backend never uses one.

Development and production should use separate clients, so that a production client ID never accepts a token from a test setup.

### Getting a token without a frontend

In the OAuth Playground, tick **Use your own OAuth credentials** and enter the client ID and secret, keep **OAuth flow: Server-side** (the client-side option returns an access token and no ID token), authorise `openid email profile`, then exchange the code. The response contains `id_token`.

Decode it locally rather than pasting it into a web decoder, because a live ID token is a credential:

```bash
echo '<id_token>' | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

A correct token shows `iss: https://accounts.google.com`, `aud` equal to our client ID, `email_verified: true`, and an `exp` an hour after `iat`.

### Claim mapping

| Claim | Column |
|------|------|
| `sub` | `AuthIdentity.providerUserId`, with `provider = GOOGLE` |
| `email` | `UserEmail.email`, normalised, `isVerified = true` |
| `given_name` | `User.firstName` — **required in our schema but not guaranteed by Google**, so fall back to the first word of `name`, then the local part of the email |
| `family_name` | `User.lastName` (nullable) |
| `name` | `User.displayName` |
| `picture` | Not stored. No avatar column, and a Google URL that can expire is worse than nothing. |

---

## G1: Configuration

`.env`:

```
AUTH_GOOGLE_ENABLED=true
GOOGLE_CLIENT_IDS=<id>.apps.googleusercontent.com
```

`env.validation.ts` follows the existing conditional pattern (`MAIL_HOST`, `RESEND_API_KEY`): the setting is required only when the feature is switched on.

```ts
AUTH_GOOGLE_ENABLED: Joi.boolean().default(false),
GOOGLE_CLIENT_IDS: Joi.string().when('AUTH_GOOGLE_ENABLED', {
    is: true,
    then: Joi.string().required().pattern(/…apps\.googleusercontent\.com…/),
    otherwise: Joi.string().optional().allow(''),
}),
```

**The default is `false`**, so a deployment that has not configured Google cannot expose the route by forgetting a variable.

**The pattern is the useful part.** It rejects a pasted client *secret* at startup rather than at the first sign-in, where the failure would look like Google rejecting the user. Verified against eight environment variations: valid ID, two IDs, spaces after commas, empty value, missing key, pasted secret, disabled with empty, and flag absent.

`configuration.ts`, nested under `auth` alongside `jwt` and `session`:

```ts
capabilities: { google: process.env.AUTH_GOOGLE_ENABLED === 'true' },
google:       { clientIds: split on ',', trim, drop empties },
```

`clientIds` is a **list** because web, iOS and Android each get their own client ID and `verifyIdToken` accepts an array for `audience`. One entry today, no change needed later.

---

## G2: Audit event migration

`AuthEventType` gains `IDENTITY_LINKED` and loses `GOOGLE_LOGIN`.

**Why `GOOGLE_LOGIN` was removed rather than kept.** It duplicates `LOGIN_SUCCESS` with `authMethod = GOOGLE`. Two event types for one action means that anyone querying sign-ins silently misses half of them. Removing an enum value in Postgres means recreating the type and rewriting the column under an exclusive lock, and it fails outright if any row still holds the value — so it is cheap now (0 rows, no writer) and expensive later. Unused values that belong to *planned* features (`PASSWORD_RESET`, `OTP_*`, `PHONE_VERIFIED`) stay; only the redundant one goes.

**Why one event covers both linking and account creation.** The metadata carries the distinction, and these are the fields an incident responder needs:

```
{ provider, providerUserId, providerEmail,
  newUser, emailWasUnverified, passwordRemoved, revokedSessions }
```

`emailWasUnverified`, `passwordRemoved` and `revokedSessions` together record that a pre-hijack case was detected and what was done about it.

Migration `20260923102201_remove_google_login_and_add_identity_linked` performs the type swap Postgres requires: create `AuthEventType_new`, cast the column, rename, drop the old type — all in one transaction. It succeeded because no row held the removed value.

---

## G3: GoogleTokenVerifier

`google-auth-library` 11 (CommonJS, so Jest parses it without the `--experimental-vm-modules` trouble `@nestjs/jwt` 12 caused).

Three files:

| File | Purpose |
|------|------|
| `identity/identity.interface.ts` | `ExternalIdentityProfile`: a verified identity in **our** vocabulary. It lives in `identity/`, not `google/`, because `IdentityService` must never learn Google's claim names. A Microsoft or GitHub verifier will produce the same shape. |
| `google/google-token-invalid.error.ts` | A plain `Error`, not an `HttpException` |
| `google/google-token-verifier.ts` | One method: `verify(idToken) -> ExternalIdentityProfile` |

**The security-critical line** is passing `audience: this.clientIds` to `verifyIdToken`. The library checks signature, issuer and expiry on its own; the audience is ours to supply, and without it any token Google ever issued would be accepted — including one minted for an attacker's own application. Pinned by a test, and confirmed by deleting the option and watching that test fail.

**Three boundaries this file keeps:**

- **It reports, it does not decide.** `email_verified` is passed through rather than enforced. Whether an unverified address may be linked to an account is policy, and `IdentityService` owns it.
- **It throws a domain error, not an HTTP status.** This is infrastructure wrapping an HTTP library; choosing 401 and writing the audit event is `GoogleAuthenticatorService`'s job. Its tests never touch Nest's HTTP layer as a result.
- **It normalises the email but not the name.** `email` is a lookup key, so it is lowercased to match `UserEmail`. `firstName` is a display value, so the user's own capitalisation survives.

**The `firstName` fallback chain** (`given_name` -> first word of `name` -> email local part) exists because `User.firstName` is required by our schema while Google does not guarantee `given_name`. Without it, a real sign-in fails on a database constraint.

9 unit tests: audience, claim mapping, lowercase email, unverified email passed through, both fallbacks, and four rejection branches (library refuses, no payload, no `sub`, no `email`).

---

## G4: IdentityService

The step that decides *which user* a verified external identity belongs to. It never sees an ID token or a Google claim name, only an `ExternalIdentityProfile`, so a second provider will need no changes here.

### The algorithm

```
resolveExternalIdentity(profile, context):
  1. AuthIdentity by (provider, providerUserId)?
       found -> account usable? -> sign in.            (email never consulted)
  2. profile.emailVerified false -> refuse.
  3. one transaction:
       UserEmail by email?
         absent            -> create user + verified primary email + identity
         present, verified  -> link identity only
         present, UNVERIFIED -> link + verify email + expire pending tokens
                                + remove password + revoke all sessions (SECURITY)
  4. P2002 -> re-check step 1 once; the winner's row is now visible.
```

### Why each step is shaped that way

**Identity before email.** A returning user is found by the provider's permanent `sub`. Google emails change, and Workspace administrators can reassign them, so letting the email re-decide identity would eventually hand one person's account to another.

**The unverified-email refusal comes after the identity lookup, not before.** An already-linked identity is proof on its own; the email is irrelevant at that point. Refusing earlier would lock out a legitimate returning user whose provider email lost its verified flag.

**The returning-user path opens no transaction.** It is the common case and reads one row. Only the write paths need atomicity.

**The pre-hijack response is all-or-nothing.** Linking an identity while failing to revoke the squatter's sessions is worse than doing neither, so link, email verification, token expiry, password removal and revocation share one unit of work. `PasswordService.removePassword` and `SessionService.revokeSessions` both take that `uow` — the use case owns the transaction, primitives accept it.

**Races are settled by the database.** Two simultaneous first sign-ins both miss step 1 and both insert; one loses on the unique constraint. Rather than serialising the path, the loser re-runs the lookup and returns the winner's user. Same principle as refresh-token rotation. A `P2002` on a *different* constraint is rethrown rather than swallowed.

**`emailVerified` is reported, not assumed.** For a returning user it is read from the stored primary email, so a Google sign-in never silently claims an address is verified when our records say otherwise.

### PasswordService.removePassword

Sets `passwordHash: null`, stamps `passwordChangedAt`, clears `mustChangePassword` and the lockout counters. It takes the caller's `UnitOfWork` rather than using its own client: on a separate connection it would commit immediately and survive a rollback of the surrounding link, leaving the password gone but the defence un-applied. It can also block on a row the open transaction already locked, which Postgres cannot detect as a deadlock.

### Tests

25 unit tests across six groups: returning user, unverified provider email, new account, existing verified account, existing unverified account (the pre-hijack case), and the race.

Verified by deliberately breaking the code and confirming the right tests fail:

| Break | Result |
|------|------|
| Keep the squatter's password | 1 test fails |
| Revoke with `LOGOUT` instead of `SECURITY` | 1 test fails |
| Skip the whole pre-hijack response | 6 tests fail |
| Let suspended and deleted accounts sign in | 2 tests fail |
| Do not retry after losing the race | 1 test fails |

Genuine concurrency and the full pre-hijack effect against real Postgres come in G7; these tests pin the decisions.

---

## G5: GoogleAuthenticatorService

The layer that turns domain errors into HTTP answers and audit rows. Google's counterpart to `PasswordAuthenticatorService`: it produces an `AuthenticationResult` and creates no session, so both sign-in methods finish through the same `AuthService.completeSignIn`.

```
authenticate(idToken, context):
  capability off                -> 404
  verifier.verify               -> GoogleTokenInvalidError        -> audit + generic 401
  identity.resolveExternalIdentity
                                -> ExternalEmailUnverifiedError   -> audit + 403 GOOGLE_EMAIL_UNVERIFIED
                                -> IdentityAccountUnavailableError-> audit + generic 401
                                -> anything else                  -> propagate, no audit
  otherwise -> { userId, GOOGLE, emailVerified, mustChangePassword: false }
```

### Why each answer is what it is

| Situation | Answer | Reasoning |
|------|------|------|
| Capability disabled | **404**, nothing verified | A deployment without Google genuinely has no such route. 403 would confirm the feature exists but is closed to this caller. |
| Invalid token | **401**, generic | Bad signature, wrong audience and expiry must be indistinguishable. The real reason goes to the audit log, never the response. |
| Google has not verified the email | **403** with `GOOGLE_EMAIL_UNVERIFIED` | Actionable, and safe: the caller already holds a Google token for that address, so nothing is disclosed that they do not know. |
| Account suspended or deleted | **401**, generic | The same answer password login gives, so account state stays private. |
| Database or network failure | **propagated** | An outage is not an authentication decision. Turning it into a 401 would tell users their sign-in failed and hide a real incident. |

**Failures are audited, never counted.** The lockout counter exists to stop password guessing. A failed Google sign-in is not a guess, and counting it would let anyone lock an account out by replaying junk tokens — the same trap that made lockout a weapon before.

**`mustChangePassword` is forced to `false`**, even if the identity layer were to report otherwise. That flag is about a password; a Google-only account has none, so a `true` value would block every route while change-password answered `NO_PASSWORD_CREDENTIAL`.

**`emailVerified` comes from our records**, via `IdentityService`, not from the Google claim. A Google sign-in never silently upgrades an address our own data says is unverified.

### Tests

15 unit tests. Verified by deliberate breakage:

| Break | Result |
|------|------|
| Trust a `mustChangePassword` coming from the identity layer | 1 test fails |
| Ignore the capability flag | 1 test fails |
| Put the token failure reason in the response | 2 tests fail |
| Stop mapping `IdentityAccountUnavailableError` | 2 tests fail |

---

## G6: The endpoint

`POST /auth/google`, public, under the 5/min `auth` rate limit rather than the general 60/min.

```ts
// AuthService
async loginWithGoogle(body: GoogleLoginDto, context: AuthContext): Promise<LoginResult> {
    const authentication = await this.googleAuth.authenticate(body.idToken, context);
    return this.completeSignIn(authentication, context);
}
```

**Two lines, and the second is shared verbatim with password login.** This is what the pre-Google refactor was for: a whole sign-in method arrived without a line of new session, cookie or token code.

`GoogleLoginDto` bounds the input at 4096 characters before checking the JWT shape, so junk input is rejected cheaply — a real Google ID token is about 1 KB.

**One response builder for both routes.** `AuthController.respondWithSession` sets the refresh cookie and builds the body field by field. Password login and Google login both call it. Two hand-written builders would eventually diverge, and the way they diverge is that the second one spreads `session` into the body and puts the raw refresh token in JSON, undoing `httpOnly`. One function, one place to get it right, and the same test guards both.

### Testing it by hand

`requests.http` has two entries: a real token pasted from the OAuth Playground, and a syntactically valid but unsigned token that must return the generic 401.

A gotcha worth recording: `.http` variables are raw text. Writing `@googleIdToken = "eyJ..."` with quotes expands to `"idToken": ""eyJ...""` and produces a JSON parse error near the end of the token, which reads like a server bug but is a quoting mistake. Define the variable without quotes.

### Tests

- **Controller** (4 new): the token and context reach the service; the refresh token never appears in the body; the cookie is set with `httpOnly` and `Path=/auth`; a rejected token (401) and a disabled capability (404) both propagate with no cookie set.
- **Orchestration** (3 new, in `auth.service.login.spec.ts` beside the password ones): the raw token goes to the Google authenticator and the password authenticator is untouched; the session is created through the same `completeSignIn`; a failed verification creates no session.

Verified by breakage: spreading the session into the Google response body (1 test fails), recording a Google sign-in as `PASSWORD` (1 fails), and creating the session before verifying the token (3 fail).

Adding a second sign-in method also changed three existing specs: every spec that constructs `AuthService` now provides a `GoogleAuthenticatorService` stub. That is the cost of constructor injection, and it is the cheap kind — the compiler and the tests point straight at each place.

---

## G7: Tests that need real infrastructure

Mocks cannot prove two things: that a unique constraint settles a race between simultaneous first sign-ins, and that the pre-hijack response actually lands on real rows. Both now have tests.

### Integration, against real Postgres (8 tests)

`identity.service.integration.spec.ts`, run with `pnpm test:integration`.

| Test | What only a real database shows |
|------|------|
| First sign-in creates user, verified primary email and identity | The nested write really produces one user with `passwordHash` null |
| The next sign-in resolves the same user, and `IDENTITY_LINKED` is recorded once | The returning path does not re-link |
| **Two simultaneous first sign-ins** produce exactly one user, one identity, one email, and both callers get the same id | Uses `installTransactionOverlapBarrier(prisma, 2)` to hold both transactions until both have arrived. Removing the `P2002` retry makes this test fail, which proves the collision is genuinely happening rather than the calls quietly serialising. |
| Linking to a **verified** account leaves the password and the live session untouched | — |
| Pre-hijack: password removed, lockout counters cleared, both sessions revoked with `SECURITY`, email verified | The whole unit of work committing together |
| Pre-hijack: no live refresh token survives | `revokeSessions` retires tokens, not just sessions |
| Pre-hijack: the pending verification token is expired | The squatter cannot finish verifying afterwards |
| Pre-hijack: one `IDENTITY_LINKED` event with `passwordRemoved: true, revokedSessions: 2` | The incident trail is written from real counts |

### End to end, through the real HTTP stack (9 tests)

`test/google-auth.e2e-spec.ts`, run with `pnpm test:e2e`.

**Only `GoogleTokenVerifier` is replaced**, with `.overrideProvider(...).useValue({ verify })`. Real Google ID tokens cannot be obtained in a test run, and that class is the single place this codebase talks to Google — which is exactly why it exists as its own injectable. Everything after it runs for real: validation pipe, guards, throttler, identity resolution, session creation, cookies, Postgres and Redis. **This is the payoff of a test seam**: one substitution buys a full-stack test of everything else.

- First sign-in returns a session and creates an account with no password, a verified email and one identity.
- The refresh token arrives only as an `HttpOnly` cookie scoped to `/auth`, and never appears in the body.
- The access token opens a guarded route, and the cookie rotates at `/auth/refresh` — so a Google session is an ordinary session in every respect.
- A returning user resolves to the same account, with still one identity.
- A token Google refuses gives a generic 401 with no cookie and no reason disclosed.
- An unverified Google email gives 403 `GOOGLE_EMAIL_UNVERIFIED`.
- A missing or non-JWT `idToken` gives 400 **without calling the verifier at all**.
- Pre-hijack, end to end: register with a password, sign in successfully, then sign in with Google on the same address — the password now returns 401 and the session it created can no longer refresh.

A detail worth keeping: `GoogleLoginDto` validates the JWT shape with `@IsJWT`, so malformed input is rejected before any verification work. E2E fixtures therefore have to be JWT-shaped, even though the verifier is replaced.

### Totals after G7

| Suite | Count |
|------|------|
| Unit | 27 suites, 295 tests |
| Integration (real Postgres) | 3 suites, 17 tests |
| End to end | 2 suites, 27 tests |

---

## G8: Nonce binding against token replay

### The problem

A Google ID token is a **bearer credential**: whoever holds it can present it, from any address, as many times as they like, for the hour Google keeps it valid. Nothing inside the token distinguishes a replay from the original request — same signature, same audience, same expiry.

Ways one leaks in practice: our own request logs, frontend error reporting that captures request bodies, a third-party script on the sign-in page, a browser extension, or any proxy where TLS terminates. The first of those was real here until this step: the pino redaction list covered `password`, `refreshToken` and `token`, but not `idToken`, so every Google sign-in wrote the whole token into the logs in plaintext. `req.body.idToken` and `req.body.nonce` are now redacted.

### The fix

1. The client asks for a nonce: `POST /auth/google/nonce`. We generate 32 random bytes, store **only their SHA-256** with a five-minute expiry, and return the raw value.
2. The client passes it to Google: `google.accounts.id.initialize({ client_id, nonce, callback })`.
3. Google puts it in the ID token as the `nonce` claim — inside the signed payload, so it cannot be altered.
4. We consume it: a conditional `updateMany` claims the row only while `usedAt IS NULL` and unexpired. A count other than 1 is a rejection.

A stolen token is then worthless: its nonce was spent by the sign-in that produced it, and the attacker cannot obtain a fresh token without authenticating to Google as the victim. It also shortens the exposure from Google's hour to our five minutes.

### Enforcement policy

> **A nonce that is present is always verified. A missing nonce is rejected only when `AUTH_GOOGLE_NONCE_REQUIRED` is on.**

Verifying a present nonce unconditionally is the important half: if the check only ran while the flag was on, an attacker could strip the claim and fall back to the permissive path. The flag exists because the browser half cannot be built yet — the nonce reaches Google through the sign-in button, which only a frontend can do — and because the OAuth Playground, the only way to obtain a real token today, never sends one.

A Joi rule makes it **mandatory in production** when Google is enabled, so the permissive mode cannot reach a deployment by accident.

### Order of operations

```
verify the token  ->  consume the nonce  ->  resolve the identity
```

Verifying first means a junk token never burns a nonce. Consuming before identity resolution means a replayed token never reaches account creation or linking. Both nonce failures — replayed/expired and missing-while-required — answer the same generic 401 while the audit log keeps `NONCE_INVALID` or `NONCE_MISSING`.

### Storage: Postgres, not Redis

`AuthNonce` (`nonceHash` unique, `provider`, `expiresAt`, `usedAt`) holds the hash, like every other token in this system.

A nonce cannot fail open — accepting a sign-in whose nonce could not be checked defeats the point — so whatever stores it becomes a hard dependency of Google sign-in. Postgres already is one. Redis deliberately is not: the access-token denylist fails open so a Redis outage never stops people signing in, and putting the nonce there would quietly make Redis mandatory.

`OAuthState` stays in the schema, reserved for the OIDC redirect flow as a future capability. That is a *pending* model rather than a *redundant* one, the same distinction applied when the redundant `GOOGLE_LOGIN` event was removed.

### Tests

| Level | Coverage |
|------|------|
| Verifier (3 new) | The `nonce` claim is returned beside the profile, is absent when the token carries none, and never lands on the identity profile — it describes the token, not the person |
| Nonce service (8) | Expiry from configuration; only the hash is stored; two issues never collide; the conditional claim matches only unused and unexpired rows; a second use is rejected |
| Authenticator (7 new) | Consumed when present; consumed **before** identity resolution; not consumed when the token itself is rejected; a bad nonce becomes the generic 401 with `NONCE_INVALID`; a present nonce is verified even with the flag off; absent is fine while off; absent is rejected with `NONCE_MISSING` when on |
| Integration, real Postgres (5) | One use stamps `usedAt`; a second use fails; **two simultaneous consumptions leave exactly one winner**; expired and never-issued are rejected |
| End to end (4) | `POST /auth/google/nonce` issues one; a token carrying it signs in; **the same token replayed with a spent nonce gets 401 and no cookie**; a nonce we never issued is rejected and creates no account |

### What still needs the frontend

Only step 2. The nonce has to reach Google through the sign-in button, so the full round trip can be exercised only once a frontend calls `initialize({ nonce })`. Until then `AUTH_GOOGLE_NONCE_REQUIRED` stays off in development, and the e2e suite proves the server half by supplying the claim through the replaced verifier.

---

## Open items

- `OAuthState` in the schema (`stateHash`, `nonceHash`, `redirectTo`) was built for the redirect flow we rejected. Either use `nonceHash` for the G8 replay protection or drop the model in a later migration.
- Expired `AuthNonce` rows are never deleted. Each sign-in leaves one behind; it belongs with the refresh-token cleanup job already on the roadmap.
- `AUTH_GOOGLE_NONCE_REQUIRED` is off in development until a frontend sends the nonce. Production refuses to start with it off while Google is enabled.
- The nonce is not bound to the browser that requested it. Binding one through an httpOnly cookie would also stop an attacker using a nonce they fetched themselves; the current design already stops token replay, which is the attack that matters.
- `google-auth-library` fetches Google's signing keys over HTTP with no timeout configured, so a sign-in can hang if that endpoint is unreachable. The keys are cached, so this only bites on a cold cache. To be addressed with the G8 hardening.

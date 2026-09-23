# Refactor before Google sign-in

**Goal:** put all password code in one place, and split login into two parts, *proving who the user is* and *starting a session*, so Google sign-in can reuse the second part.

**Rule:** this refactor must not change behaviour. The 16 e2e journeys must pass **without being edited**. If an e2e test needs to change, the refactor has changed behaviour.

---

## Target shape

```
src/auth/
  auth.controller.ts
  auth.controller.spec.ts
  auth.module.ts
  auth.service.ts                         orchestrator: register, verify email, login
  auth.service.spec.ts
  auth.service.login.spec.ts              NEW, small: tests only the orchestration
  auth.service.integration.spec.ts
  password/
    password-authenticator.service.ts     NEW: login proof → AuthenticationResult
    password-authenticator.service.spec.ts  (the current login spec, moved and adapted)
    password.service.ts                   change password (reset later)
    password.service.spec.ts
    password-hash.util.ts
    password-lockout.constants.ts         NEW: shared "lockout cleared" data
    password.interface.ts
    validation/
      meets-password-policy.decorator.ts
      is-not-breached.decorator.ts
      is-not-common-password.decorator.ts
      common-passwords.util.ts
  session/
    session.service.ts                    + its 4 spec files
    token.service.ts                      + spec
    session-denylist.service.ts           + spec
    session-cookie.util.ts
  constants/  dto/  interfaces/  utils/   unchanged, apart from the files moved out
```

**Why these boundaries:**

- `password/` contains two classes because login and change password follow opposite rules. Login gives one generic error and must take the same time on every path. Change password gives specific error codes. Keeping them apart stops a helper written for one from leaking its behaviour into the other.
- `session/` holds everything that runs *after* the user is identified, which is the same for every sign-in method. Moving it removes `providers/` completely.
- `dto/` stays as it is: DTOs describe the controller's HTTP contract, and there is still one controller.
- The shared types (`authentication-result`, `auth-context`, `session`) stay in `interfaces/`, because every sign-in method uses them.

---

## Step 0: Baseline

1. Commit the currently staged work first, so the refactor diff contains only the refactor.
2. Run everything and write down the counts:
  ```
   pnpm exec tsc --noEmit
   pnpm test                 # expect 23 suites / 233 tests
   pnpm test:integration     # expect 2 suites / 9 tests
   pnpm test:e2e             # expect 1 suite / 16 tests
  ```
3. Create a branch: `git checkout -b refactor/password-authenticator`.

---

## Step 1: Move files (no logic changes)

Use `git mv` so git records these as renames and keeps each file's history.

### 1a. Password files


| From                                                        | To                                                                                      |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `src/auth/providers/password.service.ts`                    | `src/auth/password/password.service.ts`                                                 |
| `src/auth/providers/password.service.spec.ts`               | `src/auth/password/password.service.spec.ts`                                            |
| `src/auth/utils/password-hash.util.ts`                      | `src/auth/password/password-hash.util.ts`                                               |
| `src/auth/interfaces/password.interface.ts`                 | `src/auth/password/password.interface.ts`                                               |
| `src/common/decorators/meets-password-policy.decorator.ts`  | `src/auth/password/validation/meets-password-policy.decorator.ts`                       |
| `src/common/decorators/is-not-breached.decorator.ts`        | `src/auth/password/validation/is-not-breached.decorator.ts`                             |
| `src/common/decorators/is-not-common-password.decorator.ts` | `src/auth/password/validation/is-not-common-password.decorator.ts`                      |
| `src/auth/utils/common-passwords.utils.ts`                  | `src/auth/password/validation/common-passwords.util.ts` (also fixes the plural `utils`) |


### 1b. Session files


| From                                                            | To                                        |
| --------------------------------------------------------------- | ----------------------------------------- |
| `src/auth/providers/session.service.ts`                         | `src/auth/session/session.service.ts`     |
| `src/auth/providers/session.service.spec.ts`                    | `src/auth/session/`                       |
| `src/auth/providers/session.service.revoke.spec.ts`             | `src/auth/session/`                       |
| `src/auth/providers/session.service.rotate.spec.ts`             | `src/auth/session/`                       |
| `src/auth/providers/session.service.rotate.integration.spec.ts` | `src/auth/session/`                       |
| `src/auth/providers/token.service.ts` + `token.service.spec.ts` | `src/auth/session/`                       |
| `src/auth/providers/session-denylist.service.ts` + spec         | `src/auth/session/`                       |
| `src/auth/utils/session-cookie.util.ts`                         | `src/auth/session/session-cookie.util.ts` |


### 1c. Auth service files


| From                                                  | To                                                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `src/auth/providers/auth.service.ts`                  | `src/auth/auth.service.ts`                                                                  |
| `src/auth/providers/auth.service.spec.ts`             | `src/auth/auth.service.spec.ts`                                                             |
| `src/auth/providers/auth.service.login.spec.ts`       | `src/auth/password/password-authenticator.service.spec.ts` (renamed now, adapted in step 5) |
| `src/auth/providers/auth.service.integration.spec.ts` | `src/auth/auth.service.integration.spec.ts`                                                 |


`src/auth/providers/` should now be empty. Delete it.

### 1d. Fix imports

These files import something that moved:


| File                                                       | What to fix                                                                                                                                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth.module.ts`                                           | the 5 service imports                                                                                                                                                                   |
| `auth.controller.ts`                                       | `auth.service`, `session.service`, `password.service`, `session-cookie.util`, `password.interface`                                                                                      |
| `auth.controller.spec.ts`                                  | the 3 service imports                                                                                                                                                                   |
| `auth.service.ts`                                          | `session.service`, `password-hash.util`; the `../` paths to `utils/`, `interfaces/` and `constants/` become `./`                                                                        |
| `password.service.ts`                                      | `session.service` → `../session/session.service`; `password-hash.util` → `./password-hash.util`; `password.interface` → `./password.interface`                                          |
| `password.service.spec.ts`                                 | **also the path in `jest.mock('../utils/password-hash.util')` → `jest.mock('./password-hash.util')`.** If you forget it, the mock silently stops applying and the spec runs real argon2 |
| the session specs, `session.service.ts`                    | `../utils/token.util`, `../interfaces/...`: same depth, so these stay `../`                                                                                                             |
| `common/guards/jwt-auth.guard.ts` + spec                   | `src/auth/providers/token.service` → `src/auth/session/token.service`; same for `session-denylist.service`                                                                              |
| `dto/create-new-user.dto.ts`, `dto/change-password.dto.ts` | `src/common/decorators/meets-password-policy.decorator` → `src/auth/password/validation/meets-password-policy.decorator`                                                                |
| `password/validation/meets-password-policy.decorator.ts`   | its `./is-not-breached.decorator` import stays the same; check for an `is-not-common-password` import                                                                                   |
| `password/validation/is-not-common-password.decorator.ts`  | `src/auth/utils/common-passwords.utils` → `./common-passwords.util`                                                                                                                     |


Note: the moved login spec still imports `./auth.service` and still tests `AuthService`. It moved folders, so fix its paths to `../auth.service` and `../session/session.service` for now. Step 5 rewrites it.

### 1e. Verify and commit

```
pnpm exec tsc --noEmit
git grep -n "auth/providers\|common/decorators/meets-password\|utils/password-hash\|utils/session-cookie"   # must print nothing
pnpm test && pnpm test:integration && pnpm test:e2e       # same counts as step 0
```

Commit: `refactor(auth): group password and session code into folders`.

**Why a separate commit:** a move combined with logic changes is almost impossible to review, because git's rename detection fails when a file changes too much. This commit contains only import changes.

---

## Step 2: Shared lockout constant

**Add** `src/auth/password/password-lockout.constants.ts`:

- Export one constant, CLEARED_LOCKOUT_STATE, with `passwordFailedAttempts: 0` and `passwordLockedUntil: null`.
- Type it with `satisfies Prisma.UserUpdateInput`. That checks the field names against the schema but keeps the literal type, so a renamed column fails to compile.

**Use it** (spread it into `data`):

- `PasswordService.changePassword`: replace the two inline lockout fields in the `user.update`.
- `AuthService.resetPasswordFailureState`: replace its `data`. This method moves in step 3, and the constant goes with it.

**Why a constant and not a shared function:** both callers write other fields in the same `update` and use their own transaction. Sharing the data fits both. A shared function would need extra parameters for each caller's differences.

---

## Step 3: Create `PasswordAuthenticator`

**Add** `src/auth/password/password-authenticator.service.ts`, an `@Injectable()` class.

**Dependencies:** `PrismaService`, `ConfigService`, `Logger`. **Not `SessionService`.** Leaving it out means the authenticator can't create a session, and Nest's dependency injection enforces that for you. This is the architecture rule "authenticators never create sessions", enforced by the dependency list rather than by a comment.

**Public method:**

```
authenticate(credentials: PasswordCredentials, context: AuthContext): Promise<AuthenticationResult>
```

- `PasswordCredentials` is a new small interface `{ email: string; password: string }`, in `password/password.interface.ts`. Use it instead of `LoginDto`, so the authenticator doesn't depend on the HTTP layer. `LoginDto` has the same shape, so the controller can still pass the body straight in.
- It returns `AuthenticationResult`, unchanged: `userId`, `authMethod: PASSWORD`, `emailVerified`, `mustChangePassword`.

**Moves from `AuthService` into it:**


| Member                                                                                           | Becomes                                                                                                                                      |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `login` body, from `normalizeEmail` through the failure branches, success reset and hash upgrade | `authenticate()` body, ending with `return { userId, authMethod, emailVerified, mustChangePassword }`                                        |
| `findActiveUserByEmail`                                                                          | private `findPasswordAccount(email)`: same `where`, same `select`. It no longer takes a transaction, since login always passed `this.prisma` |
| `dummyPasswordHash`                                                                              | private field, same comment                                                                                                                  |
| `recordFailedLogin`                                                                              | private, unchanged                                                                                                                           |
| `recordNonCountingLoginFailure`                                                                  | private, unchanged                                                                                                                           |
| `resetPasswordFailureState`                                                                      | private, using `CLEARED_LOCKOUT_STATE`                                                                                                       |
| `upgradePasswordHashIfNeeded`                                                                    | private, unchanged                                                                                                                           |


**Imports that move with it:** `verifyPassword`, `passwordNeedsRehash`, `hashPassword` (for the dummy hash and the upgrade), `randomBytes`, `GENERIC_LOGIN_RESPONSE`, `LOGIN_FAILURE_REASON`, `AuthMethod`, `logAuditEvent`, `UnauthorizedException`.

**Register it:** add `PasswordAuthenticator` to `providers` in `auth.module.ts`. Don't export it; nothing outside the module needs it.

**Why it's called an "authenticator":** it answers one question, "is this person who they say they are?", and returns proof. `GoogleAuthenticator` will answer the same question from a Google ID token and return the same type. That shared return type is how every sign-in method arrives at the same session code.

---

## Step 4: Slim down `AuthService`

### Remove

- The five private login helpers and `dummyPasswordHash` (moved in step 3).
- `findActiveUserByEmail` (see "Add" for its replacement in registration).
- Imports no longer used: `verifyPassword`, `passwordNeedsRehash`, `randomBytes`, `GENERIC_LOGIN_RESPONSE`, `LOGIN_FAILURE_REASON`. **Keep `logAuditEvent`,** since `verifyEmail` still writes `EMAIL_VERIFIED`. Keep `hashPassword`, since `register` uses it. `tsc` plus ESLint's unused-imports rule will confirm.

### Add

- Constructor dependency: `private readonly passwordAuthenticator: PasswordAuthenticator`.
- `**private async completeSignIn(authentication: AuthenticationResult, context: AuthContext): Promise<LoginResult>`**. It contains the current tail of `login`: call `sessionService.createSession` with the result's fields and the context, then build `LoginResult`.
**This is the single point where every sign-in method ends.** Google login will be `googleAuthenticator.authenticate(...)` followed by `completeSignIn(...)`, so sessions are issued in exactly one place.
- **Registration's own lookup:** a private `isEmailRegistered(tx, email): Promise<boolean>`, selecting only `id`.
  - It doesn't filter on `status` or `deletedAt`. Registration is asking "does anyone own this email?", which is what the database's unique constraint on email enforces. Today a suspended user's email passes the filtered lookup, fails the insert with `P2002`, and gets the generic response anyway. The response doesn't change; the unnecessary round trip goes away.
  - It no longer reads the password hash or lockout fields, which registration never used.

### Change

`login` becomes:

```
async login(body: LoginDto, context: AuthContext): Promise<LoginResult> {
    const authentication = await this.passwordAuthenticator.authenticate(body, context);
    return this.completeSignIn(authentication, context);
}
```

An authentication failure throws before `completeSignIn`, so a failed login can't create a session. That ordering is the guarantee, and step 5 tests it.

### Unchanged

`register`, `resendVerifyEmail`, `verifyEmail`, and all the email-token helpers. Google doesn't use them. Password reset will move them into a `UserTokenService` later, when a second caller exists.

---

## Step 5: Split the tests

### 5a. `password/password-authenticator.service.spec.ts` (the moved login spec)

- Build `PasswordAuthenticator` in the testing module instead of `AuthService`. Remove the `SessionService` and `EmailService` providers.
- Keep `jest.mock('argon2', ...)` as it is: the hash util still calls argon2, so the mock still intercepts.
- **Enumeration, timing and lockout tests:** keep them, changing only `service.login(...)` to `authenticator.authenticate(...)`.
- **Success tests:**
  - "resets the failure state and returns the issued session" → assert the returned `AuthenticationResult` is `{ userId: 'user-1', authMethod: AuthMethod.PASSWORD, emailVerified: true, mustChangePassword: false }`, and that the lockout reset ran.
  - "surfaces mustChangePassword" → assert it on the result, not on `user`.
  - Both hash-upgrade tests: unchanged apart from the call.
  - **Remove** "creates exactly one session" and "does not leak the request context". They belong to the orchestrator now (5b).
- **Add** one test: "never touches sessions". Assert that `prisma` has no `session` or `sessionRefreshToken` calls, so a future change that creates sessions here is caught.

### 5b. New `auth.service.login.spec.ts` (orchestrator only)

Mock `PasswordAuthenticator` and `SessionService`. Four tests:

1. Passes the body and context through to `authenticate` unchanged.
2. Calls `createSession` once, with the result's `userId`, `authMethod`, `emailVerified`, `mustChangePassword` and the context.
3. Returns `{ session, user: { id, emailVerified, mustChangePassword } }` without the context.
4. **When `authenticate` throws, `createSession` is never called and the same exception is thrown.** This is the most important test in the refactor.

### 5c. Other specs that build `AuthService`

`auth.service.spec.ts` and `auth.service.integration.spec.ts` need `{ provide: PasswordAuthenticator, useValue: {} }` added to their providers. Otherwise dependency injection fails when the module compiles. They test registration and verification, so an empty object is enough.

### 5d. Unchanged

`auth.controller.spec.ts` (it mocks `AuthService`), all session specs, `password.service.spec.ts` (apart from step 1's path fix), and **all e2e tests**.

### 5e. Check that the tests can fail

Break the code on purpose, confirm the right test fails, then undo:

- In `login`, call `completeSignIn` before `authenticate`: 5b test 4 should fail.
- In `authenticate`, skip argon2 when the user is missing: the timing test should fail.
- In `changePassword`, remove the `CLEARED_LOCKOUT_STATE` spread: a change-password assertion should fail. If none does, add one.

---

## Step 6: Unrelated fix while you're in the file

`auth.service.ts`, `updateUserEmail`: change `return tx.userEmail.update(...)` to `return await tx.userEmail.update(...)`. Without `await`, the promise fails after the `try` block has already exited, so the `P2025` handler never runs. It's the same bug that was fixed in `consumeToken`.

Commit it on its own: `fix(auth): await email update so P2025 is mapped`.

---

## Step 7: Verify and commit

```
pnpm exec tsc --noEmit
pnpm lint
pnpm test                 # suite count +1 (the new orchestrator spec); test count changes by the moves in step 5
pnpm test:integration     # 2 / 9
pnpm test:e2e             # 1 / 16, with no e2e edits
```

Then run login through `requests.http` once by hand: a wrong password and a right one. Check the 401 body is unchanged and the cookie is set.

Commit: `refactor(auth): extract PasswordAuthenticator; AuthService orchestrates sign-in`.

Update `docs/AUTHENTICATION.md`: its file paths (`SessionService` and the password policy decorator moved), and add `PasswordAuthenticator` to the patterns section as the first authenticator.

---

## Summary


|                                    | Count                                                                                                     |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Files moved                        | 22 (15 from `providers/`, plus 3 utils, 3 decorators and 1 interface)                                     |
| Files added                        | 3: `password-authenticator.service.ts`, `password-lockout.constants.ts`, new `auth.service.login.spec.ts` |
| Folders removed                    | 1: `src/auth/providers/`                                                                                  |
| Methods moved out of `AuthService` | 6 plus the login body                                                                                     |
| Methods added to `AuthService`     | 2: `completeSignIn`, `isEmailRegistered`                                                                  |
| Behaviour changes                  | none; the e2e suite proves it                                                                             |


`AuthService` shrinks from about 680 lines to about 470, and no longer contains any password-verification code.

---

## What Google adds afterwards (for context, not part of this refactor)

- `google/google-authenticator.service.ts`: verifies the Google ID token (signature, `aud` = our client ID, `iss`, expiry) and returns an `AuthenticationResult` with `authMethod: GOOGLE`.
- `identity/identity.service.ts`: finds the user by `AuthIdentity (provider, providerUserId)`, links by verified email, or creates the user. It applies the pre-account-hijacking rule: link only when both emails are verified, and otherwise remove the unverified password and revoke its sessions (see [SECURITY.md](SECURITY.md)).
- `AuthService.loginWithGoogle(idToken, context)`: `googleAuthenticator.authenticate(...)`, then `completeSignIn(...)`. This is the reason for the refactor: Google needs no session code of its own.


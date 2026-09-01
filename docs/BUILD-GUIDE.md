# SaaS backend build guide

This document takes you from an empty folder to **the current state of this repository**. Follow the chapters in order. After each chapter there is a **checkpoint** so you know you are aligned with the app.

The finished backend is a NestJS 11 API named `backend` in config (`APP_NAME=backend`). It uses PostgreSQL (Prisma 7), Redis (rate limits + email jobs), and Mailpit (local email). A person can **register**. The account is stored with a hashed password and a hashed email-verification token. A background worker sends the verification email. **Login, verify-email HTTP, Google, organizations, RBAC, and billing APIs are not implemented yet.** Their **tables** already exist in the schema.

**How to use this file:** treat each numbered step as something to do. Concept sections explain *why* before you paste code. Match file paths and behavior to this repo; copy from `src/` if a snippet is abbreviated.

---

## What “current state” means (end of this guide)

If you finished every chapter you should have:

| Area | Behavior |
|------|----------|
| Process | `pnpm run start:dev` listens on `PORT` (default 3000) |
| Health | `GET /health` returns `{ status: 'ok', database: 'ok' }` after a `SELECT 1` |
| Security | Helmet, CORS from `FRONTEND_URL`, 256kb JSON limit, global ValidationPipe, Redis throttling, Pino logs with redaction, global exception JSON |
| Database | Prisma schema + `init` migration applied; `PrismaService` with `@prisma/adapter-pg` |
| Auth | `POST /auth/register` only; `login()` and `verifyEmail()` are stubs |
| Email | BullMQ queue `email`; SMTP via Nodemailer (pooled, timeouts from env); templates; Mailpit; enqueue failure does **not** roll back the user (`emailStatus: FAILED`) |
| Not done | Verify-email API, login/sessions, OTP, OAuth, orgs, RBAC, billing runtime, Resend send implementation |

---

## Prerequisites

- Node.js 22+ (or whatever Nest 11 supports on your machine)
- pnpm
- Docker or Podman Compose
- A REST client (VS Code/Cursor REST Client using `src/requests.http`, or curl)

Create the project with the Nest CLI, or clone this repo and skip to “run locally” at the end if you only want to operate it.

---

## Chapter 1 — Create the Nest project

**Goal:** TypeScript Nest app with ESLint, Prettier, Jest. No Hello World route.

1. Run `nest new mynest` (TypeScript).
2. Use **pnpm** (`pnpm-lock.yaml`, `pnpm-workspace.yaml`). Prisma’s generate step needs workspace build allowances if you use a pnpm workspace.
3. Delete `AppController` and `AppService`. Remove them from `AppModule`. Root `GET /` should not exist.

**Why:** A SaaS API should not ship a tutorial route. Health will be the liveness URL.

**Checkpoint:** `pnpm run start:dev` starts and there is no `GET /`.

---

## Chapter 2 — Configuration (env that cannot be wrong)

**Concept:** In production, a missing `DATABASE_URL` should crash **at boot**, not on the first request. `@nestjs/config` loads `.env`. **Joi** (`env.validation.ts`) validates types and required keys. `configuration.ts` maps env vars into a nested object so the rest of the app reads `config.get('app.port')` instead of `process.env.PORT` everywhere.

1. Install: `pnpm add @nestjs/config joi`
2. Create `.env` (never commit it). Shape used **today**:

```
DATABASE_URL=postgresql://mynest:mynest_dev@localhost:5432/mynest
APP_NAME=backend
NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:3001
ENABLE_HIBP_CHECK=true
ENABLE_COMMON_PASSWORD_CHECK=true
REDIS_URL=redis://localhost:6379
THROTTLE_DEFAULT_TTL=60000
THROTTLE_DEFAULT_LIMIT=60
THROTTLE_AUTH_TTL=60000
THROTTLE_AUTH_LIMIT=5
THROTTLE_OTP_TTL=600000
THROTTLE_OTP_LIMIT=3
EMAIL_PROVIDER=smtp
MAIL_FROM="SaaS App Dev <noreply@dev.mynest.com>"
MAIL_HOST=localhost
MAIL_PORT=1025
MAIL_USER=
MAIL_PASS=
MAIL_SECURE=false
MAIL_VERIFICATION_TOKEN_TTL=24
MAIL_POOL=true
MAIL_MAX_CONNECTIONS=5
MAIL_MAX_MESSAGES=100
MAIL_CONNECTION_TIMEOUT=10000
MAIL_GREETING_TIMEOUT=10000
MAIL_SOCKET_TIMEOUT=30000
RESEND_API_KEY=
```

You can add these keys **as you reach** Redis, throttling, and email chapters. Joi currently requires all of them at boot, so for a follower building from scratch either add Joi rules incrementally or add the keys when you add the modules.

3. Implement `src/config/configuration.ts` and `src/config/env.validation.ts` as in this repo.
4. In `AppModule`:

```ts
ConfigModule.forRoot({
  isGlobal: true,
  load: [configuration],
  validationSchema: envValidationSchema,
  cache: true,
})
```

`isGlobal` means feature modules do not import ConfigModule. `cache: true` avoids re-parsing env on every `get`.

**Checkpoint:** Wrong `FRONTEND_URL` (not a URI) prevents the process from starting.

---

## Chapter 3 — HTTP security in `main.ts`

These run on **every** request. Do this **before** Auth.

Install:

```bash
pnpm add helmet class-validator class-transformer
```

Read `FRONTEND_URL` and `PORT` from `ConfigService` after `NestFactory.create(AppModule)`.

### 3.1 Helmet

**Concept:** Helmet is not login. It sets **HTTP response headers** so browsers behave more safely.

Without it, you often only send `Content-Type`. With `app.use(helmet())` you typically also get:

- **`X-Content-Type-Options: nosniff`** — the browser must not guess a different type (e.g. treat JSON as HTML/JS).
- **`X-Frame-Options` / frame-ancestors** — reduces **clickjacking** (your UI inside an attacker’s iframe).
- **`Content-Security-Policy`** — which origins may load scripts. More important for HTML pages than a JSON API.
- **`Strict-Transport-Security`** — prefer HTTPS on later visits (matters when you actually terminate TLS).
- **`Referrer-Policy`** — how much of your URL is sent to other sites.

Start with `app.use(helmet())`. Tune later if you add Swagger UI or HTML.

### 3.2 CORS

**Concept:** A **origin** is scheme + host + port. `http://localhost:3001` (frontend) and `http://localhost:3000` (API) are different origins. The browser blocks the frontend from reading the API response unless the API allows that origin.

```ts
app.enableCors({
  origin: configService.get<string>('app.frontendUrl'),
  credentials: true,
});
```

`origin` must be the real frontend URL, not `*`, if you use cookies.

**`credentials: true`** means the browser **may send cookies** on cross-origin calls (if the frontend uses `credentials: 'include'`). It does **not** mean the user is authenticated. It is for **cookie-based** sessions later. Pure `Authorization: Bearer` APIs often omit it.

### 3.3 JSON body limit

```ts
app.use(json({ limit: '256kb' }));
```

**Concept:** Express will parse the whole JSON body into memory. Without a limit, an attacker can POST tens of megabytes to `/auth/register` and exhaust RAM. Signup fields fit in 256kb.

### 3.4 Global ValidationPipe

```ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
);
```

**Concept:** Incoming JSON is mapped onto a DTO class. Decorators such as `@IsEmail()` run automatically. This must be **global**, not copied onto every controller.

| Option | Meaning |
|--------|---------|
| `whitelist: true` | Drop properties that are not on the DTO |
| `forbidNonWhitelisted: true` | **Reject** the request instead of silently dropping. Attackers send `"isAdmin": true` |
| `transform: true` | Run `class-transformer` (`@Transform` trim/lowercase) |

**Example:** DTO only has `email`. Body `{ "email": "a@x.com", "isAdmin": true }` → **400**, not a user with extra fields applied.

**Checkpoint:** `main.ts` matches this repo (Helmet, CORS, json limit, ValidationPipe, listen on `app.port`).

---

## Chapter 4 — Errors and logs

### 4.1 Global exception filter

**Concept:** Nest’s default error page can leak stacks. A filter turns exceptions into a stable JSON shape.

Register `GlobalExceptionFilter` with `APP_FILTER`. For `HttpException`, use its status and `message`. Otherwise 500 `"Internal Server Error"`. Body: `{ statusCode, message, timestamp, path }`.

**Example:** Duplicate email later becomes HTTP 409, not a Prisma stack trace.

### 4.2 Pino (nestjs-pino)

Install: `pnpm add nestjs-pino pino pino-http`

**Concept:** `console.log` is unstructured. Pino emits JSON logs. `pino-http` logs each request. **Request id:** if the client sends `x-request-id` (string, length ≤ 100), reuse it; otherwise `crypto.randomUUID()`. That lets you grep one request across API and workers.

**Redaction:** never log secrets. This app censors (among others) `password`, `newPassword`, `otp`, `refreshToken`, `accessToken`, `token`, `rawToken`, `apiKey`, `authorization`, `cookie`.

Level: `debug` when not production, `info` in production.

**Checkpoint:** Hitting any route writes a JSON line; a register body must not print the password.

---

## Chapter 5 — Health (first real route)

`HealthModule` + `HealthController`. First version: `{ status: 'ok' }`. After Prisma (Chapter 9), run `SELECT 1` and return `{ status: 'ok', database: 'ok' }`.

Add `src/requests.http`:

```
GET http://localhost:3000/health
```

**Checkpoint:** Health returns 200 without a database check until Prisma is connected; then it must fail if Postgres is down.

---

## Chapter 6 — Docker: Postgres, Redis, Mailpit

**Concept:** Local SaaS needs three extra processes: SQL, a shared cache/queue, and a fake mailbox.

`compose.yml` in this repo:

- **postgres:17-alpine** — `mynest` / `mynest_dev` / db `mynest`, port 5432, volume `postgres_data`
- **redis:8-alpine** — port 6379, volume `redis_data`
- **mailpit** — SMTP **1025**, UI **8025** (`http://localhost:8025`)

```bash
docker compose up -d
```

If Podman fails: `systemctl --user restart podman.socket`, then compose up again.

**Checkpoint:** You can connect to Postgres with `DATABASE_URL`. Redis accepts `REDIS_URL`. Mailpit UI loads (empty until Chapter 12).

---

## Chapter 7 — Prisma 7 install

Prisma 7 talks to Postgres through a **driver adapter** (`@prisma/adapter-pg` + `pg`), not the old bundled engine alone.

```bash
pnpm add -D prisma
pnpm add @prisma/client @prisma/adapter-pg pg
pnpm exec prisma init
```

You get `prisma/schema.prisma` and `prisma.config.ts` (`datasource.url` from `DATABASE_URL`).

Generator in this project:

```prisma
generator client {
  provider     = "prisma-client"
  output       = "../src/generated/prisma"
  moduleFormat = "cjs"
}
```

`moduleFormat = "cjs"` is required because Nest compiles **CommonJS**. An ESM client will fail to import.

Add `DATABASE_URL` to Joi and `configuration.ts` (`database.url`).

`.gitignore`: `.env`, `src/generated/prisma`.

`pnpm exec prisma db pull` on an empty database **fails**. That is expected. You **write** the schema next; you do not introspect emptiness.

---

## Chapter 8 — Database schema (product design)

**Concept:** Tables are the product spec. Most models have **no HTTP API** yet. That is intentional. You avoid “we’ll add organizationId later.”

Put everything in `prisma/schema.prisma`. Then:

```bash
pnpm exec prisma format
pnpm exec prisma validate
pnpm exec prisma migrate dev --name init
pnpm exec prisma migrate status
pnpm exec prisma generate
pnpm exec prisma studio
```

`migrate dev --name init` creates `prisma/migrations/..._init/` and applies it. Studio should show empty tables.

Below is **what each domain is for**. Copy the actual models from `prisma/schema.prisma` in this repo (do not invent shorter versions).

### 8.1 Identity

A **person** is `User` (UUID `id`, names, `status` ACTIVE/SUSPENDED/DEACTIVATED, `deletedAt` soft delete).

The **email is not the user**. `UserEmail` has unique `email`, `isPrimary`, `isVerified`. One user can have several emails later. Google-only users can have `passwordHash` null.

Password **policy in data**: `passwordHash`, `passwordChangedAt`, `passwordFailedAttempts`, `passwordLockedUntil`, `mustChangePassword`. Lockout is per **account**; rate limit (Chapter 10) is per **IP**.

`UserPhone` — same idea for SMS later.

`AuthIdentity` — `(provider, providerUserId)` unique; `AuthProvider` is `GOOGLE` today.

**Anti-pattern:** `users.email` UNIQUE as the only identifier. Then you cannot add a second email or Google on the same person without a rewrite.

### 8.2 Sessions (tables only)

HTTP is stateless. After login you will create a `Session` (device, IP, `authMethod` PASSWORD/GOOGLE/OTP, expiry, revoke reason).

`SessionRefreshToken` stores **`tokenHash` only**. If the DB leaks, stolen hashes should not be usable as cookies.

**Refresh rotation:** each refresh marks the old token used and issues a new one. If a **used** token appears again (`TOKEN_REUSE`), assume theft and revoke the `tokenFamilyId`. Not implemented in code yet; columns exist.

### 8.3 Challenges

Secrets that leave the server are stored **hashed**:

| Table | Use |
|-------|-----|
| `UserToken` | EMAIL_VERIFICATION, PASSWORD_RESET |
| `OtpChallenge` | codes, attempts, EMAIL/SMS, purpose |
| `OAuthState` | CSRF state for Google |

Register already creates a `UserToken`. The raw token is only for email.

### 8.4 Audit

`AuthEvent` — login failed, token reuse, OTP sent, etc. Queryable per user. Nothing writes these rows yet. Logs (Pino) are for operators; this table is for product/security history.

### 8.5 Tenancy

**Multi-tenant:** one app, many companies. Company = `Organization` (`slug`, status, `deletedAt`).

`OrganizationMembership` — user + org + `roleId`. Unique `(userId, organizationId)`. Ada can be in Acme and Beta.

`OrganizationInvitation` — hashed invite token, email, expiry.

**Anti-pattern:** only `users.organization_id`. That is single-org-per-user.

### 8.6 RBAC

`Permission.key` (e.g. `members:invite`) → `Role` (optional `organizationId` for custom roles) → `RolePermission`. Membership points at one role. No `User.isAdmin`.

### 8.7 Billing / features

Entitlements, not Stripe UI: `Feature`, `SubscriptionPlan`, `PlanFeature`, `OrganizationSubscription` (TRIALING/ACTIVE/…), `OrganizationFeatureOverride` (sales exceptions). Stripe comes **after** these tables.

**Checkpoint:** Studio shows all models. No Nest CRUD for Organization.

---

## Chapter 9 — `PrismaService` in Nest

```bash
nest g module prisma
nest g service prisma
```

`PrismaService` **extends** `PrismaClient`, passes `PrismaPg` with `database.url`, `$connect` on init, `$disconnect` on destroy.

`PrismaModule` is `@Global()`, provides and exports `PrismaService`.

Update health to `SELECT 1`.

**Checkpoint:** `GET /health` is `{ status: 'ok', database: 'ok' }`. Stop Postgres → health fails.

---

## Chapter 10 — Rate limiting (Redis)

**Concept:** Cap requests per client per time window. Stops naive brute force and cheap floods. It does **not** replace Argon2 or account lockout.

**In-memory (`@nestjs/throttler` default):** counters live in one process RAM. Three replicas behind a load balancer each allow N requests → **3N** total. Fine for a laptop demo, wrong for production SaaS.

**Redis (`@nest-lab/throttler-storage-redis` + ioredis):** every instance increments the same keys.

```bash
pnpm add @nestjs/throttler @nest-lab/throttler-storage-redis ioredis
```

`ThrottlerModule.forRootAsync` reads `throttling.default.ttl` and `limit`, `storage: new ThrottlerStorageRedisService(redis.url)`.

`APP_GUARD` → `ThrottlerGuard`.

Env: `THROTTLE_DEFAULT_*` used now. `THROTTLE_AUTH_*` and `THROTTLE_OTP_*` are in config for **later** stricter routes (`@Throttle()`). They are not applied to register yet.

**Example:** `THROTTLE_DEFAULT_LIMIT=60` and TTL 60000 → 61st request in a minute from that IP → **429**.

Redis is also used by BullMQ in Chapter 12. Same `REDIS_URL`.

**Checkpoint:** Burst requests → 429. Redis down → throttler/app errors (Redis must be up).

---

## Chapter 11 — Registration (only auth feature)

**Concept:** Sign up is not `INSERT INTO users`. You validate, hash, create related rows atomically, never return secrets, and you treat duplicate email as a conflict.

```bash
pnpm add argon2
nest g module auth
nest g controller auth
nest g service auth
```

`AuthModule` imports `EmailModule` (Chapter 12). `AppModule` imports `AuthModule`.

### 11.1 DTO `CreateNewUser`

File: `src/auth/dto/create-new-user.dto.ts`.

- Names: required (display optional), trim, max length.
- Email: `@IsEmail`, trim, lowercase.
- Password: 8–128, upper, lower, digit, special `@$!%*?&`.
- `@isNotCommonPassword` if `ENABLE_COMMON_PASSWORD_CHECK=true` (in-memory list).
- `@isNotBreachedPassword` if `ENABLE_HIBP_CHECK=true`.

**HIBP (k-anonymity):** SHA-1 the password. Send only the **first 5 hex characters** to `api.pwnedpasswords.com/range/{prefix}`. Match the rest of the hash locally. The password itself is never sent. If HIBP is down, **fail-open** (allow signup) so a third party cannot freeze registration. Complexity still applies.

### 11.2 `AuthService.register`

1. `normalizeEmail`.
2. `argon2.hash(..., { type: argon2.argon2id })` — slow, memory-hard. Never store plaintext. Never use raw SHA-256 for passwords.
3. `rawToken = randomBytes(32).toString('base64url')`. `tokenHash = sha256(rawToken)` hex. Raw token is for email only.
4. `$transaction`:
   - If active user already owns the email → `409` `EMAIL_ALREADY_EXISTS`.
   - Create `User` + nested primary `UserEmail` (`isVerified` false).
   - Create `UserToken` type `EMAIL_VERIFICATION`, expiry `now + MAIL_VERIFICATION_TOKEN_TTL` **hours** (`email.verificationTokenTtl`).
5. **After commit:** `emailService.enqueue(...)`. If enqueue returns `false`, still **201-style success** with `emailStatus: 'FAILED'` and a message to request a new link later. If true, `emailStatus: 'QUEUED'`.
6. Response `data` is only `{ id }`. No token, no hash, no password.
7. Catch Prisma `P2002` (unique race) → same 409.

`POST /auth/register` on `AuthController`.

`login()` empty. `verifyEmail()` comments only (hash, find, consume, mark verified) — **not implemented**.

**Checkpoint:** `src/requests.http` POST register. Studio: User, UserEmail unverified, UserToken hashed. Repeat email → 409. Extra JSON field → 400.

---

## Chapter 12 — Email platform

**Concept:** Sending mail is slow and flaky. Do not call SMTP inside the HTTP handler or inside a DB transaction. **Producer** (`EmailService.enqueue`) puts a job on Redis. **Worker** (`EmailProcessor`) renders a template and calls an **EmailProvider**. Auth never imports Nodemailer.

```bash
pnpm add @nestjs/bullmq bullmq nodemailer
```

### 12.1 BullMQ

`BullModule.forRootAsync` with `redis.url`. `EmailModule` registers queue name `'email'`.

`enqueue`: `jobId = idempotencyKey` (e.g. `email-verification-{tokenId}`), exponential backoff 5s, 3 attempts, `removeOnComplete: true`, `removeOnFail: false`. Catch errors, log with Pino, return `false` (register still succeeded).

Job payload: `EmailJobType` (`EMAIL_VERIFICATION` | `PASSWORD_RESET`), `to`, `userId`, `data.tokenId`, `data.rawToken`.

### 12.2 Provider port

`EmailProvider.send(message)` → `{ messageId, accepted, rejected }`.

Token `EMAIL_PROVIDER`. Bind `useExisting: SmtpEmailProvider`. `ResendEmailProvider` exists as a **stub** (empty send). Joi still allows `EMAIL_PROVIDER=resend` with `RESEND_API_KEY`; production Resend is not wired in `EmailModule` yet.

### 12.3 SMTP (Nodemailer)

`SmtpEmailProvider` uses `config.getOrThrow` for host, port, secure, pool, maxConnections, maxMessages, timeouts. Empty `MAIL_USER`/`MAIL_PASS` → `auth: undefined` (Mailpit).

`pool: true` reuses SMTP connections. `maxMessages` recycles a connection. Timeouts protect against a hung server. `onModuleDestroy` → `transporter.close()`.

**TypeScript note:** `@types/nodemailer` overloads: pooled transport requires **`pool: true` as a literal**, not `boolean` from `config.get()`. If you pass `pool: someBoolean`, TS may fail with “`host` does not exist on TransportOptions.” That error is the **wrong overload**. Use `getOrThrow` and a literal `pool: true` when pooling, or a typed `SMTPPool.Options` object. Runtime pooling can still follow env; the types are picky.

### 12.4 Templates

`EmailTemplate`: `supports(type)` + `render(job) → { to, subject, html, text }`.

`VerificationEmailTemplate` builds `{FRONTEND_URL}/auth/verify-email?token=` + urlencoded raw token. HTML and text. `EmailTemplateService` picks a template from `EMAIL_TEMPLATES` array.

The **frontend** verify page does not exist in this repo. The **API** does not consume the token yet.

### 12.5 Processor

`@Processor('email')`: render → `emailProvider.send` → log. On failure **throw** so BullMQ retries.

**Checkpoint:** Register → Mailpit shows “Verify your email”. If Redis enqueue fails, HTTP still succeeds with `emailStatus: FAILED`.

---

## Chapter 13 — Confirm you match this repo

```bash
pnpm install
docker compose up -d
pnpm exec prisma migrate deploy
pnpm exec prisma generate
pnpm run start:dev
```

1. `GET http://localhost:3000/health` → database ok.
2. `POST /auth/register` with a unique email and a strong password.
3. Prisma Studio: user + email + token hash.
4. `http://localhost:8025`: verification mail.
5. Duplicate register → 409.
6. Body with `isAdmin` → 400.

### Implemented vs not

| Done | Not done |
|------|----------|
| Config + Joi | Login, sessions, refresh reuse |
| Helmet, CORS, pipe, body limit, Redis throttle | Verify-email HTTP (stub only) |
| Pino redact + request id | OTP, Google OAuth |
| Prisma schema + health DB ping | Org / invite / RBAC APIs |
| Register + Argon2id + hashed verify token | Billing / Stripe |
| Email queue, SMTP, Mailpit, HTML template | Resend actually sending |
| Enqueue failure isolated from user create | Password reset flow |

Next work, in order: implement `verifyEmail` (hash, one-time consume, set `isVerified`), then login + sessions, then orgs. Do not start Stripe first.

---

## File map (current tree)

```
src/main.ts                 Helmet, CORS, json limit, ValidationPipe
src/app.module.ts           Config, throttler, pino, BullMQ, Health, Prisma, Auth, Email
src/config/                 configuration.ts, env.validation.ts
src/common/filters/         GlobalExceptionFilter
src/common/decorators/      HIBP + common password
src/health/                 GET /health
src/prisma/                 PrismaService (adapter-pg)
src/auth/                   register only
src/email/                  queue, processor, SMTP, templates
prisma/schema.prisma        full SaaS model
compose.yml                 postgres, redis, mailpit
src/requests.http           health + register
```

If something in your tree disagrees with this list, the **repository** is the source of truth; update this chapter when the app moves (verify-email, login, Resend).

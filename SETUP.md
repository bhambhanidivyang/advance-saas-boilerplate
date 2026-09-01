# Setup

NestJS 11 + TypeScript backend (`APP_NAME=backend`) with pnpm, Docker Postgres, and Prisma 7.

## Steps taken so far

1. **Scaffold the Nest app**
   - `nest new mynest` (TypeScript, ESLint, Prettier, Jest)
   - App name in env/config is `backend` (`APP_NAME=backend`)

2. **Use pnpm**
   - `pnpm-lock.yaml` and `pnpm-workspace.yaml` (Prisma build allowances)

3. **Remove default scaffold**
   - Dropped `AppController` / `AppService`
   - Root `GET /` is no longer served

4. **Install core dependencies**
   - `@nestjs/config`, `joi` — env config + validation
   - `class-validator`, `class-transformer` — DTO validation
   - `helmet` — security headers
   - `nestjs-pino`, `pino`, `pino-http` — structured logging

5. **Environment configuration**
   - `.env` with `APP_NAME`, `NODE_ENV`, `PORT`, `FRONTEND_URL`
   - `src/config/configuration.ts` — typed config loader
   - `src/config/env.validation.ts` — Joi schema
   - `ConfigModule.forRoot()` registered globally in `app.module.ts`

6. **Application bootstrap (`src/main.ts`)**
   - `helmet()`
   - CORS (origin from `FRONTEND_URL`)
   - JSON body limit (`256kb`)
   - Global `ValidationPipe` (whitelist, forbidNonWhitelisted, transform)
   - Port from `ConfigService`

7. **Global exception handling**
   - `HttpExceptionFilter` registered via `APP_FILTER`

8. **Structured logging**
   - `LoggerModule` (nestjs-pino), log level by `NODE_ENV`

9. **Health check**
   - `HealthModule` + `HealthController`
   - `GET /health` → `{ "status": "ok" }`
   - Unit test for the controller

10. **Manual API file**
    - `src/requests.http` (`GET http://localhost:3000/health`)

11. **PostgreSQL via Docker Compose**
    - `compose.yml` — `postgres:17-alpine`
    - Container: `mynest-postgres` on port `5432`

12. **Prisma initialization**
    - `prisma init` → `prisma/schema.prisma`, `prisma.config.ts`
    - Prisma 7, PostgreSQL provider
    - Client output: `src/generated/prisma`
    - `DATABASE_URL` in `.env` pointing at Docker Postgres

13. **`.gitignore`**
    - Ignores `.env`, `src/generated/prisma`, `src/requests.http`

14. **Prisma agent skills**
    - `.agents/skills/` and `skills-lock.json`

15. **Attempted DB introspection**
    - `pnpm exec prisma db pull` failed because the database has no tables yet

## Not done yet

| Item | Status |
|------|--------|
| Initial git commit | Repo initialized, no commits |
| Prisma models / migrations | Schema has no models |
| `prisma generate` | No client under `src/generated/prisma` |
| Prisma in NestJS | No `PrismaModule` / `PrismaService` |
| E2E test | Still expects `GET /` → `"Hello World!"` |

## Run locally

```bash
pnpm install
docker compose up -d
pnpm run start:dev
```

Health check: [http://localhost:3000/health](http://localhost:3000/health)

Postgres (from `compose.yml` / `.env`):

```
postgresql://mynest:mynest_dev@localhost:5432/mynest
```

## Stack

```
NestJS 11  →  Config + Joi  →  Pino  →  Helmet / CORS / Validation
                                      ↓
                              GET /health
                                      ↓
            Docker Postgres 17  ←  Prisma 7 (init only, no models)
```

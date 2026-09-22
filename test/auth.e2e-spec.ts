/**
 * End-to-end auth journeys against the real application: HTTP in, guards,
 * throttler, controller, service, Prisma, Redis and cookies all wired as deployed.
 *
 * Needs the same --experimental-vm-modules flag as the integration suite (Prisma 7
 * loads a WASM query compiler), a migrated Postgres and a running Redis.
 * Run via: pnpm test:e2e
 */
import 'dotenv/config';

import { randomUUID } from 'crypto';
import { INestApplication } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { configureApp } from '../src/app.setup';
import { PrismaService } from '../src/prisma/prisma.service';

const OLD_PASSWORD = 'Zq8!mK3@vR7x';
const NEW_PASSWORD = 'Wn5$pT9&hL2c';

describe('Auth (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    const email = `e2e-${randomUUID()}@example.com`;

    function api() {
        return request(app.getHttpServer());
    }

    function refreshCookie(response: request.Response): string {
        const header = response.headers['set-cookie'] as unknown as string[] | undefined;
        const cookie = header?.find((value) => value.startsWith('mn_rt='));
        return cookie ? cookie.split(';')[0] : '';
    }

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        // The same configuration main.ts applies, so these tests exercise the app
        // that actually ships rather than a bare AppModule.
        app = configureApp(moduleFixture.createNestApplication<NestExpressApplication>());
        await app.init();

        prisma = app.get(PrismaService);
    });

    afterAll(async () => {
        const userEmail = await prisma.userEmail.findUnique({
            where: { email },
            select: { userId: true },
        });
        if (userEmail) {
            // AuthEvent is onDelete: SetNull, so it outlives the user unless removed.
            await prisma.authEvent.deleteMany({ where: { userId: userEmail.userId } });
            await prisma.user.deleteMany({ where: { id: userEmail.userId } });
        }
        await app.close();
    });

    describe('registration', () => {
        it('rejects a password that fails the shared policy', async () => {
            await api()
                .post('/auth/register')
                .send({ firstName: 'E2E', lastName: 'User', email, password: 'password' })
                .expect(400);
        });

        it('accepts a strong password', async () => {
            await api()
                .post('/auth/register')
                .send({ firstName: 'E2E', lastName: 'User', email, password: OLD_PASSWORD })
                .expect(201);
        });
    });

    describe('login', () => {
        it('returns an access token in the body and the refresh token only as a cookie', async () => {
            const response = await api()
                .post('/auth/login')
                .send({ email, password: OLD_PASSWORD })
                .expect(201);

            expect(response.body).toMatchObject({ tokenType: 'Bearer' });
            expect(response.body.accessToken).toEqual(expect.any(String));
            expect(response.body).not.toHaveProperty('refreshToken');

            const cookie = refreshCookie(response);
            expect(cookie).toMatch(/^mn_rt=/);
            const raw = (response.headers['set-cookie'] as unknown as string[]).join(';');
            expect(raw).toMatch(/HttpOnly/i);
            expect(raw).toMatch(/Path=\/auth/i);
            // The cookie value must never appear in the JSON body.
            expect(JSON.stringify(response.body)).not.toContain(cookie.split('=')[1]);
        });

        // Unknown account and wrong password must be indistinguishable.
        it('answers an unknown email exactly as it answers a wrong password', async () => {
            const unknown = await api()
                .post('/auth/login')
                .send({ email: `missing-${randomUUID()}@example.com`, password: OLD_PASSWORD });
            const wrongPassword = await api()
                .post('/auth/login')
                .send({ email, password: 'Wrong!Pass9' });

            expect(unknown.status).toBe(401);
            expect(wrongPassword.status).toBe(401);
            expect(unknown.body.message).toBe(wrongPassword.body.message);
        });
    });

    describe('the guard', () => {
        it('rejects a guarded route with no token', async () => {
            const response = await api().post('/auth/logout-all').expect(401);
            expect(response.body.code).toBe('MISSING_ACCESS_TOKEN');
        });

        it('rejects a forged token', async () => {
            await api()
                .post('/auth/logout-all')
                .set('Authorization', 'Bearer not-a-real-token')
                .expect(401);
        });
    });

    describe('refresh rotation', () => {
        it('issues a new pair and retires the presented token', async () => {
            const login = await api().post('/auth/login').send({ email, password: OLD_PASSWORD });
            const firstCookie = refreshCookie(login);

            const rotated = await api()
                .post('/auth/refresh')
                .set('Cookie', firstCookie)
                .expect(201);

            expect(rotated.body.accessToken).toEqual(expect.any(String));
            const secondCookie = refreshCookie(rotated);
            expect(secondCookie).not.toBe(firstCookie);

            // The replacement works...
            await api().post('/auth/refresh').set('Cookie', secondCookie).expect(201);
        });

        it('rejects a request with no refresh cookie', async () => {
            await api().post('/auth/refresh').expect(401);
        });
    });

    describe('change password', () => {
        let accessToken: string;
        let cookie: string;
        let otherDeviceCookie: string;

        beforeAll(async () => {
            const thisDevice = await api().post('/auth/login').send({ email, password: OLD_PASSWORD });
            accessToken = thisDevice.body.accessToken;
            cookie = refreshCookie(thisDevice);

            const otherDevice = await api().post('/auth/login').send({ email, password: OLD_PASSWORD });
            otherDeviceCookie = refreshCookie(otherDevice);
        });

        it('rejects a wrong current password with 403', async () => {
            const response = await api()
                .post('/auth/change-password')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ currentPassword: 'Wrong!Pass9', newPassword: NEW_PASSWORD })
                .expect(403);

            expect(response.body.code).toBe('INVALID_CURRENT_PASSWORD');
        });

        it('rejects a new password that fails the policy', async () => {
            await api()
                .post('/auth/change-password')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ currentPassword: OLD_PASSWORD, newPassword: 'password' })
                .expect(400);
        });

        it('rejects reusing the current password', async () => {
            const response = await api()
                .post('/auth/change-password')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ currentPassword: OLD_PASSWORD, newPassword: OLD_PASSWORD })
                .expect(400);

            expect(response.body.code).toBe('PASSWORD_UNCHANGED');
        });

        it('changes the password, keeps this device and ends the others', async () => {
            const response = await api()
                .post('/auth/change-password')
                .set('Authorization', `Bearer ${accessToken}`)
                .set('Cookie', cookie)
                .send({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD })
                .expect(201);

            expect(response.body).toEqual({ success: true, revokedSessions: expect.any(Number) });
            expect(response.body.revokedSessions).toBeGreaterThanOrEqual(1);

            const replacement = refreshCookie(response);
            expect(replacement).toMatch(/^mn_rt=/);
            expect(replacement).not.toBe(cookie);

            // This device continues on its replacement cookie...
            await api().post('/auth/refresh').set('Cookie', replacement).expect(201);
            // ...its pre-change cookie is retired...
            await api().post('/auth/refresh').set('Cookie', cookie).expect(401);
            // ...and the other device is logged out.
            await api().post('/auth/refresh').set('Cookie', otherDeviceCookie).expect(401);
        });

        it('accepts only the new password afterwards', async () => {
            await api().post('/auth/login').send({ email, password: OLD_PASSWORD }).expect(401);
            await api().post('/auth/login').send({ email, password: NEW_PASSWORD }).expect(201);
        });

        it('recorded exactly one PASSWORD_CHANGED event and no false theft alarm', async () => {
            const userEmail = await prisma.userEmail.findUniqueOrThrow({
                where: { email },
                select: { userId: true },
            });

            const [changed, reuse] = await Promise.all([
                prisma.authEvent.count({
                    where: { userId: userEmail.userId, eventType: 'PASSWORD_CHANGED' },
                }),
                prisma.authEvent.count({
                    where: { userId: userEmail.userId, eventType: 'TOKEN_REUSE_DETECTED' },
                }),
            ]);

            expect(changed).toBe(1);
            expect(reuse).toBe(0);
        });
    });

    describe('logout', () => {
        it('ends the session behind the cookie and is idempotent', async () => {
            const login = await api().post('/auth/login').send({ email, password: NEW_PASSWORD });
            const cookie = refreshCookie(login);

            await api().post('/auth/logout').set('Cookie', cookie).expect(201);
            // The refresh token is dead...
            await api().post('/auth/refresh').set('Cookie', cookie).expect(401);
            // ...and logging out again still succeeds.
            await api().post('/auth/logout').set('Cookie', cookie).expect(201);
        });

        it('ends every session with logout-all', async () => {
            const login = await api().post('/auth/login').send({ email, password: NEW_PASSWORD });

            const response = await api()
                .post('/auth/logout-all')
                .set('Authorization', `Bearer ${login.body.accessToken}`)
                .expect(201);

            expect(response.body.success).toBe(true);
            await api().post('/auth/refresh').set('Cookie', refreshCookie(login)).expect(401);
        });
    });
});

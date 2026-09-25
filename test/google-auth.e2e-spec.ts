/**
 * End-to-end Google sign-in against the real application: HTTP in, guards,
 * validation pipe, throttler, Prisma, Redis and cookies as deployed.
 *
 * Only GoogleTokenVerifier is replaced. Real Google ID tokens cannot be obtained
 * in a test run, and that class is the single point where this codebase talks to
 * Google — which is why it exists as its own injectable. Everything after it,
 * including identity resolution and session creation, runs for real.
 *
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
import { GoogleTokenVerifier } from '../src/auth/google/google-token-verifier';
import { GoogleTokenInvalidError } from '../src/auth/google/google-token-invalid.error';
import { ExternalIdentityProfile } from '../src/auth/identity/identity.interface';
import { AuthProvider } from '../src/generated/prisma/client';

const PASSWORD = 'Jq4!nD8@wS2v';

/**
 * A structurally valid JWT. GoogleLoginDto checks the shape with @IsJWT before the
 * request reaches any service, so junk strings are rejected as 400 and never cost a
 * verification — which also means e2e fixtures must look like real tokens. The
 * contents are irrelevant here: the verifier is replaced.
 */
function jwtShapedToken(): string {
    const segment = (value: object) =>
        Buffer.from(JSON.stringify(value)).toString('base64url');
    return `${segment({ alg: 'RS256', kid: 'test' })}.${segment({ sub: 'test' })}.c2lnbmF0dXJl`;
}

describe('Google sign-in (e2e)', () => {
    let app: INestApplication;
    let prisma: PrismaService;
    const verify = jest.fn();
    const emails: string[] = [];

    function api() {
        return request(app.getHttpServer());
    }

    function googleEmail() {
        const email = `e2e-google-${randomUUID()}@example.com`;
        emails.push(email);
        return email;
    }

    function profileFor(email: string, overrides: Partial<ExternalIdentityProfile> = {}): ExternalIdentityProfile {
        return {
            provider: AuthProvider.GOOGLE,
            providerUserId: `google-sub-${randomUUID()}`,
            email,
            emailVerified: true,
            firstName: 'Divyang',
            lastName: 'Bhambhani',
            displayName: 'Divyang Bhambhani',
            ...overrides,
        };
    }

    function signIn(profile: ExternalIdentityProfile, nonce?: string) {
        verify.mockResolvedValue({ profile, nonce });
        return api().post('/auth/google').send({ idToken: jwtShapedToken() });
    }

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        })
            .overrideProvider(GoogleTokenVerifier)
            .useValue({ verify })
            .compile();

        app = configureApp(moduleFixture.createNestApplication<NestExpressApplication>());
        await app.init();

        prisma = app.get(PrismaService);
    });

    beforeEach(() => {
        verify.mockReset();
    });

    afterAll(async () => {
        const rows = await prisma.userEmail.findMany({
            where: { email: { in: emails } },
            select: { userId: true },
        });
        const userIds = rows.map((row) => row.userId);
        if (userIds.length > 0) {
            // AuthEvent is onDelete: SetNull, so it outlives the user unless removed.
            await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
            await prisma.user.deleteMany({ where: { id: { in: userIds } } });
        }
        await app.close();
    });

    describe('a first sign-in', () => {
        it('creates the account and returns a session', async () => {
            const email = googleEmail();

            const response = await signIn(profileFor(email)).expect(201);

            expect(response.body).toMatchObject({
                accessToken: expect.any(String),
                expiresIn: expect.any(Number),
                tokenType: 'Bearer',
                user: { emailVerified: true, mustChangePassword: false },
            });

            const user = await prisma.user.findFirstOrThrow({
                where: { emails: { some: { email } } },
                select: {
                    passwordHash: true,
                    emails: { select: { isVerified: true } },
                    authIdentities: { select: { provider: true } },
                },
            });
            expect(user.passwordHash).toBeNull();
            expect(user.emails[0].isVerified).toBe(true);
            expect(user.authIdentities).toEqual([{ provider: AuthProvider.GOOGLE }]);
        });

        it('delivers the refresh token only as an httpOnly cookie', async () => {
            const response = await signIn(profileFor(googleEmail())).expect(201);

            const cookies = response.headers['set-cookie'] as unknown as string[];
            const refresh = cookies.find((value) => value.startsWith('mn_rt='));

            expect(refresh).toBeDefined();
            expect(refresh).toContain('HttpOnly');
            expect(refresh).toContain('Path=/auth');
            expect(response.body).not.toHaveProperty('refreshToken');
            expect(JSON.stringify(response.body)).not.toContain(refresh!.split('=')[1].split(';')[0]);
        });

        it('returns an access token that opens a guarded route', async () => {
            const response = await signIn(profileFor(googleEmail())).expect(201);

            await api()
                .post('/auth/logout-all')
                .set('Authorization', `Bearer ${response.body.accessToken}`)
                .expect(201);
        });

        it('rotates the refresh cookie it issued', async () => {
            const response = await signIn(profileFor(googleEmail())).expect(201);
            const cookies = response.headers['set-cookie'] as unknown as string[];
            const cookie = cookies.find((value) => value.startsWith('mn_rt='))!.split(';')[0];

            await api().post('/auth/refresh').set('Cookie', cookie).expect(201);
        });
    });

    describe('a returning user', () => {
        it('resolves to the same account without creating a second one', async () => {
            const profile = profileFor(googleEmail());

            const first = await signIn(profile).expect(201);
            const second = await signIn(profile).expect(201);

            expect(second.body.user.id).toBe(first.body.user.id);
            expect(
                await prisma.authIdentity.count({ where: { userId: first.body.user.id } }),
            ).toBe(1);
        });
    });

    describe('rejected sign-ins', () => {
        it('answers a generic 401 for a token Google refuses, and sets no cookie', async () => {
            verify.mockRejectedValue(new GoogleTokenInvalidError('Wrong recipient'));

            const response = await api()
                .post('/auth/google')
                .send({ idToken: jwtShapedToken() })
                .expect(401);

            expect(response.headers['set-cookie']).toBeUndefined();
            expect(JSON.stringify(response.body)).not.toContain('Wrong recipient');
        });

        it('answers 403 with an actionable code when Google has not verified the email', async () => {
            const response = await signIn(
                profileFor(googleEmail(), { emailVerified: false }),
            ).expect(403);

            expect(response.body).toMatchObject({ code: 'GOOGLE_EMAIL_UNVERIFIED' });
        });

        it.each([
            ['no id token', {}],
            ['a token that is not a JWT at all', { idToken: 'not-a-real-token' }],
        ])('rejects a request with %s before reaching Google', async (_label, body) => {
            await api().post('/auth/google').send(body).expect(400);

            expect(verify).not.toHaveBeenCalled();
        });
    });

    // Pre-account hijacking, through the real HTTP stack: someone registers the
    // victim's address and never verifies it, then the victim signs in with Google.
    describe('an account registered but never verified', () => {
        it('stops the old password from working once Google proves ownership', async () => {
            const email = googleEmail();
            await api()
                .post('/auth/register')
                .send({ firstName: 'Squatter', lastName: 'User', email, password: PASSWORD })
                .expect(201);

            // The password works while the address is unclaimed.
            await api().post('/auth/login').send({ email, password: PASSWORD }).expect(201);

            await signIn(profileFor(email)).expect(201);

            // Google has now proved who owns the address; the password is gone.
            await api().post('/auth/login').send({ email, password: PASSWORD }).expect(401);
        });

        it('revokes the sessions that password created', async () => {
            const email = googleEmail();
            await api()
                .post('/auth/register')
                .send({ firstName: 'Squatter', lastName: 'User', email, password: PASSWORD })
                .expect(201);

            const passwordLogin = await api()
                .post('/auth/login')
                .send({ email, password: PASSWORD })
                .expect(201);
            const cookies = passwordLogin.headers['set-cookie'] as unknown as string[];
            const squatterCookie = cookies.find((value) => value.startsWith('mn_rt='))!.split(';')[0];

            await signIn(profileFor(email)).expect(201);

            await api().post('/auth/refresh').set('Cookie', squatterCookie).expect(401);
        });
    });

    // The nonce binds one sign-in to one token. Without it, a leaked ID token is
    // replayable for its full hour of validity.
    describe('nonce binding', () => {
        async function issuedNonce(): Promise<string> {
            const response = await api().post('/auth/google/nonce').expect(201);

            expect(response.body).toMatchObject({
                nonce: expect.any(String),
                expiresAt: expect.any(String),
            });
            return response.body.nonce as string;
        }

        it('accepts a token carrying a nonce this server issued', async () => {
            const nonce = await issuedNonce();

            await signIn(profileFor(googleEmail()), nonce).expect(201);
        });

        // The replay: the same token, presented a second time, carries the same nonce.
        it('rejects the same token replayed with its nonce already spent', async () => {
            const nonce = await issuedNonce();
            const profile = profileFor(googleEmail());

            await signIn(profile, nonce).expect(201);

            const replay = await signIn(profile, nonce).expect(401);
            expect(replay.headers['set-cookie']).toBeUndefined();
        });

        it('rejects a nonce this server never issued', async () => {
            await signIn(profileFor(googleEmail()), 'never-issued-by-us').expect(401);
        });

        // A present nonce is verified whatever the flag says, so an attacker cannot
        // strip it to fall back to the permissive path.
        it('creates no account when the nonce fails', async () => {
            const email = googleEmail();

            await signIn(profileFor(email), 'never-issued-by-us').expect(401);

            expect(await prisma.userEmail.count({ where: { email } })).toBe(0);
        });
    });
});

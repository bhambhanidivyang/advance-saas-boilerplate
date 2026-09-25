/**
 * Real PostgreSQL identity resolution. Jest's default CJS runner cannot load
 * Prisma 7's WASM query compiler unless Node is started with
 * --experimental-vm-modules. Run via: pnpm test:integration
 *
 * Covers what mocks cannot: the unique constraint settling a race between two
 * first sign-ins, and the pre-account-hijacking response applied to real rows.
 */
import 'dotenv/config';

import { randomUUID } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from 'src/prisma/prisma.service';
import { installTransactionOverlapBarrier } from 'src/common/testing/transaction-overlap-barrier';
import {
    AuthEventType,
    AuthMethod,
    AuthProvider,
    SessionRevocationReason,
    UserTokenType,
} from 'src/generated/prisma/client';
import { IdentityService } from './identity.service';
import { ExternalIdentityProfile } from './identity.interface';
import { SessionService } from '../session/session.service';
import { TokenService } from '../session/token.service';
import { SessionDenylistService } from '../session/session-denylist.service';
import { PasswordService } from '../password/password.service';
import { AuthContext } from '../interfaces/auth-context.interface';

const ABSOLUTE_TTL_SECONDS = 30 * 24 * 60 * 60;
const REFRESH_TTL_SECONDS = 14 * 24 * 60 * 60;
const GRACE_SECONDS = 15;
const MAX_ACTIVE_PER_USER = 50;

const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest-integration',
    deviceId: 'device-1',
};

describe('IdentityService (PostgreSQL)', () => {
    let service: IdentityService;
    let sessionService: SessionService;
    let prisma: PrismaService;
    const createdUserIds: string[] = [];

    const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

    beforeAll(async () => {
        if (!databaseUrl) {
            throw new Error(
                'Identity integration tests require DATABASE_URL or TEST_DATABASE_URL pointing at a migrated PostgreSQL database.',
            );
        }

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                IdentityService,
                PasswordService,
                SessionService,
                PrismaService,
                {
                    provide: SessionDenylistService,
                    useValue: { revoke: jest.fn(), isRevoked: jest.fn().mockResolvedValue(false) },
                },
                {
                    provide: TokenService,
                    useValue: {
                        generateAccessToken: jest
                            .fn()
                            .mockResolvedValue({ accessToken: 'access-token', expiresIn: 600 }),
                    },
                },
                {
                    provide: ConfigService,
                    useValue: {
                        get: (key: string) => (key === 'database.url' ? databaseUrl : undefined),
                        getOrThrow: (key: string) => {
                            if (key === 'database.url') return databaseUrl;
                            if (key === 'auth.session.absoluteTtlSeconds') return ABSOLUTE_TTL_SECONDS;
                            if (key === 'auth.session.refreshTtlSeconds') return REFRESH_TTL_SECONDS;
                            if (key === 'auth.session.refreshReuseGraceSeconds') return GRACE_SECONDS;
                            if (key === 'auth.session.maxActivePerUser') return MAX_ACTIVE_PER_USER;
                            throw new TypeError(`Configuration key "${key}" does not exist`);
                        },
                    },
                },
            ],
        }).compile();

        service = module.get(IdentityService);
        sessionService = module.get(SessionService);
        prisma = module.get(PrismaService);
        await prisma.$connect();
    });

    afterEach(async () => {
        const userIds = createdUserIds.splice(0, createdUserIds.length);
        if (userIds.length === 0) {
            return;
        }
        // AuthEvent is onDelete: SetNull, so it must go explicitly; identities,
        // emails, sessions and tokens cascade from the user.
        await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
        await prisma.user.deleteMany({ where: { id: { in: userIds } } });
    });

    afterAll(async () => {
        await prisma.$disconnect();
    });

    function googleProfile(overrides: Partial<ExternalIdentityProfile> = {}): ExternalIdentityProfile {
        return {
            provider: AuthProvider.GOOGLE,
            providerUserId: `google-sub-${randomUUID()}`,
            email: `identity-${randomUUID()}@example.com`,
            emailVerified: true,
            firstName: 'Divyang',
            lastName: 'Bhambhani',
            displayName: 'Divyang Bhambhani',
            ...overrides,
        };
    }

    /** An account registered with a password, with the email left unverified. */
    async function createPasswordUser(email: string, opts: { verified: boolean }) {
        const user = await prisma.user.create({
            data: {
                firstName: 'Squatter',
                passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$fake',
                emails: {
                    create: {
                        email,
                        isPrimary: true,
                        isVerified: opts.verified,
                        verifiedAt: opts.verified ? new Date() : null,
                    },
                },
            },
            select: { id: true },
        });
        createdUserIds.push(user.id);
        return user.id;
    }

    function identityLinkedEvents(userId: string) {
        return prisma.authEvent.findMany({
            where: { userId, eventType: AuthEventType.IDENTITY_LINKED },
        });
    }

    describe('a first sign-in', () => {
        it('creates the user, a verified primary email and the identity', async () => {
            const profile = googleProfile();

            const resolved = await service.resolveExternalIdentity(profile, context);
            createdUserIds.push(resolved.userId);

            const user = await prisma.user.findUniqueOrThrow({
                where: { id: resolved.userId },
                select: {
                    passwordHash: true,
                    firstName: true,
                    emails: { select: { email: true, isPrimary: true, isVerified: true } },
                    authIdentities: { select: { provider: true, providerUserId: true } },
                },
            });

            expect(resolved.emailVerified).toBe(true);
            expect(user.passwordHash).toBeNull();
            expect(user.firstName).toBe('Divyang');
            expect(user.emails).toEqual([
                { email: profile.email, isPrimary: true, isVerified: true },
            ]);
            expect(user.authIdentities).toEqual([
                { provider: AuthProvider.GOOGLE, providerUserId: profile.providerUserId },
            ]);
        });

        it('resolves the same user on the next sign-in without creating another', async () => {
            const profile = googleProfile();

            const first = await service.resolveExternalIdentity(profile, context);
            createdUserIds.push(first.userId);
            const second = await service.resolveExternalIdentity(profile, context);

            expect(second.userId).toBe(first.userId);
            expect(await prisma.authIdentity.count({ where: { userId: first.userId } })).toBe(1);
            // Linking is recorded once; the second sign-in is an ordinary login.
            expect(await identityLinkedEvents(first.userId)).toHaveLength(1);
        });
    });

    // Two devices, or a double-clicked button: both miss the identity lookup and both
    // try to insert. Only a real unique constraint under real concurrency proves the
    // loser recovers instead of surfacing a 500.
    describe('two first sign-ins at once', () => {
        it('creates exactly one user and both callers get it', async () => {
            const profile = googleProfile();

            const barrier = installTransactionOverlapBarrier(prisma, 2);
            let results: { userId: string; emailVerified: boolean }[];
            try {
                results = await Promise.all([
                    service.resolveExternalIdentity(profile, context),
                    service.resolveExternalIdentity(profile, context),
                ]);
            } finally {
                barrier.restore();
            }

            createdUserIds.push(...new Set(results.map((r) => r.userId)));

            expect(results[0].userId).toBe(results[1].userId);
            expect(
                await prisma.authIdentity.count({
                    where: {
                        provider: AuthProvider.GOOGLE,
                        providerUserId: profile.providerUserId,
                    },
                }),
            ).toBe(1);
            expect(
                await prisma.userEmail.count({ where: { email: profile.email } }),
            ).toBe(1);
        });
    });

    describe('linking to an account whose email is already verified', () => {
        it('links the identity and leaves the password and sessions alone', async () => {
            const email = `verified-${randomUUID()}@example.com`;
            const userId = await createPasswordUser(email, { verified: true });
            const session = await sessionService.createSession({
                userId,
                authMethod: AuthMethod.PASSWORD,
                emailVerified: true,
                mustChangePassword: false,
                context,
            });

            const resolved = await service.resolveExternalIdentity(
                googleProfile({ email }),
                context,
            );

            expect(resolved.userId).toBe(userId);
            const user = await prisma.user.findUniqueOrThrow({
                where: { id: userId },
                select: { passwordHash: true, authIdentities: { select: { id: true } } },
            });
            expect(user.passwordHash).not.toBeNull();
            expect(user.authIdentities).toHaveLength(1);
            await expect(
                prisma.session.findUniqueOrThrow({
                    where: { id: session.sessionId },
                    select: { revokedAt: true },
                }),
            ).resolves.toEqual({ revokedAt: null });
        });
    });

    // Pre-account hijacking, end to end: an attacker registered the victim's address
    // and never verified it. Google now proves the victim owns it.
    describe('linking to an account whose email was never verified', () => {
        async function arrangeSquattedAccount() {
            const email = `squatted-${randomUUID()}@example.com`;
            const userId = await createPasswordUser(email, { verified: false });

            const sessions = await Promise.all([
                sessionService.createSession({
                    userId,
                    authMethod: AuthMethod.PASSWORD,
                    emailVerified: false,
                    mustChangePassword: false,
                    context,
                }),
                sessionService.createSession({
                    userId,
                    authMethod: AuthMethod.PASSWORD,
                    emailVerified: false,
                    mustChangePassword: false,
                    context,
                }),
            ]);

            await prisma.userToken.create({
                data: {
                    userId,
                    tokenHash: `pending-${randomUUID()}`,
                    type: UserTokenType.EMAIL_VERIFICATION,
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
                },
            });

            return { email, userId, sessions };
        }

        it('removes the password, revokes every session and verifies the email', async () => {
            const { email, userId } = await arrangeSquattedAccount();

            const resolved = await service.resolveExternalIdentity(
                googleProfile({ email }),
                context,
            );

            expect(resolved).toEqual({ userId, emailVerified: true });

            const user = await prisma.user.findUniqueOrThrow({
                where: { id: userId },
                select: {
                    passwordHash: true,
                    passwordFailedAttempts: true,
                    passwordLockedUntil: true,
                    emails: { select: { isVerified: true, verifiedAt: true } },
                    authIdentities: { select: { provider: true } },
                },
            });

            expect(user.passwordHash).toBeNull();
            expect(user.passwordFailedAttempts).toBe(0);
            expect(user.passwordLockedUntil).toBeNull();
            expect(user.emails[0].isVerified).toBe(true);
            expect(user.emails[0].verifiedAt).not.toBeNull();
            expect(user.authIdentities).toEqual([{ provider: AuthProvider.GOOGLE }]);

            const sessions = await prisma.session.findMany({
                where: { userId },
                select: { revokedAt: true, revocationReason: true },
            });
            expect(sessions).toHaveLength(2);
            for (const session of sessions) {
                expect(session.revokedAt).not.toBeNull();
                expect(session.revocationReason).toBe(SessionRevocationReason.SECURITY);
            }
        });

        it('retires the refresh tokens of the revoked sessions', async () => {
            const { email, userId } = await arrangeSquattedAccount();

            await service.resolveExternalIdentity(googleProfile({ email }), context);

            const live = await prisma.sessionRefreshToken.count({
                where: { session: { userId }, revokedAt: null },
            });
            expect(live).toBe(0);
        });

        it('expires the pending verification token the squatter could still use', async () => {
            const { email, userId } = await arrangeSquattedAccount();

            await service.resolveExternalIdentity(googleProfile({ email }), context);

            const token = await prisma.userToken.findFirstOrThrow({
                where: { userId, type: UserTokenType.EMAIL_VERIFICATION },
                select: { expiresAt: true },
            });
            expect(token.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
        });

        it('records one IDENTITY_LINKED event describing what was done', async () => {
            const { email, userId } = await arrangeSquattedAccount();

            await service.resolveExternalIdentity(googleProfile({ email }), context);

            const events = await identityLinkedEvents(userId);
            expect(events).toHaveLength(1);
            expect(events[0].metadata).toMatchObject({
                provider: AuthProvider.GOOGLE,
                newUser: false,
                emailWasUnverified: true,
                passwordRemoved: true,
                revokedSessions: 2,
            });
        });
    });
});

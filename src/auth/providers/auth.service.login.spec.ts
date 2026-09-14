import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { Logger } from 'nestjs-pino';
import * as argon2 from 'argon2';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { EmailService } from 'src/email/email.service';
import { AuthMethod } from 'src/generated/prisma/client';
import { GENERIC_LOGIN_RESPONSE, LOGIN_FAILURE_REASON } from '../constants/auth.constants';
import { AuthContext } from '../interfaces/auth-context.interface';
import { IssuedSession } from '../interfaces/session.interface';
import { SessionService } from './session.service';

jest.mock('argon2', () => ({
    argon2id: 2,
    hash: jest.fn(),
    verify: jest.fn(),
    needsRehash: jest.fn(),
}));

const hashMock = argon2.hash as jest.Mock;
const verifyMock = argon2.verify as jest.Mock;
const needsRehashMock = argon2.needsRehash as jest.Mock;

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_SECONDS = 3600;

const body = { email: 'User@Example.com', password: 'CorrectPassword1!' };
const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest',
    deviceId: 'device-1',
};

const issuedSession: IssuedSession = {
    sessionId: 'session-1',
    tokenFamilyId: 'family-1',
    accessToken: 'access-token',
    expiresIn: 600,
    refreshToken: 'raw-refresh-token',
    refreshTokenExpiresAt: new Date('2026-01-15T00:00:00.000Z'),
};

function userRecord(overrides: Record<string, unknown> = {}) {
    return {
        id: 'email-1',
        userId: 'user-1',
        isVerified: true,
        user: {
            id: 'user-1',
            passwordHash: '$argon2id$real-hash',
            passwordFailedAttempts: 0,
            passwordLockedUntil: null,
            mustChangePassword: false,
            ...overrides,
        },
    };
}

describe('AuthService.login', () => {
    let service: AuthService;
    let prisma: {
        userEmail: { findUnique: jest.Mock };
        user: { update: jest.Mock };
        authEvent: { create: jest.Mock };
        $transaction: jest.Mock;
    };
    let tx: { user: { update: jest.Mock }; authEvent: { create: jest.Mock } };
    let sessionService: { createSession: jest.Mock };

    beforeEach(async () => {
        jest.clearAllMocks();
        hashMock.mockResolvedValue('$argon2id$dummy-hash');
        needsRehashMock.mockReturnValue(false);

        sessionService = { createSession: jest.fn().mockResolvedValue(issuedSession) };

        tx = {
            user: { update: jest.fn().mockResolvedValue({ passwordFailedAttempts: 1 }) },
            authEvent: { create: jest.fn() },
        };

        prisma = {
            userEmail: { findUnique: jest.fn() },
            user: { update: jest.fn() },
            authEvent: { create: jest.fn() },
            $transaction: jest.fn(async (cb: (client: typeof tx) => unknown) => cb(tx)),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: PrismaService, useValue: prisma },
                { provide: EmailService, useValue: { enqueue: jest.fn() } },
                { provide: SessionService, useValue: sessionService },
                {
                    provide: ConfigService,
                    useValue: {
                        get: jest.fn(() => 24),
                        getOrThrow: jest.fn((key: string) => {
                            if (key === 'auth.passwordMaxFailedAttempts') return MAX_FAILED_ATTEMPTS;
                            if (key === 'auth.passwordLockDurationSeconds') return LOCK_DURATION_SECONDS;
                            throw new Error(`Unexpected key ${key}`);
                        }),
                    },
                },
                { provide: Logger, useValue: { log: jest.fn(), warn: jest.fn(), error: jest.fn() } },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
    });

    describe('enumeration resistance', () => {
        it('returns an identical failure for an unknown email and a wrong password', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);
            const unknown = await service.login(body, context).catch((e) => e);

            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(false);
            const wrongPassword = await service.login(body, context).catch((e) => e);

            expect(unknown).toBeInstanceOf(UnauthorizedException);
            expect(wrongPassword).toBeInstanceOf(UnauthorizedException);
            expect(unknown.getStatus()).toBe(wrongPassword.getStatus());
            expect(unknown.getResponse()).toEqual(wrongPassword.getResponse());
            expect(unknown.message).toBe(GENERIC_LOGIN_RESPONSE);
        });

        // The timing fix, pinned: skipping argon2 on any branch reopens the oracle.
        it.each([
            ['an unknown email', null, false],
            ['an account with no password', userRecord({ passwordHash: null }), false],
            ['a locked account', userRecord({ passwordLockedUntil: new Date(Date.now() + 60_000) }), false],
            ['a wrong password', userRecord(), false],
            ['a successful login', userRecord(), true],
        ])('performs exactly one argon2 verification for %s', async (_label, record, matches) => {
            prisma.userEmail.findUnique.mockResolvedValue(record);
            verifyMock.mockResolvedValue(matches);

            await service.login(body, context).catch(() => undefined);

            expect(verifyMock).toHaveBeenCalledTimes(1);
        });

        it('verifies against the dummy hash when no account exists', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);

            await service.login(body, context).catch(() => undefined);

            expect(verifyMock).toHaveBeenCalledWith('$argon2id$dummy-hash', body.password);
        });

        it('normalizes the email before lookup', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);

            await service.login(body, context).catch(() => undefined);

            expect(prisma.userEmail.findUnique).toHaveBeenCalledWith(
                expect.objectContaining({ where: expect.objectContaining({ email: 'user@example.com' }) }),
            );
        });
    });

    describe('lockout', () => {
        it('clears the failure counter when it observes an expired lock', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(
                userRecord({ passwordFailedAttempts: 5, passwordLockedUntil: new Date(Date.now() - 60_000) }),
            );
            verifyMock.mockResolvedValue(false);

            await service.login(body, context).catch(() => undefined);

            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 'user-1' },
                data: { passwordFailedAttempts: 0, passwordLockedUntil: null },
            });
            // and only then is the failure counted, so it lands on 1, not 6
            expect(prisma.$transaction).toHaveBeenCalledTimes(1);
        });

        it('does not count an attempt against a still-locked account', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(
                userRecord({ passwordFailedAttempts: 5, passwordLockedUntil: new Date(Date.now() + 60_000) }),
            );
            verifyMock.mockResolvedValue(true);

            await expect(service.login(body, context)).rejects.toBeInstanceOf(UnauthorizedException);

            expect(prisma.$transaction).not.toHaveBeenCalled();
            expect(prisma.authEvent.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: expect.objectContaining({
                        metadata: expect.objectContaining({ reason: LOGIN_FAILURE_REASON.ACCOUNT_LOCKED }),
                    }),
                }),
            );
        });

        it('audits an unknown email without a userId', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);

            await service.login(body, context).catch(() => undefined);

            expect(prisma.authEvent.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: expect.objectContaining({
                        userId: undefined,
                        ipAddress: '203.0.113.10',
                        metadata: expect.objectContaining({ reason: LOGIN_FAILURE_REASON.USER_NOT_FOUND }),
                    }),
                }),
            );
        });

        it('attributes a no-password account to its user', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord({ passwordHash: null }));
            verifyMock.mockResolvedValue(false);

            await service.login(body, context).catch(() => undefined);

            expect(prisma.authEvent.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: expect.objectContaining({
                        userId: 'user-1',
                        metadata: expect.objectContaining({
                            reason: LOGIN_FAILURE_REASON.NO_PASSWORD_CREDENTIAL,
                        }),
                    }),
                }),
            );
        });
    });

    describe('success', () => {
        it('resets the failure state and returns the issued session and user', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);

            const result = await service.login(body, context);

            expect(result).toEqual({
                session: issuedSession,
                user: {
                    id: 'user-1',
                    emailVerified: true,
                    mustChangePassword: false,
                },
            });
            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 'user-1' },
                data: { passwordFailedAttempts: 0, passwordLockedUntil: null },
            });
        });

        it('creates exactly one session for the authenticated user', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);

            await service.login(body, context);

            expect(sessionService.createSession).toHaveBeenCalledTimes(1);
            expect(sessionService.createSession).toHaveBeenCalledWith({
                userId: 'user-1',
                authMethod: AuthMethod.PASSWORD,
                emailVerified: true,
                context,
            });
        });

        it('does not leak the request context back to the caller', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);

            const result = await service.login(body, context);

            expect(result).not.toHaveProperty('context');
        });

        it('surfaces mustChangePassword instead of blocking', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord({ mustChangePassword: true }));
            verifyMock.mockResolvedValue(true);

            await expect(service.login(body, context)).resolves.toMatchObject({
                user: { mustChangePassword: true },
            });
        });

        it('upgrades a stale password hash without touching passwordChangedAt', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);
            needsRehashMock.mockReturnValue(true);
            hashMock.mockResolvedValue('$argon2id$upgraded');

            await service.login(body, context);

            const upgrade = prisma.user.update.mock.calls.find(
                ([arg]) => arg.data.passwordHash !== undefined,
            );
            expect(upgrade[0].data).toEqual({ passwordHash: '$argon2id$upgraded' });
            expect(upgrade[0].data).not.toHaveProperty('passwordChangedAt');
        });

        it('still logs the user in when the rehash upgrade fails', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);
            needsRehashMock.mockReturnValue(true);
            hashMock.mockRejectedValueOnce(new Error('argon2 exploded'));

            await expect(service.login(body, context)).resolves.toMatchObject({
                session: issuedSession,
                user: { id: 'user-1' },
            });
        });
    });
});

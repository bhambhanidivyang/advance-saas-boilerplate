import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { Logger } from 'nestjs-pino';
import * as argon2 from 'argon2';
import { PasswordAuthenticatorService } from './password-authenticator.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthMethod } from 'src/generated/prisma/client';
import { GENERIC_LOGIN_RESPONSE, LOGIN_FAILURE_REASON } from '../constants/auth.constants';
import { AuthContext } from '../interfaces/auth-context.interface';

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

const credentials = { email: 'User@Example.com', password: 'CorrectPassword1!' };
const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest',
    deviceId: 'device-1',
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

/** Records every top-level property read, so a test can prove what was never touched. */
function tracked<T extends object>(target: T, accessed: Set<string>): T {
    return new Proxy(target, {
        get(obj, key, receiver) {
            accessed.add(String(key));
            return Reflect.get(obj, key, receiver);
        },
    });
}

describe('PasswordAuthenticatorService', () => {
    let authenticator: PasswordAuthenticatorService;
    let prisma: {
        userEmail: { findUnique: jest.Mock };
        user: { update: jest.Mock };
        authEvent: { create: jest.Mock };
        $transaction: jest.Mock;
    };
    let tx: { user: { update: jest.Mock }; authEvent: { create: jest.Mock } };
    let accessed: Set<string>;

    beforeEach(async () => {
        jest.clearAllMocks();
        hashMock.mockResolvedValue('$argon2id$dummy-hash');
        needsRehashMock.mockReturnValue(false);
        accessed = new Set();

        tx = tracked(
            {
                user: { update: jest.fn().mockResolvedValue({ passwordFailedAttempts: 1 }) },
                authEvent: { create: jest.fn() },
            },
            accessed,
        );

        prisma = {
            userEmail: { findUnique: jest.fn() },
            user: { update: jest.fn() },
            authEvent: { create: jest.fn() },
            $transaction: jest.fn(async (cb: (client: typeof tx) => unknown) => cb(tx)),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                PasswordAuthenticatorService,
                { provide: PrismaService, useValue: tracked(prisma, accessed) },
                {
                    provide: ConfigService,
                    useValue: {
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

        authenticator = module.get(PasswordAuthenticatorService);
    });

    describe('enumeration resistance', () => {
        it('returns an identical failure for an unknown email and a wrong password', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);
            const unknown = await authenticator.authenticate(credentials, context).catch((e) => e);

            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(false);
            const wrongPassword = await authenticator.authenticate(credentials, context).catch((e) => e);

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

            await authenticator.authenticate(credentials, context).catch(() => undefined);

            expect(verifyMock).toHaveBeenCalledTimes(1);
        });

        it('verifies against the dummy hash when no account exists', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);

            await authenticator.authenticate(credentials, context).catch(() => undefined);

            expect(verifyMock).toHaveBeenCalledWith('$argon2id$dummy-hash', credentials.password);
        });

        it('normalizes the email before lookup', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(null);
            verifyMock.mockResolvedValue(false);

            await authenticator.authenticate(credentials, context).catch(() => undefined);

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

            await authenticator.authenticate(credentials, context).catch(() => undefined);

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

            await expect(authenticator.authenticate(credentials, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );

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

            await authenticator.authenticate(credentials, context).catch(() => undefined);

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

            await authenticator.authenticate(credentials, context).catch(() => undefined);

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
        it('resets the failure state and returns an AuthenticationResult', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);

            const result = await authenticator.authenticate(credentials, context);

            expect(result).toEqual({
                userId: 'user-1',
                authMethod: AuthMethod.PASSWORD,
                emailVerified: true,
                mustChangePassword: false,
            });
            expect(prisma.user.update).toHaveBeenCalledWith({
                where: { id: 'user-1' },
                data: { passwordFailedAttempts: 0, passwordLockedUntil: null },
            });
        });

        it('reports an unverified email instead of blocking', async () => {
            prisma.userEmail.findUnique.mockResolvedValue({ ...userRecord(), isVerified: false });
            verifyMock.mockResolvedValue(true);

            await expect(authenticator.authenticate(credentials, context)).resolves.toMatchObject({
                emailVerified: false,
            });
        });

        it('surfaces mustChangePassword instead of blocking', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord({ mustChangePassword: true }));
            verifyMock.mockResolvedValue(true);

            await expect(authenticator.authenticate(credentials, context)).resolves.toMatchObject({
                mustChangePassword: true,
            });
        });

        // Authenticators prove identity; SessionService alone issues sessions.
        it('never touches sessions or refresh tokens', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);

            await authenticator.authenticate(credentials, context);

            expect(accessed.has('session')).toBe(false);
            expect(accessed.has('sessionRefreshToken')).toBe(false);
        });

        it('upgrades a stale password hash without touching passwordChangedAt', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);
            needsRehashMock.mockReturnValue(true);
            hashMock.mockResolvedValue('$argon2id$upgraded');

            await authenticator.authenticate(credentials, context);

            const upgrade = prisma.user.update.mock.calls.find(
                ([arg]) => arg.data.passwordHash !== undefined,
            );
            expect(upgrade[0].data).toEqual({ passwordHash: '$argon2id$upgraded' });
            expect(upgrade[0].data).not.toHaveProperty('passwordChangedAt');
        });

        it('still authenticates when the rehash upgrade fails', async () => {
            prisma.userEmail.findUnique.mockResolvedValue(userRecord());
            verifyMock.mockResolvedValue(true);
            needsRehashMock.mockReturnValue(true);
            hashMock.mockRejectedValueOnce(new Error('argon2 exploded'));

            await expect(authenticator.authenticate(credentials, context)).resolves.toMatchObject({
                userId: 'user-1',
                authMethod: AuthMethod.PASSWORD,
            });
        });
    });
});

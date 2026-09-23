import { BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, SessionRevocationReason, UserStatus } from 'src/generated/prisma/client';
import { PasswordService } from './password.service';
import { SessionService } from '../session/session.service';
import { hashPassword, verifyPassword } from './password-hash.util';
import { ChangePasswordArgs } from './password.interface';

// Mocked at the util rather than at argon2, so these tests never pay for real
// hashing and can drive the verify outcome directly.
jest.mock('./password-hash.util', () => ({
    hashPassword: jest.fn(),
    verifyPassword: jest.fn(),
}));

const hashMock = hashPassword as jest.Mock;
const verifyMock = verifyPassword as jest.Mock;

const NOW = new Date('2026-08-01T00:00:00.000Z');
const SESSION_EXPIRES_AT = new Date('2026-08-20T00:00:00.000Z');

const args: ChangePasswordArgs = {
    userId: 'user-1',
    sessionId: 'session-1',
    currentPassword: 'Current!Pass1',
    newPassword: 'Brand!New2',
    context: { ipAddress: '203.0.113.10', userAgent: 'jest', deviceId: 'device-1' },
};

function activeSession(overrides: Record<string, unknown> = {}, userOverrides: Record<string, unknown> = {}) {
    return {
        userId: 'user-1',
        expiresAt: SESSION_EXPIRES_AT,
        revokedAt: null,
        ...overrides,
        user: {
            status: UserStatus.ACTIVE,
            deletedAt: null,
            passwordHash: '$argon2id$current',
            ...userOverrides,
        },
    };
}

describe('PasswordService.changePassword', () => {
    let service: PasswordService;
    let tx: { user: { update: jest.Mock }; authEvent: { create: jest.Mock } };
    let prisma: { session: { findUnique: jest.Mock }; $transaction: jest.Mock };
    let sessionService: { revokeSessions: jest.Mock; reissueRefreshToken: jest.Mock };

    beforeEach(() => {
        jest.clearAllMocks();
        jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
        jest.setSystemTime(NOW);

        hashMock.mockResolvedValue('$argon2id$new');
        verifyMock.mockResolvedValue(true);

        tx = {
            user: { update: jest.fn().mockResolvedValue({}) },
            authEvent: { create: jest.fn().mockResolvedValue({}) },
        };

        prisma = {
            session: { findUnique: jest.fn().mockResolvedValue(activeSession()) },
            $transaction: jest.fn(async (work: (client: typeof tx) => Promise<unknown>) => work(tx)),
        };

        sessionService = {
            revokeSessions: jest.fn().mockResolvedValue(['session-2', 'session-3']),
            reissueRefreshToken: jest.fn().mockResolvedValue({
                refreshToken: 'new-refresh-token',
                refreshTokenExpiresAt: new Date('2026-08-15T00:00:00.000Z'),
            }),
        };

        service = new PasswordService(
            prisma as unknown as PrismaService,
            sessionService as unknown as SessionService,
        );
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    // The guard is stateless, so a session revoked minutes ago still carries a valid
    // access token. A credential change must not run on one.
    describe('the session re-check', () => {
        it.each([
            ['the session is gone', null],
            ['the session belongs to another user', activeSession({ userId: 'someone-else' })],
            ['the session is revoked', activeSession({ revokedAt: NOW })],
            ['the session has expired', activeSession({ expiresAt: new Date('2026-07-01T00:00:00.000Z') })],
            ['the user is suspended', activeSession({}, { status: UserStatus.SUSPENDED })],
            ['the user is soft-deleted', activeSession({}, { deletedAt: NOW })],
        ])('rejects with 401 when %s', async (_label, session) => {
            prisma.session.findUnique.mockResolvedValue(session);

            const error = await service.changePassword(args).catch((e) => e);

            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.getResponse()).toMatchObject({ code: 'SESSION_REVOKED' });
            // Not even the password is checked, and nothing is written.
            expect(verifyMock).not.toHaveBeenCalled();
            expect(prisma.$transaction).not.toHaveBeenCalled();
        });
    });

    it('rejects an account that has no password to change', async () => {
        prisma.session.findUnique.mockResolvedValue(activeSession({}, { passwordHash: null }));

        const error = await service.changePassword(args).catch((e) => e);

        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.getResponse()).toMatchObject({ code: 'NO_PASSWORD_CREDENTIAL' });
        expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    describe('re-authentication', () => {
        // 403, not 401: clients treat 401 as "session died, refresh and retry", which
        // is wrong here — the session is fine, the input is not.
        it('rejects a wrong current password with 403 and writes nothing', async () => {
            verifyMock.mockResolvedValue(false);

            const error = await service.changePassword(args).catch((e) => e);

            expect(error).toBeInstanceOf(ForbiddenException);
            expect(error.getStatus()).toBe(403);
            expect(error.getResponse()).toMatchObject({ code: 'INVALID_CURRENT_PASSWORD' });
            expect(verifyMock).toHaveBeenCalledWith(args.currentPassword, '$argon2id$current');
            expect(prisma.$transaction).not.toHaveBeenCalled();
        });

        // Counting this would let anything able to send requests as the user — an XSS,
        // say — lock the real owner out of their own account.
        it('does not touch the lockout counter on a wrong current password', async () => {
            verifyMock.mockResolvedValue(false);

            await service.changePassword(args).catch(() => undefined);

            expect(tx.user.update).not.toHaveBeenCalled();
        });

        it('rejects reusing the same password', async () => {
            const error = await service
                .changePassword({ ...args, newPassword: args.currentPassword })
                .catch((e) => e);

            expect(error).toBeInstanceOf(BadRequestException);
            expect(error.getResponse()).toMatchObject({ code: 'PASSWORD_UNCHANGED' });
            expect(prisma.$transaction).not.toHaveBeenCalled();
        });
    });

    describe('the change itself', () => {
        it('stores the new hash and clears the credential state', async () => {
            await service.changePassword(args);

            expect(hashMock).toHaveBeenCalledWith(args.newPassword);
            expect(tx.user.update).toHaveBeenCalledWith({
                where: { id: 'user-1' },
                data: {
                    passwordHash: '$argon2id$new',
                    passwordChangedAt: NOW,
                    mustChangePassword: false,
                    passwordFailedAttempts: 0,
                    passwordLockedUntil: null,
                },
            });
        });

        // argon2 is deliberately CPU-bound; holding a transaction open across it would
        // pin a database connection for ~100ms per call.
        it('hashes before opening the transaction', async () => {
            await service.changePassword(args);

            expect(hashMock.mock.invocationCallOrder[0]).toBeLessThan(
                prisma.$transaction.mock.invocationCallOrder[0],
            );
        });

        it('revokes every other session but keeps this one', async () => {
            await service.changePassword(args);

            expect(sessionService.revokeSessions).toHaveBeenCalledWith(
                expect.objectContaining({ tx }),
                { userId: 'user-1', id: { not: 'session-1' } },
                SessionRevocationReason.PASSWORD_CHANGED,
                NOW,
            );
        });

        it('retires this session own refresh tokens and issues a replacement', async () => {
            const result = await service.changePassword(args);

            expect(sessionService.reissueRefreshToken).toHaveBeenCalledWith(
                expect.objectContaining({ tx }),
                'session-1',
                SESSION_EXPIRES_AT,
                NOW,
            );
            expect(result).toEqual({
                refreshToken: 'new-refresh-token',
                refreshTokenExpiresAt: new Date('2026-08-15T00:00:00.000Z'),
                revokedSessions: 2,
            });
        });

        // Everything must land in ONE transaction, or a partial failure could change
        // the password while leaving a stolen refresh token alive.
        it('performs every write through the same unit of work', async () => {
            await service.changePassword(args);

            expect(prisma.$transaction).toHaveBeenCalledTimes(1);
            const revokeUow = sessionService.revokeSessions.mock.calls[0][0];
            const reissueUow = sessionService.reissueRefreshToken.mock.calls[0][0];
            expect(revokeUow).toBe(reissueUow);
            expect(revokeUow.tx).toBe(tx);
        });

        it('records one PASSWORD_CHANGED event naming the sessions it ended', async () => {
            await service.changePassword(args);

            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
            expect(tx.authEvent.create.mock.calls[0][0].data).toMatchObject({
                userId: 'user-1',
                sessionId: 'session-1',
                eventType: AuthEventType.PASSWORD_CHANGED,
                metadata: { deviceId: 'device-1', revokedOtherSessions: 2 },
            });
        });

        it('reports zero revoked sessions when the user had no other device', async () => {
            sessionService.revokeSessions.mockResolvedValue([]);

            const result = await service.changePassword(args);

            expect(result.revokedSessions).toBe(0);
            // The change itself is still audited.
            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
        });
    });
});

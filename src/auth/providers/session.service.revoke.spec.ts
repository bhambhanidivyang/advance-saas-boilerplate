import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    AuthEventType,
    AuthMethod,
    SessionRevocationReason,
} from 'src/generated/prisma/client';
import { SessionService } from './session.service';
import { TokenService } from './token.service';
import { SessionDenylistService } from './session-denylist.service';
import { AuthContext } from '../interfaces/auth-context.interface';

const NOW = new Date('2026-07-01T00:00:00.000Z');

const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest',
    deviceId: 'device-1',
};

describe('SessionService revocation', () => {
    let service: SessionService;
    let tx: {
        session: { findUnique: jest.Mock; updateMany: jest.Mock; findMany: jest.Mock };
        sessionRefreshToken: { updateMany: jest.Mock };
        authEvent: { create: jest.Mock };
    };
    let prisma: { $transaction: jest.Mock; sessionRefreshToken: { findUnique: jest.Mock } };

    beforeEach(() => {
        jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
        jest.setSystemTime(NOW);

        tx = {
            session: {
                findUnique: jest
                    .fn()
                    .mockResolvedValue({ userId: 'user-1', authMethod: AuthMethod.PASSWORD }),
                updateMany: jest.fn().mockResolvedValue({ count: 1 }),
                findMany: jest.fn().mockResolvedValue([{ id: 'session-1' }]),
            },
            sessionRefreshToken: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
            authEvent: { create: jest.fn().mockResolvedValue({}) },
        };

        prisma = {
            $transaction: jest.fn(async (callback: (client: typeof tx) => Promise<unknown>) =>
                callback(tx),
            ),
            sessionRefreshToken: { findUnique: jest.fn() },
        };

        service = new SessionService(
            { getOrThrow: jest.fn() } as unknown as ConfigService,
            prisma as unknown as PrismaService,
            { generateAccessToken: jest.fn() } as unknown as TokenService,
            { revoke: jest.fn(), isRevoked: jest.fn().mockResolvedValue(false) } as unknown as SessionDenylistService,
        );
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    describe('revokeSession', () => {
        it('revokes the session, its refresh tokens, and records LOGOUT once', async () => {
            await service.revokeSession('session-1', context);

            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: 'session-1', revokedAt: null },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.LOGOUT },
            });
            expect(tx.sessionRefreshToken.updateMany).toHaveBeenCalledWith({
                where: { sessionId: 'session-1', revokedAt: null },
                data: { revokedAt: NOW },
            });
            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
            expect(tx.authEvent.create.mock.calls[0][0].data).toEqual({
                userId: 'user-1',
                sessionId: 'session-1',
                eventType: AuthEventType.LOGOUT,
                authMethod: AuthMethod.PASSWORD,
                ipAddress: '203.0.113.10',
                userAgent: 'jest',
                metadata: { deviceId: 'device-1' },
            });
        });

        // A double-click must not 400, and must not log a second logout.
        it('is a silent no-op when the session is already revoked', async () => {
            tx.session.updateMany.mockResolvedValue({ count: 0 });

            await expect(service.revokeSession('session-1', context)).resolves.toBeUndefined();

            expect(tx.sessionRefreshToken.updateMany).not.toHaveBeenCalled();
            expect(tx.authEvent.create).not.toHaveBeenCalled();
        });

        it('does nothing for a session that does not exist', async () => {
            tx.session.findUnique.mockResolvedValue(null);

            await expect(service.revokeSession('missing', context)).resolves.toBeUndefined();

            expect(tx.session.updateMany).not.toHaveBeenCalled();
            expect(tx.authEvent.create).not.toHaveBeenCalled();
        });

        // Having no unrevoked tokens left is normal; it must not suppress the event.
        it('still records LOGOUT when no refresh tokens needed revoking', async () => {
            tx.sessionRefreshToken.updateMany.mockResolvedValue({ count: 0 });

            await service.revokeSession('session-1', context);

            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
        });
    });

    describe('revokeSessionByRefreshToken', () => {
        it('resolves the session from the token hash and revokes it', async () => {
            prisma.sessionRefreshToken.findUnique.mockResolvedValue({ sessionId: 'session-1' });

            await service.revokeSessionByRefreshToken('raw-token', context);

            expect(prisma.sessionRefreshToken.findUnique).toHaveBeenCalledWith(
                expect.objectContaining({ select: { sessionId: true } }),
            );
            expect(tx.session.updateMany).toHaveBeenCalled();
        });

        it('ignores a token it does not recognise', async () => {
            prisma.sessionRefreshToken.findUnique.mockResolvedValue(null);

            await expect(
                service.revokeSessionByRefreshToken('unknown-token', context),
            ).resolves.toBeUndefined();

            expect(prisma.$transaction).not.toHaveBeenCalled();
        });
    });

    describe('revokeAllSessions', () => {
        it('revokes every active session and writes one event carrying the count', async () => {
            tx.session.findMany.mockResolvedValue([
                { id: 'session-1' },
                { id: 'session-2' },
                { id: 'session-3' },
            ]);

            const revoked = await service.revokeAllSessions({
                userId: 'user-1',
                initiatingSessionId: 'session-1',
                context,
            });

            expect(revoked).toBe(3);
            // Ids are read first so the revoked set is known exactly, which the
            // denylist needs and which keeps already-revoked sessions untouched.
            expect(tx.session.findMany).toHaveBeenCalledWith({
                where: { userId: 'user-1', revokedAt: null },
                select: { id: true },
            });
            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: { in: ['session-1', 'session-2', 'session-3'] } },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.LOGOUT_ALL },
            });
            expect(tx.sessionRefreshToken.updateMany).toHaveBeenCalledWith({
                where: {
                    sessionId: { in: ['session-1', 'session-2', 'session-3'] },
                    revokedAt: null,
                },
                data: { revokedAt: NOW },
            });

            // One action, one record — not one event per session.
            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
            expect(tx.authEvent.create.mock.calls[0][0].data.eventType).toBe(
                AuthEventType.LOGOUT_ALL,
            );
            expect(tx.authEvent.create.mock.calls[0][0].data.metadata).toEqual({
                deviceId: 'device-1',
                revokedCount: 3,
                initiatingSessionId: 'session-1',
                keptSessionId: null,
            });
        });


        it('defaults to LOGOUT_ALL but accepts another reason and event type', async () => {
            tx.session.findMany.mockResolvedValue([{ id: 'session-2' }]);

            await service.revokeAllSessions({
                userId: 'user-1',
                initiatingSessionId: 'session-1',
                context,
                reason: SessionRevocationReason.PASSWORD_CHANGED,
                eventType: AuthEventType.PASSWORD_CHANGED,
            });

            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: { in: ['session-2'] } },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.PASSWORD_CHANGED },
            });
            expect(tx.authEvent.create.mock.calls[0][0].data.eventType).toBe(
                AuthEventType.PASSWORD_CHANGED,
            );
        });

        // What a password change needs: end every other device, keep this one.
        it('leaves the excepted session untouched', async () => {
            tx.session.findMany.mockResolvedValue([{ id: 'session-2' }, { id: 'session-3' }]);

            const revoked = await service.revokeAllSessions({
                userId: 'user-1',
                initiatingSessionId: 'session-1',
                context,
                exceptSessionId: 'session-1',
            });

            expect(revoked).toBe(2);
            expect(tx.session.findMany).toHaveBeenCalledWith({
                where: { userId: 'user-1', revokedAt: null, id: { not: 'session-1' } },
                select: { id: true },
            });
            expect(tx.session.updateMany.mock.calls[0][0].where.id.in).not.toContain('session-1');
            expect(tx.authEvent.create.mock.calls[0][0].data.metadata.keptSessionId).toBe(
                'session-1',
            );
        });

        it('writes nothing when the user has no active sessions', async () => {
            tx.session.findMany.mockResolvedValue([]);

            await expect(
                service.revokeAllSessions({ userId: 'user-1', context }),
            ).resolves.toBe(0);

            expect(tx.sessionRefreshToken.updateMany).not.toHaveBeenCalled();
            expect(tx.authEvent.create).not.toHaveBeenCalled();
        });
    });
});

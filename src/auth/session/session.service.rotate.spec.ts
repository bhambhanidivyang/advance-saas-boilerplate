import { createHash } from 'crypto';
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    AuthEventType,
    AuthMethod,
    SessionRevocationReason,
    UserStatus,
} from 'src/generated/prisma/client';
import { SessionService } from './session.service';
import { TokenService } from './token.service';
import { SessionDenylistService } from './session-denylist.service';
import { AuthContext } from '../interfaces/auth-context.interface';

const NOW = new Date('2026-06-01T00:00:00.000Z');
const GRACE_SECONDS = 15;
const REFRESH_TTL_SECONDS = 14 * 24 * 60 * 60;

const RAW_TOKEN = 'presented-raw-token';
const PRESENTED_HASH = createHash('sha256').update(RAW_TOKEN).digest('hex');

const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest',
    deviceId: 'device-1',
};

function storedToken(
    tokenOverrides: Record<string, unknown> = {},
    sessionOverrides: Record<string, unknown> = {},
) {
    return {
        id: 'token-1',
        usedAt: null,
        revokedAt: null,
        expiresAt: new Date('2026-06-10T00:00:00.000Z'),
        ...tokenOverrides,
        session: {
            id: 'session-1',
            userId: 'user-1',
            tokenFamilyId: 'family-1',
            authMethod: AuthMethod.PASSWORD,
            expiresAt: new Date('2026-06-20T00:00:00.000Z'),
            revokedAt: null,
            user: { status: UserStatus.ACTIVE, mustChangePassword: false },
            ...sessionOverrides,
        },
    };
}

describe('SessionService.rotateRefreshToken', () => {
    let service: SessionService;
    let tx: {
        sessionRefreshToken: { findUnique: jest.Mock; updateMany: jest.Mock; create: jest.Mock };
        session: { updateMany: jest.Mock; update: jest.Mock; findMany: jest.Mock };
        userEmail: { findFirst: jest.Mock };
        authEvent: { create: jest.Mock };
    };
    let prisma: { $transaction: jest.Mock };
    let tokenService: { generateAccessToken: jest.Mock };
    let denylist: { revoke: jest.Mock };
    // Pins the "return an outcome, never throw inside the transaction" rule: if the
    // callback threw, this stays false and the writes would have rolled back.
    let transactionCommitted: boolean;

    function expectNoWrites() {
        expect(tx.sessionRefreshToken.updateMany).not.toHaveBeenCalled();
        expect(tx.sessionRefreshToken.create).not.toHaveBeenCalled();
        expect(tx.session.updateMany).not.toHaveBeenCalled();
        expect(tx.session.update).not.toHaveBeenCalled();
        expect(tx.authEvent.create).not.toHaveBeenCalled();
    }

    function auditEventsOfType(eventType: AuthEventType) {
        return tx.authEvent.create.mock.calls.filter(([arg]) => arg.data.eventType === eventType);
    }

    beforeEach(() => {
        jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
        jest.setSystemTime(NOW);

        transactionCommitted = false;

        tx = {
            sessionRefreshToken: {
                findUnique: jest.fn().mockResolvedValue(storedToken()),
                updateMany: jest.fn().mockResolvedValue({ count: 1 }),
                create: jest.fn().mockResolvedValue({}),
            },
            session: {
                updateMany: jest.fn().mockResolvedValue({ count: 1 }),
                update: jest.fn().mockResolvedValue({}),
                findMany: jest.fn().mockResolvedValue([{ id: 'session-1' }]),
            },
            userEmail: { findFirst: jest.fn().mockResolvedValue({ isVerified: true }) },
            authEvent: { create: jest.fn().mockResolvedValue({}) },
        };

        prisma = {
            $transaction: jest.fn(async (callback: (client: typeof tx) => Promise<unknown>) => {
                const outcome = await callback(tx);
                transactionCommitted = true;
                return outcome;
            }),
        };

        tokenService = {
            generateAccessToken: jest
                .fn()
                .mockResolvedValue({ accessToken: 'access-token', expiresIn: 600 }),
        };

        denylist = { revoke: jest.fn() };

        const config = {
            getOrThrow: jest.fn((key: string) => {
                if (key === 'auth.session.refreshReuseGraceSeconds') return GRACE_SECONDS;
                if (key === 'auth.session.refreshTtlSeconds') return REFRESH_TTL_SECONDS;
                throw new TypeError(`Configuration key "${key}" does not exist`);
            }),
        };

        service = new SessionService(
            config as unknown as ConfigService,
            prisma as unknown as PrismaService,
            tokenService as unknown as TokenService,
            denylist as unknown as SessionDenylistService,
        );
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    describe('rejections that write nothing', () => {
        it('rejects an unknown token', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(null);

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
            expectNoWrites();
            expect(tokenService.generateAccessToken).not.toHaveBeenCalled();
        });

        it('rejects a token whose session is already revoked, without raising an alarm', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({}, { revokedAt: new Date('2026-05-30T00:00:00.000Z') }),
            );

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
            expectNoWrites();
        });

        it('rejects a suspended user, so suspension ends refreshing immediately', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({}, { user: { status: UserStatus.SUSPENDED, mustChangePassword: false } }),
            );

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
            expectNoWrites();
        });

        it('rejects a revoked token', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({ revokedAt: new Date('2026-05-31T00:00:00.000Z') }),
            );

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
            expectNoWrites();
        });

        it('rejects an idle-timed-out token without raising an alarm', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({ expiresAt: new Date('2026-05-31T00:00:00.000Z') }),
            );

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
            expectNoWrites();
            expect(auditEventsOfType(AuthEventType.TOKEN_REUSE_DETECTED)).toHaveLength(0);
        });
    });

    describe('an expired session', () => {
        // The rejection has a write that must survive, which only happens because the
        // transaction returns an outcome instead of throwing.
        it('is swept to EXPIRED and the sweep commits before the 401', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({}, { expiresAt: new Date('2026-05-20T00:00:00.000Z') }),
            );

            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );

            expect(transactionCommitted).toBe(true);
            expect(tx.session.findMany).toHaveBeenCalledWith({
                where: { id: 'session-1', revokedAt: null },
                select: { id: true },
            });
            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: { in: ['session-1'] } },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.EXPIRED },
            });
        });
    });

    describe('the happy path', () => {
        it('consumes the presented token with a conditional update', async () => {
            await service.rotateRefreshToken(RAW_TOKEN, context);

            expect(tx.sessionRefreshToken.findUnique).toHaveBeenCalledWith(
                expect.objectContaining({ where: { tokenHash: PRESENTED_HASH } }),
            );
            expect(tx.sessionRefreshToken.updateMany).toHaveBeenCalledWith({
                where: { id: 'token-1', usedAt: null },
                data: { usedAt: NOW },
            });
        });

        it('issues a replacement whose stored hash matches the token it returns', async () => {
            const result = await service.rotateRefreshToken(RAW_TOKEN, context);

            const stored = tx.sessionRefreshToken.create.mock.calls[0][0].data;
            expect(stored.sessionId).toBe('session-1');
            expect(stored.tokenHash).toBe(
                createHash('sha256').update(result.refreshToken).digest('hex'),
            );
            expect(result.refreshToken).not.toBe(RAW_TOKEN);
            expect(stored.expiresAt).toEqual(new Date('2026-06-15T00:00:00.000Z'));
        });

        it('touches the session timestamps and records TOKEN_REFRESH', async () => {
            await service.rotateRefreshToken(RAW_TOKEN, context);

            expect(tx.session.update).toHaveBeenCalledWith({
                where: { id: 'session-1' },
                data: {
                    lastUsedAt: NOW,
                    lastRefreshedAt: NOW,
                    ipAddress: '203.0.113.10',
                    userAgent: 'jest',
                },
            });
            expect(auditEventsOfType(AuthEventType.TOKEN_REFRESH)).toHaveLength(1);
            expect(tx.authEvent.create.mock.calls[0][0].data.metadata).toEqual({
                deviceId: 'device-1',
                graceReplay: false,
            });
        });

        it('mints the access token with the freshly read emailVerified', async () => {
            tx.userEmail.findFirst.mockResolvedValue({ isVerified: false });

            const result = await service.rotateRefreshToken(RAW_TOKEN, context);

            expect(tx.userEmail.findFirst).toHaveBeenCalledWith({
                where: { userId: 'user-1', isPrimary: true },
                select: { isVerified: true },
            });
            expect(tokenService.generateAccessToken).toHaveBeenCalledWith({
                userId: 'user-1',
                sessionId: 'session-1',
                tokenFamilyId: 'family-1',
                emailVerified: false,
                mustChangePassword: false,
                authMethod: AuthMethod.PASSWORD,
            });
            expect(result.accessToken).toBe('access-token');
            expect(result.expiresIn).toBe(600);
        });
    });

    describe('a used token inside the grace window', () => {
        it('is treated as a benign double-submit: new token, nothing revoked', async () => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({ usedAt: new Date(NOW.getTime() - 5_000) }),
            );

            const result = await service.rotateRefreshToken(RAW_TOKEN, context);

            expect(result.refreshToken).toEqual(expect.any(String));
            // Not consumed again, and nothing revoked.
            expect(tx.sessionRefreshToken.updateMany).not.toHaveBeenCalled();
            expect(tx.session.updateMany).not.toHaveBeenCalled();
            expect(auditEventsOfType(AuthEventType.TOKEN_REUSE_DETECTED)).toHaveLength(0);
            expect(tx.authEvent.create.mock.calls[0][0].data.metadata.graceReplay).toBe(true);
        });

        it('is also how a lost consume race resolves, rather than as theft', async () => {
            tx.sessionRefreshToken.findUnique
                .mockResolvedValueOnce(storedToken())
                .mockResolvedValueOnce({ usedAt: new Date(NOW.getTime() - 1_000) });
            tx.sessionRefreshToken.updateMany.mockResolvedValue({ count: 0 });

            const result = await service.rotateRefreshToken(RAW_TOKEN, context);

            expect(result.refreshToken).toEqual(expect.any(String));
            expect(tx.session.updateMany).not.toHaveBeenCalled();
            expect(auditEventsOfType(AuthEventType.TOKEN_REUSE_DETECTED)).toHaveLength(0);
        });
    });

    describe('a used token outside the grace window', () => {
        beforeEach(() => {
            tx.sessionRefreshToken.findUnique.mockResolvedValue(
                storedToken({ usedAt: new Date(NOW.getTime() - 60_000) }),
            );
            tx.session.findMany.mockResolvedValue([{ id: 'session-1' }, { id: 'session-2' }]);
        });

        it('revokes the whole family and commits that before the 401', async () => {
            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );

            expect(transactionCommitted).toBe(true);
            expect(tx.session.findMany).toHaveBeenCalledWith({
                where: { userId: 'user-1', tokenFamilyId: 'family-1', revokedAt: null },
                select: { id: true },
            });
            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: { in: ['session-1', 'session-2'] } },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.TOKEN_REUSE },
            });
            expect(tx.sessionRefreshToken.updateMany).toHaveBeenCalledWith({
                where: { sessionId: { in: ['session-1', 'session-2'] }, revokedAt: null },
                data: { revokedAt: NOW },
            });
            // The stolen token's family must also lose its live access tokens.
            expect(denylist.revoke).toHaveBeenCalledWith(['session-1', 'session-2']);
        });

        it('records TOKEN_REUSE_DETECTED and issues no replacement', async () => {
            await expect(service.rotateRefreshToken(RAW_TOKEN, context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );

            const reuse = auditEventsOfType(AuthEventType.TOKEN_REUSE_DETECTED);
            expect(reuse).toHaveLength(1);
            expect(reuse[0][0].data.metadata).toMatchObject({
                tokenFamilyId: 'family-1',
                presentedTokenId: 'token-1',
                revokedSessions: 2,
            });
            expect(tx.sessionRefreshToken.create).not.toHaveBeenCalled();
            expect(tokenService.generateAccessToken).not.toHaveBeenCalled();
        });
    });
});

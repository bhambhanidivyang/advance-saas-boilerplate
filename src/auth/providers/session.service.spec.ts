import { createHash } from 'crypto';
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
import { CreateSessionArgs } from '../interfaces/session.interface';

const NOW = new Date('2026-01-01T00:00:00.000Z');
const DAY_SECONDS = 24 * 60 * 60;
const ABSOLUTE_TTL_SECONDS = 30 * DAY_SECONDS;
const REFRESH_TTL_SECONDS = 14 * DAY_SECONDS;
const MAX_ACTIVE_PER_USER = 10;

const args: CreateSessionArgs = {
    userId: 'user-1',
    authMethod: AuthMethod.PASSWORD,
    emailVerified: true,
    context: {
        ipAddress: '203.0.113.10',
        userAgent: 'jest',
        deviceId: 'device-1',
    },
};

function createConfig(ttls: { absolute: number; refresh: number; maxActive?: number }) {
    return {
        getOrThrow: jest.fn((key: string) => {
            if (key === 'auth.session.absoluteTtlSeconds') return ttls.absolute;
            if (key === 'auth.session.refreshTtlSeconds') return ttls.refresh;
            if (key === 'auth.session.maxActivePerUser') return ttls.maxActive ?? MAX_ACTIVE_PER_USER;
            throw new TypeError(`Configuration key "${key}" does not exist`);
        }),
    };
}

describe('SessionService.createSession', () => {
    let service: SessionService;
    let tx: {
        session: { create: jest.Mock; findMany: jest.Mock; updateMany: jest.Mock };
        sessionRefreshToken: { create: jest.Mock; updateMany: jest.Mock };
        authEvent: { create: jest.Mock };
    };
    // Deliberately has no model delegates: any write that bypasses the
    // transaction client would throw instead of silently succeeding.
    let prisma: { $transaction: jest.Mock };
    let tokenService: { generateAccessToken: jest.Mock };
    let denylist: { revoke: jest.Mock; isRevoked: jest.Mock };

    function buildService(
        ttls: { absolute: number; refresh: number; maxActive?: number } = {
            absolute: ABSOLUTE_TTL_SECONDS,
            refresh: REFRESH_TTL_SECONDS,
        },
    ) {
        service = new SessionService(
            createConfig(ttls) as unknown as ConfigService,
            prisma as unknown as PrismaService,
            tokenService as unknown as TokenService,
            denylist as unknown as SessionDenylistService,
        );
    }

    beforeEach(() => {
        // Freeze the clock so expiry timestamps can be asserted exactly. Microtask
        // scheduling stays real so awaited mocks resolve normally.
        jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
        jest.setSystemTime(NOW);

        tx = {
            session: {
                create: jest.fn().mockResolvedValue({ id: 'session-1', tokenFamilyId: 'family-1' }),
                // No existing sessions by default, so the cap never trips.
                findMany: jest.fn().mockResolvedValue([]),
                updateMany: jest.fn().mockResolvedValue({ count: 0 }),
            },
            sessionRefreshToken: {
                create: jest.fn().mockResolvedValue({}),
                updateMany: jest.fn().mockResolvedValue({ count: 0 }),
            },
            authEvent: { create: jest.fn().mockResolvedValue({}) },
        };

        prisma = {
            $transaction: jest.fn(async (callback: (client: typeof tx) => unknown) => callback(tx)),
        };

        denylist = { revoke: jest.fn(), isRevoked: jest.fn().mockResolvedValue(false) };

        tokenService = {
            generateAccessToken: jest.fn().mockResolvedValue({ accessToken: 'access-token', expiresIn: 600 }),
        };

        buildService();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    describe('the session row', () => {
        it('is written with an absolute expiry of now + the absolute TTL', async () => {
            await service.createSession(args);

            expect(tx.session.create).toHaveBeenCalledTimes(1);
            expect(tx.session.create.mock.calls[0][0].data).toEqual({
                userId: 'user-1',
                authMethod: AuthMethod.PASSWORD,
                expiresAt: new Date('2026-01-31T00:00:00.000Z'),
                ipAddress: '203.0.113.10',
                userAgent: 'jest',
                deviceId: 'device-1',
                deviceName: null,
            });
        });

        it('stores null rather than a malformed IP address, which inet would reject', async () => {
            await service.createSession({
                ...args,
                context: { ...args.context, ipAddress: 'bogus' },
            });

            expect(tx.session.create.mock.calls[0][0].data.ipAddress).toBeNull();
            expect(tx.authEvent.create.mock.calls[0][0].data.ipAddress).toBeNull();
        });
    });

    describe('the refresh token row', () => {
        it('gets its own refresh TTL when that ends before the session does', async () => {
            const result = await service.createSession(args);

            const stored = tx.sessionRefreshToken.create.mock.calls[0][0].data;
            expect(stored.sessionId).toBe('session-1');
            expect(stored.expiresAt).toEqual(new Date('2026-01-15T00:00:00.000Z'));
            expect(result.refreshTokenExpiresAt).toEqual(stored.expiresAt);
        });

        // With the real config (30d session, 14d refresh) the clamp never triggers,
        // so it has to be forced here or that line is untested.
        it('is clamped to the session expiry when the refresh TTL is longer', async () => {
            buildService({ absolute: 1 * DAY_SECONDS, refresh: 14 * DAY_SECONDS });

            const result = await service.createSession(args);

            const sessionExpiresAt = tx.session.create.mock.calls[0][0].data.expiresAt;
            const refreshExpiresAt = tx.sessionRefreshToken.create.mock.calls[0][0].data.expiresAt;

            expect(sessionExpiresAt).toEqual(new Date('2026-01-02T00:00:00.000Z'));
            expect(refreshExpiresAt).toEqual(sessionExpiresAt);
            expect(result.refreshTokenExpiresAt).toEqual(sessionExpiresAt);
        });

        // Phase 7 will hash the raw token from the cookie and look it up by this
        // value. If they ever disagree, every refresh fails as "unknown token".
        it('stores only the sha256 hash of the raw token it hands out', async () => {
            const result = await service.createSession(args);

            const storedHash = tx.sessionRefreshToken.create.mock.calls[0][0].data.tokenHash;
            const expectedHash = createHash('sha256').update(result.refreshToken).digest('hex');

            expect(storedHash).toBe(expectedHash);
            expect(storedHash).not.toBe(result.refreshToken);
        });

        it('issues a fresh random token on every login', async () => {
            const first = await service.createSession(args);
            const second = await service.createSession(args);

            expect(first.refreshToken).not.toBe(second.refreshToken);
            // 32 random bytes as base64url: URL-safe, no padding.
            expect(first.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });
    });

    describe('the transaction boundary', () => {
        it('performs all three writes through the same transaction client', async () => {
            await service.createSession(args);

            expect(prisma.$transaction).toHaveBeenCalledTimes(1);
            expect(tx.session.create).toHaveBeenCalledTimes(1);
            expect(tx.sessionRefreshToken.create).toHaveBeenCalledTimes(1);
            expect(tx.authEvent.create).toHaveBeenCalledTimes(1);
        });

        it('records LOGIN_SUCCESS against the session it just created', async () => {
            await service.createSession(args);

            expect(tx.authEvent.create.mock.calls[0][0].data).toEqual({
                userId: 'user-1',
                sessionId: 'session-1',
                eventType: AuthEventType.LOGIN_SUCCESS,
                authMethod: AuthMethod.PASSWORD,
                ipAddress: '203.0.113.10',
                userAgent: 'jest',
                metadata: { deviceId: 'device-1' },
            });
        });

        it('never mints an access token when a write inside the transaction fails', async () => {
            tx.authEvent.create.mockRejectedValue(new Error('db down'));

            await expect(service.createSession(args)).rejects.toThrow('db down');
            expect(tokenService.generateAccessToken).not.toHaveBeenCalled();
        });
    });

    describe('the access token', () => {
        // The sid claim is what logout will revoke by. If it pointed anywhere but
        // the row that was actually created, logout would revoke nothing.
        it('is minted for the session that was actually created', async () => {
            await service.createSession(args);

            expect(tokenService.generateAccessToken).toHaveBeenCalledTimes(1);
            expect(tokenService.generateAccessToken).toHaveBeenCalledWith({
                userId: 'user-1',
                sessionId: 'session-1',
                tokenFamilyId: 'family-1',
                emailVerified: true,
                authMethod: AuthMethod.PASSWORD,
            });
        });

        it('is minted only after the transaction has committed', async () => {
            await service.createSession(args);

            const committedAt = prisma.$transaction.mock.invocationCallOrder[0];
            const mintedAt = tokenService.generateAccessToken.mock.invocationCallOrder[0];
            const lastWriteAt = tx.authEvent.create.mock.invocationCallOrder[0];

            expect(mintedAt).toBeGreaterThan(committedAt);
            expect(mintedAt).toBeGreaterThan(lastWriteAt);
        });

        it('takes expiresIn from the token service rather than a separate config read', async () => {
            tokenService.generateAccessToken.mockResolvedValue({ accessToken: 'access-token', expiresIn: 123 });

            const result = await service.createSession(args);

            expect(result).toEqual({
                sessionId: 'session-1',
                tokenFamilyId: 'family-1',
                accessToken: 'access-token',
                expiresIn: 123,
                refreshToken: expect.any(String),
                refreshTokenExpiresAt: new Date('2026-01-15T00:00:00.000Z'),
            });
        });
    });

    describe('the per-user session cap', () => {
        function existingSessions(count: number) {
            return Array.from({ length: count }, (_unused, index) => ({
                id: `old-session-${index + 1}`,
            }));
        }

        it('counts only sessions that are still usable', async () => {
            await service.createSession(args);

            expect(tx.session.findMany).toHaveBeenCalledWith({
                where: { userId: 'user-1', revokedAt: null, expiresAt: { gt: NOW } },
                select: { id: true },
                // Least recently used first, so eviction drops the stalest device
                // rather than an old-but-active one.
                orderBy: { lastUsedAt: 'asc' },
            });
        });

        it('evicts nothing while the user is below the cap', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(3));

            await service.createSession(args);

            expect(tx.session.updateMany).not.toHaveBeenCalled();
            expect(tx.session.create).toHaveBeenCalledTimes(1);
        });

        it('evicts the least recently used session once the cap is reached', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(MAX_ACTIVE_PER_USER));

            await service.createSession(args);

            expect(tx.session.updateMany).toHaveBeenCalledWith({
                where: { id: { in: ['old-session-1'] }, revokedAt: null },
                data: { revokedAt: NOW, revocationReason: SessionRevocationReason.SESSION_LIMIT },
            });
            expect(tx.sessionRefreshToken.updateMany).toHaveBeenCalledWith({
                where: { sessionId: { in: ['old-session-1'] }, revokedAt: null },
                data: { revokedAt: NOW },
            });
        });

        // A login must never be refused for being at the cap: the password was right,
        // and a blocked user cannot free a slot because logout needs a session.
        it('still issues the new session after evicting', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(MAX_ACTIVE_PER_USER));

            const result = await service.createSession(args);

            expect(result.sessionId).toBe('session-1');
            expect(result.refreshToken).toEqual(expect.any(String));
        });

        // Converges when the account is already over, e.g. after the config is lowered.
        it('evicts enough sessions to land back at the cap', async () => {
            buildService({
                absolute: ABSOLUTE_TTL_SECONDS,
                refresh: REFRESH_TTL_SECONDS,
                maxActive: 10,
            });
            tx.session.findMany.mockResolvedValue(existingSessions(12));

            await service.createSession(args);

            expect(tx.session.updateMany.mock.calls[0][0].where.id.in).toEqual([
                'old-session-1',
                'old-session-2',
                'old-session-3',
            ]);
        });

        // Evicted sessions keep a usable access token for up to its TTL unless the
        // denylist is told about them, so this is the assertion that makes eviction
        // actually take effect rather than only being recorded.
        it('denylists the evicted sessions after the transaction commits', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(MAX_ACTIVE_PER_USER));

            await service.createSession(args);

            expect(denylist.revoke).toHaveBeenCalledWith(['old-session-1']);
        });

        it('denylists nothing when no session was evicted', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(3));

            await service.createSession(args);

            expect(denylist.revoke).toHaveBeenCalledWith([]);
        });

        it('records one SESSION_REVOKED event naming the evicted sessions', async () => {
            tx.session.findMany.mockResolvedValue(existingSessions(MAX_ACTIVE_PER_USER));

            await service.createSession(args);

            const evictionEvents = tx.authEvent.create.mock.calls.filter(
                ([arg]) => arg.data.eventType === AuthEventType.SESSION_REVOKED,
            );
            expect(evictionEvents).toHaveLength(1);
            expect(evictionEvents[0][0].data.metadata).toEqual({
                deviceId: 'device-1',
                maxActivePerUser: MAX_ACTIVE_PER_USER,
                evictedSessionIds: ['old-session-1'],
            });
        });
    });
});

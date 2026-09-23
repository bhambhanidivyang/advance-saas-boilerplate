import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { SessionDenylistService } from './session-denylist.service';

const ACCESS_TTL_SECONDS = 600;

const pipeline = { set: jest.fn(), exec: jest.fn() };
const redisClient = {
    set: jest.fn(),
    exists: jest.fn(),
    pipeline: jest.fn(() => pipeline),
    quit: jest.fn().mockResolvedValue('OK'),
    on: jest.fn(),
};

jest.mock('ioredis', () => ({
    __esModule: true,
    default: jest.fn(() => redisClient),
}));

function build(enabled: boolean) {
    const logger = { error: jest.fn(), warn: jest.fn(), log: jest.fn() };
    const config = {
        getOrThrow: jest.fn((key: string) => {
            if (key === 'auth.session.denylistEnabled') return enabled;
            if (key === 'auth.jwt.accessTtlSeconds') return ACCESS_TTL_SECONDS;
            if (key === 'redis.url') return 'redis://localhost:6379';
            throw new TypeError(`Configuration key "${key}" does not exist`);
        }),
    };

    const service = new SessionDenylistService(
        config as unknown as ConfigService,
        logger as unknown as Logger,
    );

    return { service, logger };
}

describe('SessionDenylistService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        pipeline.set.mockReturnValue(pipeline);
        pipeline.exec.mockResolvedValue([]);
    });

    describe('when disabled', () => {
        it('opens no connection and makes no calls', async () => {
            const { service } = build(false);

            await service.revoke(['session-1']);

            expect(await service.isRevoked('session-1')).toBe(false);
            expect(redisClient.pipeline).not.toHaveBeenCalled();
            expect(redisClient.exists).not.toHaveBeenCalled();
        });
    });

    describe('when enabled', () => {
        it('records each session with the access-token TTL', async () => {
            const { service } = build(true);

            await service.revoke(['session-1', 'session-2']);

            expect(pipeline.set).toHaveBeenCalledWith(
                'revoked:sid:session-1', '1', 'EX', ACCESS_TTL_SECONDS,
            );
            expect(pipeline.set).toHaveBeenCalledWith(
                'revoked:sid:session-2', '1', 'EX', ACCESS_TTL_SECONDS,
            );
            expect(pipeline.exec).toHaveBeenCalledTimes(1);
        });

        it('skips Redis entirely for an empty list', async () => {
            const { service } = build(true);

            await service.revoke([]);

            expect(redisClient.pipeline).not.toHaveBeenCalled();
        });

        it.each([
            [1, true],
            [0, false],
        ])('reports exists=%p as revoked=%p', async (existsResult, expected) => {
            const { service } = build(true);
            redisClient.exists.mockResolvedValue(existsResult);

            expect(await service.isRevoked('session-1')).toBe(expected);
            expect(redisClient.exists).toHaveBeenCalledWith('revoked:sid:session-1');
        });

        // Fails open on purpose: this narrows an already-short window, so a cache
        // outage must not take authentication down with it.
        it('falls open and logs when a read fails', async () => {
            const { service, logger } = build(true);
            redisClient.exists.mockRejectedValue(new Error('redis down'));

            expect(await service.isRevoked('session-1')).toBe(false);
            expect(logger.error).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'SESSION_DENYLIST_READ_FAILED' }),
            );
        });

        it('logs rather than throwing when a write fails, so revocation still commits', async () => {
            const { service, logger } = build(true);
            pipeline.exec.mockRejectedValue(new Error('redis down'));

            await expect(service.revoke(['session-1'])).resolves.toBeUndefined();
            expect(logger.error).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'SESSION_DENYLIST_WRITE_FAILED' }),
            );
        });

        it('closes the connection on shutdown', async () => {
            const { service } = build(true);

            await service.onModuleDestroy();

            expect(redisClient.quit).toHaveBeenCalledTimes(1);
        });
    });
});

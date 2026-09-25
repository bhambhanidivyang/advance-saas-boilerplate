import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { PrismaService } from 'src/prisma/prisma.service';
import { CleanupService } from './cleanup.service';

const NOW = new Date('2026-09-24T03:17:00.000Z');
const DAY = 24 * 60 * 60 * 1000;

const RETENTION = {
    'maintenance.refreshTokenRetentionDays': 30,
    'maintenance.userTokenRetentionDays': 7,
    'maintenance.authNonceRetentionDays': 1,
} as Record<string, number>;

/** The `where` of the first delete issued against a table. */
function firstWhere(model: { deleteMany: jest.Mock }) {
    return model.deleteMany.mock.calls[0][0].where;
}

describe('CleanupService', () => {
    let service: CleanupService;
    let prisma: {
        sessionRefreshToken: { deleteMany: jest.Mock };
        userToken: { deleteMany: jest.Mock };
        authNonce: { deleteMany: jest.Mock };
    };
    let logger: { log: jest.Mock; warn: jest.Mock; error: jest.Mock };

    beforeEach(async () => {
        jest.clearAllMocks();

        const empty = () => ({ deleteMany: jest.fn().mockResolvedValue({ count: 0 }) });
        prisma = {
            sessionRefreshToken: empty(),
            userToken: empty(),
            authNonce: empty(),
        };
        logger = { log: jest.fn(), warn: jest.fn(), error: jest.fn() };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                CleanupService,
                { provide: PrismaService, useValue: prisma },
                { provide: Logger, useValue: logger },
                {
                    provide: ConfigService,
                    useValue: {
                        getOrThrow: jest.fn((key: string) => {
                            if (key in RETENTION) return RETENTION[key];
                            throw new Error(`Unexpected key ${key}`);
                        }),
                    },
                },
            ],
        }).compile();

        service = module.get(CleanupService);
    });

    describe('what it deletes', () => {
        it.each([
            ['sessionRefreshToken', 30],
            ['userToken', 7],
            ['authNonce', 1],
        ])('cuts %s at its configured retention', async (model, days) => {
            await service.cleanup(NOW);

            expect(firstWhere(prisma[model as keyof typeof prisma])).toEqual({
                expiresAt: { lt: new Date(NOW.getTime() - days * DAY) },
            });
        });

        // The rule the whole job hangs on. Reuse detection revokes a token family by
        // finding a used refresh token; deleting rows because they were used, rather
        // than because they expired, turns a replayed stolen token into an ordinary
        // 401 and silently disables theft detection.
        it('never selects refresh tokens by whether they were used', async () => {
            await service.cleanup(NOW);

            expect(firstWhere(prisma.sessionRefreshToken)).not.toHaveProperty('usedAt');
            expect(firstWhere(prisma.sessionRefreshToken)).not.toHaveProperty('revokedAt');
        });

        // An unused expired token is just as dead as a used one, and filtering on
        // usedAt would leave the larger half of the table forever.
        it('removes expired user tokens whether or not they were used', async () => {
            await service.cleanup(NOW);

            expect(firstWhere(prisma.userToken)).not.toHaveProperty('usedAt');
        });

        // AuthEvent.sessionId is onDelete: SetNull, so deleting sessions would strip
        // the session id from historical audit rows.
        it('leaves sessions alone', async () => {
            await service.cleanup(NOW);

            expect(prisma).not.toHaveProperty('session.deleteMany.mock.calls.0');
        });
    });

    describe('batching', () => {
        it('bounds every statement', async () => {
            await service.cleanup(NOW);

            for (const model of Object.values(prisma)) {
                expect(model.deleteMany.mock.calls[0][0].limit).toBe(1000);
            }
        });

        it('stops as soon as a batch comes back short', async () => {
            prisma.authNonce.deleteMany.mockResolvedValueOnce({ count: 1000 });

            const result = await service.cleanup(NOW);

            expect(prisma.authNonce.deleteMany).toHaveBeenCalledTimes(2);
            expect(result.deletedAuthNonces).toBe(1000);
        });

        // A backlog is worked down over several runs rather than one run holding the
        // database for an hour.
        it('gives up after the batch limit and says so', async () => {
            prisma.authNonce.deleteMany.mockResolvedValue({ count: 1000 });

            const result = await service.cleanup(NOW);

            expect(prisma.authNonce.deleteMany).toHaveBeenCalledTimes(50);
            expect(result.deletedAuthNonces).toBe(50_000);
            expect(logger.warn).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'CLEANUP_BATCH_LIMIT_REACHED' }),
            );
        });

        it('issues one statement per table when nothing is expired', async () => {
            const result = await service.cleanup(NOW);

            expect(prisma.sessionRefreshToken.deleteMany).toHaveBeenCalledTimes(1);
            expect(result).toEqual({
                deletedRefreshTokens: 0,
                deletedUserTokens: 0,
                deletedAuthNonces: 0,
            });
        });
    });

    describe('reporting', () => {
        it('returns and logs the counts per table', async () => {
            prisma.sessionRefreshToken.deleteMany.mockResolvedValue({ count: 12 });
            prisma.userToken.deleteMany.mockResolvedValue({ count: 3 });
            prisma.authNonce.deleteMany.mockResolvedValue({ count: 7 });

            const result = await service.cleanup(NOW);

            expect(result).toEqual({
                deletedRefreshTokens: 12,
                deletedUserTokens: 3,
                deletedAuthNonces: 7,
            });
            // A cleanup job that quietly stops working is invisible without this.
            expect(logger.log).toHaveBeenCalledWith(
                expect.objectContaining({
                    code: 'CLEANUP_COMPLETED',
                    deletedRefreshTokens: 12,
                    deletedUserTokens: 3,
                    deletedAuthNonces: 7,
                    durationMs: expect.any(Number),
                }),
            );
        });
    });
});

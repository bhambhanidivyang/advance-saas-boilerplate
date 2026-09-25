import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'crypto';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthProvider } from 'src/generated/prisma/client';
import { GoogleNonceService } from './google-nonce.service';
import { GoogleNonceInvalidError } from './google-nonce-invalid.error';

const TTL_SECONDS = 300;
const NOW = new Date('2026-09-24T10:00:00.000Z');

function sha256(value: string) {
    return createHash('sha256').update(value).digest('hex');
}

describe('GoogleNonceService', () => {
    let service: GoogleNonceService;
    let prisma: {
        authNonce: { create: jest.Mock; updateMany: jest.Mock };
    };

    beforeEach(async () => {
        jest.clearAllMocks();

        prisma = {
            authNonce: {
                create: jest.fn().mockResolvedValue({}),
                updateMany: jest.fn().mockResolvedValue({ count: 1 }),
            },
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                GoogleNonceService,
                { provide: PrismaService, useValue: prisma },
                {
                    provide: ConfigService,
                    useValue: {
                        getOrThrow: jest.fn((key: string) => {
                            if (key === 'auth.google.nonceTtlSeconds') return TTL_SECONDS;
                            throw new Error(`Unexpected key ${key}`);
                        }),
                    },
                },
            ],
        }).compile();

        service = module.get(GoogleNonceService);
    });

    describe('issue', () => {
        it('returns a nonce that expires after the configured lifetime', async () => {
            const issued = await service.issue(NOW);

            expect(issued.nonce).toEqual(expect.any(String));
            expect(issued.expiresAt).toEqual(new Date(NOW.getTime() + TTL_SECONDS * 1000));
        });

        // A database leak must not yield usable nonces, the same rule refresh and
        // verification tokens follow.
        it('stores only the hash, never the nonce itself', async () => {
            const { nonce } = await service.issue(NOW);

            const stored = prisma.authNonce.create.mock.calls[0][0].data;
            expect(stored.nonceHash).toBe(sha256(nonce));
            expect(JSON.stringify(stored)).not.toContain(nonce);
            expect(stored.provider).toBe(AuthProvider.GOOGLE);
        });

        it('never issues the same nonce twice', async () => {
            const first = await service.issue(NOW);
            const second = await service.issue(NOW);

            expect(first.nonce).not.toBe(second.nonce);
        });
    });

    describe('consume', () => {
        // Single use comes from the conditional update: the row is claimed only while
        // unused and unexpired, so two replays cannot both see a count of 1. Reading
        // first and then writing would let both through.
        it('claims the nonce only while it is unused and unexpired', async () => {
            await service.consume('raw-nonce', NOW);

            expect(prisma.authNonce.updateMany).toHaveBeenCalledWith({
                where: {
                    nonceHash: sha256('raw-nonce'),
                    provider: AuthProvider.GOOGLE,
                    usedAt: null,
                    expiresAt: { gt: NOW },
                },
                data: { usedAt: NOW },
            });
        });

        it('accepts a nonce it claimed', async () => {
            await expect(service.consume('raw-nonce', NOW)).resolves.toBeUndefined();
        });

        // Unknown, already used and expired are indistinguishable here on purpose:
        // the update simply matches nothing, and the caller answers a generic 401.
        it('rejects a nonce it could not claim', async () => {
            prisma.authNonce.updateMany.mockResolvedValue({ count: 0 });

            await expect(service.consume('raw-nonce', NOW)).rejects.toBeInstanceOf(
                GoogleNonceInvalidError,
            );
        });

        it('rejects the second use of one nonce', async () => {
            prisma.authNonce.updateMany
                .mockResolvedValueOnce({ count: 1 })
                .mockResolvedValueOnce({ count: 0 });

            await expect(service.consume('raw-nonce', NOW)).resolves.toBeUndefined();
            await expect(service.consume('raw-nonce', NOW)).rejects.toBeInstanceOf(
                GoogleNonceInvalidError,
            );
        });
    });
});

/**
 * Real PostgreSQL nonce consumption. The single-use guarantee comes from a
 * conditional UPDATE, and only a real MVCC engine shows what two simultaneous
 * replays actually do to it.
 *
 * Run via: pnpm test:integration
 */
import 'dotenv/config';

import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthProvider } from 'src/generated/prisma/client';
import { GoogleNonceService } from './google-nonce.service';
import { GoogleNonceInvalidError } from './google-nonce-invalid.error';

const TTL_SECONDS = 300;

describe('GoogleNonceService (PostgreSQL)', () => {
    let service: GoogleNonceService;
    let prisma: PrismaService;
    const issuedHashes: string[] = [];

    const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

    beforeAll(async () => {
        if (!databaseUrl) {
            throw new Error(
                'Nonce integration tests require DATABASE_URL or TEST_DATABASE_URL pointing at a migrated PostgreSQL database.',
            );
        }

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                GoogleNonceService,
                PrismaService,
                {
                    provide: ConfigService,
                    useValue: {
                        get: (key: string) => (key === 'database.url' ? databaseUrl : undefined),
                        getOrThrow: (key: string) => {
                            if (key === 'database.url') return databaseUrl;
                            if (key === 'auth.google.nonceTtlSeconds') return TTL_SECONDS;
                            throw new TypeError(`Configuration key "${key}" does not exist`);
                        },
                    },
                },
            ],
        }).compile();

        service = module.get(GoogleNonceService);
        prisma = module.get(PrismaService);
        await prisma.$connect();
    });

    afterEach(async () => {
        const hashes = issuedHashes.splice(0, issuedHashes.length);
        if (hashes.length > 0) {
            await prisma.authNonce.deleteMany({ where: { nonceHash: { in: hashes } } });
        }
    });

    afterAll(async () => {
        await prisma.$disconnect();
    });

    async function issueNonce() {
        const { nonce } = await service.issue(new Date());
        const row = await prisma.authNonce.findFirstOrThrow({
            where: { provider: AuthProvider.GOOGLE, usedAt: null },
            orderBy: { createdAt: 'desc' },
            select: { nonceHash: true },
        });
        issuedHashes.push(row.nonceHash);
        return nonce;
    }

    it('accepts a nonce once and stamps it used', async () => {
        const nonce = await issueNonce();

        await expect(service.consume(nonce, new Date())).resolves.toBeUndefined();

        const row = await prisma.authNonce.findFirstOrThrow({
            where: { nonceHash: issuedHashes[issuedHashes.length - 1] },
            select: { usedAt: true },
        });
        expect(row.usedAt).not.toBeNull();
    });

    // The replay this whole step exists to stop: the same stolen token, presented
    // twice, carries the same nonce.
    it('rejects the second use of the same nonce', async () => {
        const nonce = await issueNonce();

        await service.consume(nonce, new Date());

        await expect(service.consume(nonce, new Date())).rejects.toBeInstanceOf(
            GoogleNonceInvalidError,
        );
    });

    // Two replays arriving together must not both win. The conditional UPDATE makes
    // the second one match zero rows, because the first holds the row lock and the
    // second re-evaluates `usedAt IS NULL` after it commits.
    it('lets exactly one of two simultaneous consumptions succeed', async () => {
        const nonce = await issueNonce();

        const results = await Promise.allSettled([
            service.consume(nonce, new Date()),
            service.consume(nonce, new Date()),
        ]);

        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
    });

    it('rejects an expired nonce', async () => {
        const nonce = await issueNonce();
        const wellAfterExpiry = new Date(Date.now() + (TTL_SECONDS + 60) * 1000);

        await expect(service.consume(nonce, wellAfterExpiry)).rejects.toBeInstanceOf(
            GoogleNonceInvalidError,
        );
    });

    it('rejects a nonce that was never issued', async () => {
        await expect(service.consume('never-issued', new Date())).rejects.toBeInstanceOf(
            GoogleNonceInvalidError,
        );
    });
});

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { PrismaService } from 'src/prisma/prisma.service';
import { CleanupResult } from './interfaces/cleanup.interface';

/** Rows removed per statement, so no single delete holds locks for long. */
const BATCH_SIZE = 1000;
/** Bounds one run: a backlog is worked down over several runs, not in one burst. */
const MAX_BATCHES = 50;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Deletes expired authentication rows.
 *
 * The rule that governs every cutoff here: **delete on expiry, never on use**.
 * Reuse detection finds a used refresh token and revokes its family; remove that
 * row while the token could still be presented and a replayed stolen token stops
 * looking like theft and starts looking like an unknown token — a plain 401, no
 * family revocation, no alert. Past expiry the row can no longer authenticate
 * anything, so it is safe to drop.
 *
 * Sessions are deliberately not touched: AuthEvent.sessionId is onDelete: SetNull,
 * so deleting sessions would strip the session id from historical audit rows.
 */
@Injectable()
export class CleanupService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly config: ConfigService,
        private readonly logger: Logger,
    ) {}

    async cleanup(now: Date = new Date()): Promise<CleanupResult> {
        const startedAt = Date.now();

        const deletedRefreshTokens = await this.deleteInBatches('refreshTokens', (cutoff) =>
            this.prisma.sessionRefreshToken.deleteMany({
                where: { expiresAt: { lt: cutoff } },
                limit: BATCH_SIZE,
            }),
            this.cutoff(now, 'maintenance.refreshTokenRetentionDays'),
        );

        // Every expired token, used or not. An unused expired token is just as dead,
        // and filtering on usedAt would leave the larger half of the table forever.
        const deletedUserTokens = await this.deleteInBatches('userTokens', (cutoff) =>
            this.prisma.userToken.deleteMany({
                where: { expiresAt: { lt: cutoff } },
                limit: BATCH_SIZE,
            }),
            this.cutoff(now, 'maintenance.userTokenRetentionDays'),
        );

        const deletedAuthNonces = await this.deleteInBatches('authNonces', (cutoff) =>
            this.prisma.authNonce.deleteMany({
                where: { expiresAt: { lt: cutoff } },
                limit: BATCH_SIZE,
            }),
            this.cutoff(now, 'maintenance.authNonceRetentionDays'),
        );

        const result = { deletedRefreshTokens, deletedUserTokens, deletedAuthNonces };

        this.logger.log({
            code: 'CLEANUP_COMPLETED',
            ...result,
            durationMs: Date.now() - startedAt,
        });

        return result;
    }

    private cutoff(now: Date, configKey: string): Date {
        return new Date(now.getTime() - this.config.getOrThrow<number>(configKey) * MS_PER_DAY);
    }

    /**
     * Repeats a bounded delete until a short batch shows the table is drained.
     *
     * One unbounded DELETE over a year of rows holds locks, writes a huge WAL
     * transaction, and loses all its work if it fails at 99%. Batching makes progress
     * durable and keeps each lock brief; MAX_BATCHES stops one run monopolising the
     * database when there is a large backlog.
     */
    private async deleteInBatches(
        label: string,
        deleteBatch: (cutoff: Date) => Promise<{ count: number }>,
        cutoff: Date,
    ): Promise<number> {
        let deleted = 0;

        for (let batch = 0; batch < MAX_BATCHES; batch++) {
            const { count } = await deleteBatch(cutoff);
            deleted += count;

            if (count < BATCH_SIZE) {
                return deleted;
            }
        }

        // Still full at the cap: rows remain, and the next run continues from here.
        this.logger.warn({
            code: 'CLEANUP_BATCH_LIMIT_REACHED',
            table: label,
            deleted,
            message: 'Cleanup stopped at the batch limit; remaining rows are left for the next run',
        });

        return deleted;
    }
}

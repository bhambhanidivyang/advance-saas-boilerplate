import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import Redis from 'ioredis';

/**
 * Closes the revocation gap left by stateless access tokens.
 *
 * A revoked session's access token stays valid until it expires, because
 * JwtAuthGuard verifies a signature and touches no database. This service records
 * revoked session ids in Redis so the guard can reject them immediately, with a TTL
 * equal to the ACCESS token lifetime — nothing else outlives a revocation, so
 * storage is O(revocations in the last accessTtl seconds), not O(sessions).
 *
 * Fails OPEN on Redis errors. This narrows an already-short window rather than
 * being a primary control, so a cache blip must not take authentication down with
 * it. Errors are logged loudly because a silent denylist is worse than none.
 *
 * Entirely inert when auth.session.denylistEnabled is false: no connection is
 * opened and no Redis call is made.
 */
@Injectable()
export class SessionDenylistService implements OnModuleDestroy {
    private readonly enabled: boolean;
    private readonly ttlSeconds: number;
    private client?: Redis;

    constructor(
        private readonly config: ConfigService,
        private readonly logger: Logger,
    ) {
        this.enabled = this.config.getOrThrow<boolean>('auth.session.denylistEnabled');
        this.ttlSeconds = this.config.getOrThrow<number>('auth.jwt.accessTtlSeconds');

        if (this.enabled) {
            this.client = new Redis(this.config.getOrThrow<string>('redis.url'), {
                // Do not queue commands while disconnected: a denylist read must fail
                // fast and fall open rather than hang the request.
                enableOfflineQueue: false,
                maxRetriesPerRequest: 1,
            });
            this.client.on('error', (error) => {
                this.logger.error({ code: 'SESSION_DENYLIST_REDIS_ERROR', err: error });
            });
        }
    }

    async onModuleDestroy(): Promise<void> {
        await this.client?.quit().catch(() => undefined);
    }

    /**
     * Marks sessions as revoked. Call AFTER the database transaction commits: writing
     * from inside it would leave a denylist entry behind on rollback, locking a user
     * out of a session that is still live.
     */
    async revoke(sessionIds: string[]): Promise<void> {
        if (!this.enabled || !this.client || sessionIds.length === 0) {
            return;
        }

        try {
            const pipeline = this.client.pipeline();
            for (const sessionId of sessionIds) {
                pipeline.set(this.key(sessionId), '1', 'EX', this.ttlSeconds);
            }
            await pipeline.exec();
        } catch (error) {
            this.logger.error({
                code: 'SESSION_DENYLIST_WRITE_FAILED',
                err: error,
                sessionIds,
            });
        }
    }

    /** Called on every authenticated request when enabled, so it stays a single GET. */
    async isRevoked(sessionId: string): Promise<boolean> {
        if (!this.enabled || !this.client) {
            return false;
        }

        try {
            return (await this.client.exists(this.key(sessionId))) === 1;
        } catch (error) {
            // Fail open: see the class comment.
            this.logger.error({
                code: 'SESSION_DENYLIST_READ_FAILED',
                err: error,
                sessionId,
            });
            return false;
        }
    }

    private key(sessionId: string): string {
        return `revoked:sid:${sessionId}`;
    }
}

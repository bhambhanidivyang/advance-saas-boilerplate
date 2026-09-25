import { Module, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { Logger } from 'nestjs-pino';
import { CleanupService } from './cleanup.service';
import { CleanupProcessor } from './cleanup.processor';

export const CLEANUP_JOB_ID = 'expired-auth-rows';

@Module({
    imports: [BullModule.registerQueue({ name: 'cleanup' })],
    providers: [CleanupService, CleanupProcessor],
})
export class MaintenanceModule implements OnModuleInit {
    constructor(
        @InjectQueue('cleanup') private readonly queue: Queue,
        private readonly config: ConfigService,
        private readonly logger: Logger,
    ) {}

    /**
     * Registers the schedule itself, rather than relying on an external cron.
     *
     * The fixed jobId is what makes this safe with several instances: BullMQ keeps
     * one repeatable schedule per id, so ten instances booting still produce one run
     * per period, and exactly one worker picks it up. An in-process cron would fire
     * in every instance at once.
     */
    async onModuleInit(): Promise<void> {
        if (!this.config.getOrThrow<boolean>('maintenance.cleanupEnabled')) {
            this.logger.warn({
                code: 'CLEANUP_DISABLED',
                message: 'Expired auth rows will not be cleaned up',
            });
            return;
        }

        const pattern = this.config.getOrThrow<string>('maintenance.cleanupCron');

        // BullMQ 6 replaced `repeat` on add() with job schedulers. upsert is what
        // makes re-registering on every boot safe: the schedule is keyed by id, so
        // restarts and extra instances update one schedule instead of stacking up.
        await this.queue.upsertJobScheduler(
            CLEANUP_JOB_ID,
            { pattern },
            {
                name: CLEANUP_JOB_ID,
                opts: {
                    attempts: 3,
                    backoff: { type: 'exponential', delay: 60_000 },
                    removeOnComplete: true,
                    // Keep the last failures for inspection; a silent cleanup failure
                    // shows up first as a full disk.
                    removeOnFail: 50,
                },
            },
        );

        this.logger.log({ code: 'CLEANUP_SCHEDULED', pattern });
    }
}

import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from 'nestjs-pino';
import { CleanupService } from './cleanup.service';
import { CleanupJob } from './interfaces/cleanup.interface';

/**
 * concurrency 1: two cleanup runs would compete for the same rows and gain nothing,
 * since the work is bounded by the database, not by the worker.
 */
@Processor('cleanup', { concurrency: 1 })
export class CleanupProcessor extends WorkerHost {
    constructor(
        private readonly cleanupService: CleanupService,
        private readonly logger: Logger,
    ) {
        super();
    }

    // Failures propagate on purpose: BullMQ then retries with backoff, and the run is
    // idempotent, so a repeat simply finds fewer rows.
    async process(job: Job<CleanupJob>): Promise<void> {
        await this.cleanupService.cleanup();
    }

    @OnWorkerEvent('failed')
    onFailed(job: Job<CleanupJob>, error: Error) {
        this.logger.error({
            code: 'CLEANUP_JOB_FAILED',
            jobId: job?.id,
            attempts: job?.attemptsMade,
            err: error,
        });
    }
}

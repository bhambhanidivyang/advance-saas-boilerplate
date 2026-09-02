import { OnWorkerEvent, Processor, WorkerHost } from "@nestjs/bullmq";
import { Job, UnrecoverableError } from 'bullmq';
import { EmailJob } from "./interfaces/email-job.interface";
import { EMAIL_PROVIDER } from "./constants/email.constants";
import type { EmailProvider } from "./interfaces/email-provider.interface";
import { Inject } from "@nestjs/common";
import { EmailTemplateService } from "./templates/email-template.service";
import { Logger } from "nestjs-pino";

@Processor('email', {
    // how many jobs can be concurrently handled by the worker
    concurrency: Number(process.env.MAIL_QUEUE_CONCURRENCY) || 5,
    // controls how fast your workers process jobs from a queue, eg: 50 jobs per seconds
    limiter: {
        // max request per duration (usually per second)
        max: Number(process.env.MAIL_QUEUE_RATE_LIMIT_MAX) || 50,
        // rate limit duration, usually 1 second
        duration: Number(process.env.MAIL_QUEUE_RATE_LIMIT_DURATION) || 1000,
    },
})
export class EmailProcessor extends WorkerHost {
    constructor(
        @Inject(EMAIL_PROVIDER) private readonly emailProvider: EmailProvider,
        private readonly emailTemplateService: EmailTemplateService,
        private readonly logger: Logger
    ) {
        super();
    }

    async process(job: Job<EmailJob>): Promise<void> {
        this.logger.log(
            {
                jobId: job.id,
                jobType: job.name,
                attempt: job.attemptsMade + 1,
            },
            'Processing email job'
        );
        const message = this.emailTemplateService.render(job.data);
        this.logger.log(
            {
                jobId: job.id,
                jobType: job.name,
                subject: message.subject
            },
            'Email Message Created'
        );
        const result = await this.emailProvider.send(message);
        this.logger.log(
            {
                jobId: job.id,
                jobType: job.name,
                messageId: result.messageId,
                acceptedCount: result.accepted.length,
                rejectedCount: result.rejected.length
            },
            'Email Sent');
    }

    // BullMQ worker failure event - listen for worker-level events and detect final-failure
    @OnWorkerEvent('failed')
    onFailed(
        job: Job<EmailJob> | undefined,
        error: Error,
    ): void {
        if (!job) {
            this.logger.error(
                { err: error },
                'Email Job Failed Without Job Data',
            );
            return;
        }

        // if a job has received UnrecoverableError, or attempts eliminated, consider it final failure
        const isFinalFailure = (error instanceof UnrecoverableError) || (job.attemptsMade >= (job.opts.attempts ?? 1));

        this.logger.error(
            {
                jobId: job.id,
                jobType: job.name,
                attemptsMade: job.attemptsMade,
                maxAttempts: job.opts.attempts ?? 1,
                finalFailure: isFinalFailure,
                err: error,
            },
            'Email Job Failed'
        );

        if (!isFinalFailure) {
            return;
        }
    }
}
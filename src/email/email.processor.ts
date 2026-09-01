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
        try {
            this.logger.log(`Processing email job: ${job.name}, attempt ${job.attemptsMade + 1}`);
            const message = this.emailTemplateService.render(job.data);
            this.logger.log({to: message.to,subject: message.subject}, 'EMAIL MESSAGE CREATED');
            const result = await this.emailProvider.send(message);
            this.logger.log({messageId: result.messageId,accepted: result.accepted,rejected: result.rejected}, 'EMAIL QUEUED');
        } catch(error) {
            this.logger.error(error, 'EMAIL PROCESSING FAILED');
            throw error;
        }
        
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
                'EMAIL JOB FAILED WITHOUT JOB DATA',
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
            'EMAIL JOB FAILED'
        );

        if (!isFinalFailure) {
            return;
        }
    }
}
import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import { EmailJob } from './interfaces/email-job.interface';
import { Queue } from 'bullmq';
import { Logger } from 'nestjs-pino';

@Injectable()
export class EmailService {
    constructor(@InjectQueue('email') private readonly emailQueue: Queue<EmailJob>, private readonly logger: Logger){}
    async enqueue(job: EmailJob): Promise<boolean> {
        try {
            await this.emailQueue.add(job.type, job, {
                // job id should handle idempotency - no two exactly same jobs must be in queue
                jobId: job.idempotencyKey,

                // waits for a specific duration before trying again. 
                // For 3 attempts: immediate 1st attempt, 
                // 5 secs for second attempt and multiplied (5x2) 10 secs delay for third attempt
                backoff: {
                    type: 'exponential',
                    delay: 5000
                },
                // max attempts allowed to process a job
                attempts: 3,

                // remove successfully completed jobs from queue
                removeOnComplete: true,

                // Dont remvoe a failed job from queue
                removeOnFail: false
            });
            return true;
        } catch(error) {
            this.logger.error(
                {
                    err: error,
                    jobType: job.type,
                    idempotencyKey: job.idempotencyKey,
                },
                'Failed to enqueue email job',
            );
            return false;
        }
    }
}

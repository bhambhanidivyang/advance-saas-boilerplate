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
                jobId: job.idempotencyKey,
                backoff: {
                    type: 'exponential',
                    delay: 5000
                },
                attempts: 3,
                removeOnComplete: true,
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

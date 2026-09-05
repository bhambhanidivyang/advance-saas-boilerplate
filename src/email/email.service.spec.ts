import { Test, TestingModule } from '@nestjs/testing';
import { getQueueToken } from '@nestjs/bullmq';
import { Logger } from 'nestjs-pino';
import { EmailService } from './email.service';
import { EmailJob, EmailJobType } from './interfaces/email-job.interface';

describe('EmailService', () => {
  let service: EmailService;
  const add = jest.fn();
  const logger = {
    error: jest.fn(),
    log: jest.fn(),
  };

  const job: EmailJob = {
    type: EmailJobType.EMAIL_VERIFICATION,
    idempotencyKey: 'email-verification:user-1:token-1',
    userId: 'user-1',
    organizationId: 'org-1',
    to: 'recipient@test.invalid',
    data: {
      tokenId: 'token-1',
      rawToken: 'raw-token-value',
    },
  };

  beforeEach(async () => {
    add.mockReset();
    logger.error.mockReset();
    logger.log.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailService,
        { provide: getQueueToken('email'), useValue: { add } },
        { provide: Logger, useValue: logger },
      ],
    }).compile();

    service = module.get(EmailService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('enqueue', () => {
    it('should add a BullMQ job with the job type as the name and the job payload as data', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await service.enqueue(job);

      expect(add).toHaveBeenCalledWith(
        EmailJobType.EMAIL_VERIFICATION,
        job,
        expect.any(Object),
      );
    });

    it('should pass type, idempotencyKey, userId, organizationId, to, tokenId, and rawToken in job data', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await service.enqueue(job);

      const [, jobData] = add.mock.calls[0];
      expect(jobData).toEqual({
        type: EmailJobType.EMAIL_VERIFICATION,
        idempotencyKey: 'email-verification:user-1:token-1',
        userId: 'user-1',
        organizationId: 'org-1',
        to: 'recipient@test.invalid',
        data: {
          tokenId: 'token-1',
          rawToken: 'raw-token-value',
        },
      });
    });

    it('should omit organizationId when it is not present on the job', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });
      const jobWithoutOrg: EmailJob = {
        type: job.type,
        idempotencyKey: job.idempotencyKey,
        userId: job.userId,
        to: job.to,
        data: job.data,
      };

      await service.enqueue(jobWithoutOrg);

      const [, jobData] = add.mock.calls[0];
      expect(jobData).toEqual(jobWithoutOrg);
      expect(jobData).not.toHaveProperty('organizationId');
    });

    it('should use the idempotency key as the BullMQ jobId', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await service.enqueue(job);

      expect(add).toHaveBeenCalledWith(
        job.type,
        job,
        expect.objectContaining({ jobId: job.idempotencyKey }),
      );
    });

    it('should configure 3 attempts with exponential backoff of 5000ms', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await service.enqueue(job);

      expect(add).toHaveBeenCalledWith(
        job.type,
        job,
        expect.objectContaining({
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 5000,
          },
        }),
      );
    });

    it('should remove completed jobs and keep failed jobs', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await service.enqueue(job);

      expect(add).toHaveBeenCalledWith(
        job.type,
        job,
        expect.objectContaining({
          removeOnComplete: true,
          removeOnFail: false,
        }),
      );
    });

    it('should return true when the job is queued successfully', async () => {
      add.mockResolvedValue({ id: job.idempotencyKey });

      await expect(service.enqueue(job)).resolves.toBe(true);
    });

    it('should return false and not throw when queue.add fails', async () => {
      const queueError = new Error('queue unavailable');
      add.mockRejectedValue(queueError);

      await expect(service.enqueue(job)).resolves.toBe(false);
      expect(logger.error).toHaveBeenCalledWith(
        {
          err: queueError,
          jobType: job.type,
          idempotencyKey: job.idempotencyKey,
        },
        'Failed to enqueue email job',
      );
    });
  });
});

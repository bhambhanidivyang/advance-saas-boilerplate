import { Test, TestingModule } from '@nestjs/testing';
import { Job } from 'bullmq';
import { Logger } from 'nestjs-pino';
import { EmailProcessor } from './email.processor';
import { EmailTemplateService } from './templates/email-template.service';
import { EMAIL_PROVIDER } from './constants/email.constants';
import { EmailJob, EmailJobType } from './interfaces/email-job.interface';
import { EmailMessage, EmailSendResult } from './interfaces/email-provider.interface';
import { EmailPermanentError, EmailRetryableError } from './errors/email.errors';

describe('EmailProcessor', () => {
  const render = jest.fn();
  const send = jest.fn();
  const logger = {
    log: jest.fn(),
    error: jest.fn(),
  };

  const jobData: EmailJob = {
    type: EmailJobType.EMAIL_VERIFICATION,
    idempotencyKey: 'email-verification:user-1:token-1',
    userId: 'user-1',
    to: 'recipient@test.invalid',
    data: {
      tokenId: 'token-1',
      rawToken: 'raw-token-value',
    },
  };

  const message: EmailMessage = {
    to: jobData.to,
    subject: 'Verify your email',
    html: '<p>Verify</p>',
    text: 'Verify',
    idempotencyKey: jobData.idempotencyKey,
  };

  const sendResult: EmailSendResult = {
    messageId: 'smtp-message-id',
    accepted: [jobData.to],
    rejected: [],
  };

  let processor: EmailProcessor;

  function createJob(overrides: Partial<Job<EmailJob>> = {}): Job<EmailJob> {
    return {
      id: jobData.idempotencyKey,
      name: EmailJobType.EMAIL_VERIFICATION,
      data: jobData,
      attemptsMade: 0,
      opts: { attempts: 3 },
      ...overrides,
    } as Job<EmailJob>;
  }

  beforeEach(async () => {
    render.mockReset();
    send.mockReset();
    logger.log.mockReset();
    logger.error.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailProcessor,
        { provide: EmailTemplateService, useValue: { render } },
        { provide: EMAIL_PROVIDER, useValue: { send } },
        { provide: Logger, useValue: logger },
      ],
    }).compile();

    processor = module.get(EmailProcessor);
  });

  describe('process', () => {
    it('should render the job through the template service and send the EmailMessage', async () => {
      render.mockReturnValue(message);
      send.mockResolvedValue(sendResult);
      const job = createJob();

      await expect(processor.process(job)).resolves.toBeUndefined();

      expect(render).toHaveBeenCalledWith(job.data);
      expect(send).toHaveBeenCalledWith(message);
    });

    it('should propagate template rendering failures without swallowing them', async () => {
      const templateError = new EmailPermanentError('No email template found for job type: PASSWORD_RESET');
      render.mockImplementation(() => {
        throw templateError;
      });

      await expect(processor.process(createJob())).rejects.toBe(templateError);
      expect(send).not.toHaveBeenCalled();
    });

    it('should propagate EmailRetryableError from the provider so BullMQ can retry', async () => {
      render.mockReturnValue(message);
      const retryable = new EmailRetryableError('Temporary SMTP failure: 450');
      send.mockRejectedValue(retryable);

      await expect(processor.process(createJob())).rejects.toBe(retryable);
    });

    it('should propagate EmailPermanentError from the provider so BullMQ does not retry', async () => {
      render.mockReturnValue(message);
      const permanent = new EmailPermanentError('Permanent SMTP failure: 550');
      send.mockRejectedValue(permanent);

      await expect(processor.process(createJob())).rejects.toBe(permanent);
    });
  });

  describe('onFailed', () => {
    it('should treat an intermediate retryable failure as not final', () => {
      processor.onFailed(
        createJob({ attemptsMade: 1 }),
        new EmailRetryableError('Temporary SMTP connection failure: ETIMEDOUT'),
      );

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          jobId: jobData.idempotencyKey,
          jobType: EmailJobType.EMAIL_VERIFICATION,
          attemptsMade: 1,
          maxAttempts: 3,
          finalFailure: false,
        }),
        'Email Job Failed',
      );
    });

    it('should treat exhausted attempts as a final failure', () => {
      processor.onFailed(
        createJob({ attemptsMade: 3 }),
        new EmailRetryableError('Temporary SMTP connection failure: ETIMEDOUT'),
      );

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          attemptsMade: 3,
          maxAttempts: 3,
          finalFailure: true,
        }),
        'Email Job Failed',
      );
    });

    it('should treat EmailPermanentError as a final failure immediately', () => {
      processor.onFailed(
        createJob({ attemptsMade: 0 }),
        new EmailPermanentError('Permanent SMTP failure: 550'),
      );

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          attemptsMade: 0,
          finalFailure: true,
        }),
        'Email Job Failed',
      );
    });

    it('should handle a missing job without throwing', () => {
      const error = new Error('worker failed');

      expect(() => processor.onFailed(undefined, error)).not.toThrow();
      expect(logger.error).toHaveBeenCalledWith(
        { err: error },
        'Email Job Failed Without Job Data',
      );
    });
  });
});

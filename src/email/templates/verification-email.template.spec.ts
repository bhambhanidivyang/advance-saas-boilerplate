import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { VerificationEmailTemplate } from './verification-email.template';
import { EmailJob, EmailJobType } from '../interfaces/email-job.interface';
import { EmailPermanentError } from '../errors/email.errors';
import { generateEmailTemplateUrl } from '../utils/email.utils';

describe('VerificationEmailTemplate', () => {
  const frontendUrl = 'https://app.test.invalid';
  const job: EmailJob = {
    type: EmailJobType.EMAIL_VERIFICATION,
    idempotencyKey: 'email-verification:user-1:token-1',
    userId: 'user-1',
    organizationId: 'org-1',
    to: 'recipient@test.invalid',
    data: {
      tokenId: 'token-1',
      rawToken: 'raw token/+value?',
    },
  };

  async function createTemplate(): Promise<VerificationEmailTemplate> {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VerificationEmailTemplate,
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: jest.fn((key: string) => {
              if (key === 'app.frontendUrl') {
                return frontendUrl;
              }
              throw new Error(`Missing config: ${key}`);
            }),
          },
        },
      ],
    }).compile();

    return module.get(VerificationEmailTemplate);
  }

  it('should support EMAIL_VERIFICATION and not other job types', async () => {
    const template = await createTemplate();

    expect(template.supports(EmailJobType.EMAIL_VERIFICATION)).toBe(true);
    expect(template.supports(EmailJobType.PASSWORD_RESET)).toBe(false);
  });

  it('should produce an EmailMessage for the job recipient with the verification subject', async () => {
    const template = await createTemplate();

    const message = template.render(job);

    expect(message.to).toBe(job.to);
    expect(message.subject).toBe('Verify your email');
    expect(message.idempotencyKey).toBe(job.idempotencyKey);
  });

  it('should include verification copy and the generated verification URL in html and text', async () => {
    const template = await createTemplate();
    const expectedUrl = generateEmailTemplateUrl(
      `${frontendUrl}/auth/verify-email?token=`,
      job.data.rawToken,
    );

    const message = template.render(job);

    expect(message.html).toContain('Verify your email');
    expect(message.html).toContain('Verify Email');
    expect(message.html).toContain(expectedUrl);
    expect(message.text).toContain('Verify your email');
    expect(message.text).toContain(expectedUrl);
    expect(message.text).toContain('This link will expire in 24 hours');
  });

  it('should URL-encode the raw token when building the verification URL', async () => {
    const template = await createTemplate();

    const message = template.render(job);
    const expectedUrl = `${frontendUrl}/auth/verify-email?token=${encodeURIComponent(job.data.rawToken)}`;

    expect(message.html).toContain(expectedUrl);
    expect(message.html).not.toContain(`${frontendUrl}/auth/verify-email?token=${job.data.rawToken}`);
  });

  it('should require rawToken on the job and fail permanently when it is missing', async () => {
    const template = await createTemplate();
    const jobWithoutToken: EmailJob = {
      ...job,
      data: {
        tokenId: 'token-1',
        rawToken: undefined as unknown as string,
      },
    };

    expect(() => template.render(jobWithoutToken)).toThrow(EmailPermanentError);
    expect(() => template.render(jobWithoutToken)).toThrow(
      'Email Verification job is missing rawToken',
    );
  });

  it('should render successfully when the job includes both tokenId and rawToken', async () => {
    const template = await createTemplate();
    const completeJob: EmailJob = {
      ...job,
      data: {
        tokenId: 'token-1',
        rawToken: 'raw token/+value?',
      },
    };

    const message = template.render(completeJob);

    expect(completeJob.data.tokenId).toBeTruthy();
    expect(completeJob.data.rawToken).toBeTruthy();
    expect(message.html).toContain(encodeURIComponent(completeJob.data.rawToken));
    expect(message.idempotencyKey).toBe(completeJob.idempotencyKey);
  });
});

import { Test, TestingModule } from '@nestjs/testing';
import { EmailTemplateService } from './email-template.service';
import { EMAIL_TEMPLATES } from '../constants/email.constants';
import { EmailJob, EmailJobType } from '../interfaces/email-job.interface';
import { EmailMessage } from '../interfaces/email-provider.interface';
import { EmailTemplate } from '../interfaces/email-template.interface';
import { EmailPermanentError } from '../errors/email.errors';

describe('EmailTemplateService', () => {
  const job: EmailJob = {
    type: EmailJobType.EMAIL_VERIFICATION,
    idempotencyKey: 'email-verification:user-1:token-1',
    userId: 'user-1',
    to: 'recipient@test.invalid',
    data: {
      tokenId: 'token-1',
      rawToken: 'raw-token-value',
    },
  };

  const renderedMessage: EmailMessage = {
    to: job.to,
    subject: 'Verify your email',
    html: '<p>Verify</p>',
    text: 'Verify',
    idempotencyKey: job.idempotencyKey,
  };

  async function createService(templates: EmailTemplate[]): Promise<EmailTemplateService> {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailTemplateService,
        { provide: EMAIL_TEMPLATES, useValue: templates },
      ],
    }).compile();

    return module.get(EmailTemplateService);
  }

  it('should select the matching template, render with the job, and return the EmailMessage', async () => {
    const matchingTemplate: EmailTemplate = {
      supports: jest.fn().mockReturnValue(true),
      render: jest.fn().mockReturnValue(renderedMessage),
    };
    const unusedTemplate: EmailTemplate = {
      supports: jest.fn().mockReturnValue(false),
      render: jest.fn(),
    };
    const service = await createService([unusedTemplate, matchingTemplate]);

    const result = service.render(job);

    expect(matchingTemplate.supports).toHaveBeenCalledWith(EmailJobType.EMAIL_VERIFICATION);
    expect(matchingTemplate.render).toHaveBeenCalledWith(job);
    expect(result).toBe(renderedMessage);
    expect(unusedTemplate.render).not.toHaveBeenCalled();
  });

  it('should throw EmailPermanentError for an unsupported EmailJobType', async () => {
    const unusedTemplate: EmailTemplate = {
      supports: jest.fn().mockReturnValue(false),
      render: jest.fn(),
    };
    const service = await createService([unusedTemplate]);
    const unsupportedJob: EmailJob = {
      ...job,
      type: EmailJobType.PASSWORD_RESET,
    };

    expect(() => service.render(unsupportedJob)).toThrow(EmailPermanentError);
    expect(() => service.render(unsupportedJob)).toThrow(
      'No email template found for job type: PASSWORD_RESET',
    );
    expect(unusedTemplate.render).not.toHaveBeenCalled();
  });

  it('should use only the first matching template when multiple templates are registered', async () => {
    const firstMatch: EmailTemplate = {
      supports: jest.fn().mockReturnValue(true),
      render: jest.fn().mockReturnValue(renderedMessage),
    };
    const secondMatch: EmailTemplate = {
      supports: jest.fn().mockReturnValue(true),
      render: jest.fn(),
    };
    const service = await createService([firstMatch, secondMatch]);

    const result = service.render(job);

    expect(result).toBe(renderedMessage);
    expect(firstMatch.render).toHaveBeenCalledTimes(1);
    expect(secondMatch.supports).not.toHaveBeenCalled();
    expect(secondMatch.render).not.toHaveBeenCalled();
  });
});

import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import { ResendEmailProvider } from './resend-email.provider';
import { EmailPermanentError, EmailRetryableError } from '../errors/email.errors';
import { EmailMessage } from '../interfaces/email-provider.interface';

jest.mock('resend');

const MockedResend = Resend as jest.MockedClass<typeof Resend>;

async function getRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to reject');
}

describe('ResendEmailProvider', () => {
  const send = jest.fn();
  const apiKey = 'test-resend-api-key';
  const configuredFrom = 'noreply@test.invalid';

  const message: EmailMessage = {
    to: 'recipient@test.invalid',
    subject: 'Verify your email',
    html: '<p>Verify</p>',
    text: 'Verify',
    idempotencyKey: 'idempotency-key-1',
  };

  function createConfigService() {
    const store: Record<string, string> = {
      'email.resend.apiKey': apiKey,
      'email.from': configuredFrom,
    };

    return {
      getOrThrow: jest.fn((key: string) => {
        const value = store[key];
        if (value === undefined) {
          throw new Error(`Missing config: ${key}`);
        }
        return value;
      }),
    };
  }

  async function createProvider(): Promise<ResendEmailProvider> {
    send.mockReset();
    MockedResend.mockReset();
    MockedResend.mockImplementation(
      () =>
        ({
          emails: { send },
        }) as unknown as Resend,
    );

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ResendEmailProvider,
        { provide: ConfigService, useValue: createConfigService() },
      ],
    }).compile();

    return module.get(ResendEmailProvider);
  }

  describe('constructor', () => {
    it('should construct the Resend client with the configured API key', async () => {
      await createProvider();

      expect(MockedResend).toHaveBeenCalledWith(apiKey);
    });
  });

  describe('successful send', () => {
    it('should pass message fields and the idempotency key to Resend and return a normalized result', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: { id: 'resend-message-id' },
        error: null,
      });

      const result = await provider.send(message);

      expect(send).toHaveBeenCalledWith(
        {
          from: configuredFrom,
          to: message.to,
          subject: message.subject,
          html: message.html,
          text: message.text,
        },
        {
          idempotencyKey: message.idempotencyKey,
        },
      );
      expect(result).toEqual({
        messageId: 'resend-message-id',
        accepted: [message.to],
        rejected: [],
      });
    });

    it('should let message.from override the configured email.from', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: { id: 'resend-message-id' },
        error: null,
      });

      await provider.send({ ...message, from: 'override@test.invalid' });

      expect(send).toHaveBeenCalledWith(
        expect.objectContaining({ from: 'override@test.invalid' }),
        expect.anything(),
      );
    });
  });

  describe('Resend API status classification', () => {
    it('should classify a 429 as retryable and not permanent', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: null,
        error: { statusCode: 429, message: 'Too many requests', name: 'rate_limit_exceeded' },
      });

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect(error).not.toBeInstanceOf(EmailPermanentError);
      expect((error as EmailRetryableError).message).toContain('429');
    });

    it('should classify a 5xx Resend failure as retryable', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: null,
        error: { statusCode: 503, message: 'Service unavailable' },
      });

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect(error).not.toBeInstanceOf(EmailPermanentError);
      expect((error as EmailRetryableError).message).toContain('503');
    });

    it('should classify a permanent 4xx such as 403 as EmailPermanentError', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: null,
        error: { statusCode: 403, message: 'Forbidden' },
      });

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailPermanentError);
      expect(error).not.toBeInstanceOf(EmailRetryableError);
      expect((error as EmailPermanentError).message).toContain('403');
    });
  });

  describe('network errors', () => {
    const networkCodes = [
      'ECONNRESET',
      'ETIMEDOUT',
      'ECONNREFUSED',
      'EAI_AGAIN',
      'ENETUNREACH',
      'EHOSTUNREACH',
      'ENOTFOUND',
    ];

    it.each(networkCodes)(
      'should retry transient Resend network failures with code %s',
      async (code) => {
        const provider = await createProvider();
        const original = Object.assign(new Error(`connect ${code}`), { code });
        send.mockRejectedValue(original);

        const error = await getRejection(provider.send(message));

        expect(error).toBeInstanceOf(EmailRetryableError);
        expect(error).not.toBeInstanceOf(EmailPermanentError);
        expect((error as EmailRetryableError).message).toContain(code);
        expect((error as EmailRetryableError).cause).toBe(original);
      },
    );
  });

  describe('generic and unknown errors', () => {
    it('should classify a generic Error without a known network code as retryable', async () => {
      const provider = await createProvider();
      const original = new Error('unexpected Resend SDK failure');
      send.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect((error as EmailRetryableError).message).toBe(
        'unexpected Resend SDK failure',
      );
      expect((error as EmailRetryableError).cause).toBe(original);
    });

    it('should classify a non-Error thrown value as retryable', async () => {
      const provider = await createProvider();
      send.mockRejectedValue('resend exploded');

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect((error as EmailRetryableError).message).toBe('Unknown Resend error');
      expect((error as EmailRetryableError).cause).toBe('resend exploded');
    });
  });

  describe('already-classified errors', () => {
    it('should preserve an already-classified EmailRetryableError', async () => {
      const provider = await createProvider();
      const original = new EmailRetryableError('already retryable');
      send.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBe(original);
    });

    it('should preserve an already-classified EmailPermanentError', async () => {
      const provider = await createProvider();
      const original = new EmailPermanentError('already permanent');
      send.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBe(original);
    });

    it('should not reclassify a classified error thrown from result.error', async () => {
      const provider = await createProvider();
      send.mockResolvedValue({
        data: null,
        error: { statusCode: 403, message: 'Forbidden' },
      });

      await expect(provider.send(message)).rejects.toBeInstanceOf(EmailPermanentError);
    });
  });
});

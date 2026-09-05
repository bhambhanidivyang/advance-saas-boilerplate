import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { SmtpEmailProvider } from './smtp-email.provider';
import { EmailPermanentError, EmailRetryableError } from '../errors/email.errors';
import { EmailMessage } from '../interfaces/email-provider.interface';

jest.mock('nodemailer');

const mockedCreateTransport = nodemailer.createTransport as jest.MockedFunction<
  typeof nodemailer.createTransport
>;

async function getRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to reject');
}

describe('SmtpEmailProvider', () => {
  const sendMail = jest.fn();
  const close = jest.fn();

  const smtpConfig = {
    'email.smtp.host': 'smtp.test.invalid',
    'email.smtp.port': 587,
    'email.smtp.secure': false,
    'email.smtp.pool': true,
    'email.smtp.maxConnections': 5,
    'email.smtp.maxMessages': 100,
    'email.smtp.connectionTimeout': 10000,
    'email.smtp.greetingTimeout': 10000,
    'email.smtp.socketTimeout': 30000,
    'email.smtp.user': 'smtp-user',
    'email.smtp.password': 'smtp-password',
    'email.from': 'noreply@test.invalid',
  };

  const message: EmailMessage = {
    to: 'recipient@test.invalid',
    subject: 'Verify your email',
    html: '<p>Verify</p>',
    text: 'Verify',
    idempotencyKey: 'idempotency-key-1',
  };

  function createConfigService(overrides: Record<string, unknown> = {}) {
    const store = { ...smtpConfig, ...overrides };

    return {
      getOrThrow: jest.fn((key: string) => {
        const value = store[key];
        if (value === undefined) {
          throw new Error(`Missing config: ${key}`);
        }
        return value;
      }),
      get: jest.fn((key: string) => store[key]),
    };
  }

  async function createProvider(
    overrides: Record<string, unknown> = {},
  ): Promise<SmtpEmailProvider> {
    sendMail.mockReset();
    close.mockReset();
    mockedCreateTransport.mockReset();
    mockedCreateTransport.mockReturnValue({ sendMail, close } as never);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SmtpEmailProvider,
        { provide: ConfigService, useValue: createConfigService(overrides) },
      ],
    }).compile();

    return module.get(SmtpEmailProvider);
  }

  function createSmtpError(overrides: {
    message?: string;
    code?: string;
    responseCode?: number | string;
    response?: string;
  }): Error & {
    code?: string;
    responseCode?: number | string;
    response?: string;
  } {
    const error = new Error(overrides.message ?? 'SMTP error') as Error & {
      code?: string;
      responseCode?: number | string;
      response?: string;
    };

    if (overrides.code !== undefined) {
      error.code = overrides.code;
    }
    if (overrides.responseCode !== undefined) {
      error.responseCode = overrides.responseCode;
    }
    if (overrides.response !== undefined) {
      error.response = overrides.response;
    }

    return error;
  }

  describe('successful send', () => {
    it('should send mail with from, to, subject, html, and text and return a normalized result', async () => {
      const provider = await createProvider();
      sendMail.mockResolvedValue({
        messageId: '<smtp-message-id@test.invalid>',
        accepted: ['recipient@test.invalid'],
        rejected: [],
      });

      const result = await provider.send(message);

      expect(sendMail).toHaveBeenCalledWith({
        from: 'noreply@test.invalid',
        to: 'recipient@test.invalid',
        subject: 'Verify your email',
        html: '<p>Verify</p>',
        text: 'Verify',
      });
      expect(result).toEqual({
        messageId: '<smtp-message-id@test.invalid>',
        accepted: ['recipient@test.invalid'],
        rejected: [],
      });
    });

    it('should let message.from override the configured email.from', async () => {
      const provider = await createProvider();
      sendMail.mockResolvedValue({
        messageId: '<smtp-message-id@test.invalid>',
        accepted: ['recipient@test.invalid'],
        rejected: [],
      });

      await provider.send({
        ...message,
        from: 'override@test.invalid',
      });

      expect(sendMail).toHaveBeenCalledWith(
        expect.objectContaining({ from: 'override@test.invalid' }),
      );
    });

    it('should stringify accepted and rejected addresses in the normalized result', async () => {
      const provider = await createProvider();
      sendMail.mockResolvedValue({
        messageId: '<smtp-message-id@test.invalid>',
        accepted: ['ok@test.invalid'],
        rejected: ['rejected@test.invalid'],
      });

      await expect(provider.send(message)).resolves.toEqual({
        messageId: '<smtp-message-id@test.invalid>',
        accepted: ['ok@test.invalid'],
        rejected: ['rejected@test.invalid'],
      });
    });
  });

  describe('SMTP status classification', () => {
    it('should classify SMTP 4xx errors as retryable and preserve the original error as cause', async () => {
      const provider = await createProvider();
      const original = createSmtpError({ responseCode: 450, message: 'Mailbox busy' });
      sendMail.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect(error).not.toBeInstanceOf(EmailPermanentError);
      expect((error as EmailRetryableError).message).toContain('450');
      expect((error as EmailRetryableError).cause).toBe(original);
    });

    it('should classify SMTP 5xx errors as permanent and not retryable', async () => {
      const provider = await createProvider();
      const original = createSmtpError({ responseCode: 550, message: 'Mailbox unavailable' });
      sendMail.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailPermanentError);
      expect(error).not.toBeInstanceOf(EmailRetryableError);
      expect((error as EmailPermanentError).message).toContain('550');
      expect((error as EmailPermanentError).cause).toBe(original);
    });
  });

  describe('network errors', () => {
    const networkCodes = [
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ECONNRESET',
      'EAI_AGAIN',
      'ENETUNREACH',
      'EHOSTUNREACH',
      'ENOTFOUND',
    ];

    it.each(networkCodes)(
      'should classify SMTP network error %s as retryable',
      async (code) => {
        const provider = await createProvider();
        const original = createSmtpError({ code, message: `connect ${code}` });
        sendMail.mockRejectedValue(original);

        const error = await getRejection(provider.send(message));

        expect(error).toBeInstanceOf(EmailRetryableError);
        expect(error).not.toBeInstanceOf(EmailPermanentError);
        expect((error as EmailRetryableError).message).toContain(code);
        expect((error as EmailRetryableError).cause).toBe(original);
      },
    );
  });

  describe('TLS/system errors', () => {
    it('should classify ERR_TLS_* errors as permanent', async () => {
      const provider = await createProvider();
      const original = createSmtpError({
        code: 'ERR_TLS_CERT_ALTNAME_INVALID',
        message: 'TLS certificate mismatch',
      });
      sendMail.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailPermanentError);
      expect(error).not.toBeInstanceOf(EmailRetryableError);
      expect((error as EmailPermanentError).message).toContain(
        'ERR_TLS_CERT_ALTNAME_INVALID',
      );
    });

    it('should classify ERR_ASSERTION as a permanent system failure', async () => {
      const provider = await createProvider();
      const original = createSmtpError({ code: 'ERR_ASSERTION', message: 'assertion failed' });
      sendMail.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailPermanentError);
      expect((error as EmailPermanentError).message).toContain('ERR_ASSERTION');
    });
  });

  describe('regex fallback', () => {
    it('should classify response text containing a 5xx code as permanent when responseCode is missing', async () => {
      const provider = await createProvider();
      const original = createSmtpError({
        message: 'send failed',
        response: '550 5.1.1 User unknown',
      });
      sendMail.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBeInstanceOf(EmailPermanentError);
    });

    it('should classify a message containing a 4xx code as retryable when responseCode is missing', async () => {
      const provider = await createProvider();
      const original = createSmtpError({
        message: 'temporary failure 450 try again later',
      });
      sendMail.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBeInstanceOf(EmailRetryableError);
    });
  });

  describe('unknown errors', () => {
    it('should classify an unknown Error as retryable', async () => {
      const provider = await createProvider();
      const original = new Error('unexpected SMTP client failure');
      sendMail.mockRejectedValue(original);

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect((error as EmailRetryableError).message).toBe('Unknown SMTP error');
      expect((error as EmailRetryableError).cause).toBe(original);
    });

    it('should classify a non-Error thrown value as retryable', async () => {
      const provider = await createProvider();
      sendMail.mockRejectedValue('smtp exploded');

      const error = await getRejection(provider.send(message));

      expect(error).toBeInstanceOf(EmailRetryableError);
      expect((error as EmailRetryableError).message).toBe('Unknown error type');
      expect((error as EmailRetryableError).cause).toBe('smtp exploded');
    });
  });

  describe('already-classified errors', () => {
    it('should preserve an already-classified EmailRetryableError', async () => {
      const provider = await createProvider();
      const original = new EmailRetryableError('already retryable');
      sendMail.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBe(original);
    });

    it('should preserve an already-classified EmailPermanentError', async () => {
      const provider = await createProvider();
      const original = new EmailPermanentError('already permanent');
      sendMail.mockRejectedValue(original);

      await expect(provider.send(message)).rejects.toBe(original);
    });
  });

  describe('transport configuration', () => {
    it('should create the transporter with SMTP settings from ConfigService', async () => {
      await createProvider();

      expect(mockedCreateTransport).toHaveBeenCalledWith({
        host: 'smtp.test.invalid',
        port: 587,
        secure: false,
        pool: true,
        maxConnections: 5,
        maxMessages: 100,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 30000,
        auth: {
          user: 'smtp-user',
          pass: 'smtp-password',
        },
      });
    });

    it('should omit SMTP auth when username or password is absent', async () => {
      await createProvider({
        'email.smtp.user': undefined,
        'email.smtp.password': undefined,
      });

      expect(mockedCreateTransport).toHaveBeenCalledWith(
        expect.objectContaining({ auth: undefined }),
      );
    });
  });

  describe('shutdown', () => {
    it('should close the transporter on module destroy', async () => {
      const provider = await createProvider();

      await provider.onModuleDestroy();

      expect(close).toHaveBeenCalledTimes(1);
    });
  });
});

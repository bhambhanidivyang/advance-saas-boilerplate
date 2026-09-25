/**
 * Real PostgreSQL AuthService tests. Jest's default CJS runner cannot load
 * Prisma 7's WASM query compiler unless Node is started with
 * --experimental-vm-modules. Run via: pnpm test:integration
 *
 * Uses DATABASE_URL or TEST_DATABASE_URL (a migrated Postgres instance).
 * This repo has no dedicated test-database harness or Testcontainers setup.
 */
import 'dotenv/config';

import { createHash, randomBytes, randomUUID } from 'crypto';
import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from 'nestjs-pino';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { installTransactionOverlapBarrier } from 'src/common/testing/transaction-overlap-barrier';
import { EmailService } from 'src/email/email.service';
import { SessionService } from './session/session.service';
import { PasswordAuthenticatorService } from './password/password-authenticator.service';
import { GoogleAuthenticatorService } from './google/google-authenticator.service';
import { GoogleNonceService } from './google/google-nonce.service';
import {
  AuthEventType,
  Prisma,
  UserTokenType,
} from 'src/generated/prisma/client';
import { GENERIC_VERIFICATION_RESPONSE } from './constants/auth.constants';
import { EmailJobType } from 'src/email/interfaces/email-job.interface';

const COOLDOWN_SECONDS = 60;
const VERIFICATION_TOKEN_TTL_HOURS = 24;

type EnqueuedVerificationJob = {
  type: EmailJobType;
  idempotencyKey: string;
  userId: string;
  to: string;
  data: {
    tokenId: string;
    rawToken: string;
  };
};

function hashToken(rawToken: string) {
  return createHash('sha256').update(rawToken).digest('hex');
}

function metadataEmailId(metaData: Prisma.JsonValue | null): string | undefined {
  if (
    !metaData ||
    typeof metaData !== 'object' ||
    Array.isArray(metaData) ||
    !('userEmailId' in metaData) ||
    typeof metaData.userEmailId !== 'string'
  ) {
    return undefined;
  }

  return metaData.userEmailId;
}

function exceptionMessage(error: unknown): string {
  if (error instanceof BadRequestException) {
    const response = error.getResponse();
    if (typeof response === 'string') {
      return response;
    }
    if (
      typeof response === 'object' &&
      response &&
      'message' in response
    ) {
      const message = (response as { message: string | string[] }).message;
      return Array.isArray(message) ? message.join(' ') : message;
    }
  }

  throw error;
}

describe('AuthService concurrency (PostgreSQL)', () => {
  let service: AuthService;
  let prisma: PrismaService;
  let enqueue: jest.Mock;
  let logger: {
    log: jest.Mock;
    warn: jest.Mock;
    error: jest.Mock;
  };
  const createdUserIds: string[] = [];

  const databaseUrl =
    process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

  beforeAll(async () => {
    if (!databaseUrl) {
      throw new Error(
        'AuthService integration tests require DATABASE_URL or TEST_DATABASE_URL pointing at a migrated PostgreSQL database. This repository has no separate test-database harness; tests reuse the project Postgres instance.',
      );
    }

    enqueue = jest.fn().mockResolvedValue(true);
    logger = {
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        PrismaService,
        { provide: EmailService, useValue: { enqueue } },
        // These tests exercise register/resend/verify only; login is covered by
        // the unit specs and the rotation integration spec.
        { provide: SessionService, useValue: { createSession: jest.fn() } },
        // Login is covered in auth.service.login.spec.ts; these specs never reach it.
        { provide: PasswordAuthenticatorService, useValue: {} },
        { provide: GoogleAuthenticatorService, useValue: {} },
        { provide: GoogleNonceService, useValue: { issue: jest.fn() } },
        {
          provide: ConfigService,
          useValue: {
            get: (key: string) => {
              if (key === 'database.url') {
                return databaseUrl;
              }
              if (key === 'email.verificationTokenTtl') {
                return VERIFICATION_TOKEN_TTL_HOURS;
              }
              if (key === 'auth.authVerificationResendCooldown') {
                return COOLDOWN_SECONDS;
              }
              return undefined;
            },
          },
        },
        { provide: Logger, useValue: logger },
      ],
    }).compile();

    service = module.get(AuthService);
    prisma = module.get(PrismaService);
    await prisma.$connect();
  });

  afterEach(async () => {
    const userIds = createdUserIds.splice(0, createdUserIds.length);
    if (userIds.length === 0) {
      return;
    }

    await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
    await prisma.user.deleteMany({ where: { id: { in: userIds } } });
    enqueue.mockClear();
    logger.log.mockClear();
    logger.warn.mockClear();
    logger.error.mockClear();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function createUnverifiedEmail(options?: {
    previousTokenCreatedAt?: Date;
  }) {
    const email = `auth-concurrency-${randomUUID()}@example.com`;
    const rawToken = randomBytes(32).toString('base64url');
    const user = await prisma.user.create({
      data: {
        firstName: 'Concurrency',
        lastName: 'Test',
        emails: {
          create: {
            email,
            isPrimary: true,
            isVerified: false,
          },
        },
      },
      include: { emails: true },
    });
    createdUserIds.push(user.id);

    const userEmail = user.emails[0];
    const previousToken = await prisma.userToken.create({
      data: {
        userId: user.id,
        tokenHash: hashToken(rawToken),
        type: UserTokenType.EMAIL_VERIFICATION,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        createdAt:
          options?.previousTokenCreatedAt ??
          new Date(Date.now() - (COOLDOWN_SECONDS + 30) * 1000),
        metaData: {
          userEmailId: userEmail.id,
        },
      },
    });

    return { email, user, userEmail, previousToken, rawToken };
  }

  async function tokensForEmail(userId: string, emailId: string) {
    const tokens = await prisma.userToken.findMany({
      where: {
        userId,
        type: UserTokenType.EMAIL_VERIFICATION,
      },
      orderBy: { createdAt: 'asc' },
    });

    return tokens.filter((token) => metadataEmailId(token.metaData) === emailId);
  }

  describe('A. concurrent resend', () => {
    it('allows exactly one new verification token and one enqueued email', async () => {
      const { email, user, userEmail, previousToken } =
        await createUnverifiedEmail({
          previousTokenCreatedAt: new Date(
            Date.now() - (COOLDOWN_SECONDS + 30) * 1000,
          ),
        });

      const barrier = installTransactionOverlapBarrier(prisma, 2);
      let results: Array<{ success: boolean; message: string }>;
      try {
        results = await Promise.all([
          service.resendVerifyEmail(email),
          service.resendVerifyEmail(email),
        ]);
      } finally {
        barrier.restore();
      }

      expect(results).toEqual([
        {
          success: true,
          message: GENERIC_VERIFICATION_RESPONSE,
        },
        {
          success: true,
          message: GENERIC_VERIFICATION_RESPONSE,
        },
      ]);

      const retryWarnings = logger.warn.mock.calls.filter(
        (call) => call[0]?.code === 'VERIFICATION_RESEND_TRANSACTION_RETRY',
      );
      if (retryWarnings.length > 0) {
        expect(barrier.getTransactionCalls()).toBeGreaterThan(2);
        expect(retryWarnings.length).toBeGreaterThan(0);
      }

      const cooldownLogs = logger.log.mock.calls.filter(
        (call) =>
          call[0]?.code === 'COOLDOWN' || call[0]?.code === 'COOLDOWN_ACTIVE',
      );
      expect(cooldownLogs.length).toBeGreaterThan(0);

      const tokens = await tokensForEmail(user.id, userEmail.id);
      const original = tokens.find((token) => token.id === previousToken.id);
      const createdDuringRace = tokens.filter(
        (token) => token.id !== previousToken.id,
      );

      expect(original).toBeDefined();
      expect(original!.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
      expect(createdDuringRace).toHaveLength(1);

      const committedToken = createdDuringRace[0];
      expect(committedToken.expiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(enqueue).toHaveBeenCalledTimes(1);

      const job = enqueue.mock.calls[0][0] as EnqueuedVerificationJob;
      expect(job).toMatchObject({
        type: EmailJobType.EMAIL_VERIFICATION,
        idempotencyKey: `email-verification-${committedToken.id}`,
        userId: user.id,
        to: email,
        data: {
          tokenId: committedToken.id,
        },
      });
      expect(hashToken(job.data.rawToken)).toBe(committedToken.tokenHash);
    });
  });

  describe('B. concurrent verification of the same token', () => {
    it('consumes the token exactly once', async () => {
      const { user, userEmail, rawToken, previousToken } =
        await createUnverifiedEmail({
          previousTokenCreatedAt: new Date(),
        });

      const barrier = installTransactionOverlapBarrier(prisma, 2);
      let results: PromiseSettledResult<{ message: string }>[];
      try {
        results = await Promise.allSettled([
          service.verifyEmail({ rawToken }),
          service.verifyEmail({ rawToken }),
        ]);
      } finally {
        barrier.restore();
      }

      const fulfilled = results.filter(
        (result): result is PromiseFulfilledResult<{ message: string }> =>
          result.status === 'fulfilled',
      );
      const rejected = results.filter(
        (result): result is PromiseRejectedResult =>
          result.status === 'rejected',
      );

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(fulfilled[0].value).toEqual({
        message: 'Email verified successfully',
      });
      expect(exceptionMessage(rejected[0].reason)).toBe(
        'Verification token has already been used',
      );

      const token = await prisma.userToken.findUnique({
        where: { id: previousToken.id },
      });
      expect(token?.usedAt).toEqual(expect.any(Date));

      const emailRecord = await prisma.userEmail.findUnique({
        where: { id: userEmail.id },
      });
      expect(emailRecord?.isVerified).toBe(true);
      expect(emailRecord?.verifiedAt).toEqual(expect.any(Date));

      const events = await prisma.authEvent.findMany({
        where: {
          userId: user.id,
          eventType: AuthEventType.EMAIL_VERIFIED,
        },
      });
      expect(events).toHaveLength(1);
      expect(events[0].metadata).toEqual({ userEmailId: userEmail.id });
    });
  });

  describe('C. normal resend after cooldown', () => {
    it('creates a new token, expires the previous token, and enqueues one email', async () => {
      const { email, user, userEmail, previousToken } =
        await createUnverifiedEmail({
          previousTokenCreatedAt: new Date(
            Date.now() - (COOLDOWN_SECONDS + 30) * 1000,
          ),
        });

      await expect(service.resendVerifyEmail(email)).resolves.toEqual({
        success: true,
        message: GENERIC_VERIFICATION_RESPONSE,
      });

      const tokens = await tokensForEmail(user.id, userEmail.id);
      const original = tokens.find((token) => token.id === previousToken.id);
      const created = tokens.filter((token) => token.id !== previousToken.id);

      expect(original!.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
      expect(created).toHaveLength(1);
      expect(enqueue).toHaveBeenCalledTimes(1);

      const job = enqueue.mock.calls[0][0] as EnqueuedVerificationJob;
      expect(job.data.tokenId).toBe(created[0].id);
      expect(hashToken(job.data.rawToken)).toBe(created[0].tokenHash);
      expect(job.idempotencyKey).toBe(`email-verification-${created[0].id}`);
    });
  });

  describe('D. resend during cooldown', () => {
    it('does not create a token or enqueue email', async () => {
      const { email, user, userEmail, previousToken } =
        await createUnverifiedEmail({
          previousTokenCreatedAt: new Date(),
        });

      await expect(service.resendVerifyEmail(email)).resolves.toEqual({
        success: true,
        message: GENERIC_VERIFICATION_RESPONSE,
      });

      const tokens = await tokensForEmail(user.id, userEmail.id);
      expect(tokens).toHaveLength(1);
      expect(tokens[0].id).toBe(previousToken.id);
      expect(tokens[0].expiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(enqueue).not.toHaveBeenCalled();
    });
  });
});

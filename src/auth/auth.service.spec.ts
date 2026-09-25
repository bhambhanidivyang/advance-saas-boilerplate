import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { EmailService } from 'src/email/email.service';
import { Prisma } from 'src/generated/prisma/client';
import { GENERIC_VERIFICATION_RESPONSE } from './constants/auth.constants';
import { SessionService } from './session/session.service';
import { PasswordAuthenticatorService } from './password/password-authenticator.service';
import { GoogleAuthenticatorService } from './google/google-authenticator.service';
import { GoogleNonceService } from './google/google-nonce.service';

const COOLDOWN_SECONDS = 60;
const VERIFICATION_TOKEN_TTL_HOURS = 24;

function createP2034Error() {
  return new Prisma.PrismaClientKnownRequestError(
    'Transaction failed due to a write conflict or a deadlock',
    {
      code: 'P2034',
      clientVersion: 'test',
    },
  );
}

describe('AuthService', () => {
  let service: AuthService;
  let prisma: {
    userEmail: { findUnique: jest.Mock };
    $transaction: jest.Mock;
  };
  let emailService: { enqueue: jest.Mock };
  let tx: {
    userToken: {
      findFirst: jest.Mock;
      updateMany: jest.Mock;
      create: jest.Mock;
    };
  };

  beforeEach(async () => {
    tx = {
      userToken: {
        findFirst: jest.fn(),
        updateMany: jest.fn(),
        create: jest.fn(),
      },
    };

    prisma = {
      userEmail: {
        findUnique: jest.fn(),
      },
      $transaction: jest.fn(async (callback: (client: typeof tx) => unknown) =>
        callback(tx),
      ),
    };

    emailService = {
      enqueue: jest.fn().mockResolvedValue(true),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: EmailService, useValue: emailService },
        { provide: SessionService, useValue: { createSession: jest.fn() } },
        // Login is covered in auth.service.login.spec.ts; these specs never reach it.
        { provide: PasswordAuthenticatorService, useValue: {} },
        { provide: GoogleAuthenticatorService, useValue: {} },
        { provide: GoogleNonceService, useValue: { issue: jest.fn() } },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'email.verificationTokenTtl') {
                return VERIFICATION_TOKEN_TTL_HOURS;
              }
              if (key === 'auth.authVerificationResendCooldown') {
                return COOLDOWN_SECONDS;
              }
              return undefined;
            }),
          },
        },
        {
          provide: Logger,
          useValue: {
            log: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('resendVerifyEmail during cooldown', () => {
    it('returns the generic response without creating a token or enqueueing email', async () => {
      prisma.userEmail.findUnique.mockResolvedValue({
        id: 'email-1',
        userId: 'user-1',
        isVerified: false,
      });
      tx.userToken.findFirst.mockResolvedValue({
        createdAt: new Date(),
      });

      await expect(service.resendVerifyEmail('User@Example.com')).resolves.toEqual({
        success: true,
        message: GENERIC_VERIFICATION_RESPONSE,
      });

      expect(tx.userToken.updateMany).not.toHaveBeenCalled();
      expect(tx.userToken.create).not.toHaveBeenCalled();
      expect(emailService.enqueue).not.toHaveBeenCalled();
    });
  });

  describe('P2034 retry exhaustion', () => {
    it('retries the resend transaction exactly 3 times and then propagates P2034', async () => {
      prisma.userEmail.findUnique.mockResolvedValue({
        id: 'email-1',
        userId: 'user-1',
        isVerified: false,
      });
      const serializationError = createP2034Error();
      prisma.$transaction.mockRejectedValue(serializationError);

      await expect(service.resendVerifyEmail('user@example.com')).rejects.toBe(
        serializationError,
      );

      expect(prisma.$transaction).toHaveBeenCalledTimes(3);
      expect(emailService.enqueue).not.toHaveBeenCalled();
    });
  });
});

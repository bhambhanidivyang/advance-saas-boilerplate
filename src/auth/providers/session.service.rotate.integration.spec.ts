/**
 * Real PostgreSQL rotation tests. Jest's default CJS runner cannot load Prisma 7's
 * WASM query compiler unless Node is started with --experimental-vm-modules.
 * Run via: pnpm test:integration
 *
 * Uses DATABASE_URL or TEST_DATABASE_URL (a migrated Postgres instance).
 */
import 'dotenv/config';

import { randomUUID } from 'crypto';
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from 'src/prisma/prisma.service';
import { installTransactionOverlapBarrier } from 'src/common/testing/transaction-overlap-barrier';
import {
  AuthEventType,
  AuthMethod,
  SessionRevocationReason,
} from 'src/generated/prisma/client';
import { SessionService } from './session.service';
import { TokenService } from './token.service';
import { SessionDenylistService } from './session-denylist.service';
import { AuthContext } from '../interfaces/auth-context.interface';

const ABSOLUTE_TTL_SECONDS = 30 * 24 * 60 * 60;
const REFRESH_TTL_SECONDS = 14 * 24 * 60 * 60;
const GRACE_SECONDS = 15;
// High enough that these tests never trip the cap; eviction is covered by the unit spec.
const MAX_ACTIVE_PER_USER = 50;

const context: AuthContext = {
  ipAddress: '203.0.113.10',
  userAgent: 'jest-integration',
  deviceId: 'device-1',
};

describe('SessionService rotation concurrency (PostgreSQL)', () => {
  let service: SessionService;
  let prisma: PrismaService;
  const createdUserIds: string[] = [];

  const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

  beforeAll(async () => {
    if (!databaseUrl) {
      throw new Error(
        'Rotation integration tests require DATABASE_URL or TEST_DATABASE_URL pointing at a migrated PostgreSQL database.',
      );
    }

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SessionService,
        PrismaService,
        // Disabled in these tests: revocation semantics live in Postgres, and the
        // denylist only narrows the access-token window.
        {
          provide: SessionDenylistService,
          useValue: { revoke: jest.fn(), isRevoked: jest.fn().mockResolvedValue(false) },
        },
        {
          provide: TokenService,
          useValue: {
            generateAccessToken: jest
              .fn()
              .mockResolvedValue({ accessToken: 'access-token', expiresIn: 600 }),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: (key: string) => (key === 'database.url' ? databaseUrl : undefined),
            getOrThrow: (key: string) => {
              if (key === 'database.url') return databaseUrl;
              if (key === 'auth.session.absoluteTtlSeconds') return ABSOLUTE_TTL_SECONDS;
              if (key === 'auth.session.refreshTtlSeconds') return REFRESH_TTL_SECONDS;
              if (key === 'auth.session.refreshReuseGraceSeconds') return GRACE_SECONDS;
              if (key === 'auth.session.maxActivePerUser') return MAX_ACTIVE_PER_USER;
              throw new TypeError(`Configuration key "${key}" does not exist`);
            },
          },
        },
      ],
    }).compile();

    service = module.get(SessionService);
    prisma = module.get(PrismaService);
    await prisma.$connect();
  });

  afterEach(async () => {
    const userIds = createdUserIds.splice(0, createdUserIds.length);
    if (userIds.length === 0) {
      return;
    }
    // AuthEvent is onDelete: SetNull, so it must be removed explicitly; sessions
    // and refresh tokens cascade from the user.
    await prisma.authEvent.deleteMany({ where: { userId: { in: userIds } } });
    await prisma.user.deleteMany({ where: { id: { in: userIds } } });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function createLoggedInUser() {
    const user = await prisma.user.create({
      data: {
        firstName: 'Rotation',
        passwordHash: 'not-used-by-these-tests',
        emails: {
          create: { email: `rotate-${randomUUID()}@example.com`, isPrimary: true, isVerified: true },
        },
      },
      select: { id: true },
    });
    createdUserIds.push(user.id);

    const session = await service.createSession({
      userId: user.id,
      authMethod: AuthMethod.PASSWORD,
      emailVerified: true,
      context,
    });

    return { userId: user.id, session };
  }

  function reuseEventsFor(userId: string) {
    return prisma.authEvent.count({
      where: { userId, eventType: AuthEventType.TOKEN_REUSE_DETECTED },
    });
  }

  describe('two requests presenting the same refresh token at once', () => {
    // A legitimate client double-submits all the time: two calls 401 together, or a
    // retry follows a dropped response. Only a real MVCC engine produces the
    // interleaving where one UPDATE waits on the other's row lock.
    it('both succeed, the session survives, and nothing is flagged as theft', async () => {
      const { userId, session } = await createLoggedInUser();

      const barrier = installTransactionOverlapBarrier(prisma, 2);
      let results: Awaited<ReturnType<SessionService['rotateRefreshToken']>>[];
      try {
        results = await Promise.all([
          service.rotateRefreshToken(session.refreshToken, context),
          service.rotateRefreshToken(session.refreshToken, context),
        ]);
      } finally {
        barrier.restore();
      }

      expect(results).toHaveLength(2);
      results.forEach((result) => {
        expect(result.accessToken).toBe('access-token');
        expect(result.refreshToken).toEqual(expect.any(String));
      });
      // Two distinct children, each usable by whichever caller received it.
      expect(results[0].refreshToken).not.toBe(results[1].refreshToken);

      const stored = await prisma.session.findUniqueOrThrow({
        where: { id: session.sessionId },
        select: { revokedAt: true, revocationReason: true },
      });
      expect(stored.revokedAt).toBeNull();
      expect(stored.revocationReason).toBeNull();

      expect(await reuseEventsFor(userId)).toBe(0);

      // The parent was consumed exactly once.
      const refreshTokens = await prisma.sessionRefreshToken.findMany({
        where: { sessionId: session.sessionId },
        select: { usedAt: true },
      });
      expect(refreshTokens.filter((token) => token.usedAt !== null)).toHaveLength(1);
    });
  });

  describe('a used token replayed outside the grace window', () => {
    it('revokes the family and records exactly one TOKEN_REUSE_DETECTED', async () => {
      const { userId, session } = await createLoggedInUser();

      await service.rotateRefreshToken(session.refreshToken, context);

      // Backdate the consumed parent past the grace window. Fake timers cannot be
      // used here: the comparison timestamps come from the database.
      await prisma.sessionRefreshToken.updateMany({
        where: { sessionId: session.sessionId, usedAt: { not: null } },
        data: { usedAt: new Date(Date.now() - (GRACE_SECONDS + 60) * 1000) },
      });

      await expect(
        service.rotateRefreshToken(session.refreshToken, context),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      const stored = await prisma.session.findUniqueOrThrow({
        where: { id: session.sessionId },
        select: { revokedAt: true, revocationReason: true },
      });
      expect(stored.revokedAt).not.toBeNull();
      expect(stored.revocationReason).toBe(SessionRevocationReason.TOKEN_REUSE);

      const refreshTokens = await prisma.sessionRefreshToken.findMany({
        where: { sessionId: session.sessionId },
        select: { revokedAt: true },
      });
      expect(refreshTokens.every((token) => token.revokedAt !== null)).toBe(true);

      expect(await reuseEventsFor(userId)).toBe(1);
    });

    it('leaves the replacement token unusable once the family is revoked', async () => {
      const { session } = await createLoggedInUser();

      const rotated = await service.rotateRefreshToken(session.refreshToken, context);

      await prisma.sessionRefreshToken.updateMany({
        where: { sessionId: session.sessionId, usedAt: { not: null } },
        data: { usedAt: new Date(Date.now() - (GRACE_SECONDS + 60) * 1000) },
      });

      await expect(
        service.rotateRefreshToken(session.refreshToken, context),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      // The legitimate client's own token dies with the family — that is the point
      // of revoking on suspected theft.
      await expect(
        service.rotateRefreshToken(rotated.refreshToken, context),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('logging out one device', () => {
    // The bug this catches is an over-broad updateMany: revoking by userId instead
    // of by session id would quietly log the user out everywhere.
    it('leaves the user other sessions still able to rotate', async () => {
      const { userId, session: first } = await createLoggedInUser();

      const second = await service.createSession({
        userId,
        authMethod: AuthMethod.PASSWORD,
        emailVerified: true,
        context,
      });

      await service.revokeSession(first.sessionId, context);

      const revoked = await prisma.session.findUniqueOrThrow({
        where: { id: first.sessionId },
        select: { revokedAt: true, revocationReason: true },
      });
      expect(revoked.revokedAt).not.toBeNull();
      expect(revoked.revocationReason).toBe(SessionRevocationReason.LOGOUT);

      // The logged-out session's token is dead...
      await expect(
        service.rotateRefreshToken(first.refreshToken, context),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      // ...while the other device carries on.
      const rotated = await service.rotateRefreshToken(second.refreshToken, context);
      expect(rotated.accessToken).toBe('access-token');

      const survivor = await prisma.session.findUniqueOrThrow({
        where: { id: second.sessionId },
        select: { revokedAt: true },
      });
      expect(survivor.revokedAt).toBeNull();
    });

    it('revokes every session on logout-all and records one event', async () => {
      const { userId, session: first } = await createLoggedInUser();
      const second = await service.createSession({
        userId,
        authMethod: AuthMethod.PASSWORD,
        emailVerified: true,
        context,
      });

      const revokedCount = await service.revokeAllSessions(userId, first.sessionId, context);
      expect(revokedCount).toBe(2);

      const sessions = await prisma.session.findMany({
        where: { userId },
        select: { revokedAt: true, revocationReason: true },
      });
      expect(sessions).toHaveLength(2);
      expect(
        sessions.every(
          (session) =>
            session.revokedAt !== null &&
            session.revocationReason === SessionRevocationReason.LOGOUT_ALL,
        ),
      ).toBe(true);

      await expect(
        service.rotateRefreshToken(second.refreshToken, context),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      const logoutAllEvents = await prisma.authEvent.count({
        where: { userId, eventType: AuthEventType.LOGOUT_ALL },
      });
      expect(logoutAllEvents).toBe(1);
    });
  });
});

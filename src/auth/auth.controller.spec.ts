import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import type { Request, Response } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from './providers/auth.service';
import { CreateNewUser } from './dto/create-new-user.dto';
import { ResendVerification } from './dto/resend-verification.dto';
import { LoginDto } from './dto/login.dto';
import { LoginResult } from './interfaces/login.interface';
import { SessionService } from './providers/session.service';
import { IssuedSession } from './interfaces/session.interface';
import { AuthMethod } from 'src/generated/prisma/client';

// Mirrors the real cookie config: SESSION_COOKIE_DOMAIN is empty in .env, which
// configuration.ts maps to undefined (a host-only cookie).
const cookieConfig: Record<string, unknown> = {
  'auth.cookie.name': 'mn_rt',
  'auth.cookie.domain': undefined,
  'auth.cookie.sameSite': 'lax',
  'auth.cookie.secure': false,
};

describe('AuthController', () => {
  let controller: AuthController;
  let authService: {
    register: jest.Mock;
    resendVerifyEmail: jest.Mock;
    verifyEmail: jest.Mock;
    login: jest.Mock;
  };
  let sessionService: {
    rotateRefreshToken: jest.Mock;
    revokeSessionByRefreshToken: jest.Mock;
    revokeAllSessions: jest.Mock;
  };
  let logger: { log: jest.Mock };

  beforeEach(async () => {
    authService = {
      register: jest.fn(),
      resendVerifyEmail: jest.fn(),
      verifyEmail: jest.fn(),
      login: jest.fn(),
    };
    sessionService = {
      rotateRefreshToken: jest.fn(),
      revokeSessionByRefreshToken: jest.fn(),
      revokeAllSessions: jest.fn().mockResolvedValue(2),
    };
    logger = { log: jest.fn() };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: authService,
        },
        {
          provide: SessionService,
          useValue: sessionService,
        },
        {
          provide: Logger,
          useValue: logger,
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => cookieConfig[key]),
            // Faithful to the real ConfigService: getOrThrow throws on undefined.
            getOrThrow: jest.fn((key: string) => {
              const value = cookieConfig[key];
              if (value === undefined) {
                throw new TypeError(`Configuration key "${key}" does not exist`);
              }
              return value;
            }),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('calls authService.register with the request body and returns its result unchanged', async () => {
      const body: CreateNewUser = {
        firstName: 'Jane',
        lastName: 'Doe',
        displayName: 'JaneD',
        email: 'jane@example.com',
        password: 'Sup3r$ecret!',
      };
      const serviceResult = {
        success: true,
        data: { id: 'user-1' },
        emailStatus: 'QUEUED',
        message: 'Account created successfully. Please verify your email to continue.',
      };
      authService.register.mockResolvedValue(serviceResult);

      const result = await controller.register(body);

      expect(authService.register).toHaveBeenCalledTimes(1);
      expect(authService.register).toHaveBeenCalledWith(body);
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.register without swallowing or transforming them', async () => {
      const body: CreateNewUser = {
        firstName: 'Jane',
        lastName: 'Doe',
        displayName: 'JaneD',
        email: 'jane@example.com',
        password: 'Sup3r$ecret!',
      };
      const error = new Error('registration failed');
      authService.register.mockRejectedValue(error);

      await expect(controller.register(body)).rejects.toBe(error);
    });
  });

  describe('resendVerifyEmail', () => {
    it('calls authService.resendVerifyEmail with the email from the body and returns its result unchanged', async () => {
      const body: ResendVerification = { email: 'jane@example.com' };
      const serviceResult = { success: true, message: 'generic response' };
      authService.resendVerifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.resendVerifyEmail(body);

      expect(authService.resendVerifyEmail).toHaveBeenCalledTimes(1);
      expect(authService.resendVerifyEmail).toHaveBeenCalledWith(body.email);
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.resendVerifyEmail without swallowing or transforming them', async () => {
      const body: ResendVerification = { email: 'jane@example.com' };
      const error = new Error('resend failed');
      authService.resendVerifyEmail.mockRejectedValue(error);

      await expect(controller.resendVerifyEmail(body)).rejects.toBe(error);
    });
  });

  describe('verifyEmail', () => {
    it('passes the raw token (and tokenId) from the query params to authService.verifyEmail and returns its result unchanged', async () => {
      const params = { tokenId: 'token-id-1', rawToken: 'raw-token-value' };
      const serviceResult = { message: 'Email verified successfully' };
      authService.verifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.verifyEmail(params);

      expect(authService.verifyEmail).toHaveBeenCalledTimes(1);
      expect(authService.verifyEmail).toHaveBeenCalledWith(params);
      expect(result).toBe(serviceResult);
    });

    it('passes the raw token through even when tokenId is not provided', async () => {
      const params = { rawToken: 'raw-token-only' };
      const serviceResult = { message: 'Email verified successfully' };
      authService.verifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.verifyEmail(params);

      expect(authService.verifyEmail).toHaveBeenCalledWith(params);
      expect(authService.verifyEmail.mock.calls[0][0].rawToken).toBe('raw-token-only');
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.verifyEmail without swallowing or transforming them', async () => {
      const params = { rawToken: 'raw-token-value' };
      const error = new Error('Invalid verification token');
      authService.verifyEmail.mockRejectedValue(error);

      await expect(controller.verifyEmail(params)).rejects.toBe(error);
    });
  });

  describe('login', () => {
    const body: LoginDto = { email: 'jane@example.com', password: 'Sup3r$ecret!' };
    const headers: Record<string, string> = { 'user-agent': 'jest', 'device-id': 'device-1' };
    const req = {
      ip: '203.0.113.10',
      get: (name: string) => headers[name.toLowerCase()],
    } as unknown as Request;

    const loginResult: LoginResult = {
      session: {
        sessionId: 'session-1',
        tokenFamilyId: 'family-1',
        accessToken: 'access-token',
        expiresIn: 600,
        refreshToken: 'raw-refresh-token',
        refreshTokenExpiresAt: new Date(Date.now() + 60_000),
      },
      user: { id: 'user-1', emailVerified: true, mustChangePassword: false },
    };

    let res: { cookie: jest.Mock };

    beforeEach(() => {
      res = { cookie: jest.fn() };
      authService.login.mockResolvedValue(loginResult);
    });

    // Regression guard for the leak: one careless `...session` spread in the
    // controller would put the raw refresh token in the JSON body.
    it('never returns the refresh token in the response body', async () => {
      const response = await controller.login(body, req, res as unknown as Response);

      expect(response).not.toHaveProperty('refreshToken');
      // Catches the token nested anywhere, e.g. under a spread `session` key.
      expect(JSON.stringify(response)).not.toContain(loginResult.session.refreshToken);
      expect(response).toEqual({
        accessToken: 'access-token',
        expiresIn: 600,
        tokenType: 'Bearer',
        user: loginResult.user,
      });
    });

    it('sets the refresh token as the configured httpOnly cookie', async () => {
      await controller.login(body, req, res as unknown as Response);

      expect(res.cookie).toHaveBeenCalledTimes(1);
      expect(res.cookie).toHaveBeenCalledWith(
        'mn_rt',
        'raw-refresh-token',
        expect.objectContaining({ httpOnly: true, path: '/auth' }),
      );
    });
  });

  describe('refresh', () => {
    const issued: IssuedSession = {
      sessionId: 'session-1',
      tokenFamilyId: 'family-1',
      accessToken: 'new-access-token',
      expiresIn: 600,
      refreshToken: 'new-refresh-token',
      refreshTokenExpiresAt: new Date(Date.now() + 60_000),
    };

    const headers: Record<string, string> = { 'user-agent': 'jest', 'device-id': 'device-1' };

    function request(cookies: Record<string, string>) {
      return {
        ip: '203.0.113.10',
        get: (name: string) => headers[name.toLowerCase()],
        cookies,
      } as unknown as Request;
    }

    let res: { cookie: jest.Mock; clearCookie: jest.Mock };

    beforeEach(() => {
      res = { cookie: jest.fn(), clearCookie: jest.fn() };
      sessionService.rotateRefreshToken.mockResolvedValue(issued);
    });

    it('rotates the token taken from the cookie', async () => {
      await controller.refresh(request({ mn_rt: 'old-refresh-token' }), res as unknown as Response);

      expect(sessionService.rotateRefreshToken).toHaveBeenCalledTimes(1);
      expect(sessionService.rotateRefreshToken).toHaveBeenCalledWith('old-refresh-token', {
        ipAddress: '203.0.113.10',
        userAgent: 'jest',
        deviceId: 'device-1',
      });
    });

    it('sets the replacement token as the cookie and keeps it out of the body', async () => {
      const response = await controller.refresh(
        request({ mn_rt: 'old-refresh-token' }),
        res as unknown as Response,
      );

      expect(res.cookie).toHaveBeenCalledWith(
        'mn_rt',
        'new-refresh-token',
        expect.objectContaining({ httpOnly: true, path: '/auth' }),
      );
      expect(response).toEqual({
        accessToken: 'new-access-token',
        expiresIn: 600,
        tokenType: 'Bearer',
      });
      expect(JSON.stringify(response)).not.toContain('new-refresh-token');
    });

    it('rejects a request with no cookie without calling the service', async () => {
      await expect(
        controller.refresh(request({}), res as unknown as Response),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      expect(sessionService.rotateRefreshToken).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledWith('mn_rt', expect.objectContaining({ path: '/auth' }));
    });

    it('clears the cookie when rotation is rejected', async () => {
      const error = new UnauthorizedException('Session expired. Please log in again.');
      sessionService.rotateRefreshToken.mockRejectedValue(error);

      await expect(
        controller.refresh(request({ mn_rt: 'stale-refresh-token' }), res as unknown as Response),
      ).rejects.toBe(error);

      expect(res.clearCookie).toHaveBeenCalledTimes(1);
      // Cleared without maxAge so the attributes match what was originally set.
      expect(res.clearCookie.mock.calls[0][1]).not.toHaveProperty('maxAge');
      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  describe('logout', () => {
    const headers: Record<string, string> = { 'user-agent': 'jest', 'device-id': 'device-1' };

    function request(cookies: Record<string, string>) {
      return {
        ip: '203.0.113.10',
        get: (name: string) => headers[name.toLowerCase()],
        cookies,
      } as unknown as Request;
    }

    let res: { cookie: jest.Mock; clearCookie: jest.Mock };

    beforeEach(() => {
      res = { cookie: jest.fn(), clearCookie: jest.fn() };
    });

    it('revokes the session behind the cookie and clears it', async () => {
      const response = await controller.logout(
        request({ mn_rt: 'raw-refresh-token' }),
        res as unknown as Response,
      );

      expect(sessionService.revokeSessionByRefreshToken).toHaveBeenCalledWith('raw-refresh-token', {
        ipAddress: '203.0.113.10',
        userAgent: 'jest',
        deviceId: 'device-1',
      });
      expect(res.clearCookie).toHaveBeenCalledWith(
        'mn_rt',
        expect.objectContaining({ httpOnly: true, path: '/auth' }),
      );
      expect(res.clearCookie.mock.calls[0][1]).not.toHaveProperty('maxAge');
      expect(response).toEqual({ success: true });
    });

    // Clicking log out must never fail, even with no session to end.
    it('succeeds with no cookie, without calling the service', async () => {
      const response = await controller.logout(request({}), res as unknown as Response);

      expect(sessionService.revokeSessionByRefreshToken).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledTimes(1);
      expect(response).toEqual({ success: true });
    });
  });

  describe('logoutAll', () => {
    const headers: Record<string, string> = { 'user-agent': 'jest', 'device-id': 'device-1' };
    const req = {
      ip: '203.0.113.10',
      get: (name: string) => headers[name.toLowerCase()],
      cookies: {},
    } as unknown as Request;

    const user = {
      userId: 'user-1',
      sessionId: 'session-1',
      tokenFamilyId: 'family-1',
      emailVerified: true,
      authMethod: AuthMethod.PASSWORD,
    };

    it('revokes every session for the caller and reports the count', async () => {
      const res = { cookie: jest.fn(), clearCookie: jest.fn() };

      const response = await controller.logoutAll(user, req, res as unknown as Response);

      expect(sessionService.revokeAllSessions).toHaveBeenCalledWith('user-1', 'session-1', {
        ipAddress: '203.0.113.10',
        userAgent: 'jest',
        deviceId: 'device-1',
      });
      expect(res.clearCookie).toHaveBeenCalledWith(
        'mn_rt',
        expect.objectContaining({ httpOnly: true, path: '/auth' }),
      );
      expect(response).toEqual({ success: true, revokedSessions: 2 });
    });
  });
});

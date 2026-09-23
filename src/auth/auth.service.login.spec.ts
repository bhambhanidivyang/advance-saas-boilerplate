import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { Logger } from 'nestjs-pino';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { EmailService } from 'src/email/email.service';
import { AuthMethod } from 'src/generated/prisma/client';
import { GENERIC_LOGIN_RESPONSE } from './constants/auth.constants';
import { AuthContext } from './interfaces/auth-context.interface';
import { AuthenticationResult } from './interfaces/authentication-result.interface';
import { IssuedSession } from './interfaces/session.interface';
import { SessionService } from './session/session.service';
import { PasswordAuthenticatorService } from './password/password-authenticator.service';

/**
 * Login as orchestration only: prove identity, then start a session. The proof
 * itself — timing, enumeration, lockout — is PasswordAuthenticatorService's spec.
 */
describe('AuthService.login', () => {
    const body = { email: 'user@example.com', password: 'CorrectPassword1!' };
    const context: AuthContext = { ipAddress: '203.0.113.10', userAgent: 'jest', deviceId: 'device-1' };

    const authentication: AuthenticationResult = {
        userId: 'user-1',
        authMethod: AuthMethod.PASSWORD,
        emailVerified: true,
        mustChangePassword: false,
    };

    const issuedSession: IssuedSession = {
        sessionId: 'session-1',
        tokenFamilyId: 'family-1',
        accessToken: 'access-token',
        expiresIn: 600,
        refreshToken: 'raw-refresh-token',
        refreshTokenExpiresAt: new Date('2026-01-15T00:00:00.000Z'),
    };

    let service: AuthService;
    let passwordAuthenticator: { authenticate: jest.Mock };
    let sessionService: { createSession: jest.Mock };

    beforeEach(async () => {
        passwordAuthenticator = { authenticate: jest.fn().mockResolvedValue(authentication) };
        sessionService = { createSession: jest.fn().mockResolvedValue(issuedSession) };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: PasswordAuthenticatorService, useValue: passwordAuthenticator },
                { provide: SessionService, useValue: sessionService },
                { provide: PrismaService, useValue: {} },
                { provide: EmailService, useValue: {} },
                { provide: ConfigService, useValue: { get: jest.fn() } },
                { provide: Logger, useValue: { log: jest.fn(), warn: jest.fn(), error: jest.fn() } },
            ],
        }).compile();

        service = module.get(AuthService);
    });

    it('hands the credentials and context to the password authenticator unchanged', async () => {
        await service.login(body, context);

        expect(passwordAuthenticator.authenticate).toHaveBeenCalledTimes(1);
        expect(passwordAuthenticator.authenticate).toHaveBeenCalledWith(body, context);
    });

    it('creates exactly one session from the authentication result', async () => {
        await service.login(body, context);

        expect(sessionService.createSession).toHaveBeenCalledTimes(1);
        expect(sessionService.createSession).toHaveBeenCalledWith({
            userId: 'user-1',
            authMethod: AuthMethod.PASSWORD,
            emailVerified: true,
            mustChangePassword: false,
            context,
        });
    });

    it('returns the session and user without leaking the request context', async () => {
        const result = await service.login(body, context);

        expect(result).toEqual({
            session: issuedSession,
            user: { id: 'user-1', emailVerified: true, mustChangePassword: false },
        });
        expect(result).not.toHaveProperty('context');
    });

    // The guarantee the refactor exists to protect: no proof, no session.
    it('never creates a session when authentication fails, and rethrows the same error', async () => {
        const failure = new UnauthorizedException(GENERIC_LOGIN_RESPONSE);
        passwordAuthenticator.authenticate.mockRejectedValue(failure);

        await expect(service.login(body, context)).rejects.toBe(failure);

        expect(sessionService.createSession).not.toHaveBeenCalled();
    });

    // Every sign-in method finishes through the same step, so it must carry the
    // authenticator's method through rather than assume PASSWORD.
    it('passes the authenticated method through to the session', async () => {
        passwordAuthenticator.authenticate.mockResolvedValue({
            ...authentication,
            authMethod: AuthMethod.GOOGLE,
            mustChangePassword: true,
        });

        await service.login(body, context);

        expect(sessionService.createSession).toHaveBeenCalledWith(
            expect.objectContaining({ authMethod: AuthMethod.GOOGLE, mustChangePassword: true }),
        );
    });
});

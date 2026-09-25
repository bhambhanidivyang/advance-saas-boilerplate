import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { ForbiddenException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, AuthMethod, AuthProvider } from 'src/generated/prisma/client';
import { GoogleAuthenticatorService } from './google-authenticator.service';
import { GoogleTokenVerifier } from './google-token-verifier';
import { GoogleNonceService } from './google-nonce.service';
import { GoogleNonceInvalidError } from './google-nonce-invalid.error';
import { GoogleTokenInvalidError } from './google-token-invalid.error';
import { IdentityService } from '../identity/identity.service';
import {
    ExternalEmailUnverifiedError,
    IdentityAccountUnavailableError,
} from '../identity/identity.error';
import { ExternalIdentityProfile } from '../identity/identity.interface';
import { AuthContext } from '../interfaces/auth-context.interface';
import { GENERIC_GOOGLE_LOGIN_RESPONSE, GOOGLE_FAILURE_REASON } from '../constants/auth.constants';

const context: AuthContext = {
    ipAddress: '203.0.113.10',
    userAgent: 'jest',
    deviceId: 'device-1',
};

const profile: ExternalIdentityProfile = {
    provider: AuthProvider.GOOGLE,
    providerUserId: 'google-sub-1',
    email: 'divyang@example.com',
    emailVerified: true,
    firstName: 'Divyang',
    lastName: 'Bhambhani',
    displayName: 'Divyang Bhambhani',
};

/** The single LOGIN_FAILED row written during a call. */
function auditedFailure(prisma: { authEvent: { create: jest.Mock } }) {
    const call = prisma.authEvent.create.mock.calls.find(
        ([arg]) => arg.data.eventType === AuthEventType.LOGIN_FAILED,
    );
    return call?.[0].data;
}

describe('GoogleAuthenticatorService', () => {
    let authenticator: GoogleAuthenticatorService;
    let verifier: { verify: jest.Mock };
    let identityService: { resolveExternalIdentity: jest.Mock };
    let prisma: { authEvent: { create: jest.Mock }; user: { update: jest.Mock } };
    let nonceService: { issue: jest.Mock; consume: jest.Mock };
    let googleEnabled: boolean;
    let nonceRequired: boolean;

    beforeEach(async () => {
        jest.clearAllMocks();
        googleEnabled = true;
        nonceRequired = false;

        verifier = { verify: jest.fn().mockResolvedValue({ profile }) };
        identityService = {
            resolveExternalIdentity: jest
                .fn()
                .mockResolvedValue({ userId: 'user-1', emailVerified: true }),
        };
        prisma = { authEvent: { create: jest.fn() }, user: { update: jest.fn() } };
        nonceService = { issue: jest.fn(), consume: jest.fn().mockResolvedValue(undefined) };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                GoogleAuthenticatorService,
                { provide: GoogleTokenVerifier, useValue: verifier },
                { provide: GoogleNonceService, useValue: nonceService },
                { provide: Logger, useValue: { log: jest.fn(), warn: jest.fn(), error: jest.fn() } },
                { provide: IdentityService, useValue: identityService },
                { provide: PrismaService, useValue: prisma },
                {
                    provide: ConfigService,
                    useValue: {
                        getOrThrow: jest.fn((key: string) => {
                            if (key === 'auth.capabilities.google') return googleEnabled;
                            if (key === 'auth.google.nonceRequired') return nonceRequired;
                            throw new Error(`Unexpected key ${key}`);
                        }),
                    },
                },
            ],
        }).compile();

        authenticator = module.get(GoogleAuthenticatorService);
    });

    describe('a successful sign-in', () => {
        it('returns an AuthenticationResult for the resolved user', async () => {
            await expect(authenticator.authenticate('id-token', context)).resolves.toEqual({
                userId: 'user-1',
                authMethod: AuthMethod.GOOGLE,
                emailVerified: true,
                mustChangePassword: false,
            });
        });

        it('verifies the token before resolving an identity', async () => {
            await authenticator.authenticate('id-token', context);

            expect(verifier.verify).toHaveBeenCalledWith('id-token');
            expect(identityService.resolveExternalIdentity).toHaveBeenCalledWith(profile, context);
            expect(verifier.verify.mock.invocationCallOrder[0]).toBeLessThan(
                identityService.resolveExternalIdentity.mock.invocationCallOrder[0],
            );
        });

        // A password lockout is about password guessing, and Google users may have no
        // password at all. Nothing here reads or writes the counters.
        it('never touches the lockout counters', async () => {
            await authenticator.authenticate('id-token', context);

            expect(prisma.user.update).not.toHaveBeenCalled();
        });

        it('writes no failure event', async () => {
            await authenticator.authenticate('id-token', context);

            expect(prisma.authEvent.create).not.toHaveBeenCalled();
        });

        // mustChangePassword is about a password. A Google-only account has none, so a
        // true value would block every route while change-password answered
        // NO_PASSWORD_CREDENTIAL: an unescapable state.
        it('never asks a Google user to change a password', async () => {
            identityService.resolveExternalIdentity.mockResolvedValue({
                userId: 'user-1',
                emailVerified: true,
                mustChangePassword: true,
            });

            await expect(authenticator.authenticate('id-token', context)).resolves.toMatchObject({
                mustChangePassword: false,
            });
        });

        // Reported by IdentityService from our own records, never assumed from Google.
        it('passes through an unverified stored email', async () => {
            identityService.resolveExternalIdentity.mockResolvedValue({
                userId: 'user-1',
                emailVerified: false,
            });

            await expect(authenticator.authenticate('id-token', context)).resolves.toMatchObject({
                emailVerified: false,
            });
        });
    });

    describe('when the capability is switched off', () => {
        beforeEach(() => {
            googleEnabled = false;
        });

        it('answers 404 without verifying anything', async () => {
            await expect(authenticator.authenticate('id-token', context)).rejects.toBeInstanceOf(
                NotFoundException,
            );

            expect(verifier.verify).not.toHaveBeenCalled();
            expect(identityService.resolveExternalIdentity).not.toHaveBeenCalled();
        });
    });

    describe('an invalid token', () => {
        beforeEach(() => {
            verifier.verify.mockRejectedValue(new GoogleTokenInvalidError('Wrong recipient'));
        });

        it('answers a generic 401', async () => {
            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.message).toBe(GENERIC_GOOGLE_LOGIN_RESPONSE);
        });

        // Bad signature, wrong audience and expiry must be indistinguishable, and the
        // reason must never reach the caller.
        it('keeps the reason out of the response and in the audit log', async () => {
            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(JSON.stringify(error.getResponse())).not.toContain('Wrong recipient');
            expect(auditedFailure(prisma)).toMatchObject({
                eventType: AuthEventType.LOGIN_FAILED,
                authMethod: AuthMethod.GOOGLE,
                ipAddress: '203.0.113.10',
                metadata: expect.objectContaining({
                    reason: GOOGLE_FAILURE_REASON.INVALID_TOKEN,
                    provider: AuthProvider.GOOGLE,
                }),
            });
        });

        it('resolves no identity', async () => {
            await authenticator.authenticate('id-token', context).catch(() => undefined);

            expect(identityService.resolveExternalIdentity).not.toHaveBeenCalled();
        });
    });

    describe('an email Google has not verified', () => {
        beforeEach(() => {
            identityService.resolveExternalIdentity.mockRejectedValue(
                new ExternalEmailUnverifiedError(),
            );
        });

        // Actionable, and safe to state: the caller already holds a Google token for
        // this address, so nothing is disclosed that they do not know.
        it('answers 403 with a code the client can act on', async () => {
            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(error).toBeInstanceOf(ForbiddenException);
            expect(error.getResponse()).toMatchObject({ code: 'GOOGLE_EMAIL_UNVERIFIED' });
        });

        it('audits the attempt against the provider account', async () => {
            await authenticator.authenticate('id-token', context).catch(() => undefined);

            expect(auditedFailure(prisma)).toMatchObject({
                metadata: expect.objectContaining({
                    reason: GOOGLE_FAILURE_REASON.EMAIL_UNVERIFIED,
                    providerUserId: 'google-sub-1',
                }),
            });
        });
    });

    describe('a suspended or deleted account', () => {
        beforeEach(() => {
            identityService.resolveExternalIdentity.mockRejectedValue(
                new IdentityAccountUnavailableError(),
            );
        });

        // The same generic 401 password login gives, so account state stays private.
        it('answers the generic 401 rather than naming the account state', async () => {
            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.message).toBe(GENERIC_GOOGLE_LOGIN_RESPONSE);
            expect(JSON.stringify(error.getResponse())).not.toMatch(/suspend|delete/i);
        });

        it('audits the reason', async () => {
            await authenticator.authenticate('id-token', context).catch(() => undefined);

            expect(auditedFailure(prisma)).toMatchObject({
                metadata: expect.objectContaining({
                    reason: GOOGLE_FAILURE_REASON.ACCOUNT_UNAVAILABLE,
                }),
            });
        });
    });

    describe('an unexpected failure', () => {
        // A database outage is not an authentication decision: it must surface as a
        // 500, not as "your Google sign-in failed".
        it('propagates rather than turning into a 401', async () => {
            identityService.resolveExternalIdentity.mockRejectedValue(new Error('connection lost'));

            await expect(authenticator.authenticate('id-token', context)).rejects.toThrow(
                'connection lost',
            );

            expect(prisma.authEvent.create).not.toHaveBeenCalled();
        });
    });

    // Without a nonce an ID token is replayable for its whole hour of validity: it is
    // a bearer credential, and nothing in the token distinguishes a replay from the
    // original request.
    describe('the nonce', () => {
        it('is consumed when the token carries one', async () => {
            verifier.verify.mockResolvedValue({ profile, nonce: 'client-nonce' });

            await authenticator.authenticate('id-token', context);

            expect(nonceService.consume).toHaveBeenCalledWith('client-nonce', expect.any(Date));
        });

        // A replayed token must never reach account creation or linking.
        it('is consumed before any identity is resolved', async () => {
            verifier.verify.mockResolvedValue({ profile, nonce: 'client-nonce' });

            await authenticator.authenticate('id-token', context);

            expect(nonceService.consume.mock.invocationCallOrder[0]).toBeLessThan(
                identityService.resolveExternalIdentity.mock.invocationCallOrder[0],
            );
        });

        // Verifying first means junk tokens never burn a nonce.
        it('is not consumed when the token itself is rejected', async () => {
            verifier.verify.mockRejectedValue(new GoogleTokenInvalidError('Wrong recipient'));

            await authenticator.authenticate('id-token', context).catch(() => undefined);

            expect(nonceService.consume).not.toHaveBeenCalled();
        });

        it('turns a replayed or expired nonce into the generic 401', async () => {
            verifier.verify.mockResolvedValue({ profile, nonce: 'client-nonce' });
            nonceService.consume.mockRejectedValue(new GoogleNonceInvalidError('Invalid nonce'));

            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.message).toBe(GENERIC_GOOGLE_LOGIN_RESPONSE);
            expect(identityService.resolveExternalIdentity).not.toHaveBeenCalled();
            expect(auditedFailure(prisma)).toMatchObject({
                metadata: expect.objectContaining({ reason: GOOGLE_FAILURE_REASON.NONCE_INVALID }),
            });
        });

        // A token whose nonce is checked only when the flag is on would be trivially
        // bypassed by stripping it. A present nonce is always verified.
        it('is still verified when the flag does not require one', async () => {
            nonceRequired = false;
            verifier.verify.mockResolvedValue({ profile, nonce: 'client-nonce' });
            nonceService.consume.mockRejectedValue(new GoogleNonceInvalidError('Invalid nonce'));

            await expect(authenticator.authenticate('id-token', context)).rejects.toBeInstanceOf(
                UnauthorizedException,
            );
        });

        it('is optional while the flag is off', async () => {
            nonceRequired = false;
            verifier.verify.mockResolvedValue({ profile, nonce: undefined });

            await expect(authenticator.authenticate('id-token', context)).resolves.toMatchObject({
                userId: 'user-1',
            });
            expect(nonceService.consume).not.toHaveBeenCalled();
        });

        it('is mandatory once the flag is on', async () => {
            nonceRequired = true;
            verifier.verify.mockResolvedValue({ profile, nonce: undefined });

            const error = await authenticator.authenticate('id-token', context).catch((e) => e);

            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.message).toBe(GENERIC_GOOGLE_LOGIN_RESPONSE);
            expect(identityService.resolveExternalIdentity).not.toHaveBeenCalled();
            expect(auditedFailure(prisma)).toMatchObject({
                metadata: expect.objectContaining({ reason: GOOGLE_FAILURE_REASON.NONCE_MISSING }),
            });
        });
    });
});

import { ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, AuthMethod, AuthProvider } from 'src/generated/prisma/client';
import { logAuditEvent } from 'src/common/audit/log-auth-event';
import { AuthContext } from '../interfaces/auth-context.interface';
import { AuthenticationResult } from '../interfaces/authentication-result.interface';
import { GENERIC_GOOGLE_LOGIN_RESPONSE, GOOGLE_FAILURE_REASON } from '../constants/auth.constants';
import { IdentityService } from '../identity/identity.service';
import { ExternalEmailUnverifiedError, IdentityAccountUnavailableError } from '../identity/identity.error';
import { GoogleTokenVerifier } from './google-token-verifier';
import { GoogleTokenInvalidError } from './google-token-invalid.error';
import { GoogleNonceService } from './google-nonce.service';
import { GoogleNonceInvalidError } from './google-nonce-invalid.error';

/**
 * Google as a way to prove identity: verify the token, resolve it to a user, and
 * hand back an AuthenticationResult. Creates no session — that stays with
 * AuthService.completeSignIn, shared with password login.
 */
@Injectable()
export class GoogleAuthenticatorService {
    constructor(
        private readonly verifier: GoogleTokenVerifier,
        private readonly identityService: IdentityService,
        private readonly prisma: PrismaService,
        private readonly config: ConfigService,
        private readonly nonceService: GoogleNonceService,
        private readonly logger: Logger,
    ) {}

    async authenticate(idToken: string, context: AuthContext): Promise<AuthenticationResult> {
        // The application capability. Checked here rather than in the controller so
        // every future caller is covered. 404 because a deployment without Google
        // genuinely has no such sign-in route.
        if (!this.config.getOrThrow<boolean>('auth.capabilities.google')) {
            this.logger.error({
                code: GOOGLE_FAILURE_REASON.CAPABILITY_UNAVAILABLE,
                message: 'Google sign-in is not enabled',
            });
            throw new NotFoundException();
        }

        // 1. Verify the token and get the profile
        const {profile, nonce} = await this.verifyToken(idToken, context);
        // 2. Enforce the nonce
        await this.enforceNonce(nonce, context);
        // 3. Resolve the identity and get the user id and email verified status
        const identity = await this.resolveIdentity(profile, context);

        return {
            userId: identity.userId,
            authMethod: AuthMethod.GOOGLE,
            emailVerified: identity.emailVerified,
            // Always false: that flag is about a password. A Google-only account has
            // none, so a true value would block every route while change-password
            // answered NO_PASSWORD_CREDENTIAL — an unescapable state.
            mustChangePassword: false,
        };
    }

    // Verify the token and get the profile
    private async verifyToken(idToken: string, context: AuthContext) {
        try {
            return await this.verifier.verify(idToken);
        } catch (error) {
            if (error instanceof GoogleTokenInvalidError) {
                await this.recordFailure(context, GOOGLE_FAILURE_REASON.INVALID_TOKEN);
                throw new UnauthorizedException(GENERIC_GOOGLE_LOGIN_RESPONSE);
            }
            throw error;
        }
    }

    // Resolve the identity and get the user id and email verified status
    private async resolveIdentity(profile, context: AuthContext) {
        try {
            return await this.identityService.resolveExternalIdentity(profile, context);
        } catch (error) {
            // Actionable and safe to state plainly: the caller already holds a Google
            // token for this address, so nothing is revealed that they do not know.
            if (error instanceof ExternalEmailUnverifiedError) {
                await this.recordFailure(context, GOOGLE_FAILURE_REASON.EMAIL_UNVERIFIED, profile.providerUserId);
                throw new ForbiddenException({
                    message: 'Verify this email address with Google before signing in',
                    code: 'GOOGLE_EMAIL_UNVERIFIED',
                });
            }
            // Suspended or deleted: the same generic 401 password login gives, so the
            // account's state is not disclosed.
            if (error instanceof IdentityAccountUnavailableError) {
                await this.recordFailure(context, GOOGLE_FAILURE_REASON.ACCOUNT_UNAVAILABLE, profile.providerUserId);
                throw new UnauthorizedException(GENERIC_GOOGLE_LOGIN_RESPONSE);
            }
            throw error;
        }
    }

    /**
     * Audited, never counted. The lockout counter exists to stop password guessing;
     * a failed Google sign-in is not a guess, and counting it would let anyone lock
     * an account out by replaying junk tokens.
     */
    private async recordFailure(
        context: AuthContext,
        reason: string,
        providerUserId?: string,
    ): Promise<void> {
        await logAuditEvent({
            tx: this.prisma,
            eventType: AuthEventType.LOGIN_FAILED,
            authMethod: AuthMethod.GOOGLE,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            metadata: {
                deviceId: context.deviceId,
                reason,
                provider: AuthProvider.GOOGLE,
                ...(providerUserId ? { providerUserId } : {}),
            },
        });
    }

    /**
     * Enforce the nonce by checking if it is present and valid
     */
    private async enforceNonce(nonce: string | undefined, context: AuthContext): Promise<void> {
        // A nonce that is present is always checked, whatever the flag says — otherwise
        // an attacker replaying a token could simply strip it.
        if (nonce) {
            try {
                await this.nonceService.consume(nonce, new Date());
                return;
            } catch (error) {
                if (error instanceof GoogleNonceInvalidError) {
                    await this.recordFailure(context, GOOGLE_FAILURE_REASON.NONCE_INVALID);
                    throw new UnauthorizedException(GENERIC_GOOGLE_LOGIN_RESPONSE);
                }
                throw error;
            }
        }
    
        if (this.config.getOrThrow<boolean>('auth.google.nonceRequired')) {
            await this.recordFailure(context, GOOGLE_FAILURE_REASON.NONCE_MISSING);
            throw new UnauthorizedException(GENERIC_GOOGLE_LOGIN_RESPONSE);
        }
    }
    
}

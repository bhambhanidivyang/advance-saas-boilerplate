import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    AuthEventType,
    Prisma,
    SessionRevocationReason,
    UserStatus,
    UserTokenType,
} from 'src/generated/prisma/client';
import { logAuditEvent } from 'src/common/audit/log-auth-event';
import { runUnitOfWork, UnitOfWork } from 'src/common/prisma/unit-of-work';
import { AuthContext } from '../interfaces/auth-context.interface';
import { SessionService } from '../session/session.service';
import { PasswordService } from '../password/password.service';
import { ExternalIdentityProfile, ResolvedIdentity } from './identity.interface';
import { ExternalEmailUnverifiedError, IdentityAccountUnavailableError } from './identity.error';

/**
 * Turns a verified external identity into one of our users: returning, linked, or
 * newly created.
 *
 * Provider-agnostic on purpose. It never sees an ID token or a Google claim name,
 * only an ExternalIdentityProfile, so a second provider needs no changes here.
 */
@Injectable()
export class IdentityService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly sessionService: SessionService,
        private readonly passwordService: PasswordService,
    ) {}

    // Resolve an external identity into a user
    async resolveExternalIdentity(
        profile: ExternalIdentityProfile,
        context: AuthContext,
    ): Promise<ResolvedIdentity> {
        // 1. Known identity: the provider's user id is the only thing consulted. The
        //    email is ignored, because it can change and must not re-decide identity.
        const linked = await this.findLinkedUser(profile);
        if (linked) {
            return linked;
        }

        // 2. Nothing else may be done on an email the provider has not confirmed.
        if (!profile.emailVerified) {
            throw new ExternalEmailUnverifiedError();
        }

        // 3. If the identity is not linked, create a new user or link to an existing one
        try {
            return await this.linkOrCreate(profile, context);
        } catch (error) {
            // Two first sign-ins at once: both missed step 1, both inserted, one
            // lost. The winner's row is now visible, so repeat the lookup. Same
            // principle as refresh rotation: the database decides the winner.
            if (this.isUniqueViolation(error)) {
                const afterRace = await this.findLinkedUser(profile);
                if (afterRace) {
                    return afterRace;
                }
            }
            throw error;
        }
    }

    private async findLinkedUser(
        profile: ExternalIdentityProfile,
    ): Promise<ResolvedIdentity | null> {
        // Find the identity in the database by provider and provider user id
        const identity = await this.prisma.authIdentity.findUnique({
            where: {
                provider_providerUserId: {
                    provider: profile.provider,
                    providerUserId: profile.providerUserId,
                },
            },
            select: {
                user: {
                    select: {
                        id: true,
                        status: true,
                        deletedAt: true,
                        emails: {
                            where: { isPrimary: true },
                            select: { isVerified: true },
                            take: 1,
                        },
                    },
                },
            },
        });

        // If the identity is not found, return null
        if (!identity) {
            return null;
        }

        // If the user is not active or deleted, throw an error
        this.assertUsable(identity.user);

        // Return the user id and email verified status
        return {
            userId: identity.user.id,
            emailVerified: identity.user.emails[0]?.isVerified ?? false,
        };
    }

    // Link or create a user
    private async linkOrCreate(
        profile: ExternalIdentityProfile,
        context: AuthContext,
    ): Promise<ResolvedIdentity> {
        // Run a unit of work to link or create a user
        return runUnitOfWork(this.prisma, async (uow) => {
            // Find the existing email in the database
            const existingEmail = await uow.tx.userEmail.findUnique({
                where: { email: profile.email },
                select: {
                    id: true,
                    isVerified: true,
                    user: {
                        select: { id: true, status: true, deletedAt: true, passwordHash: true },
                    },
                },
            });

            // If the email is not found, create a new user
            if (!existingEmail) {
                return this.createUser(uow, profile, context);
            }

            // If the user is not active or deleted, throw an error
            this.assertUsable(existingEmail.user);

            // If the email is found, link to the existing user
            return this.linkToExistingUser(uow, profile, existingEmail, context);
        });
    }

    // Create a user
    private async createUser(
        uow: UnitOfWork,
        profile: ExternalIdentityProfile,
        context: AuthContext,
    ): Promise<ResolvedIdentity> {
        const now = new Date();

        // 1. Create a new user
        // No passwordHash: this account has never had a password, and change-password
        // will correctly answer NO_PASSWORD_CREDENTIAL until one is set.
        const user = await uow.tx.user.create({
            data: {
                firstName: profile.firstName,
                lastName: profile.lastName,
                displayName: profile.displayName,
                emails: {
                    create: {
                        email: profile.email,
                        isPrimary: true,
                        isVerified: true,
                        verifiedAt: now,
                    },
                },
                authIdentities: {
                    create: {
                        provider: profile.provider,
                        providerUserId: profile.providerUserId,
                    },
                },
            },
            select: { id: true },
        });

        // 2. Audit the created user
        await this.auditLink(uow, user.id, profile, context, {
            newUser: true,
            emailWasUnverified: false,
            passwordRemoved: false,
            revokedSessions: 0,
        });

        return { userId: user.id, emailVerified: true };
    }

    // Link to an existing user
    private async linkToExistingUser(
        uow: UnitOfWork,
        profile: ExternalIdentityProfile,
        existingEmail: {
            id: string;
            isVerified: boolean;
            user: { id: string; passwordHash: string | null };
        },
        context: AuthContext,
    ): Promise<ResolvedIdentity> {
        const now = new Date();
        const userId = existingEmail.user.id;

        // 1. Create a new auth identity
        await uow.tx.authIdentity.create({
            data: {
                userId,
                provider: profile.provider,
                providerUserId: profile.providerUserId,
            },
        });

        let passwordRemoved = false;
        let revokedSessions = 0;

        // Pre-account hijacking: someone registered this address and never proved they
        // owned it. The provider has now proved the opposite person owns it, so
        // everything the unverified registration created must go.
        if (!existingEmail.isVerified) {
            // 3. Update the email to be verified
            await uow.tx.userEmail.update({
                where: { id: existingEmail.id },
                data: { isVerified: true, verifiedAt: now },
            });

            // 4. Update the email verification tokens to be expired
            await uow.tx.userToken.updateMany({
                where: { userId, type: UserTokenType.EMAIL_VERIFICATION, usedAt: null },
                data: { expiresAt: now },
            });

            // 5. Remove the password if it exists
            if (existingEmail.user.passwordHash) {
                await this.passwordService.removePassword(uow, userId, now);
                passwordRemoved = true;
            }

            // 6. Revoke the sessions
            const revoked = await this.sessionService.revokeSessions(
                uow,
                { userId },
                SessionRevocationReason.SECURITY,
                now,
            );
            revokedSessions = revoked.length;
        }

        // 3. Audit the linked user
        await this.auditLink(uow, userId, profile, context, {
            newUser: false,
            emailWasUnverified: !existingEmail.isVerified,
            passwordRemoved,
            revokedSessions,
        });

        // Return the user id and email verified status
        return { userId, emailVerified: true };
    }

    // Audit the linked user
    private async auditLink(
        uow: UnitOfWork,
        userId: string,
        profile: ExternalIdentityProfile,
        context: AuthContext,
        outcome: {
            newUser: boolean;
            emailWasUnverified: boolean;
            passwordRemoved: boolean;
            revokedSessions: number;
        },
    ): Promise<void> {
        await logAuditEvent({
            tx: uow.tx,
            userId,
            eventType: AuthEventType.IDENTITY_LINKED,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            metadata: {
                provider: profile.provider,
                providerUserId: profile.providerUserId,
                providerEmail: profile.email,
                deviceId: context.deviceId,
                ...outcome,
            },
        });
    }

    // If the user is not active or deleted, throw an error
    private assertUsable(user: { status: UserStatus; deletedAt: Date | null }): void {
        if (user.status !== UserStatus.ACTIVE || user.deletedAt) {
            throw new IdentityAccountUnavailableError();
        }
    }

    // If the error is a unique violation, return true
    private isUniqueViolation(error: unknown): boolean {
        return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
    }
}

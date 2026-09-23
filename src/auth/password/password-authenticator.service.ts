import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Logger } from "nestjs-pino";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthContext } from "../interfaces/auth-context.interface";
import { AuthenticationResult } from "../interfaces/authentication-result.interface";
import { normalizeEmail } from "../utils/auth.util";
import { AuthEventType, AuthMethod, Prisma, UserStatus } from "src/generated/prisma/client";
import { hashPassword, passwordNeedsRehash, verifyPassword } from "./password-hash.util";
import { randomBytes } from "node:crypto";
import { logAuditEvent } from "src/common/audit/log-auth-event";
import { GENERIC_LOGIN_RESPONSE, LOGIN_FAILURE_REASON } from "../constants/auth.constants";
import { CLEARED_LOCKOUT_STATE } from "./password-lockout.constants";
import { PasswordCredentials } from "./password.interface";

@Injectable()
export class PasswordAuthenticatorService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly config: ConfigService,
        private readonly logger: Logger
    ) {}

    async authenticate(credentials: PasswordCredentials, context: AuthContext): Promise<AuthenticationResult> {
        const { email, password } = credentials;
        const normalizedEmail = normalizeEmail(email);

        const result = await this.findPasswordAccount(normalizedEmail);

        const now = new Date();
        const user = result?.user;
        const isLocked = !!user?.passwordLockedUntil && user.passwordLockedUntil > now;

        // Decide what to verify against BEFORE verifying, so every path performs
        // exactly one argon2 comparison and costs the same wall-clock time.
        const hashToVerify =
            !user || !user.passwordHash || isLocked
                ? await this.dummyPasswordHash
                : user.passwordHash;

        const valid = await verifyPassword(
            password,
            hashToVerify,
        );

        // ---- failure paths: all indistinguishable to the caller ----

        if (!result || !user) {
            await this.recordNonCountingLoginFailure(context, LOGIN_FAILURE_REASON.USER_NOT_FOUND);
            throw new UnauthorizedException(GENERIC_LOGIN_RESPONSE);
        }

        if (!user.passwordHash) {
            // Account exists but has no password credential (e.g. OAuth-only).
            await this.recordNonCountingLoginFailure(
                context, LOGIN_FAILURE_REASON.NO_PASSWORD_CREDENTIAL, user.id,
            );
            throw new UnauthorizedException(GENERIC_LOGIN_RESPONSE);
        }

        if (isLocked) {
            await this.recordNonCountingLoginFailure(
                context, LOGIN_FAILURE_REASON.ACCOUNT_LOCKED, user.id,
            );
            throw new UnauthorizedException(GENERIC_LOGIN_RESPONSE);
        }

        if (!valid) {
            // An expired lock must clear the counter, or the next single failure
            // re-locks immediately (5 -> 6 >= 5) and the user is stuck at one
            // attempt per lock duration, forever.
            if (user.passwordLockedUntil) {
                await this.resetPasswordFailureState(user.id);
            }
            // failed-login handling
            await this.recordFailedLogin(user.id, context);
            throw new UnauthorizedException(GENERIC_LOGIN_RESPONSE);
        }

        // reset password failure state so the next failed-login sequence starts from zero
        await this.resetPasswordFailureState(user.id);
        await this.upgradePasswordHashIfNeeded(user.id, user.passwordHash, password);

        return {
            userId: user.id,
            authMethod: AuthMethod.PASSWORD,
            emailVerified: result.isVerified,
            mustChangePassword: user.mustChangePassword
        }
    }

    /** HELPER FUNCTIONS **/
    // find the active user by email
    private async findPasswordAccount(email: string) {
        return this.prisma.userEmail.findUnique({
            where: {
                email,
                user: {
                    status: UserStatus.ACTIVE,
                    // Checked explicitly rather than relying on deletion also moving
                    // status off ACTIVE. Nothing in the schema enforces that pairing,
                    // and authentication must not depend on another column being
                    // maintained correctly forever.
                    deletedAt: null,
                },
            },
            select: {
                id: true,
                userId: true,
                isVerified: true,
                user: {
                    select: {
                        id: true,
                        passwordHash: true,
                        passwordFailedAttempts: true,
                        passwordLockedUntil: true,
                        mustChangePassword: true
                    }
                }
            }
        })
    }

    /**
     * A real argon2id hash of random bytes, computed once at startup so it always
     * costs the same as a genuine verification. Verified against on every path
     * where there is no real hash, so response time never reveals whether an
     * account exists.
     */
    private readonly dummyPasswordHash: Promise<string> = hashPassword(randomBytes(32).toString('hex'));

     /**
     * Audits a login failure that must NOT advance the lockout counter — either
     * there is no account to count against, or it is already locked.
     */
     private async recordNonCountingLoginFailure(
        context: AuthContext,
        reason: string,
        userId?: string,
    ): Promise<void> {
        await logAuditEvent({
            tx: this.prisma,
            userId,
            eventType: AuthEventType.LOGIN_FAILED,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            metadata: { deviceId: context.deviceId, reason },
        });
    }

    /**
     * Login is the only moment the plaintext password is available, so it is the
     * only chance to migrate a hash to stronger parameters. Best-effort: a failure
     * here must never turn a successful login into an error.
     */
    private async upgradePasswordHashIfNeeded(
        userId: string,
        currentHash: string,
        password: string,
    ): Promise<void> {
        try {
            if (!passwordNeedsRehash(currentHash)) {
                return;
            }
            const passwordHash = await hashPassword(password);
            // Deliberately NOT touching passwordChangedAt — the user did not
            // change their password, we only re-encoded it.
            await this.prisma.user.update({ where: { id: userId }, data: { passwordHash } });
            this.logger.log({ code: 'PASSWORD_HASH_UPGRADED', userId });
        } catch (error) {
            this.logger.warn({ code: 'PASSWORD_HASH_UPGRADE_FAILED', err: error, userId });
        }
    }

    // record a failed login
    private async recordFailedLogin(
        userId: string,
        context: AuthContext,
    ): Promise<void> {
        const maxFailedAttempts = this.config.getOrThrow<number>('auth.passwordMaxFailedAttempts');
        const lockDurationSeconds = this.config.getOrThrow<number>('auth.passwordLockDurationSeconds');

        await this.prisma.$transaction(async (tx) => {
            // Atomic at the row level: concurrent failures cannot lose an increment.
            const { passwordFailedAttempts } = await tx.user.update({
                where: { id: userId },
                data: { passwordFailedAttempts: { increment: 1 } },
                select: { passwordFailedAttempts: true },
            });

            if (passwordFailedAttempts >= maxFailedAttempts) {
                await tx.user.update({
                    where: { id: userId },
                    data: {
                        passwordLockedUntil: new Date(Date.now() + lockDurationSeconds * 1000),
                    },
                });
            }

            await logAuditEvent({
                tx,
                userId,
                eventType: AuthEventType.LOGIN_FAILED,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                metadata: {
                    deviceId: context.deviceId,
                    reason: LOGIN_FAILURE_REASON.INVALID_PASSWORD,
                    attempts: passwordFailedAttempts,
                    locked: passwordFailedAttempts >= maxFailedAttempts,
                },
            });
        });
    }

    // reset password failure state so the next failed-login sequence starts from zero
    private async resetPasswordFailureState(
        userId: string,
    ): Promise<void> {
        await this.prisma.user.update({
            where: { id: userId },
            data: CLEARED_LOCKOUT_STATE,
        });
    }
}
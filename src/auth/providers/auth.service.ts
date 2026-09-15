import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateNewUser } from '../dto/create-new-user.dto';
import { normalizeEmail } from '../utils/auth.util';
import { generateRawToken, generateTokenHash } from '../utils/token.util';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, AuthMethod, Prisma, UserStatus, UserTokenType } from 'src/generated/prisma/client';
import * as argon2 from 'argon2';
import { EmailService } from 'src/email/email.service';
import { EmailJobType } from 'src/email/interfaces/email-job.interface';
import { ConfigService } from '@nestjs/config';
import { VerifyEmailParams } from '../auth.controller';
import { Logger } from 'nestjs-pino';
import { ConsumeTokenArgs, CoolDownArgs, CreateNewTokenArgs, CreateVerificationTokenArgs, EnqueueEmailArgs, ExpireActiveTokenArgs, FindAndValidateTokenArgs } from '../interfaces/token.interface';
import { CreateNewUserArgs, UpdateUserEmailArgs } from '../interfaces/user.interface';
import { GENERIC_REGISTRATION_RESPONSE, GENERIC_VERIFICATION_RESPONSE, GENERIC_LOGIN_RESPONSE, LOGIN_FAILURE_REASON } from '../constants/auth.constants';
import { AuthContext } from '../interfaces/auth-context.interface';
import { withSerializableRetry } from 'src/common/prisma/serializable-retry';
import { randomBytes } from 'crypto';
import { LoginDto } from '../dto/login.dto';
import { logAuditEvent } from 'src/common/audit/log-auth-event';
import { SessionService } from './session.service';
import { LoginResult } from '../interfaces/login.interface';
import { AuthenticationResult } from '../interfaces/authentication-result.interface';

/**
 * argon2 cost parameters, pinned rather than left to library defaults so an
 * upgrade of the argon2 package cannot silently change our security posture or
 * verification latency. These values match argon2 0.45.1's defaults, so pinning
 * them is a no-op today.
 *
 * needsRehash() compares ONLY these cost fields — it ignores `type` entirely —
 * which is why the variant is kept separate below.
 */
const PASSWORD_HASH_COSTS = {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
} as const;

const PASSWORD_HASH_OPTIONS = {
    ...PASSWORD_HASH_COSTS,
    type: argon2.argon2id,
} as const;


@Injectable()
export class AuthService {
    private readonly verificationTokenTtl: number;
    constructor(
        private readonly prisma: PrismaService,
        private readonly emailService: EmailService,
        private readonly config: ConfigService,
        private readonly logger: Logger,
        private readonly sessionService: SessionService
    ) {
         this.verificationTokenTtl = this.config.get<number>('email.verificationTokenTtl')!;
    }

    // register a new user
    async register(body: CreateNewUser) {
        const { email, password, firstName, lastName, displayName } = body;

        // Normalize email
        const normalizedEmail = normalizeEmail(email);

        // Hashing the password
        const passwordHash = await this.hashPassword(password);

        try {
            // Adding new user using transaction
            const newUser = await this.prisma.$transaction(async (tx) => {
                // find the existing active user by email
                const existingActiveUserEmail = await this.findActiveUserByEmail(tx, normalizedEmail);
                // if the existing active user by email is found, return a generic registration response
                if (existingActiveUserEmail) {
                    this.logger.log({
                        code: 'EMAIL_ALREADY_EXISTS',
                        message: 'An account with this email already exists.',
                    });
                    return { created: false as const }
                }
    
                // create a new user
                const user = await this.createNewUser({tx, firstName, lastName, displayName, passwordHash, normalizedEmail});
                // get the user's primary email
                const userEmail = user.emails[0];

                // create a new verification token
                const tokenResponse = await this.createNewToken({tx, userId: user.id, emailId: userEmail.id, type: UserTokenType.EMAIL_VERIFICATION});
                // return the user and token id
                return { created: true as const, user, tokenId: tokenResponse.token.id, rawToken: tokenResponse.rawToken };
            });

            // if the user is not created, return a generic registration response
            if (!newUser.created) {
                return {
                    success: true,
                    message: GENERIC_REGISTRATION_RESPONSE,
                };
            }

            // enqueue the verification email
            const isEmailEnqueued = await this.enqueueMail({newToken: newUser.tokenId, userId: newUser.user.id, normalizedEmail, rawToken: newUser.rawToken});

            // if the email is not enqueued, return a generic registration response
            if (!isEmailEnqueued) {
                return {
                    success: true,
                    data: { id: newUser.user.id },
                    emailStatus: 'FAILED',
                    message: 'Account created successfully, but we encountered an issue sending your verification email. Please log in to request a new link.'
                };
            }

            // return success
            return {
                success: true,
                data: {
                    id: newUser.user.id
                },
                emailStatus: 'QUEUED',
                message: 'Account created successfully. Please verify your email to continue.'
            };
        } catch (error) {
            // if the error is a known error, return a generic registration response
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
                this.logger.log({
                    code: 'EMAIL_ALREADY_EXISTS',
                    message: 'An account with this email already exists.',
                });

                return {
                    success: true,
                    message: GENERIC_REGISTRATION_RESPONSE,
                };
            }
            // if the error is not a known error, throw the error
            throw error;
        }
    }

    // login a user
    async login(body: LoginDto, context: AuthContext): Promise<LoginResult> {
        const { email, password } = body;
        const normalizedEmail = normalizeEmail(email);

        const result = await this.findActiveUserByEmail(this.prisma, normalizedEmail);

        const now = new Date();
        const user = result?.user;
        const isLocked = !!user?.passwordLockedUntil && user.passwordLockedUntil > now;

        // Decide what to verify against BEFORE verifying, so every path performs
        // exactly one argon2 comparison and costs the same wall-clock time.
        const hashToVerify =
            !user || !user.passwordHash || isLocked
                ? await this.dummyPasswordHash
                : user.passwordHash;

        const valid = await this.verifyPassword(
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

        const authentication: AuthenticationResult = {
            userId: user.id,
            authMethod: AuthMethod.PASSWORD,
            emailVerified: result.isVerified,
            mustChangePassword: user.mustChangePassword
        }

        const newSession = await this.sessionService.createSession({
            userId: authentication.userId,
            authMethod: authentication.authMethod,
            emailVerified: authentication.emailVerified,
            context,
        });

        return {
            user: {
                id: authentication.userId,
                emailVerified: authentication.emailVerified,
                mustChangePassword: authentication.mustChangePassword
            },
            session: newSession
        };
    }

    // resend a verification email
    async resendVerifyEmail(email: string) {
        // normalize email
        const normalizedEmail = normalizeEmail(email);
        
        // get mail details
        const mailDetails = await this.getMailDetails(normalizedEmail);

        // if the mail details are not found, return a generic verification response
        if (!mailDetails) {
            return {
                success: true,
                message: GENERIC_VERIFICATION_RESPONSE,
            };
        }
        
        const {id: emailId, isVerified, userId} = mailDetails;

        // is email already verified
        if (isVerified) {
            this.logger.log({
                code: 'EMAIL_ALREADY_VERIFIED',
                message: 'Email is already verified.',
            });
        
            return {
                success: true,
                message: GENERIC_VERIFICATION_RESPONSE,
            };
        }

        // create a new verification token with retry
        const transactionResult = await this.createVerificationTokenWithRetry({userId, emailId});

        // if the cooldown is active, return a generic verification response
        if (transactionResult.allowed === false) {
            this.logger.log({
                code: 'COOLDOWN_ACTIVE',
                msg: 'Cooldown is active.'
            });
            return {
                success: true,
                message: GENERIC_VERIFICATION_RESPONSE,
            };
        }

        const { token, rawToken } = transactionResult;

        // enqueue email
        const isEmailEnqueued = await this.enqueueMail({newToken: token.id, userId, normalizedEmail, rawToken});
        if (!isEmailEnqueued) {
            this.logger.error({
                code: 'VERIFICATION_EMAIL_ENQUEUE_FAILED',
                message: 'Failed to enqueue verification email.',
            });
        
            return {
                success: true,
                message: GENERIC_VERIFICATION_RESPONSE,
            };
        }
        
        // return success
        return {
            success: true,
            message: GENERIC_VERIFICATION_RESPONSE
        }
    }

    // verify a user's email
    async verifyEmail(params: VerifyEmailParams) {
        const { rawToken } = params;
        // hash raw token
        const hashedToken = generateTokenHash(rawToken);

        return await this.prisma.$transaction(async (tx) => {
            const { tokenId, userId, userEmailId } = await this.findAndValidateToken({tx, hashedToken});

            // atomically consume token
            await this.consumeToken({tx, tokenId});

            // update user email
            await this.updateUserEmail({tx, userEmailId});

            // Log the audit event
            await logAuditEvent({tx, userId, eventType: AuthEventType.EMAIL_VERIFIED, metadata: { userEmailId }});

            // return success
            return {
                message: 'Email verified successfully',
            };
        });
    }

    /** HELPER FUNCTIONS **/
    // create a new user
    private async createNewUser(args: CreateNewUserArgs) {
        const { tx, firstName, lastName, displayName, passwordHash, normalizedEmail } = args;
        return tx.user.create({
            data: {
                firstName,
                lastName,
                displayName,
                passwordHash,
                passwordChangedAt: new Date(),
                emails: {
                    create: {
                        email: normalizedEmail,
                        isPrimary: true,
                    },
                },
            },
            include: {
                emails: true,
            },
        });
    }

    // find the active user by email
    private async findActiveUserByEmail(tx: Prisma.TransactionClient, email: string) {
        return tx.userEmail.findUnique({
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

    // get mail details
    private async getMailDetails(email: string) {
        return this.prisma.userEmail.findUnique({
            select: { id: true, userId: true, isVerified: true },
            where: { email }
        });
    }

    // expire all active token associated with that mail for Email Verification
    private async expireVerificationTokenByMail(args: ExpireActiveTokenArgs) {
        const { tx, emailId, userId, type } = args;
        return tx.userToken.updateMany({
            data: {
                expiresAt: new Date()
            },
            where: {
                userId,
                type,
                metaData: {
                    path: ['userEmailId'],
                    equals: emailId,
                },
            }
        });
    }

    // create a new verification token
    private async createNewToken(args: CreateNewTokenArgs) {
        const { tx, userId, emailId, type } = args;
        // generate a raw token
        const rawToken = generateRawToken();
        // hash the raw token
        const hashedToken = generateTokenHash(rawToken);
        // create a new verification token
        const token = await tx.userToken.create({
            data: {
                userId,
                tokenHash: hashedToken,
                type,
                expiresAt: new Date(Date.now() + 1000 * 60 * 60 * this.verificationTokenTtl),
                metaData: {
                    userEmailId: emailId,
                },
            }
        });
        return { token, rawToken };
    }

    // check if the verification cooldown is active
    private async isVerificationCooldownActive(args: CoolDownArgs): Promise<boolean> {
        const { tx, userId, emailId, type } = args;
        // find the latest verification token
        const latestVerificationToken = await tx.userToken.findFirst({
            where: {
                userId,
                type,
                metaData: {
                    path: ['userEmailId'],
                    equals: emailId,
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
            select: {
                createdAt: true,
            },
        });

        // if the latest verification token is not found, return false
        if (!latestVerificationToken) {
            this.logger.log({
                code: 'LATEST_VERIFICATION_TOKEN_NOT_FOUND',
                message: 'Latest verification token not found.',
            });
    
            return false;
        }

        const createdAt = latestVerificationToken.createdAt.getTime();
        const cooldownTime = this.config.get<number>('auth.authVerificationResendCooldown')!;
        const cooldownEndsAt = createdAt + (cooldownTime * 1000);

        // if the cooldown is active, return true
        if (Date.now() < cooldownEndsAt) {
            this.logger.log({
                code: 'COOLDOWN',
                message: 'Cooldown in progress.',
            });
    
            return true;
        }
    
        // if the cooldown is not active, return false
        return false;
    }

    // create a new verification token with retry
    private async createVerificationTokenWithRetry(args: CreateVerificationTokenArgs) {
        const { userId, emailId } = args;
        return await withSerializableRetry(this.prisma, this.logger, async(tx) => 
            {
                // Cooldown check
                const isCooldownActive = await this.isVerificationCooldownActive({tx, userId, emailId, type: UserTokenType.EMAIL_VERIFICATION});
                if (isCooldownActive) {
                    return { allowed: false as const, token: null };
                }

                // expire all active token associated with that mail for Email Verification
                await this.expireVerificationTokenByMail({tx, emailId, userId, type: UserTokenType.EMAIL_VERIFICATION});

                // create a new verification token with new token hash
                const tokenResponse = await this.createNewToken({tx, userId, emailId, type: UserTokenType.EMAIL_VERIFICATION});
                return { allowed: true as const, token: tokenResponse.token, rawToken: tokenResponse.rawToken };
            },
            {logCode: 'VERIFICATION_TOKEN_CREATION_FAILED', logMessage: 'Failed to create verification token.'});
    }

    // find and validate a token
    private async findAndValidateToken(args: FindAndValidateTokenArgs) {
        const { tx, hashedToken } = args;
        // find token
        const storedToken = await tx.userToken.findUnique({
            where: {
                tokenHash: hashedToken
            },
        });

        // validate the token is not null and is of type EMAIL_VERIFICATION
        if (!storedToken || (storedToken.type !== UserTokenType.EMAIL_VERIFICATION)) {
            throw new BadRequestException('Invalid verification token');
        }

        const { id: tokenId, userId, metaData, usedAt, expiresAt } = storedToken;

        // validate the token is not used
        if (usedAt) {
            throw new BadRequestException('Verification token has already been used');
        }

        // validate the token is not expired
        if (expiresAt && expiresAt <= new Date()) {
            throw new BadRequestException('Verification token has expired');
        }

        // validate the user email metadata
        const userEmailMetadata = metaData  as { userEmailId?: string } | null;
        if (
            !userEmailMetadata ||
            typeof userEmailMetadata !== 'object' ||
            Array.isArray(userEmailMetadata) ||
            typeof userEmailMetadata.userEmailId !== 'string'
        ) {
            throw new BadRequestException('Invalid verification token');
        }
        const userEmailId = userEmailMetadata.userEmailId;
        return { tokenId, userId, userEmailId };
    }

    // consume a token
    private async consumeToken(args: ConsumeTokenArgs) {
        const { tx, tokenId } = args;
        try {
            return await tx.userToken.update({
                where: {
                    id: tokenId,
                    usedAt: null,
                },
                data: {
                    usedAt: new Date(),
                },
            });
        } catch (error) {
            // if the error is a known error, throw a bad request exception
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
                throw new BadRequestException('Verification token has already been used');
            }
            throw error; // Propagate unexpected DB errors    
        }
    }

    // update a user email
    private async updateUserEmail(args: UpdateUserEmailArgs) {
        const { tx, userEmailId } = args;
        try {
            // Safely update email record
            return tx.userEmail.update({
                where: { id: userEmailId },
                data: {
                    isVerified: true,
                    verifiedAt: new Date()
                }
            });

        } catch (error) {
            // Handle scenario where userEmailId doesn't exist in the DB
            if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
                throw new BadRequestException('Associated email record not found');
            }
            throw error; // Propagate unexpected DB errors
        }
    }

    // enqueue a verification email
    private async enqueueMail(args: EnqueueEmailArgs) {
        const { newToken, userId, normalizedEmail, rawToken } = args;
        return this.emailService.enqueue({
            type: EmailJobType.EMAIL_VERIFICATION,
            idempotencyKey: `email-verification-${newToken}`,
            userId: userId,
            to: normalizedEmail,
            data: {
                tokenId: newToken,
                rawToken,
            }
        });
    }

    // hash a password
    private async hashPassword(password: string): Promise<string> {
        return argon2.hash(password, PASSWORD_HASH_OPTIONS);
    }

    // verify a password
    private async verifyPassword(
        password: string,
        passwordHash: string,
    ): Promise<boolean> {
        return argon2.verify(passwordHash, password);
    }

    /**
     * A real argon2id hash of random bytes, computed once at startup so it always
     * costs the same as a genuine verification. Verified against on every path
     * where there is no real hash, so response time never reveals whether an
     * account exists.
     */
    private readonly dummyPasswordHash: Promise<string> = argon2.hash(
        randomBytes(32).toString('hex'),
        PASSWORD_HASH_OPTIONS
    );

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
            if (!argon2.needsRehash(currentHash, PASSWORD_HASH_COSTS)) {
                return;
            }
            const passwordHash = await this.hashPassword(password);
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
            data: {
                passwordFailedAttempts: 0,
                passwordLockedUntil: null,
            },
        });
    }
}
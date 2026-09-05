import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateNewUser } from './dto/create-new-user.dto';
import { normalizeEmail } from './utils/auth.utils';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, Prisma, UserStatus, UserTokenType } from 'src/generated/prisma/client';
import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';
import { EmailService } from 'src/email/email.service';
import { EmailJobType } from 'src/email/interfaces/email-job.interface';
import { ConfigService } from '@nestjs/config';
import { VerifyEmailParams } from './auth.controller';
import { Logger } from 'nestjs-pino';
import { CoolDownArgs, CreateNewTokenArgs, CreateVerificationTokenArgs, EnqueueEmailArgs, ExpireActiveTokenArgs } from './interfaces/resend-email.interface';
import { GENERIC_REGISTRATION_RESPONSE, GENERIC_VERIFICATION_RESPONSE } from './constants/auth.constants';

/**
 * 
 * Following is how NEXT UI for the next page of register will look like
┌──────────────────────────────────┐
│                                  │
│       Check your email           │
│                                  │
│  We sent a verification link to  │
│  d••••@gmail.com                 │
│                                  │
│  Open your email and click the   │
│  verification link to continue.  │
│                                  │
│       [ Resend email ]           │
│                                  │
│  You can resend in 28 seconds.   │
│                                  │
│  Wrong email? Change email       │
│                                  │
└──────────────────────────────────┘

 */

@Injectable()
export class AuthService {
    private readonly verificationTokenTtl: number;
    constructor(
        private readonly prisma: PrismaService,
        private readonly emailService: EmailService,
        private readonly config: ConfigService,
        private readonly logger: Logger
    ) {
         this.verificationTokenTtl = this.config.get<number>('email.verificationTokenTtl')!;
    }

    // register a new user
    async register(body: CreateNewUser) {
        const { email, password, firstName, lastName, displayName } = body;

        // Normalize email
        const normalizedEmail = normalizeEmail(email);

        // Hashing the password
        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id,
        });

        // Generate a raw token for the user
        const rawToken = randomBytes(32).toString('base64url');
        // Hash the raw token
        const tokenHash = this.generateTokenHash(rawToken);

        try {
            // Adding new user using transaction
            const newUser = await this.prisma.$transaction(async (tx) => {
                const existingActiveUserEmail = await this.findActiveUserByEmail(tx, normalizedEmail);
        
                if (existingActiveUserEmail) {
                    this.logger.log({
                        code: 'EMAIL_ALREADY_EXISTS',
                        message: 'An account with this email already exists.',
                    });
                    return { created: false as const }
                }
    
                const user = await tx.user.create({
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
                const userEmail = user.emails[0];

                const userToken = await tx.userToken.create({
                    data: {
                        userId: user.id,
                        tokenHash,
                        type: UserTokenType.EMAIL_VERIFICATION,
                        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * this.verificationTokenTtl),
                        metaData: {
                            userEmailId: userEmail.id,
                        },
                    },
                });
    
                return { created: true as const, user, tokenId: userToken.id };
            });

            if (!newUser.created) {
                return {
                    success: true,
                    message: GENERIC_REGISTRATION_RESPONSE,
                };
            }

            const isEmailEnqueued: boolean = await this.emailService.enqueue({
                type: EmailJobType.EMAIL_VERIFICATION,
                idempotencyKey: `email-verification-${newUser.tokenId}`,
                userId: newUser.user.id,
                to: normalizedEmail,
                data: {
                    tokenId: newUser.tokenId,
                    rawToken,
                },
            });

            if (!isEmailEnqueued) {
                return {
                    success: true,
                    data: { id: newUser.user.id },
                    emailStatus: 'FAILED',
                    message: 'Account created successfully, but we encountered an issue sending your verification email. Please log in to request a new link.'
                };
            }

            return {
                success: true,
                data: {
                    id: newUser.user.id
                },
                emailStatus: 'QUEUED',
                message: 'Account created successfully. Please verify your email to continue.'
            };
        } catch (error) {
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
            throw error;
        }
    }

    // login a user
    async login() {}

    // get mail details
    private async getMailDetails(email: string) {
        return this.prisma.userEmail.findUnique({
            select: { id: true, userId: true, isVerified: true },
            where: { email }
        });
    }

    // expire all active token associated with that mail for Email Verification
    private async expireVerificationTokenByMail(args: ExpireActiveTokenArgs) {
        const { tx, emailId, userId } = args;
        return tx.userToken.updateMany({
            data: {
                expiresAt: new Date()
            },
            where: {
                userId,
                type: UserTokenType.EMAIL_VERIFICATION,
                metaData: {
                    path: ['userEmailId'],
                    equals: emailId,
                },
            }
        });
    }

    // create a new verification token
    private async createNewToken(args: CreateNewTokenArgs) {
        const { tx, userId, hashedToken, emailId } = args;
        return tx.userToken.create({
            data: {
                userId: userId,
                tokenHash: hashedToken,
                type: UserTokenType.EMAIL_VERIFICATION,
                expiresAt: new Date(Date.now() + 1000 * 60 * 60 * this.verificationTokenTtl),
                metaData: {
                    userEmailId: emailId,
                },
            }
        });
    }

    // enqueue a verification email
    private async enqueueMail(args: EnqueueEmailArgs) {
        const { newToken, userId, normalizedEmail, rawToken } = args;
        return this.emailService.enqueue({
            type: EmailJobType.EMAIL_VERIFICATION,
            idempotencyKey: `email-verification-${newToken.id}`,
            userId: userId,
            to: normalizedEmail,
            data: {
                tokenId: newToken.id,
                rawToken,
            }
        });
    }

    // check if the verification cooldown is active
    private async isVerificationCooldownActive(args: CoolDownArgs): Promise<boolean> {
        const { tx, userId, emailId } = args;
        // find the latest verification token
        const latestVerificationToken = await tx.userToken.findFirst({
            where: {
                userId,
                type: UserTokenType.EMAIL_VERIFICATION,
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
        // max retries for creating a new verification token
        const maxRetries = this.config.get<number>('auth.authVerificationResendMaxRetries')!;
        // retry loop
        for (let attempt = 0; attempt < maxRetries; attempt++) {
            try {
                // create a new verification token with retry
                return await this.prisma.$transaction(async (tx) =>
                    {
                        // Cooldown check
                        const isCooldownActive = await this.isVerificationCooldownActive({tx, userId, emailId});
                        if (isCooldownActive) {
                            return { allowed: false as const, token: null };
                        }
        
                        // expire all active token associated with that mail for Email Verification
                        await this.expireVerificationTokenByMail({tx, emailId, userId});
        
                        // create a new hash
                        const rawToken = this.generateRawToken();
                        const hashedToken = this.generateTokenHash(rawToken);
        
                        // create a new verification token with new token hash
                        const token = await this.createNewToken({tx, userId, hashedToken, emailId});
                        return { allowed: true as const, token, rawToken };
                    },
                    // transaction isolation level
                    {
                        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
                    },
                );
            } catch(error) {
                // if the error is a known error and we are not at the last attempt, retry
                if (
                    error instanceof Prisma.PrismaClientKnownRequestError &&
                    error.code === 'P2034' &&
                    attempt < maxRetries - 1
                ) {
                    this.logger.warn({
                        code: 'VERIFICATION_RESEND_TRANSACTION_RETRY',
                        message: 'Retrying verification resend transaction.',
                        attempt: attempt + 1,
                    });
        
                    continue;
                }
                // if the error is not a known error or we are at the last attempt, throw the error
                throw error;
            }
            
        }
        // if we have exhausted all retries, throw an error
        throw new Error('Unreachable');
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
        const isEmailEnqueued = await this.enqueueMail({newToken: token, userId, normalizedEmail, rawToken});
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
        const hashedToken = this.generateTokenHash(rawToken);

        return await this.prisma.$transaction(async (tx) => {
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

            // validate the token is not used
            if (storedToken.usedAt) {
                throw new BadRequestException('Verification token has already been used');
            }

            // validate the token is not expired
            if (storedToken.expiresAt && storedToken.expiresAt <= new Date()) {
                throw new BadRequestException('Verification token has expired');
            }

            // validate the user email metadata
            const userEmailMetadata = storedToken.metaData  as { userEmailId?: string } | null;
            if (
                !userEmailMetadata ||
                typeof userEmailMetadata !== 'object' ||
                Array.isArray(userEmailMetadata) ||
                !('userEmailId' in userEmailMetadata) ||
                typeof userEmailMetadata.userEmailId !== 'string'
            ) {
                throw new BadRequestException('Invalid verification token');
            }

            // atomically consume token
            try {
                await tx.userToken.update({
                    where: {
                        id: storedToken.id,
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

            try {
                // Safely update email record
                await tx.userEmail.update({
                    where: { id: userEmailMetadata.userEmailId },
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

            // Log the audit event
            await tx.authEvent.create({
                data: {
                    userId: storedToken.userId,
                    eventType: AuthEventType.EMAIL_VERIFIED,
                    metadata: {
                        userEmailId: userEmailMetadata.userEmailId,
                    },
                },
            });

            return {
                message: 'Email verified successfully',
            };
        });
    }

    // find the active user by email
    private findActiveUserByEmail(tx: Prisma.TransactionClient, email: string) {
        return tx.userEmail.findUnique({
            where: {
                email,
                user: {
                    status: UserStatus.ACTIVE
                },
            },
        })
    }

    // generate a raw token
    private generateRawToken() {
        return randomBytes(32).toString('base64url');
    }

    // generate a token hash
    private generateTokenHash(rawToken: string) {
        return createHash('sha256').update(rawToken).digest('hex')
    }
}
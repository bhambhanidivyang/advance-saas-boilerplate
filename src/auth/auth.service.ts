import { ConflictException, Injectable } from '@nestjs/common';
import { CreateNewUser } from './dto/create-new-user.dto';
import { normalizeEmail } from './utils/auth.utils';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, UserStatus, UserTokenType } from 'src/generated/prisma/client';
import * as argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';
import { EmailService } from 'src/email/email.service';
import { EmailJobType } from 'src/email/interfaces/email-job.interface';
import { ConfigService } from '@nestjs/config';

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
    constructor(
        private readonly prisma: PrismaService,
        private readonly emailService: EmailService,
        private readonly config: ConfigService
    ) {}
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
        const tokenHash = createHash('sha256').update(rawToken).digest('hex');

        try {
            // Adding new user using transaction
            const newUser = await this.prisma.$transaction(async (tx) => {
                const existingActiveUserEmail = await this.findActiveUserByEmail(tx, normalizedEmail);
        
                if (existingActiveUserEmail) {
                    throw new ConflictException({
                        code: 'EMAIL_ALREADY_EXISTS',
                        message: 'An account with this email already exists.',
                    });
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
                });

                const verification_token_ttl: number = this.config.get<number>('email.verificationTokenTtl')!;
    
                const userToken = await tx.userToken.create({
                    data: {
                        userId: user.id,
                        tokenHash,
                        type: UserTokenType.EMAIL_VERIFICATION,
                        expiresAt: new Date(Date.now() + 1000 * 60 * 60 * verification_token_ttl),
                    },
                });
    
                return { user, tokenId: userToken.id };
            });            

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
                throw new ConflictException({
                    code: 'EMAIL_ALREADY_EXISTS',
                    message: 'An account with this email already exists.',
                });
            }
            throw error;
        }
    }

    async login() {}

    async verifyEmail(rawToken: string) {
        // hash raw token
        // find token
        // validate
        // atomically consume token
        // mark email verified
    }

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
}
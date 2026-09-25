import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from 'src/prisma/prisma.service';
import {
    AuthEventType,
    AuthProvider,
    Prisma,
    SessionRevocationReason,
    UserStatus,
} from 'src/generated/prisma/client';
import { IdentityService } from './identity.service';
import { SessionService } from '../session/session.service';
import { PasswordService } from '../password/password.service';
import { ExternalIdentityProfile } from './identity.interface';
import { ExternalEmailUnverifiedError, IdentityAccountUnavailableError } from './identity.error';
import { AuthContext } from '../interfaces/auth-context.interface';

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

/** A linked AuthIdentity row as findLinkedUser selects it. */
function identityRow(overrides: { status?: UserStatus; deletedAt?: Date | null; isVerified?: boolean } = {}) {
    return {
        user: {
            id: 'user-1',
            status: overrides.status ?? UserStatus.ACTIVE,
            deletedAt: overrides.deletedAt ?? null,
            emails: [{ isVerified: overrides.isVerified ?? true }],
        },
    };
}

/** A UserEmail row as linkOrCreate selects it. */
function emailRow(overrides: {
    isVerified?: boolean;
    passwordHash?: string | null;
    status?: UserStatus;
    deletedAt?: Date | null;
} = {}) {
    return {
        id: 'email-1',
        isVerified: overrides.isVerified ?? true,
        user: {
            id: 'user-1',
            status: overrides.status ?? UserStatus.ACTIVE,
            deletedAt: overrides.deletedAt ?? null,
            passwordHash: overrides.passwordHash ?? null,
        },
    };
}

function uniqueViolation(target: string) {
    return new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
        code: 'P2002',
        clientVersion: 'test',
        meta: { target },
    });
}

/** The metadata of the single IDENTITY_LINKED event written during a call. */
function auditedMetadata(tx: { authEvent: { create: jest.Mock } }) {
    const linked = tx.authEvent.create.mock.calls.find(
        ([arg]) => arg.data.eventType === AuthEventType.IDENTITY_LINKED,
    );
    return linked?.[0].data.metadata;
}

describe('IdentityService', () => {
    let service: IdentityService;
    let prisma: {
        authIdentity: { findUnique: jest.Mock };
        $transaction: jest.Mock;
    };
    let tx: {
        userEmail: { findUnique: jest.Mock; update: jest.Mock };
        user: { create: jest.Mock; update: jest.Mock };
        authIdentity: { create: jest.Mock };
        userToken: { updateMany: jest.Mock };
        authEvent: { create: jest.Mock };
    };
    let sessionService: { revokeSessions: jest.Mock };
    let passwordService: { removePassword: jest.Mock };

    beforeEach(async () => {
        jest.clearAllMocks();

        tx = {
            userEmail: { findUnique: jest.fn(), update: jest.fn() },
            user: { create: jest.fn().mockResolvedValue({ id: 'new-user-1' }), update: jest.fn() },
            authIdentity: { create: jest.fn() },
            userToken: { updateMany: jest.fn() },
            authEvent: { create: jest.fn() },
        };

        prisma = {
            authIdentity: { findUnique: jest.fn().mockResolvedValue(null) },
            $transaction: jest.fn(async (cb: (client: typeof tx) => unknown) => cb(tx)),
        };

        sessionService = { revokeSessions: jest.fn().mockResolvedValue([]) };
        passwordService = { removePassword: jest.fn() };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                IdentityService,
                { provide: PrismaService, useValue: prisma },
                { provide: SessionService, useValue: sessionService },
                { provide: PasswordService, useValue: passwordService },
            ],
        }).compile();

        service = module.get(IdentityService);
    });

    describe('a returning user', () => {
        it('resolves by the provider user id and opens no transaction', async () => {
            prisma.authIdentity.findUnique.mockResolvedValue(identityRow());

            await expect(service.resolveExternalIdentity(profile, context)).resolves.toEqual({
                userId: 'user-1',
                emailVerified: true,
            });

            expect(prisma.authIdentity.findUnique).toHaveBeenCalledWith(
                expect.objectContaining({
                    where: {
                        provider_providerUserId: {
                            provider: AuthProvider.GOOGLE,
                            providerUserId: 'google-sub-1',
                        },
                    },
                }),
            );
            expect(prisma.$transaction).not.toHaveBeenCalled();
        });

        // The provider's email may have changed since linking; identity is the `sub`.
        it('ignores a changed provider email', async () => {
            prisma.authIdentity.findUnique.mockResolvedValue(identityRow());

            await expect(
                service.resolveExternalIdentity({ ...profile, email: 'moved@example.com' }, context),
            ).resolves.toEqual({ userId: 'user-1', emailVerified: true });

            expect(tx.userEmail.findUnique).not.toHaveBeenCalled();
        });

        it('reports the primary email verification state as stored', async () => {
            prisma.authIdentity.findUnique.mockResolvedValue(identityRow({ isVerified: false }));

            await expect(service.resolveExternalIdentity(profile, context)).resolves.toMatchObject({
                emailVerified: false,
            });
        });

        it.each([
            ['suspended', { status: UserStatus.SUSPENDED }],
            ['deleted', { deletedAt: new Date() }],
        ])('refuses a %s account', async (_label, overrides) => {
            prisma.authIdentity.findUnique.mockResolvedValue(identityRow(overrides));

            await expect(service.resolveExternalIdentity(profile, context)).rejects.toBeInstanceOf(
                IdentityAccountUnavailableError,
            );
        });
    });

    describe('an unverified provider email', () => {
        it('is refused, and nothing is written', async () => {
            await expect(
                service.resolveExternalIdentity({ ...profile, emailVerified: false }, context),
            ).rejects.toBeInstanceOf(ExternalEmailUnverifiedError);

            expect(prisma.$transaction).not.toHaveBeenCalled();
        });

        // A linked identity is proof enough on its own; the email is not consulted.
        it('still signs in a user whose identity is already linked', async () => {
            prisma.authIdentity.findUnique.mockResolvedValue(identityRow());

            await expect(
                service.resolveExternalIdentity({ ...profile, emailVerified: false }, context),
            ).resolves.toMatchObject({ userId: 'user-1' });
        });
    });

    describe('a new account', () => {
        beforeEach(() => {
            tx.userEmail.findUnique.mockResolvedValue(null);
        });

        it('creates the user, a verified primary email and the identity together', async () => {
            await expect(service.resolveExternalIdentity(profile, context)).resolves.toEqual({
                userId: 'new-user-1',
                emailVerified: true,
            });

            expect(tx.user.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: expect.objectContaining({
                        firstName: 'Divyang',
                        lastName: 'Bhambhani',
                        displayName: 'Divyang Bhambhani',
                        emails: {
                            create: expect.objectContaining({
                                email: 'divyang@example.com',
                                isPrimary: true,
                                isVerified: true,
                            }),
                        },
                        authIdentities: {
                            create: {
                                provider: AuthProvider.GOOGLE,
                                providerUserId: 'google-sub-1',
                            },
                        },
                    }),
                }),
            );
        });

        // An account that has never had a password must not carry a hash, so that
        // change-password correctly answers NO_PASSWORD_CREDENTIAL.
        it('sets no password hash', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(tx.user.create.mock.calls[0][0].data).not.toHaveProperty('passwordHash');
        });

        it('records one IDENTITY_LINKED event marking a new user', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(auditedMetadata(tx)).toMatchObject({
                provider: AuthProvider.GOOGLE,
                providerUserId: 'google-sub-1',
                providerEmail: 'divyang@example.com',
                newUser: true,
                emailWasUnverified: false,
                passwordRemoved: false,
                revokedSessions: 0,
            });
        });

        it('touches neither passwords nor sessions', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(passwordService.removePassword).not.toHaveBeenCalled();
            expect(sessionService.revokeSessions).not.toHaveBeenCalled();
        });
    });

    describe('an existing account whose email is verified', () => {
        beforeEach(() => {
            tx.userEmail.findUnique.mockResolvedValue(emailRow({ passwordHash: '$argon2id$hash' }));
        });

        // Both sides have confirmed the same address, so linking is safe and the
        // existing password stays usable.
        it('links the identity and leaves the credential alone', async () => {
            await expect(service.resolveExternalIdentity(profile, context)).resolves.toEqual({
                userId: 'user-1',
                emailVerified: true,
            });

            expect(tx.authIdentity.create).toHaveBeenCalledWith({
                data: {
                    userId: 'user-1',
                    provider: AuthProvider.GOOGLE,
                    providerUserId: 'google-sub-1',
                },
            });
            expect(passwordService.removePassword).not.toHaveBeenCalled();
            expect(sessionService.revokeSessions).not.toHaveBeenCalled();
            expect(tx.userEmail.update).not.toHaveBeenCalled();
        });

        it('records the link as an existing user', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(auditedMetadata(tx)).toMatchObject({
                newUser: false,
                emailWasUnverified: false,
                passwordRemoved: false,
                revokedSessions: 0,
            });
        });

        it.each([
            ['suspended', { status: UserStatus.SUSPENDED }],
            ['deleted', { deletedAt: new Date() }],
        ])('refuses to link to a %s account', async (_label, overrides) => {
            tx.userEmail.findUnique.mockResolvedValue(emailRow(overrides));

            await expect(service.resolveExternalIdentity(profile, context)).rejects.toBeInstanceOf(
                IdentityAccountUnavailableError,
            );

            expect(tx.authIdentity.create).not.toHaveBeenCalled();
        });
    });

    // Pre-account hijacking: someone registered this address and never proved they
    // owned it. Google has now proved the other person owns it, so everything that
    // unverified registration created has to go.
    describe('an existing account whose email was never verified', () => {
        beforeEach(() => {
            tx.userEmail.findUnique.mockResolvedValue(
                emailRow({ isVerified: false, passwordHash: '$argon2id$squatter' }),
            );
            sessionService.revokeSessions.mockResolvedValue(['session-1', 'session-2']);
        });

        it('links the identity and marks the email verified', async () => {
            await expect(service.resolveExternalIdentity(profile, context)).resolves.toEqual({
                userId: 'user-1',
                emailVerified: true,
            });

            expect(tx.authIdentity.create).toHaveBeenCalled();
            expect(tx.userEmail.update).toHaveBeenCalledWith(
                expect.objectContaining({
                    where: { id: 'email-1' },
                    data: expect.objectContaining({ isVerified: true }),
                }),
            );
        });

        it('removes the password that was never proven to belong to anyone', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(passwordService.removePassword).toHaveBeenCalledTimes(1);
            expect(passwordService.removePassword).toHaveBeenCalledWith(
                expect.objectContaining({ tx }),
                'user-1',
                expect.any(Date),
            );
        });

        it('revokes every session of that account for a security reason', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(sessionService.revokeSessions).toHaveBeenCalledWith(
                expect.objectContaining({ tx }),
                { userId: 'user-1' },
                SessionRevocationReason.SECURITY,
                expect.any(Date),
            );
        });

        it('expires the pending verification tokens the squatter could still use', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(tx.userToken.updateMany).toHaveBeenCalledWith(
                expect.objectContaining({
                    where: expect.objectContaining({ userId: 'user-1', usedAt: null }),
                }),
            );
        });

        // Everything above runs in the caller's transaction, so a failure anywhere
        // leaves none of it applied.
        it('does all of it in one transaction', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(prisma.$transaction).toHaveBeenCalledTimes(1);
        });

        it('records what was done, for the incident trail', async () => {
            await service.resolveExternalIdentity(profile, context);

            expect(auditedMetadata(tx)).toMatchObject({
                newUser: false,
                emailWasUnverified: true,
                passwordRemoved: true,
                revokedSessions: 2,
            });
        });

        it('skips the password removal when the account never had one', async () => {
            tx.userEmail.findUnique.mockResolvedValue(
                emailRow({ isVerified: false, passwordHash: null }),
            );

            await service.resolveExternalIdentity(profile, context);

            expect(passwordService.removePassword).not.toHaveBeenCalled();
            expect(sessionService.revokeSessions).toHaveBeenCalled();
            expect(auditedMetadata(tx)).toMatchObject({ passwordRemoved: false });
        });
    });

    describe('two first sign-ins at once', () => {
        it('returns the winner rather than failing the loser', async () => {
            tx.userEmail.findUnique.mockResolvedValue(null);
            tx.user.create.mockRejectedValue(uniqueViolation('AuthIdentity_provider_providerUserId_key'));
            // The winning transaction has committed by the time the loser retries.
            prisma.authIdentity.findUnique
                .mockResolvedValueOnce(null)
                .mockResolvedValueOnce(identityRow());

            await expect(service.resolveExternalIdentity(profile, context)).resolves.toEqual({
                userId: 'user-1',
                emailVerified: true,
            });

            expect(prisma.authIdentity.findUnique).toHaveBeenCalledTimes(2);
        });

        it('rethrows when the conflict was not this identity', async () => {
            tx.userEmail.findUnique.mockResolvedValue(null);
            tx.user.create.mockRejectedValue(uniqueViolation('UserEmail_email_key'));
            prisma.authIdentity.findUnique.mockResolvedValue(null);

            await expect(service.resolveExternalIdentity(profile, context)).rejects.toBeInstanceOf(
                Prisma.PrismaClientKnownRequestError,
            );
        });

        it('does not retry on an unrelated failure', async () => {
            tx.userEmail.findUnique.mockResolvedValue(null);
            tx.user.create.mockRejectedValue(new Error('connection lost'));

            await expect(service.resolveExternalIdentity(profile, context)).rejects.toThrow(
                'connection lost',
            );

            expect(prisma.authIdentity.findUnique).toHaveBeenCalledTimes(1);
        });
    });
});

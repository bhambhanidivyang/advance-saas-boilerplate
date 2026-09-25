import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client } from 'google-auth-library';
import { AuthProvider } from 'src/generated/prisma/client';
import { GoogleTokenVerifier as GoogleTokenVerifier } from './google-token-verifier';
import { GoogleTokenInvalidError } from './google-token-invalid.error';

const verifyIdTokenMock = jest.fn();

jest.mock('google-auth-library', () => ({
    OAuth2Client: jest.fn().mockImplementation(() => ({ verifyIdToken: verifyIdTokenMock })),
}));

const CLIENT_IDS = ['111-web.apps.googleusercontent.com', '222-ios.apps.googleusercontent.com'];

function googlePayload(overrides: Record<string, unknown> = {}) {
    return {
        sub: '102255932280773743268',
        email: 'Divyang@Example.com',
        email_verified: true,
        given_name: 'Divyang',
        family_name: 'Bhambhani',
        name: 'Divyang Bhambhani',
        ...overrides,
    };
}

/** Makes verifyIdToken resolve with a ticket whose payload is `payload`. */
function resolvesWith(payload: unknown) {
    verifyIdTokenMock.mockResolvedValue({ getPayload: () => payload });
}

describe('GoogleTokenVerifier', () => {
    let verifier: GoogleTokenVerifier;

    beforeEach(async () => {
        jest.clearAllMocks();

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                GoogleTokenVerifier,
                {
                    provide: ConfigService,
                    useValue: {
                        getOrThrow: jest.fn((key: string) => {
                            if (key === 'auth.google.clientIds') return CLIENT_IDS;
                            throw new Error(`Unexpected key ${key}`);
                        }),
                    },
                },
            ],
        }).compile();

        verifier = module.get(GoogleTokenVerifier);
    });

    // Without the audience, a token minted for any other Google app would be accepted.
    it('verifies against every configured client id', async () => {
        resolvesWith(googlePayload());

        await verifier.verify('id-token');

        expect(verifyIdTokenMock).toHaveBeenCalledWith({
            idToken: 'id-token',
            audience: CLIENT_IDS,
        });
    });

    it('maps the Google claims onto a normalised profile', async () => {
        resolvesWith(googlePayload());

        await expect(verifier.verify('id-token')).resolves.toEqual({
            profile: {
                provider: AuthProvider.GOOGLE,
                providerUserId: '102255932280773743268',
                email: 'divyang@example.com',
                emailVerified: true,
                firstName: 'Divyang',
                lastName: 'Bhambhani',
                displayName: 'Divyang Bhambhani',
            },
            nonce: undefined,
        });
    });

    it('reports an unverified Google email instead of rejecting it', async () => {
        resolvesWith(googlePayload({ email_verified: false }));

        await expect(verifier.verify('id-token')).resolves.toMatchObject({
            profile: { emailVerified: false },
        });
    });

    it.each([
        ['the first word of name', { given_name: undefined }, 'Divyang'],
        ['the email local part', { given_name: undefined, name: undefined, email: 'Solo@Example.com' }, 'Solo'],
    ])('falls back to %s for the first name', async (_label, overrides, expected) => {
        resolvesWith(googlePayload(overrides));

        await expect(verifier.verify('id-token')).resolves.toMatchObject({
            profile: { firstName: expected },
        });
    });

    it('rejects a token Google refuses', async () => {
        verifyIdTokenMock.mockRejectedValue(new Error('Wrong recipient'));

        await expect(verifier.verify('id-token')).rejects.toBeInstanceOf(GoogleTokenInvalidError);
    });

    it.each([
        ['no payload', undefined],
        ['no subject', googlePayload({ sub: undefined })],
        ['no email', googlePayload({ email: undefined })],
    ])('rejects a token with %s', async (_label, payload) => {
        resolvesWith(payload);

        await expect(verifier.verify('id-token')).rejects.toBeInstanceOf(GoogleTokenInvalidError);
    });

    // The nonce belongs to the token, not to the person, so it is returned beside the
    // profile rather than on it. GoogleAuthenticatorService decides what to do with it.
    it('returns the nonce claim when the client bound one', async () => {
        resolvesWith(googlePayload({ nonce: 'client-nonce' }));

        await expect(verifier.verify('id-token')).resolves.toMatchObject({ nonce: 'client-nonce' });
    });

    it('returns no nonce when the token carries none', async () => {
        resolvesWith(googlePayload());

        const verified = await verifier.verify('id-token');

        expect(verified.nonce).toBeUndefined();
    });

    it('keeps the nonce off the identity profile', async () => {
        resolvesWith(googlePayload({ nonce: 'client-nonce' }));

        const verified = await verifier.verify('id-token');

        expect(verified.profile).not.toHaveProperty('nonce');
    });
});

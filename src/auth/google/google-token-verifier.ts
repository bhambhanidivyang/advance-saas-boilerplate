import { Injectable } from "@nestjs/common";
import { ExternalIdentityProfile, VerifiedExternalToken } from "../identity/identity.interface";
import { ConfigService } from "@nestjs/config";
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { AuthProvider } from "src/generated/prisma/enums";
import { normalizeEmail } from "../utils/auth.util";
import { GoogleTokenInvalidError } from "./google-token-invalid.error";

// IdentityService must never know Google's claim names. 
// When Microsoft or GitHub sign-in arrives, 
// it produces the same shape and IdentityService doesn't change.
// Translating one provider's vocabulary into ours is the verifier's whole job.
@Injectable()
export class GoogleTokenVerifier {
    private client = new OAuth2Client();
    private clientIds: string[];

    constructor(private readonly config: ConfigService) {
        this.clientIds = this.config.getOrThrow<string[]>('auth.google.clientIds');
    }

    async verify(idToken: string): Promise<VerifiedExternalToken> {
        let payload: TokenPayload | undefined;

        try {
            // `audience` is the security-critical argument. Without it we would accept
            // any token Google ever issued, including one minted for an attacker's own
            // application, which is account takeover by token substitution.
            const ticket = await this.client.verifyIdToken({
                idToken,
                audience: this.clientIds,
            });
            // getPayload() returns the payload of the token as a TokenPayload object
            payload = ticket.getPayload();
        } catch (error) {
            throw new GoogleTokenInvalidError('Google rejected the ID token', { cause: error });
        }

        if (!payload) {
            throw new GoogleTokenInvalidError('Google ID token carried no payload');
        }
        if (!payload.sub) {
            throw new GoogleTokenInvalidError('Google ID token has no subject');
        }
        if (!payload.email) {
            throw new GoogleTokenInvalidError('Google ID token has no email');
        }

        return {
            profile: {
                provider: AuthProvider.GOOGLE,
                providerUserId: payload.sub,
                email: normalizeEmail(payload.email),
                // Passed through, never enforced here: whether an unverified address may be
                // linked to an account is a policy question, and IdentityService owns it.
                emailVerified: payload.email_verified === true,
                firstName: this.resolveFirstName(payload),
                lastName: payload.family_name,
                displayName: payload.name,
            },
            nonce: payload.nonce,
        };
    }

    /**
     * `User.firstName` is required by our schema, but Google does not guarantee
     * `given_name` — some Workspace accounts send only `name`. Falling back keeps a
     * real sign-in from failing on a database constraint.
     */
    private resolveFirstName(payload: TokenPayload): string {
        return (
            payload.given_name?.trim() ||
            payload.name?.trim().split(/\s+/)[0] ||
            payload.email!.split('@')[0]
        );
    }
}
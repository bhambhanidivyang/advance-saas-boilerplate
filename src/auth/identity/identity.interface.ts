import { AuthProvider } from "src/generated/prisma/enums";

/**
 * A verified identity from an external provider, in our vocabulary rather than
 * theirs. Every provider's verifier produces this shape, so IdentityService never
 * learns what Google calls its claims.
 */
export interface ExternalIdentityProfile {
    provider: AuthProvider;
    /** The provider's permanent user id. Google's `sub`. Never the email. */
    providerUserId: string;
    /** Normalised. Whether it may be trusted is `emailVerified`, decided by the caller. */
    email: string;
    emailVerified: boolean;
    firstName: string;
    lastName?: string;
    displayName?: string;
}

export interface ResolvedIdentity {
    userId: string;
    emailVerified: boolean;
}

export interface VerifiedExternalToken {
    profile: ExternalIdentityProfile;
    /** Present only when the client asked Google to bind one. */
    nonce?: string;
}
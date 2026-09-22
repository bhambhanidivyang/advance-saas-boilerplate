import { AuthMethod } from 'src/generated/prisma/client';

export interface MintAccessTokenArgs {
    userId: string;
    sessionId: string;
    tokenFamilyId: string;
    emailVerified: boolean;
    mustChangePassword: boolean;
    authMethod: AuthMethod;
}

/** Claim names are kept short — this token rides on every request. */
export interface AccessTokenClaims {
    sub: string;        // userId
    sid: string;        // sessionId
    fam: string;        // tokenFamilyId, for correlating a rotation chain
    ev: boolean;        // emailVerified
    mcp: boolean;       // mustChangePassword
    amr: AuthMethod[];  // authentication methods used
    jti: string;        // jti is a unique identifier for the token
    iss: string;        // Issuer
    aud: string;        // Audience
    iat: number;        // Issued At
    exp: number;        // Expiration Time
}
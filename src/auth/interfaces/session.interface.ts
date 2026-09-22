import { AuthMethod } from "src/generated/prisma/enums";
import { AuthContext } from "./auth-context.interface";

export interface CreateSessionArgs {
    userId: string;
    authMethod: AuthMethod;
    emailVerified: boolean;
    mustChangePassword: boolean;
    context: AuthContext;
}

export interface IssuedSession {
    sessionId: string;
    tokenFamilyId: string;
    accessToken: string;
    expiresIn: number;
    refreshToken: string;
    refreshTokenExpiresAt: Date;
}
/**
 * Outcome of a rotation attempt. The transaction RETURNS one of these rather than
 * throwing, because the failure paths have writes that must still commit (the
 * lazy expiry sweep, the family revocation). Throwing inside the transaction
 * would roll those writes back and leave a stolen token working.
 */
export type RotationOutcome =
    | {
          kind: 'ROTATED';
          userId: string;
          sessionId: string;
          tokenFamilyId: string;
          authMethod: AuthMethod;
          emailVerified: boolean;
          mustChangePassword: boolean;
          refreshToken: string;
          refreshTokenExpiresAt: Date;
          graceReplay: boolean;
      }
    | { kind: 'REJECTED'; reason: string };

/** Revokes every active session for a user (logout everywhere). */
export interface RevokeAllSessionsArgs {
    userId: string;
    context: AuthContext;
    /** The session that asked; recorded on the audit event. */
    initiatingSessionId?: string;
}

export interface LogoutResponse {
    success: true;
    revokedSessions?: number;
}

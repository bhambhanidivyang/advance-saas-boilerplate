import { AuthEventType, AuthMethod, SessionRevocationReason } from "src/generated/prisma/enums";
import { AuthContext } from "./auth-context.interface";

export interface CreateSessionArgs {
    userId: string;
    authMethod: AuthMethod;
    emailVerified: boolean;
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
          refreshToken: string;
          refreshTokenExpiresAt: Date;
          graceReplay: boolean;
      }
    | {
          kind: 'REJECTED';
          reason: string;
          /** Sessions revoked by the theft path, to be denylisted after commit. */
          revokedSessionIds?: string[];
      };

/**
 * Bulk session revocation. The reason and event type are parameters because the
 * same operation serves several account-level actions (logout everywhere, a
 * password change, an admin action), and `exceptSessionId` exists so a password
 * change does not log the user out of the tab they just used.
 */
export interface RevokeAllSessionsArgs {
    userId: string;
    context: AuthContext;
    /** Recorded on the audit event; also the session kept when exceptSessionId is set. */
    initiatingSessionId?: string;
    reason?: SessionRevocationReason;
    eventType?: AuthEventType;
    /** Left active. Typically the caller's own session. */
    exceptSessionId?: string;
}

export interface LogoutResponse {
    success: true;
    revokedSessions?: number;
}

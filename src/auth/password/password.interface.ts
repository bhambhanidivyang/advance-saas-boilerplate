import { AuthContext } from "../interfaces/auth-context.interface";

export interface ChangePasswordArgs {
    userId: string;
    /** From the verified access token: the session the caller is using right now. */
    sessionId: string;
    currentPassword: string;
    newPassword: string;
    context: AuthContext;
}

export interface ChangePasswordResult {
    /** Replacement for the caller's own refresh token. Goes in the cookie only. */
    refreshToken: string;
    refreshTokenExpiresAt: Date;
    revokedSessions: number;
}

export interface ChangePasswordResponse {
    success: true;
    revokedSessions: number;
}

export interface PasswordCredentials {
    email: string;
    password: string;
}

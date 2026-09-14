import { IssuedSession } from "./session.interface";

export interface LoginResult {
    session: IssuedSession;
    user: LoginUser;
}

export interface LoginUser {
    id: string;
    emailVerified: boolean;
    mustChangePassword: boolean;
}

export interface LoginResponse {
    accessToken: string;
    expiresIn: number;
    tokenType: 'Bearer';
    user: LoginUser;
}
export interface RefreshResponse {
    accessToken: string;
    expiresIn: number;
    tokenType: 'Bearer';
}

import type { Request } from 'express';
import { AuthMethod } from 'src/generated/prisma/client';

export interface AuthenticatedUser {
    userId: string;
    sessionId: string;
    tokenFamilyId: string;
    emailVerified: boolean;
    mustChangePassword: boolean;
    authMethod: AuthMethod;
}

export interface RequestWithUser extends Request {
    user?: AuthenticatedUser;
}

export interface AuthenticatedRequest extends Request {
    user: AuthenticatedUser;
}
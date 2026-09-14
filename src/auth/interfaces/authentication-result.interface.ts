import { AuthMethod } from "src/generated/prisma/enums";

export interface AuthenticationResult {
    userId: string;
    authMethod: AuthMethod;
    emailVerified: boolean;
    mustChangePassword: boolean;
}

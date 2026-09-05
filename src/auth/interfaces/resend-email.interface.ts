import { Prisma } from "@prisma/client/extension";
import { UserToken } from "src/generated/prisma/client";

export interface ExpireActiveTokenArgs {
    tx: Prisma.TransactionClient;
    emailId: string;
    userId: string;
}

export interface CreateNewTokenArgs {
    tx: Prisma.TransactionClient;
    userId: string;
    hashedToken: string;
    emailId: string;
}

export interface EnqueueEmailArgs {
    newToken: UserToken;
    userId: string;
    normalizedEmail: string;
    rawToken: string;
}

export interface CoolDownArgs {
    tx: Prisma.TransactionClient;
    userId: string;
    emailId: string;
}

export interface CreateVerificationTokenArgs {
    userId: string;
    emailId: string;
}
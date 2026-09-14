import { Prisma, UserTokenType } from "src/generated/prisma/client";

export interface ExpireActiveTokenArgs {
    tx: Prisma.TransactionClient;
    emailId: string;
    userId: string;
    type: UserTokenType;
}

export interface CreateNewTokenArgs {
    tx: Prisma.TransactionClient;
    userId: string;
    emailId: string;
    type: UserTokenType;
}

export interface CoolDownArgs {
    tx: Prisma.TransactionClient;
    userId: string;
    emailId: string;
    type: UserTokenType;
}

export interface CreateVerificationTokenArgs {
    userId: string;
    emailId: string;
}

export interface FindAndValidateTokenArgs {
    tx: Prisma.TransactionClient;
    hashedToken: string;
}

export interface ConsumeTokenArgs {
    tx: Prisma.TransactionClient;
    tokenId: string;
}

export interface EnqueueEmailArgs {
    newToken: string;
    userId: string;
    normalizedEmail: string;
    rawToken: string;
}
import { Prisma } from "src/generated/prisma/client";

export interface CreateNewUserArgs {
    tx: Prisma.TransactionClient;
    firstName: string;
    lastName: string;
    displayName: string;
    passwordHash: string;
    normalizedEmail: string;
}

export interface UpdateUserEmailArgs {
    tx: Prisma.TransactionClient;
    userEmailId: string;
}
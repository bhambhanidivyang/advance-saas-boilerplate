import { Prisma, AuthEventType, AuthMethod } from "src/generated/prisma/client";

export interface LogAuditEventArgs {
    tx: Prisma.TransactionClient;
    userId?: string;
    eventType: AuthEventType;
    metadata: Record<string, any>;
    sessionId?: string;
    authMethod?: AuthMethod;
    ipAddress?: string;
    userAgent?: string;
}
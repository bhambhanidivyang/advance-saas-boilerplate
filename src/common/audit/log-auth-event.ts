import { LogAuditEventArgs } from "src/auth/interfaces/audit.interface";
import { normalizeIpAddress } from "../utils/ip.util";

// log an audit event
export async function logAuditEvent(args: LogAuditEventArgs) {
    const { tx, userId, eventType, metadata, sessionId, authMethod, ipAddress, userAgent } = args;
    return tx.authEvent.create({
        data: {
            userId,
            eventType,
            metadata,
            sessionId,
            authMethod,
            // The controller already sanitizes, but this makes the service safe on
            // its own: a bad value here raises Postgres 22P02 and rolls back the
            // entire transaction, silently losing whatever else it was writing.
            ipAddress: normalizeIpAddress(ipAddress),
            userAgent,
        },
    });
}
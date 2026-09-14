import type { Request } from 'express';
import { normalizeIpAddress } from 'src/common/utils/ip.util';
import { AuthContext } from '../interfaces/auth-context.interface';

// Normalize email to lowercase
export function normalizeEmail (email: string): string {
    return email.toLowerCase();
}

function clamp(value: string | undefined, maxLength: number): string | undefined {
    const trimmed = value?.trim();
    return trimmed ? trimmed.slice(0, maxLength) : undefined;
}

/**
 * Builds an AuthContext from a request, sanitizing every client-controlled value
 * at the boundary so no downstream writer has to remember to.
 */
export function buildAuthContext(req: Request): AuthContext {
    return {
        ipAddress: normalizeIpAddress(req.ip) ?? undefined,
        userAgent: clamp(req.get('user-agent'), (Number(process.env.MAX_USER_AGENT_LENGTH) || 1000)),
        deviceId: clamp(req.get('device-id'), (Number(process.env.MAX_DEVICE_ID_LENGTH) || 255)),
    };
}

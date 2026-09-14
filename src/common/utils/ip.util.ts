import { isIP } from 'node:net';

/**
 * Normalizes a client IP for storage in a Postgres `inet` column.
 *
 * Returns null for anything that is not a valid IPv4/IPv6 address, so a malformed
 * or hostile X-Forwarded-For can never reach the database and raise 22P02. Never
 * throws — a bad header must not be able to break a login.
 */
export function normalizeIpAddress(raw?: string | null): string | null {
    if (!raw) {
        return null;
    }

    // X-Forwarded-For may arrive as "client, proxy1, proxy2" — the client is first.
    let value = raw.split(',')[0].trim();

    if (!value) {
        return null;
    }

    // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1) down to plain IPv4.
    if (value.toLowerCase().startsWith('::ffff:')) {
        const mapped = value.slice(7);
        if (isIP(mapped) === 4) {
            value = mapped;
        }
    }

    return isIP(value) === 0 ? null : value;
}
import { createHash, randomBytes } from 'crypto';

/** 256 bits of entropy, URL-safe. Used for email-verification and refresh tokens. */
export function generateRawToken(): string {
    return randomBytes(32).toString('base64url');
}

/** Tokens are never stored raw — only this hash reaches the database. */
export function generateTokenHash(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
}

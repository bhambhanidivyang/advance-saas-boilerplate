import { ConfigService } from "@nestjs/config";
import { CookieOptions } from "express";

/**
 * Cookie attributes for the refresh token.
 *
 * Logout (Phase 8) must clear the cookie with these SAME attributes — browsers
 * silently ignore a clear whose path/domain/sameSite/secure don't match the
 * original — so setting and clearing must both come from this one function.
 * Call it without `expiresAt` when clearing.
 */
export function buildCookieOptionsFromConfig(config: ConfigService, expiresAt?: Date): CookieOptions {
    const options: CookieOptions = {
        httpOnly: true,
        path: '/auth',
        domain: config.get<string>('auth.cookie.domain'),
        secure: config.getOrThrow<boolean>('auth.cookie.secure'),
        sameSite: config.getOrThrow<'lax'|'strict'|'none'>('auth.cookie.sameSite'),
    }
    if (expiresAt) {
        // Express wants milliseconds. Derived from the clamped expiry rather than the
        // raw TTL, so the cookie can never outlive the token it carries.
        options.maxAge = Math.max(0, expiresAt.getTime() - Date.now());
    }
    return options;
}
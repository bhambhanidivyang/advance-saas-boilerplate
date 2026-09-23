import { Prisma } from 'src/generated/prisma/client';

/**
 * The lockout counters in their cleared state. Spread into a user update wherever
 * the failure sequence must start again from zero: a successful login, an expired
 * lock, a password change and, later, a password reset.
 *
 * `satisfies` checks the field names against the schema while keeping the literal
 * type, so renaming a column breaks the build here rather than silently at runtime.
 */
export const CLEARED_LOCKOUT_STATE = {
    passwordFailedAttempts: 0,
    passwordLockedUntil: null,
} as const satisfies Prisma.UserUpdateInput;

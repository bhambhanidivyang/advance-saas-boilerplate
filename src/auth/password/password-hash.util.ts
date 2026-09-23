import * as argon2 from 'argon2';

/**
 * argon2 cost parameters, pinned rather than left to library defaults so an
 * upgrade of the argon2 package cannot silently change our security posture or
 * verification latency. These values match argon2 0.45.1's defaults.
 *
 * needsRehash() compares ONLY these cost fields — it ignores `type` entirely —
 * which is why the variant is kept separate below.
 *
 * Lives here rather than in a service because every path that creates or checks a
 * password credential (login, registration, change, reset) must use the same
 * parameters, and a pure module is the simplest thing they can all share.
 */
export const PASSWORD_HASH_COSTS = {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
} as const;

export const PASSWORD_HASH_OPTIONS = {
    ...PASSWORD_HASH_COSTS,
    type: argon2.argon2id,
} as const;

export function hashPassword(password: string): Promise<string> {
    return argon2.hash(password, PASSWORD_HASH_OPTIONS);
}

export function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
    return argon2.verify(passwordHash, password);
}

export function passwordNeedsRehash(passwordHash: string): boolean {
    return argon2.needsRehash(passwordHash, PASSWORD_HASH_COSTS);
}

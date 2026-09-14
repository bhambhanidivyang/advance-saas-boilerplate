export const GENERIC_REGISTRATION_RESPONSE = 'If an account can be created with this email, you will receive a verification email soon.';
export const GENERIC_VERIFICATION_RESPONSE = 'If an account can be verified with this email, you will receive a verification email soon.';
export const GENERIC_LOGIN_RESPONSE = 'Invalid Email or Password';
export const LOGIN_FAILURE_REASON = {
    USER_NOT_FOUND: 'USER_NOT_FOUND',
    NO_PASSWORD_CREDENTIAL: 'NO_PASSWORD_CREDENTIAL',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    INVALID_PASSWORD: 'INVALID_PASSWORD',
} as const;
export const GENERIC_REFRESH_FAILURE = 'Session expired. Please log in again.';
export const REFRESH_FAILURE_REASON = {
    TOKEN_NOT_FOUND: 'TOKEN_NOT_FOUND',
    TOKEN_REVOKED: 'TOKEN_REVOKED',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    SESSION_REVOKED: 'SESSION_REVOKED',
    SESSION_EXPIRED: 'SESSION_EXPIRED',
    USER_NOT_ACTIVE: 'USER_NOT_ACTIVE',
    TOKEN_REUSE: 'TOKEN_REUSE',
} as const;

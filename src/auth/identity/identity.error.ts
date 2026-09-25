/** The provider did not confirm the email, so it cannot be used to link or create. */
export class ExternalEmailUnverifiedError extends Error {
    constructor() {
        super('The provider has not verified this email address');
        this.name = 'ExternalEmailUnverifiedError';
    }
}

/** The account exists but cannot sign in: suspended, deactivated or deleted. */
export class IdentityAccountUnavailableError extends Error {
    constructor() {
        super('The account is not available');
        this.name = 'IdentityAccountUnavailableError';
    }
}

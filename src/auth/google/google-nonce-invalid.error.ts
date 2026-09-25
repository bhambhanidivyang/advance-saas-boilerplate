/**
 * The presented Google nonce is invalid.
 */
export class GoogleNonceInvalidError extends Error {
    constructor(reason: string, options?: { cause?: unknown }) {
        super(reason, options);
        this.name = 'GoogleNonceInvalidError';
    }
}

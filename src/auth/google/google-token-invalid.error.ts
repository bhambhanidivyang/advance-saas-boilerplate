/**
 * The presented Google ID token could not be trusted: bad signature, wrong
 * audience, expired, or missing the claims we need.
 *
 * Deliberately not an HttpException. This layer wraps an HTTP library; choosing a
 * status code and writing the audit event is GoogleAuthenticatorService's job.
 */
export class GoogleTokenInvalidError extends Error {
    constructor(reason: string, options?: { cause?: unknown }) {
        super(reason, options);
        this.name = 'GoogleTokenInvalidError';
    }
}

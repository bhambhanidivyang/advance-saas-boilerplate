export enum EmailJobType {
    EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
    PASSWORD_RESET = 'PASSWORD_RESET'
}

export interface EmailJob {
    /** Which email to send; selects the template (e.g. verification vs password reset). */
    type: EmailJobType,
    /** Unique key used as the BullMQ jobId so the same send is not queued twice. */
    idempotencyKey: string,
    /** Recipient user this job belongs to. */
    userId: string,
    /** Optional tenant/org for the user, when emails are scoped to an organization. */
    organizationId?: string,
    /** Destination email address. */
    to: string,
    data: {
        /** Persisted UserToken id this email is tied to. */
        tokenId: string,
        /** One-time plaintext token embedded in the email link; never stored hashed here. */
        rawToken: string
    }
}
import { UnrecoverableError } from "bullmq";

export class EmailRetryableError extends Error {
    constructor(message: string, options?: {cause?: unknown}) {
        super(message, options);
        this.name = 'EmailRetryableError';
    }
}

/**
This is how the flow of throwing EmailPermanentError works when we want BullMQ to not retry further for permanent errors:
Nodemailer
   │
   │ throws original SMTP error
   ▼
SmtpEmailProvider.send()
   │
   │ catch(error)
   ▼
classifySmtpError(error)
   │
   │ returns EmailPermanentError
   ▼
throw EmailPermanentError
   │
   ▼
EmailProcessor catch(error)
   │
   │ throw error
   ▼
BullMQ Worker
   │
   │ sees UnrecoverableError
   ▼
FAILED
   │
   X
 NO RETRY
 */
export class EmailPermanentError extends UnrecoverableError {
    constructor(message: string, options?: {cause?: unknown}) {
        super(message);
        this.name = 'EmailPermanentError';
        if (options && 'cause' in options) {
            this.cause = options.cause;
        }
    }
}
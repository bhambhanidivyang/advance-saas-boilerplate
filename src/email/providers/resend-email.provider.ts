import { Injectable } from "@nestjs/common";
import { EmailMessage, EmailProvider, EmailSendResult } from "../interfaces/email-provider.interface";
import { Resend } from "resend";
import { ConfigService } from "@nestjs/config";
import { EmailPermanentError, EmailRetryableError } from "../errors/email.errors";

@Injectable()
export class ResendEmailProvider implements EmailProvider {
    private readonly resend: Resend;
    constructor(private readonly config: ConfigService) {
        this.resend = new Resend(this.config.getOrThrow<string>('email.resend.apiKey'));
    }
    async send(message: EmailMessage): Promise<EmailSendResult> {
        try {
            const result = await this.resend.emails.send(
                {
                    from:
                        message.from ??
                        this.config.getOrThrow<string>('email.from'),
                    to: message.to,
                    subject: message.subject,
                    html: message.html,
                    text: message.text,
                },
                {
                    idempotencyKey: message.idempotencyKey,
                },
            );
    
            if (result.error) {
                throw this.classifyError(result.error);
            }
    
            return {
                messageId: result.data?.id ?? '',
                accepted: [message.to],
                rejected: [],
            };
        } catch(error) {
            throw this.classifyError(error);
        }
    }

    private classifyError(error: unknown): Error {
        if (
            error instanceof EmailRetryableError ||
            error instanceof EmailPermanentError
        ) {
            return error;
        }
        
        if (
            typeof error === 'object' &&
            error !== null
        ) {
            const resendError = error as {
                statusCode?: number;
                message?: string;
                name?: string;
            };
    
            const statusCode = resendError.statusCode;
    
            if (statusCode === 429) {
                return new EmailRetryableError(
                    `Resend rate limit exceeded: ${statusCode}`,
                    { cause: error },
                );
            }
    
            if (
                statusCode !== undefined &&
                statusCode >= 500 &&
                statusCode < 600
            ) {
                return new EmailRetryableError(
                    `Temporary Resend failure: ${statusCode}`,
                    { cause: error },
                );
            }
    
            if (
                statusCode !== undefined &&
                statusCode >= 400 &&
                statusCode < 500
            ) {
                return new EmailPermanentError(
                    `Permanent Resend failure: ${statusCode}`,
                    { cause: error },
                );
            }
        }
    
        if (error instanceof Error) {
            const errorCode = (error as NodeJS.ErrnoException).code?.toUpperCase();

            const retryableNetworkErrors = new Set([
                'ETIMEDOUT',
                'ECONNRESET',
                'ECONNREFUSED',
                'EAI_AGAIN',
                'ENETUNREACH',
                'EHOSTUNREACH',
                'ENOTFOUND',
            ]);

            if (errorCode && retryableNetworkErrors.has(errorCode)) {
                return new EmailRetryableError(
                    `Temporary Resend connection failure: ${errorCode}`,
                    { cause: error },
                );
            }

            return new EmailRetryableError(
                error.message,
                { cause: error },
            );
        }
    
        return new EmailRetryableError(
            'Unknown Resend error',
            { cause: error },
        );
    }
}
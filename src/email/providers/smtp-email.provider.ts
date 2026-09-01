import { ConfigService } from "@nestjs/config";
import { EmailMessage, EmailProvider, EmailSendResult } from "../interfaces/email-provider.interface";
import { Transporter } from "nodemailer";
import * as nodemailer from "nodemailer";
import { Injectable } from "@nestjs/common";
import { EmailPermanentError, EmailRetryableError } from "../errors/email.errors";

@Injectable()
export class SmtpEmailProvider implements EmailProvider {
    private readonly transporter: Transporter;
    constructor(private readonly config: ConfigService) {
        this.transporter = nodemailer.createTransport({
            // SMTP server hostname, e.g. smtp.example.com
            host: this.config.getOrThrow<string>('email.smtp.host'),
        
            // SMTP server port, e.g. 587 (STARTTLS) or 465 (implicit TLS)
            port: this.config.getOrThrow<number>('email.smtp.port'),
        
            // Whether to use TLS immediately when establishing the SMTP connection.
            // Usually false for 587 and true for 465.
            secure: this.config.getOrThrow<boolean>('email.smtp.secure'),
        
            // Reuse persistent SMTP connections instead of opening a new
            // connection for every email.
            pool: this.config.getOrThrow<boolean>('email.smtp.pool'),
        
            // Maximum number of SMTP connections kept open simultaneously.
            maxConnections: this.config.getOrThrow<number>('email.smtp.maxConnections'),
        
            // Maximum number of emails sent through one connection
            // before Nodemailer recycles that connection.
            maxMessages: this.config.getOrThrow<number>('email.smtp.maxMessages'),
        
            // Maximum time (ms) allowed to establish a connection
            // to the SMTP server.
            connectionTimeout: this.config.getOrThrow<number>('email.smtp.connectionTimeout'),
        
            // Maximum time (ms) to wait for the SMTP server's initial
            // greeting after the connection is established.
            greetingTimeout: this.config.getOrThrow<number>('email.smtp.greetingTimeout'),
        
            // Maximum time (ms) an established SMTP connection can remain
            // inactive/unresponsive before it is considered timed out.
            // It's basically protection against an established connection becoming unresponsive.
            socketTimeout: this.config.getOrThrow<number>('email.smtp.socketTimeout'),
        
            // SMTP authentication credentials, if authentication is required.
            auth: this.getAuth()
        });
    }
    async send(message: EmailMessage): Promise<EmailSendResult> {
        try {
            const result = await this.transporter.sendMail({
                from: message.from ?? this.config.getOrThrow<string>('email.from'),
                to: message.to,
                subject: message.subject,
                html: message.html,
                text: message.text
            });
    
            return {
                messageId: result.messageId,
                accepted: result.accepted.map(String),
                rejected: result.rejected.map(String)
            }
        } catch(error) {
            throw this.classifySmtpError(error);
        }
    }

    async onModuleDestroy(): Promise<void> {
        this.transporter.close();
    }

    private getAuth () {
        const user = this.config.get<string>('email.smtp.user');
        const password = this.config.get<string>('email.smtp.password');

        if (!user || !password) {
            return undefined;
        }

        return {
            user: user,
            pass: password
        }
    }

    private classifySmtpError(error: unknown): Error {
        if (!(error instanceof Error)) {
            return new EmailRetryableError('Unknown error type', {cause: error});
        }

        // Cast the error so TypeScript allows you to access the custom network properties
        const smtpError = error as Error & {
            code?: string,
            responseCode?: number | string, 
            response?: string
        }

        // SMTP 4xx = temporary failure → retry
        if (
            smtpError.responseCode !== undefined &&
            Number(smtpError.responseCode) >= 400 &&
            Number(smtpError.responseCode) < 500
        ) {
            return new EmailRetryableError(
                `Temporary SMTP failure: ${smtpError.responseCode}`,
                { cause: error },
            );
        }

        // SMTP 5xx = permanent failure → don't retry
        if (
            smtpError.responseCode !== undefined &&
            Number(smtpError.responseCode) >= 500 &&
            Number(smtpError.responseCode) < 600
        ) {
            return new EmailPermanentError(
                `Permanent SMTP failure: ${smtpError.responseCode}`,
                { cause: error },
            );
        }

        const errorCode = smtpError.code?.toUpperCase();

        // Network / connection failures → retry
        const retryableNetworkErrors = new Set([
            'ETIMEDOUT',
            'ECONNRESET',
            'ECONNREFUSED',
            'EAI_AGAIN',
            'ENETUNREACH',
            'EHOSTUNREACH',
            'ENOTFOUND'
        ]);

        if (
            errorCode &&
            retryableNetworkErrors.has(errorCode)
        ) {
            return new EmailRetryableError(
                `Temporary SMTP connection failure: ${errorCode}`,
                { cause: error },
            );
        }

        // Permanent local failures (TLS configuration or bad assertions shouldn't retry)
        if (errorCode?.startsWith('ERR_TLS_') || errorCode === 'ERR_ASSERTION') {
            return new EmailPermanentError(
                `Permanent system/TLS failure: ${errorCode}`,
                { cause: error },
            );
        }

        // Regex Fallback: Scan text properties for embedded status codes if explicit ones are missing.
        // Uses word boundaries (\b) to avoid accidentally matching IP addresses or random string components.
        const errorText = `${smtpError.message} ${smtpError.response ?? ''}`;

        if (/\b5\d{2}\b/.test(errorText)) {
            return new EmailPermanentError(
                'Permanent SMTP failure detected in response text',
                { cause: error },
            );
        }

        if (/\b4\d{2}\b/.test(errorText)) {
            return new EmailRetryableError(
                'Temporary SMTP failure detected in response text',
                { cause: error },
            );
        }

        // Unknown SMTP errors should be treated conservatively.
        return new EmailRetryableError(
            'Unknown SMTP error',
            { cause: error },
        );
    }
}
import { ConfigService } from "@nestjs/config";
import { EmailJob, EmailJobType } from "../interfaces/email-job.interface";
import { EmailMessage } from "../interfaces/email-provider.interface";
import { EmailTemplate } from "../interfaces/email-template.interface";
import { generateEmailTemplateUrl } from "../utils/email.utils";
import { Injectable } from "@nestjs/common";
import { EmailPermanentError } from "../errors/email.errors";

@Injectable()
export class VerificationEmailTemplate implements EmailTemplate {
    constructor(private readonly config: ConfigService){}
    supports(type: EmailJobType): boolean {
        return type === EmailJobType.EMAIL_VERIFICATION;
    }

    render(job: EmailJob): EmailMessage {
        const token = job.data.rawToken;
        if (typeof token !== 'string') {
            throw new EmailPermanentError('Email Verification job is missing rawToken');
        }
        const frontendUrl = this.config.getOrThrow<string>('app.frontendUrl');
        const verificationUrl = generateEmailTemplateUrl(`${frontendUrl}/auth/verify-email?token=`, token);
        return {
            to: job.to,
            subject: 'Verify your email',
            html: `
                <h1>Verify your email</h1>
                <p>Please click the link below to verify your email address.</p>
                <p>
                    <a href="${verificationUrl}">
                        Verify Email
                    </a>
                </p>
                <p>This link will expire in 24 hours.</p>
            `,
            text: `
                Verify your email

                Please visit the following link to verify your email:

                ${verificationUrl}

                This link will expire in 24 hours.
            `,
            idempotencyKey: job.idempotencyKey
        };
    }
}
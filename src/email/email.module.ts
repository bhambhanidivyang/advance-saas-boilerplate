import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { EmailService } from './email.service';
import { EmailProcessor } from './email.processor';
import { SmtpEmailProvider } from './providers/smtp-email.provider';
import { EMAIL_PROVIDER, EMAIL_TEMPLATES } from './constants/email.constants';
import { VerificationEmailTemplate } from './templates/verification-email.template';
import { EmailTemplate } from './interfaces/email-template.interface';
import { EmailTemplateService } from './templates/email-template.service';
import { ConfigService } from '@nestjs/config';
import { ResendEmailProvider } from './providers/resend-email.provider';
import { EmailProvider, EmailProviderType } from './interfaces/email-provider.interface';

@Module({
    imports: [
        BullModule.registerQueue({
            name: 'email'
        })
    ],
    providers: [
        EmailService,
        EmailProcessor,
        SmtpEmailProvider,
        ResendEmailProvider,
        {
            provide: EMAIL_PROVIDER,
            inject: [ConfigService, SmtpEmailProvider, ResendEmailProvider],
            useFactory:(
                config: ConfigService,
                smtpProvider: SmtpEmailProvider,
                resendProvider: ResendEmailProvider
            ): EmailProvider => {
                const provider = config.getOrThrow<EmailProviderType>('email.provider');

                switch (provider) {
                    case EmailProviderType.SMTP:
                        return smtpProvider;
                
                    case EmailProviderType.RESEND:
                        return resendProvider;
                
                    default:
                        throw new Error(`Unsupported email provider: ${provider}`);
                }
            }
        },
        EmailTemplateService,
        VerificationEmailTemplate,
        {
            provide: EMAIL_TEMPLATES,
            useFactory: (verificationTemplate: VerificationEmailTemplate): EmailTemplate[] => [
                verificationTemplate
            ],
            inject: [VerificationEmailTemplate]
        }
    ],
    exports: [EmailService]
})
export class EmailModule {}

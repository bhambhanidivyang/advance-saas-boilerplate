import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { EmailService } from './email.service';
import { EmailProcessor } from './email.processor';
import { SmtpEmailProvider } from './providers/smtp-email.provider';
import { EMAIL_PROVIDER, EMAIL_TEMPLATES } from './constants/email.constants';
import { VerificationEmailTemplate } from './templates/verification-email.template';
import { EmailTemplate } from './interfaces/email-template.interface';
import { EmailTemplateService } from './templates/email-template.service';

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
        {
            provide: EMAIL_PROVIDER,
            useExisting: SmtpEmailProvider
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

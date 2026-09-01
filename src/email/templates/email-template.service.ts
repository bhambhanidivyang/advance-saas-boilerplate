import { Inject } from "@nestjs/common";
import type { EmailJob } from "../interfaces/email-job.interface";
import type { EmailMessage } from "../interfaces/email-provider.interface";
import type { EmailTemplate } from "../interfaces/email-template.interface";
import { EMAIL_TEMPLATES } from "../constants/email.constants";
import { EmailPermanentError } from "../errors/email.errors";

export class EmailTemplateService {
    constructor(@Inject(EMAIL_TEMPLATES) private readonly templates: EmailTemplate[]){}
    render(job: EmailJob): EmailMessage {
        const template = this.templates.find((template) => template.supports(job.type));
        if (!template) {
            throw new EmailPermanentError(`No email template found for job type: ${job.type}`);
        }
        return template.render(job);
    }
}
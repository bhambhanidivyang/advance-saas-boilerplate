import { EmailJob } from "./email-job.interface";
import { EmailMessage } from "./email-provider.interface";

export interface EmailTemplate {
    supports(type: EmailJob['type']): boolean;
    render(job: EmailJob): EmailMessage
}
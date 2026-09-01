import { Injectable } from "@nestjs/common";
import { EmailProvider } from "../interfaces/email-provider.interface";

@Injectable()
export class ResendEmailProvider implements EmailProvider {
    async send() {
        return {
            messageId: '',
            accepted: [],
            rejected: []
        }
    }
}
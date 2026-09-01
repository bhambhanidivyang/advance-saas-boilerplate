export interface EmailMessage {
    to: string;
    subject: string;
    html: string;
    text?: string;
    from?: string;
}

export interface EmailProvider {
    send(message: EmailMessage): Promise<EmailSendResult>;
}

export interface EmailSendResult {
    messageId?: string;
    accepted: string[];
    rejected: string[];
}
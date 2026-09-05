import { Body, Controller, Param, Post, Query } from '@nestjs/common';
import { CreateNewUser } from './dto/create-new-user.dto';
import { AuthService } from './auth.service';
import { Logger } from 'nestjs-pino';
import { ResendVerification } from './dto/resend-verification.dto';

export interface VerifyEmailParams {
    tokenId?: string;
    rawToken: string;
}

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly logger: Logger
    ) {}
    @Post('register')
    async register (@Body() body: CreateNewUser) {
        return await this.authService.register(body);
    }

    @Post('resend-verification-email')
    async resendVerifyEmail (@Body() body: ResendVerification) {
        const { email } = body;
        return await this.authService.resendVerifyEmail(email);
    }

    @Post('verify-email')
    async verifyEmail (@Query() params: VerifyEmailParams) {
        this.logger.log(params, 'verifying email');
        return await this.authService.verifyEmail(params);
    }
}

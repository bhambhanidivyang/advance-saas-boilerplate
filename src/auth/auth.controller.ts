import { Body, Controller, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { CreateNewUser } from './dto/create-new-user.dto';
import { AuthService } from './providers/auth.service';
import { ResendVerification } from './dto/resend-verification.dto';
import { LoginDto } from './dto/login.dto';
import { SkipThrottle } from '@nestjs/throttler';
import { buildAuthContext } from './utils/auth.util';
import { Public } from 'src/common/decorators/public.decorator';
import { LoginResponse, RefreshResponse } from './interfaces/login.interface';
import { LogoutResponse } from './interfaces/session.interface';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import type { AuthenticatedUser } from './interfaces/authenticated-request.interface';
import { ConfigService } from '@nestjs/config';
import { buildCookieOptionsFromConfig } from './utils/session-cookie.util';
import { SessionService } from './providers/session.service';
import { GENERIC_REFRESH_FAILURE } from './constants/auth.constants';

export interface VerifyEmailParams {
    tokenId?: string;
    rawToken: string;
}

@SkipThrottle({ auth: true, otp: true })
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly sessionService: SessionService,
        private readonly config: ConfigService
    ) {}

    @Public()
    @Post('register')
    async register (@Body() body: CreateNewUser) {
        return await this.authService.register(body);
    }

    @Public()
    @Post('resend-verification-email')
    async resendVerifyEmail (@Body() body: ResendVerification) {
        const { email } = body;
        return await this.authService.resendVerifyEmail(email);
    }

    @Public()
    @Post('verify-email')
    async verifyEmail (@Query() params: VerifyEmailParams) {
        return await this.authService.verifyEmail(params);
    }

    @Public()
    @SkipThrottle({ auth: false })
    @Post('login')
    async login (
        @Body() body: LoginDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<LoginResponse> {
        const result = await this.authService.login(body, buildAuthContext(req));
        const { session, user } = result;
        
        // Using res.cookie(name, value, options);
        res.cookie(
            this.config.getOrThrow<string>('auth.cookie.name'), // name
            session.refreshToken, // value
            buildCookieOptionsFromConfig(this.config, session.refreshTokenExpiresAt) // options
        );

        // Built field by field on purpose. Returning `session`, or spreading it, would
        // put the raw refresh token in the JSON body and defeat httpOnly entirely.
        return {
            accessToken: session.accessToken,
            expiresIn: session.expiresIn,
            tokenType: 'Bearer',
            user: user
        }
    }

    @Public()
    @SkipThrottle({ auth: false })
    @Post('refresh')
    async refresh (
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<RefreshResponse> {
        const cookieName = this.config.getOrThrow<string>('auth.cookie.name');
        const rawToken = req.cookies?.[cookieName];

        // No cookie: nothing to rotate, so do not call the service at all.
        if (!rawToken) {
            res.clearCookie(cookieName, buildCookieOptionsFromConfig(this.config));
            throw new UnauthorizedException(GENERIC_REFRESH_FAILURE);
        }

        try {
            const session = await this.sessionService.rotateRefreshToken(
                rawToken,
                buildAuthContext(req)
            );

            res.cookie(
                cookieName,
                session.refreshToken,
                buildCookieOptionsFromConfig(this.config, session.refreshTokenExpiresAt)
            );

            // Field by field, same leak rule as login: the raw refresh token lives
            // only in the cookie, never in the JSON body.
            return {
                accessToken: session.accessToken,
                expiresIn: session.expiresIn,
                tokenType: 'Bearer',
            };
        } catch (error) {
            // Cleared with no expiresAt so the attributes match what was set —
            // browsers ignore a clear whose attributes differ. Headers set before
            // the rethrow survive into the exception filter's response.
            res.clearCookie(cookieName, buildCookieOptionsFromConfig(this.config));
            throw error;
        }
    }

    @Public()
    @SkipThrottle({ auth: false })
    @Post('logout')
    async logout (
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<LogoutResponse> {
        const cookieName = this.config.getOrThrow<string>('auth.cookie.name');
        const rawToken = req.cookies?.[cookieName];

        // Public on purpose: the access token has very likely expired by the time
        // someone clicks log out, and a guarded route would 401 instead of logging
        // them out. The refresh cookie is the credential here, and with no cookie
        // there is simply nothing to revoke — so this stays idempotent rather than
        // failing.
        if (rawToken) {
            await this.sessionService.revokeSessionByRefreshToken(rawToken, buildAuthContext(req));
        }

        res.clearCookie(cookieName, buildCookieOptionsFromConfig(this.config));
        return { success: true };
    }

    // Guarded, unlike /logout: revoking every device is a bigger hammer, so it is
    // worth requiring a currently valid access token.
    @SkipThrottle({ auth: false })
    @Post('logout-all')
    async logoutAll (
        @CurrentUser() user: AuthenticatedUser,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ): Promise<LogoutResponse> {
        const revokedSessions = await this.sessionService.revokeAllSessions(
            user.userId,
            user.sessionId,
            buildAuthContext(req)
        );

        res.clearCookie(
            this.config.getOrThrow<string>('auth.cookie.name'),
            buildCookieOptionsFromConfig(this.config)
        );

        return { success: true, revokedSessions };
    }
}

import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ALLOW_PASSWORD_CHANGE_PENDING } from '../decorators/allow-password-change-pending.decorator';
import { RequestWithUser } from 'src/auth/interfaces/authenticated-request.interface';

/**
 * Enforces User.mustChangePassword, which login only reported until now.
 *
 * Runs after JwtAuthGuard and reads the mcp claim, so it costs no database query.
 * The claim is therefore up to one access-token lifetime stale: a user whose flag
 * was just set keeps their current token until it expires, and a user who has just
 * changed their password gets a clean claim on their next refresh.
 *
 * Public routes are unaffected — they have no authenticated user to hold the flag.
 */
@Injectable()
export class PasswordChangeRequiredGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest<RequestWithUser>();

        if (!request.user?.mustChangePassword) {
            return true;
        }

        const allowed = this.reflector.getAllAndOverride<boolean>(ALLOW_PASSWORD_CHANGE_PENDING, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (allowed) {
            return true;
        }

        throw new ForbiddenException({
            message: 'You must change your password before continuing',
            code: 'PASSWORD_CHANGE_REQUIRED',
        });
    }
}

import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { RequestWithUser } from 'src/auth/interfaces/authenticated-request.interface';


/**
 * Applied per-route with @UseGuards, NOT globally — most routes should work for an
 * unverified user. Reads the `ev` claim, so it can be up to one access-token TTL
 * stale after a user verifies. Phase 7 refreshes the claim on rotation.
 */
@Injectable()
export class EmailVerifiedGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest<RequestWithUser>();

        if (!request.user) {
            throw new UnauthorizedException(
                'Authentication required',
            );
        }

        if (!request.user.emailVerified) {
            throw new ForbiddenException('Email verification required');
        }
        return true;
    }
}
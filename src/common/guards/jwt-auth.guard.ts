import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { RequestWithUser } from "src/auth/interfaces/authenticated-request.interface";
import { TokenService } from "src/auth/providers/token.service";
import { SessionDenylistService } from "src/auth/providers/session-denylist.service";

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        private readonly tokenService: TokenService,
        private readonly denylist: SessionDenylistService
    ) {}
    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Check if requested endpoint is public
        const isPublic = this.reflector.getAllAndOverride<boolean>(
            IS_PUBLIC_KEY,
            [context.getHandler(), context.getClass()]
        );
        if (isPublic) return true;
        // get bearer token from request
        const request = context.switchToHttp().getRequest<RequestWithUser>();
        const token = this.extractBearerToken(request.headers.authorization);
        // if no token, unauthorized
        if (!token) {
            throw new UnauthorizedException({
                message: 'Access token is missing',
                code: 'MISSING_ACCESS_TOKEN'
            });
        }

        try {
            // verify token and get claims
            const claims = await this.tokenService.verifyAccessToken(token);

            // Signature verification alone cannot see a revocation, so a logged-out
            // session's token would stay usable until it expired. Inert (and free)
            // unless auth.session.denylistEnabled is on.
            if (await this.denylist.isRevoked(claims.sid)) {
                throw new UnauthorizedException({
                    message: 'Session is no longer active',
                    code: 'SESSION_REVOKED'
                });
            }
            // attach user detais to request.user
            request.user = {
                userId: claims.sub,
                sessionId: claims.sid,
                tokenFamilyId: claims.fam,
                emailVerified: claims.ev,
                authMethod: claims.amr?.[0],
            }
            return true;
        } catch(error) {
            // Already a decided rejection (e.g. a denylisted session): pass it through
            // rather than relabelling it as an invalid token.
            if (error instanceof UnauthorizedException) {
                throw error;
            }
            if ((error as Error)?.name === 'TokenExpiredError') {
                throw new UnauthorizedException({
                    message: 'Access token expired',
                    code: 'TOKEN_EXPIRED'
                });
            }
            // Everything else is deliberately opaque.
            throw new UnauthorizedException('Invalid access token');
        }
    }

    private extractBearerToken(header?: string) {
        if (!header) return null;

        const parts = header.split(' ');
        if (parts.length !== 2) {
            return null;
        }

        const [scheme, value] = parts;

        if (scheme.toLowerCase() !== 'bearer') {
            return null;
        }
        return value.trim() || null;
    }
}
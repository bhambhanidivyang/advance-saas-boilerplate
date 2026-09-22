import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { TokenService } from 'src/auth/providers/token.service';
import { SessionDenylistService } from 'src/auth/providers/session-denylist.service';
import { AuthMethod } from 'src/generated/prisma/client';

const validClaims = {
    sub: 'user-1',
    sid: 'session-1',
    fam: 'family-1',
    ev: true,
    mcp: false,
    amr: [AuthMethod.PASSWORD],
    jti: 'jti-1',
    iss: 'mynest-api-test',
    aud: 'mynest-app-test',
    iat: 1_000,
    exp: 1_600,
};

function createContext(headers: Record<string, string> = {}) {
    const request: Record<string, any> = { headers };
    const context = {
        getHandler: () => () => undefined,
        getClass: () => class {},
        switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;

    return { context, request };
}

describe('JwtAuthGuard', () => {
    let guard: JwtAuthGuard;
    let reflector: { getAllAndOverride: jest.Mock };
    let tokenService: { verifyAccessToken: jest.Mock };
    let denylist: { isRevoked: jest.Mock };

    beforeEach(() => {
        reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) };
        tokenService = { verifyAccessToken: jest.fn() };
        denylist = { isRevoked: jest.fn().mockResolvedValue(false) };

        guard = new JwtAuthGuard(
            reflector as unknown as Reflector,
            tokenService as unknown as TokenService,
            denylist as unknown as SessionDenylistService,
        );
    });

    it('lets a @Public() route through without any token', async () => {
        reflector.getAllAndOverride.mockReturnValue(true);
        const { context } = createContext();

        await expect(guard.canActivate(context)).resolves.toBe(true);
        expect(tokenService.verifyAccessToken).not.toHaveBeenCalled();
    });

    it('populates request.user from the verified claims', async () => {
        tokenService.verifyAccessToken.mockResolvedValue(validClaims);
        const { context, request } = createContext({ authorization: 'Bearer good-token' });

        await expect(guard.canActivate(context)).resolves.toBe(true);
        expect(tokenService.verifyAccessToken).toHaveBeenCalledWith('good-token');
        expect(request.user).toEqual({
            userId: 'user-1',
            sessionId: 'session-1',
            tokenFamilyId: 'family-1',
            emailVerified: true,
            mustChangePassword: false,
            authMethod: AuthMethod.PASSWORD,
        });
    });

    it('accepts a lower-case bearer scheme (RFC 6750 says it is case-insensitive)', async () => {
        tokenService.verifyAccessToken.mockResolvedValue(validClaims);
        const { context } = createContext({ authorization: 'bearer good-token' });

        await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    describe('rejects malformed credentials without calling the verifier', () => {
        it.each([
            ['a missing Authorization header', undefined],
            ['a Basic scheme', 'Basic dXNlcjpwYXNz'],
            ['an empty bearer token', 'Bearer '],
            ['a bare token with no scheme', 'good-token'],
            ['a three-part header', 'Bearer good-token extra'],
        ])('%s', async (_label, authorization) => {
            const { context } = createContext(
                authorization === undefined ? {} : { authorization },
            );

            await expect(guard.canActivate(context)).rejects.toBeInstanceOf(UnauthorizedException);
            expect(tokenService.verifyAccessToken).not.toHaveBeenCalled();
        });
    });

    it('surfaces TOKEN_EXPIRED so the client knows to refresh rather than re-login', async () => {
        tokenService.verifyAccessToken.mockRejectedValue(
            Object.assign(new Error('jwt expired'), { name: 'TokenExpiredError' }),
        );
        const { context } = createContext({ authorization: 'Bearer expired-token' });

        const error = await guard.canActivate(context).catch((e) => e);

        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.getResponse()).toMatchObject({ code: 'TOKEN_EXPIRED' });
    });

    it('stays opaque about every other verification failure', async () => {
        tokenService.verifyAccessToken.mockRejectedValue(
            Object.assign(new Error('invalid signature'), { name: 'JsonWebTokenError' }),
        );
        const { context } = createContext({ authorization: 'Bearer forged-token' });

        const error = await guard.canActivate(context).catch((e) => e);

        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.getResponse()).not.toMatchObject({ code: 'TOKEN_EXPIRED' });
    });

    it('does not leave request.user set when verification fails', async () => {
        tokenService.verifyAccessToken.mockRejectedValue(new Error('nope'));
        const { context, request } = createContext({ authorization: 'Bearer bad-token' });

        await expect(guard.canActivate(context)).rejects.toBeInstanceOf(UnauthorizedException);
        expect(request.user).toBeUndefined();
    });

    describe('the session denylist', () => {
        it('rejects a token whose session has been revoked', async () => {
            tokenService.verifyAccessToken.mockResolvedValue(validClaims);
            denylist.isRevoked.mockResolvedValue(true);
            const { context, request } = createContext({ authorization: 'Bearer good-token' });

            const error = await guard.canActivate(context).catch((e) => e);

            expect(denylist.isRevoked).toHaveBeenCalledWith('session-1');
            expect(error).toBeInstanceOf(UnauthorizedException);
            expect(error.getResponse()).toMatchObject({ code: 'SESSION_REVOKED' });
            // The rejection must not be relabelled as an invalid token by the catch.
            expect(request.user).toBeUndefined();
        });

        it('is not consulted for a @Public() route', async () => {
            reflector.getAllAndOverride.mockReturnValue(true);
            const { context } = createContext();

            await expect(guard.canActivate(context)).resolves.toBe(true);
            expect(denylist.isRevoked).not.toHaveBeenCalled();
        });
    });
});

import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthMethod } from 'src/generated/prisma/client';
import { PasswordChangeRequiredGuard } from './password-change-required.guard';

function createContext(user?: Record<string, unknown>) {
    const request: Record<string, unknown> = { user };
    return {
        getHandler: () => () => undefined,
        getClass: () => class {},
        switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
}

function authenticatedUser(mustChangePassword: boolean) {
    return {
        userId: 'user-1',
        sessionId: 'session-1',
        tokenFamilyId: 'family-1',
        emailVerified: true,
        mustChangePassword,
        authMethod: AuthMethod.PASSWORD,
    };
}

describe('PasswordChangeRequiredGuard', () => {
    let guard: PasswordChangeRequiredGuard;
    let reflector: { getAllAndOverride: jest.Mock };

    beforeEach(() => {
        reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) };
        guard = new PasswordChangeRequiredGuard(reflector as unknown as Reflector);
    });

    it('blocks a user who still has to change their password', () => {
        const error = (() => {
            try {
                guard.canActivate(createContext(authenticatedUser(true)));
            } catch (e) {
                return e;
            }
        })() as ForbiddenException;

        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.getResponse()).toMatchObject({ code: 'PASSWORD_CHANGE_REQUIRED' });
    });

    it('lets that user reach a route marked as an escape hatch', () => {
        reflector.getAllAndOverride.mockReturnValue(true);

        expect(guard.canActivate(createContext(authenticatedUser(true)))).toBe(true);
    });

    it('lets an ordinary user through', () => {
        expect(guard.canActivate(createContext(authenticatedUser(false)))).toBe(true);
        expect(reflector.getAllAndOverride).not.toHaveBeenCalled();
    });

    // Public routes never have a user attached, so there is no flag to enforce.
    it('ignores an unauthenticated request', () => {
        expect(guard.canActivate(createContext(undefined))).toBe(true);
    });
});

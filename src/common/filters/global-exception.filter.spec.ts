import {
    ArgumentsHost,
    BadRequestException,
    HttpException,
    HttpStatus,
    UnauthorizedException,
} from '@nestjs/common';
import { Logger } from 'nestjs-pino';
import { GlobalExceptionFilter } from './global-exception.filter';

describe('GlobalExceptionFilter', () => {
    let filter: GlobalExceptionFilter;
    let logger: { error: jest.Mock };
    let response: { status: jest.Mock; json: jest.Mock };

    function host(): ArgumentsHost {
        return {
            switchToHttp: () => ({
                getRequest: () => ({ url: '/auth/login', method: 'POST', id: 'req-1' }),
                getResponse: () => response,
            }),
        } as unknown as ArgumentsHost;
    }

    function body() {
        return response.json.mock.calls[0][0];
    }

    beforeEach(() => {
        logger = { error: jest.fn() };
        response = { status: jest.fn(() => response), json: jest.fn() };
        filter = new GlobalExceptionFilter(logger as unknown as Logger);
    });

    it('passes through the status and message of a built-in exception', () => {
        filter.catch(new UnauthorizedException('Invalid Email or Password'), host());

        expect(response.status).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
        expect(body()).toMatchObject({
            statusCode: 401,
            message: 'Invalid Email or Password',
            path: '/auth/login',
            requestId: 'req-1',
        });
    });

    it('forwards a code when the exception carries one', () => {
        filter.catch(
            new UnauthorizedException({ message: 'Access token expired', code: 'TOKEN_EXPIRED' }),
            host(),
        );

        expect(body()).toMatchObject({ message: 'Access token expired', code: 'TOKEN_EXPIRED' });
    });

    // An absent code should be absent, not an empty string.
    it('omits the code key entirely when there is none', () => {
        filter.catch(new UnauthorizedException('nope'), host());

        expect(body()).not.toHaveProperty('code');
    });

    // ValidationPipe puts a string[] in message, not a string.
    it('preserves a validation error array', () => {
        filter.catch(
            new BadRequestException(['email must be an email', 'password is too short']),
            host(),
        );

        expect(body().message).toEqual(['email must be an email', 'password is too short']);
    });

    // getResponse() returns a bare string here, unlike Nest's built-in exceptions.
    it('handles an HttpException constructed with a plain string', () => {
        filter.catch(new HttpException('boom', HttpStatus.BAD_REQUEST), host());

        expect(response.status).toHaveBeenCalledWith(400);
        expect(body().message).toBe('boom');
    });

    // Allowlist, not spread: an exception payload must not leak internals.
    it('drops unknown fields from the exception payload', () => {
        filter.catch(
            new BadRequestException({
                message: 'bad',
                code: 'BAD',
                internalQuery: 'SELECT * FROM "User"',
                passwordHash: '$argon2id$leak',
            }),
            host(),
        );

        expect(body()).not.toHaveProperty('internalQuery');
        expect(body()).not.toHaveProperty('passwordHash');
        expect(Object.keys(body()).sort()).toEqual(
            ['code', 'message', 'path', 'requestId', 'statusCode', 'timestamp'].sort(),
        );
    });

    describe('an unexpected error', () => {
        it('becomes a generic 500 that leaks nothing', () => {
            filter.catch(new Error('connection string: postgres://user:pw@host'), host());

            expect(response.status).toHaveBeenCalledWith(500);
            expect(body().message).toBe('Internal Server Error');
            expect(JSON.stringify(body())).not.toContain('postgres://');
        });

        // Without this the only record of a real bug is a bare 500 in an access log.
        it('is logged with the original error', () => {
            const error = new Error('kaboom');
            filter.catch(error, host());

            expect(logger.error).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'UNHANDLED_EXCEPTION', err: error }),
                'Unhandled exception',
            );
        });

        it('does not log ordinary HTTP exceptions as bugs', () => {
            filter.catch(new UnauthorizedException('nope'), host());

            expect(logger.error).not.toHaveBeenCalled();
        });
    });
});

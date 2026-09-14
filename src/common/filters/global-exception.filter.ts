import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from "@nestjs/common";
import { Logger } from "nestjs-pino";
import { Request, Response } from 'express';

const GENERIC_SERVER_ERROR = 'Internal Server Error';

interface ErrorResponseBody {
    statusCode: number;
    message: string | string[];
    code?: string;
    requestId?: string;
    timestamp: string;
    path: string;
}

/**
 * @Catch() with no arguments receives anything thrown, so `exception` is genuinely
 * unknown — it is narrowed below rather than asserted.
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
    constructor(private readonly logger: Logger) {}

    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const request = ctx.getRequest<Request>();
        const response = ctx.getResponse<Response>();

        const { status, message, code } = this.describe(exception);

        if (!(exception instanceof HttpException)) {
            // The only place an unexpected error can be captured. Without this a real
            // bug becomes a bare 500 with no stack trace in any log.
            this.logger.error(
                {
                    code: 'UNHANDLED_EXCEPTION',
                    err: exception,
                    method: request.method,
                    path: request.url,
                },
                'Unhandled exception',
            );
        }

        const body: ErrorResponseBody = {
            statusCode: status,
            message,
            // Omitted rather than empty: an absent code should be absent, not "".
            ...(code ? { code } : {}),
            // Set by pino's genReqId, so a user can quote it and it can be grepped.
            ...(request.id ? { requestId: String(request.id) } : {}),
            timestamp: new Date().toISOString(),
            path: request.url,
        };

        response.status(status).json(body);
    }

    private describe(exception: unknown): {
        status: number;
        message: string | string[];
        code?: string;
    } {
        if (!(exception instanceof HttpException)) {
            // Never surface an internal error's text to the caller.
            return { status: HttpStatus.INTERNAL_SERVER_ERROR, message: GENERIC_SERVER_ERROR };
        }

        const status = exception.getStatus();
        const payload = exception.getResponse();

        // `new HttpException('boom', 400)` returns a bare string here, while Nest's
        // built-in exceptions return an object. Both have to be handled or a 400
        // would be served with the generic 500 text.
        if (typeof payload === 'string') {
            return { status, message: payload };
        }

        if (typeof payload !== 'object' || payload === null) {
            return { status, message: exception.message || GENERIC_SERVER_ERROR };
        }

        const record = payload as Record<string, unknown>;

        // Allowlisted on purpose. Spreading the payload would leak whatever an
        // exception happened to be constructed with — raw input, DB rows, internals.
        return {
            status,
            // ValidationPipe puts a string[] here, not a string.
            message: this.readMessage(record) ?? exception.message ?? GENERIC_SERVER_ERROR,
            code: typeof record.code === 'string' ? record.code : undefined,
        };
    }

    private readMessage(record: Record<string, unknown>): string | string[] | undefined {
        const { message } = record;

        if (typeof message === 'string') {
            return message;
        }
        if (Array.isArray(message) && message.every((entry) => typeof entry === 'string')) {
            return message as string[];
        }
        return undefined;
    }
}

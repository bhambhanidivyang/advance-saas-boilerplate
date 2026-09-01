import { ArgumentsHost, Catch, ExceptionFilter, HttpException } from "@nestjs/common";
import { Request, Response } from 'express';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
    catch(exception: HttpException, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const request = ctx.getRequest<Request>();
        const response = ctx.getResponse<Response>();

        const isHttpException = exception instanceof HttpException;

        let status = 500;
        let message = 'Internal Server Error';

        if (isHttpException) {
            const exceptionResponse = exception.getResponse();
            status = exception.getStatus();
            message = (typeof exceptionResponse === 'object' && exceptionResponse !== null && 'message' in exceptionResponse) ? exceptionResponse.message as string : 'Internal Server Error';
        }

        response.status(status).json({
            statusCode: status,
            message,
            timestamp: new Date().toISOString(),
            path: request.url
        })
    }
}
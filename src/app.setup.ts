import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { json } from 'express';
import cookieParser from 'cookie-parser';

/**
 * Everything that turns a bare Nest app into THIS app: proxy trust, security
 * headers, CORS, body limits, cookie parsing and validation.
 *
 * Extracted from main.ts so end-to-end tests can boot the same configuration they
 * deploy. A test app built straight from AppModule has no ValidationPipe and no
 * cookie parser, so it would quietly pass tests against an application that does
 * not exist in production.
 */
export function configureApp(app: NestExpressApplication): NestExpressApplication {
    const configService = app.get(ConfigService);

    // Must be set before any request is handled: req.ip, req.protocol and req.secure
    // all derive from it, and ThrottlerGuard keys its buckets on req.ip.
    app.set('trust proxy', configService.get<boolean | number | string>('auth.trustProxy')!);

    app.use(helmet());

    app.enableCors({
        origin: configService.get<string>('app.frontendUrl'),
        credentials: true,
    });

    app.use(json({ limit: '256kb' }));

    app.use(cookieParser());

    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
        }),
    );

    return app;
}

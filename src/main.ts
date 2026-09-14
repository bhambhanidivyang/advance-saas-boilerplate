import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { json } from 'express';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);

  // Must be set before any request is handled: req.ip, req.protocol and req.secure
  // all derive from it, and ThrottlerGuard keys its buckets on req.ip.
  app.set('trust proxy', configService.get<boolean | number | string>('auth.trustProxy')!);

  app.use(helmet());

  app.enableCors({
    origin: configService.get<string>('app.frontendUrl'),
    credentials: true
  });

  app.use(json({
    limit: '256kb'
  }));

  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true
    })
  );

  app.enableShutdownHooks();

  await app.listen(configService.get<number>('app.port')!);
}
bootstrap();

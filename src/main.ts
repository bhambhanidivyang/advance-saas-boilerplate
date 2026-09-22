import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // Shared with the e2e harness so tests exercise the deployed configuration.
  configureApp(app);

  app.enableShutdownHooks();

  await app.listen(app.get(ConfigService).get<number>('app.port')!);
}
bootstrap();

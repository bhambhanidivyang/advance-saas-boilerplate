import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import { ConfigModule, ConfigService } from '@nestjs/config';
import configuration from './config/configuration'
import { envValidationSchema } from './config/env.validation';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { LoggerModule } from 'nestjs-pino';
import { HealthModule } from './health/health.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { BullModule } from '@nestjs/bullmq';
import { EmailModule } from './email/email.module';
import crypto from 'node:crypto';
import { JwtModule } from '@nestjs/jwt';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { PasswordChangeRequiredGuard } from './common/guards/password-change-required.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema: envValidationSchema,
      cache: true
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            name: 'default',
            ttl: config.get<number>('throttling.default.ttl')!,
            limit: config.get<number>('throttling.default.limit')!
          },
          {
            name: 'auth',
            ttl: config.get<number>('throttling.auth.ttl')!,
            limit: config.get<number>('throttling.auth.limit')!
          },
          {
            name: 'otp',
            ttl: config.get<number>('throttling.otp.ttl')!,
            limit: config.get<number>('throttling.otp.limit')!
          }
        ],
        storage: new ThrottlerStorageRedisService(
          config.get<string>('redis.url')!
        )
      })
    }),
    LoggerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        pinoHttp: {
          level: config.get<string>('app.environment') === 'production' ? 'info' : 'debug',
          transport:
            process.env.NODE_ENV !== 'production'
            ? {
                target: 'pino-pretty',
                options: {
                  colorize: true,
                  singleLine: true,
                  translateTime: 'SYS:standard',
                  levelFirst: true,
                  messageFormat: '{msg}',
                  ignore: 'pid,hostname',
                },
              }
            : undefined,
          genReqId: (req) => {
            const incoming = req.headers['x-request-id'];
            if (
              typeof incoming === 'string' &&
              incoming.length <= 100
            ) {
              return incoming;
            }        
            return crypto.randomUUID();
          },
          redact: {
            paths: [
              'req.headers.authorization',
              'req.headers.cookie',
              'req.body.password',
              'req.body.currentPassword',
              'req.body.newPassword',
              'req.body.passwordHash',
              'req.body.otp',
              'req.body.verificationCode',
              'req.body.refreshToken',
              'req.body.accessToken',
              'req.body.token',
              'req.body.tokenHash',
              'req.body.rawToken',
              'req.body.clientSecret',
              'req.body.apiKey',
              'req.body.idToken',
              'req.body.nonce',
            ],
            censor: '[REDACTED]'
          }
        }
      })
    }),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow('auth.jwt.accessSecret')
      }),
    }),
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        connection: {
          url: configService.get<string>('redis.url')!
        }
      }),
    }),
    HealthModule,
    PrismaModule,
    AuthModule,
    EmailModule
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: GlobalExceptionFilter
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard
    },
    {
      // After JwtAuthGuard: it reads the user that guard attaches.
      provide: APP_GUARD,
      useClass: PasswordChangeRequiredGuard
    }
  ]
})
export class AppModule {}

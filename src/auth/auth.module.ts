import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './providers/auth.service';
import { EmailModule } from 'src/email/email.module';
import { TokenService } from './providers/token.service';
import { SessionService } from './providers/session.service';
import { SessionDenylistService } from './providers/session-denylist.service';
import { PasswordService } from './providers/password.service';

@Module({
  imports: [EmailModule],
  controllers: [AuthController],
  providers: [AuthService, TokenService, SessionService, SessionDenylistService, PasswordService],
  exports: [TokenService, SessionService, SessionDenylistService]
})
export class AuthModule {}

import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { EmailModule } from 'src/email/email.module';
import { TokenService } from './session/token.service';
import { SessionService } from './session/session.service';
import { SessionDenylistService } from './session/session-denylist.service';
import { PasswordService } from './password/password.service';
import { PasswordAuthenticatorService } from './password/password-authenticator.service';
import { GoogleTokenVerifier } from './google/google-token-verifier';
import { IdentityService } from './identity/identity.service';
import { GoogleAuthenticatorService } from './google/google-authenticator.service';
import { GoogleNonceService } from './google/google-nonce.service';

@Module({
  imports: [EmailModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    TokenService,
    SessionService,
    SessionDenylistService,
    PasswordService,
    PasswordAuthenticatorService,
    GoogleTokenVerifier,
    IdentityService,
    GoogleAuthenticatorService,
    GoogleNonceService
  ],
  exports: [TokenService, SessionService, SessionDenylistService]
})
export class AuthModule {}

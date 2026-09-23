import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { MeetsPasswordPolicy } from 'src/auth/password/validation/meets-password-policy.decorator';

export class ChangePasswordDto {
    // An EXISTING password, so no policy rules — only a length bound, because an
    // unbounded string handed to argon2 is a cheap CPU-exhaustion vector.
    @IsString()
    @IsNotEmpty()
    @MaxLength(128)
    currentPassword: string;

    @MeetsPasswordPolicy()
    newPassword: string;
}

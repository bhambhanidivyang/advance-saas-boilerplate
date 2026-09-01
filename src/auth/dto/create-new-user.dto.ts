import { IsEmail, IsString, IsNotEmpty, MinLength, MaxLength, IsOptional, Matches } from "class-validator";
import { Transform } from "class-transformer";
import { isNotCommonPassword } from "src/common/decorators/is-not-common-password.decorator";
import { isNotBreachedPassword } from "src/common/decorators/is-not-breached.decorator";

export class CreateNewUser {
    @IsString({ message: 'First name must be a string.' })
    @IsNotEmpty({ message: 'First name is required.' })
    @MinLength(1, { message: 'First name must be at least 1 character.' })
    @MaxLength(50, { message: 'First name must not exceed 50 characters.' })
    @Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
    firstName: string;

    @IsString({ message: 'Last name must be a string.' })
    @IsNotEmpty({ message: 'Last name is required.' })
    @MinLength(1, { message: 'Last name must be at least 1 character.' })
    @MaxLength(50, { message: 'Last name must not exceed 50 characters.' })
    @Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
    lastName: string;

    @IsOptional()
    @IsString({ message: 'Display name must be a string.' })
    @MinLength(2, { message: 'Display name must be at least 2 characters.' })
    @MaxLength(50, { message: 'Display name must not exceed 50 characters.' })
    @Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
    displayName: string;

    @IsEmail({}, { message: 'Please provide a valid email address.' })
    @IsNotEmpty({ message: 'Email is required.' })
    @MaxLength(255, { message: 'Email must not exceed 255 characters.' })
    @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
    email: string;

    @IsString({ message: 'Password must be a string.' })
    @IsNotEmpty({ message: 'Password is required.' })
    @MinLength(8, { message: 'Password must be at least 8 characters long.' })
    @MaxLength(128, { message: 'Password must not exceed 128 characters.' })
    @Matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
        {
        message:
            'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
        },
    )
    @isNotCommonPassword({
        message: 'This password is on a common blocklist and cannot be used.',
      })
    @isNotBreachedPassword({
        message: 'This password has been exposed in a global data breach. Please pick a different one.',
    })
    password: string;
}
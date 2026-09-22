import { IsEmail, IsString, IsNotEmpty, MinLength, MaxLength, IsOptional } from "class-validator";
import { MeetsPasswordPolicy } from "src/common/decorators/meets-password-policy.decorator";
import { Transform } from "class-transformer";

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

    @MeetsPasswordPolicy()
    password: string;
}
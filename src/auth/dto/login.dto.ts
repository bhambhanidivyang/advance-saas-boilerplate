import { Transform } from "class-transformer";
import { IsEmail, IsString, MaxLength, MinLength } from "class-validator";

export class LoginDto {
    @IsEmail()
    @Transform(({value}) => value?.trim().toLowerCase())
    email: string;

    @IsString()
    @MinLength(8)
    @MaxLength(128)
    password: string;
}
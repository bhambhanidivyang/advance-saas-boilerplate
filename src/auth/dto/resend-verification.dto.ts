import { IsEmail } from "class-validator";

export class ResendVerification {
    @IsEmail()
    email: string;
}
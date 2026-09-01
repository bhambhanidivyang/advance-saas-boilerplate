import { Body, Controller, Post } from '@nestjs/common';
import { CreateNewUser } from './dto/create-new-user.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}
    @Post('register')
    async register (@Body() body: CreateNewUser) {
        return await this.authService.register(body);
    }
}

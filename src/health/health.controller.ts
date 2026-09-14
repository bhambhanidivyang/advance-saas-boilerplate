import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Public } from 'src/common/decorators/public.decorator';
import { PrismaService } from 'src/prisma/prisma.service';

@Public()
@SkipThrottle({ auth: true, otp: true })
@Controller('health')
export class HealthController {
    constructor(private readonly prisma: PrismaService) {}
    @Get()
    async health() {
        await this.prisma.$queryRaw`SELECT 1`;

        return {
        status: 'ok',
        database: 'ok',
        };
    }
}

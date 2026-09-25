import { Injectable } from "@nestjs/common";
import { generateRawToken, generateTokenHash } from "../utils/token.util";
import { AuthProvider } from "src/generated/prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { GoogleNonceInvalidError } from "./google-nonce-invalid.error";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class GoogleNonceService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly config: ConfigService
    ) {}

    /** Issues a single-use value the client hands to Google; only its hash is kept. */
    async issue(now: Date): Promise<{ nonce: string; expiresAt: Date }> {
        const nonce = generateRawToken();
        const expiresAt = new Date(
            now.getTime() + this.config.getOrThrow<number>('auth.google.nonceTtlSeconds') * 1000,
        );

        await this.prisma.authNonce.create({
            data: {
                provider: AuthProvider.GOOGLE,
                nonceHash: generateTokenHash(nonce),
                expiresAt,
            },
        });

        return { nonce, expiresAt };
    }

    /**
     * Single use is enforced by the conditional update, not by reading first: two
     * requests replaying one nonce cannot both see a row count of 1. Same technique
     * as refresh-token rotation.
     */
    async consume(nonce: string, now: Date): Promise<void> {
        const { count } = await this.prisma.authNonce.updateMany({
            where: {
                nonceHash: generateTokenHash(nonce),
                provider: AuthProvider.GOOGLE,
                usedAt: null,
                expiresAt: { gt: now },
            },
            data: { usedAt: now },
        });

        if (count !== 1) {
            throw new GoogleNonceInvalidError('Invalid nonce');
        }
    }
}

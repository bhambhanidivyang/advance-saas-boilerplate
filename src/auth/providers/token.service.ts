import { ConfigService } from "@nestjs/config";
import { AccessTokenClaims, MintAccessTokenArgs } from "../interfaces/access-token-claims.interface";
import { JwtService } from "@nestjs/jwt";
import { randomUUID } from "node:crypto";
import { Injectable } from "@nestjs/common";

@Injectable()
export class TokenService {
    private readonly secret: string;
    private readonly issuer: string;
    private readonly audience: string;
    private readonly ttlSeconds: number;
    private readonly kid: string;

    constructor(
        private readonly config: ConfigService,
        private readonly jwt: JwtService
    ) {
        this.secret = config.getOrThrow<string>('auth.jwt.accessSecret');
        this.issuer = config.getOrThrow<string>('auth.jwt.issuer');
        this.audience = config.getOrThrow<string>('auth.jwt.audience');
        this.ttlSeconds = config.getOrThrow<number>('auth.jwt.accessTtlSeconds');
        this.kid = config.getOrThrow<string>('auth.jwt.accessKid');
    }

    async generateAccessToken(args: MintAccessTokenArgs): Promise<{ accessToken: string; expiresIn: number }> {
        const { userId, sessionId, tokenFamilyId, emailVerified, authMethod} = args;

        const accessToken = await this.jwt.signAsync({
            sid: sessionId,
            fam: tokenFamilyId,
            ev: emailVerified,
            amr: [authMethod],
            jti: randomUUID(),
        },
        {
            secret: this.secret,
            algorithm: 'HS256',
            subject: userId,
            issuer: this.issuer,
            audience: this.audience,
            expiresIn: this.ttlSeconds,
            keyid: this.kid,   // enables key rotation without a code change
        });

        return { accessToken, expiresIn: this.ttlSeconds };
    }

    async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
        return this.jwt.verifyAsync<AccessTokenClaims>(token, {
            secret: this.secret,
            algorithms: ['HS256'],
            issuer: this.issuer,
            audience: this.audience,
            clockTolerance: 5
        });
    }
}
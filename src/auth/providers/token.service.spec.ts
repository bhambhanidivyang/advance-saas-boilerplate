import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { TokenService } from './token.service';
import { AuthMethod } from 'src/generated/prisma/client';

const SECRET = 'test-secret-at-least-32-characters-long!!';
const OTHER_SECRET = 'a-completely-different-secret-32-chars!!!';
const ISSUER = 'mynest-api-test';
const AUDIENCE = 'mynest-app-test';
const TTL = 600;
const KID = 'v1';

const mintArgs = {
    userId: 'user-1',
    sessionId: 'session-1',
    tokenFamilyId: 'family-1',
    emailVerified: true,
    authMethod: AuthMethod.PASSWORD,
};

describe('TokenService', () => {
    let service: TokenService;
    let jwt: JwtService;

    beforeEach(async () => {
        const config = {
            getOrThrow: jest.fn((key: string) => {
                switch (key) {
                    case 'auth.jwt.accessSecret': return SECRET;
                    case 'auth.jwt.accessTtlSeconds': return TTL;
                    case 'auth.jwt.issuer': return ISSUER;
                    case 'auth.jwt.audience': return AUDIENCE;
                    case 'auth.jwt.accessKid': return KID;
                    default: throw new Error(`Unexpected config key: ${key}`);
                }
            }),
        };

        const module: TestingModule = await Test.createTestingModule({
            imports: [JwtModule.register({})],
            providers: [
                TokenService,
                { provide: ConfigService, useValue: config },
            ],
        }).compile();

        service = module.get<TokenService>(TokenService);
        jwt = module.get<JwtService>(JwtService);
    });

    describe('generateAccessToken', () => {
        it('mints a token that verifies and carries every expected claim', async () => {
            const { accessToken, expiresIn } = await service.generateAccessToken(mintArgs);

            expect(expiresIn).toBe(TTL);

            const claims = await service.verifyAccessToken(accessToken);
            expect(claims.sub).toBe('user-1');
            expect(claims.sid).toBe('session-1');
            expect(claims.fam).toBe('family-1');
            expect(claims.ev).toBe(true);
            expect(claims.amr).toEqual([AuthMethod.PASSWORD]);
            expect(claims.iss).toBe(ISSUER);
            expect(claims.aud).toBe(AUDIENCE);
            expect(claims.jti).toEqual(expect.any(String));
            expect(claims.exp - claims.iat).toBe(TTL);
        });

        it('stamps the kid header so keys can be rotated without a code change', async () => {
            const { accessToken } = await service.generateAccessToken(mintArgs);
            const header = JSON.parse(
                Buffer.from(accessToken.split('.')[0], 'base64url').toString(),
            );

            expect(header.alg).toBe('HS256');
            expect(header.kid).toBe(KID);
        });

        it('gives every token a distinct jti', async () => {
            const first = await service.generateAccessToken(mintArgs);
            const second = await service.generateAccessToken(mintArgs);

            const a = await service.verifyAccessToken(first.accessToken);
            const b = await service.verifyAccessToken(second.accessToken);

            expect(a.jti).not.toBe(b.jti);
        });

        it('propagates emailVerified: false rather than defaulting it', async () => {
            const { accessToken } = await service.generateAccessToken({ ...mintArgs, emailVerified: false });
            const claims = await service.verifyAccessToken(accessToken);

            expect(claims.ev).toBe(false);
        });
    });

    describe('verifyAccessToken', () => {
        // The single most important test here: without `algorithms: ['HS256']` on
        // verify, the token's own header chooses how it gets validated.
        it('rejects an unsigned "alg: none" forgery', async () => {
            const now = Math.floor(Date.now() / 1000);
            const header = Buffer.from(
                JSON.stringify({ alg: 'none', typ: 'JWT' }),
            ).toString('base64url');
            const payload = Buffer.from(
                JSON.stringify({
                    sub: 'attacker',
                    sid: 'forged-session',
                    fam: 'forged-family',
                    ev: true,
                    amr: [AuthMethod.PASSWORD],
                    iss: ISSUER,
                    aud: AUDIENCE,
                    iat: now,
                    exp: now + TTL,
                }),
            ).toString('base64url');

            await expect(
                service.verifyAccessToken(`${header}.${payload}.`),
            ).rejects.toThrow();
        });

        it('rejects a token signed with a different secret', async () => {
            const forged = await jwt.signAsync(
                { sid: 's', fam: 'f', ev: true, amr: [AuthMethod.PASSWORD] },
                {
                    secret: OTHER_SECRET,
                    algorithm: 'HS256',
                    subject: 'attacker',
                    issuer: ISSUER,
                    audience: AUDIENCE,
                    expiresIn: TTL,
                },
            );

            await expect(service.verifyAccessToken(forged)).rejects.toThrow();
        });

        it('rejects a token issued by someone else', async () => {
            const wrongIssuer = await jwt.signAsync(
                { sid: 's', fam: 'f', ev: true, amr: [AuthMethod.PASSWORD] },
                {
                    secret: SECRET,
                    algorithm: 'HS256',
                    subject: 'user-1',
                    issuer: 'some-other-service',
                    audience: AUDIENCE,
                    expiresIn: TTL,
                },
            );

            await expect(service.verifyAccessToken(wrongIssuer)).rejects.toThrow();
        });

        it('rejects a token minted for a different audience', async () => {
            const wrongAudience = await jwt.signAsync(
                { sid: 's', fam: 'f', ev: true, amr: [AuthMethod.PASSWORD] },
                {
                    secret: SECRET,
                    algorithm: 'HS256',
                    subject: 'user-1',
                    issuer: ISSUER,
                    audience: 'some-other-app',
                    expiresIn: TTL,
                },
            );

            await expect(service.verifyAccessToken(wrongAudience)).rejects.toThrow();
        });

        it('rejects an expired token beyond the clock tolerance', async () => {
            const expired = await jwt.signAsync(
                { sid: 's', fam: 'f', ev: true, amr: [AuthMethod.PASSWORD] },
                {
                    secret: SECRET,
                    algorithm: 'HS256',
                    subject: 'user-1',
                    issuer: ISSUER,
                    audience: AUDIENCE,
                    expiresIn: -30,
                },
            );

            await expect(service.verifyAccessToken(expired)).rejects.toThrow(/expired/i);
        });

        it('rejects a structurally invalid token', async () => {
            await expect(service.verifyAccessToken('not-a-jwt')).rejects.toThrow();
        });
    });
});

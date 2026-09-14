import { ConfigService } from "@nestjs/config";
import { CreateSessionArgs, IssuedSession, RotationOutcome } from "../interfaces/session.interface";
import { PrismaService } from "src/prisma/prisma.service";
import { TokenService } from "./token.service";
import { SessionDenylistService } from "./session-denylist.service";
import { generateRawToken, generateTokenHash } from "../utils/token.util";
import { normalizeIpAddress } from "src/common/utils/ip.util";
import { logAuditEvent } from 'src/common/audit/log-auth-event';
import { AuthEventType, AuthMethod, SessionRevocationReason, UserStatus } from "src/generated/prisma/enums";
import { Prisma } from "src/generated/prisma/client";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthContext } from "../interfaces/auth-context.interface";
import { GENERIC_REFRESH_FAILURE, REFRESH_FAILURE_REASON } from "../constants/auth.constants";

@Injectable()
export class SessionService {
    constructor(
        private readonly config: ConfigService,
        private readonly prisma: PrismaService,
        private readonly tokenService: TokenService,
        private readonly denylist: SessionDenylistService,
    ) {}

    async createSession(args: CreateSessionArgs): Promise<IssuedSession> {
        // Read max active sessions per user
        const maxSessions = this.config.getOrThrow<number>('auth.session.maxActivePerUser');
        // Read absoluteTtlSeconds from session config
        const absoluteTtl = this.config.getOrThrow<number>('auth.session.absoluteTtlSeconds');

        const now = new Date();

        // compute session expiry
        const sessionExpiresAt = new Date(now.getTime() + absoluteTtl * 1000);

        const result = await this.prisma.$transaction(async (tx) => {
            // Only sessions that are actually usable count toward the cap: a session
            // past its absolute expiry is dead even though the lazy sweep has not
            // marked it yet, and should not block a new login.
            const activeSessions = await tx.session.findMany({
                where: { userId: args.userId, revokedAt: null, expiresAt: { gt: now } },
                select: { id: true },
                orderBy: { lastUsedAt: 'asc' },
            });

            // Evict the least recently used rather than rejecting the login: the
            // password was correct, and a blocked user has no way to free a slot
            // (logging out elsewhere needs a session they cannot get).
            let evictedSessionIds: string[] = [];
            const evictCount = activeSessions.length - maxSessions + 1;
            if (evictCount > 0) {
                const evictedIds = activeSessions.slice(0, evictCount).map((s) => s.id);
                await tx.session.updateMany({
                    where: { id: { in: evictedIds }, revokedAt: null },
                    data: {
                        revokedAt: now,
                        revocationReason: SessionRevocationReason.SESSION_LIMIT,
                    },
                });
                await tx.sessionRefreshToken.updateMany({
                    where: { sessionId: { in: evictedIds }, revokedAt: null },
                    data: { revokedAt: now },
                });
                await logAuditEvent({
                    tx,
                    userId: args.userId,
                    eventType: AuthEventType.SESSION_REVOKED,
                    ipAddress: args.context.ipAddress,
                    userAgent: args.context.userAgent,
                    metadata: {
                        deviceId: args.context.deviceId,
                        maxActivePerUser: maxSessions,
                        evictedSessionIds: evictedIds,
                    },
                });
            }

            // create session
            const session = await tx.session.create({
                data: {
                    userId: args.userId,
                    expiresAt: sessionExpiresAt,
                    ipAddress: normalizeIpAddress(args.context.ipAddress),
                    userAgent: args.context.userAgent,
                    deviceId: args.context.deviceId,
                    deviceName: null,
                    authMethod: args.authMethod
                },
                select: { id: true, tokenFamilyId: true },
            });

            // create refresh token
            const refresh = await this.createRefreshToken(tx, session.id, sessionExpiresAt, now);

            // log audit event
            await logAuditEvent({
                tx,
                userId: args.userId,
                sessionId: session.id,
                eventType: AuthEventType.LOGIN_SUCCESS,
                authMethod: args.authMethod,
                ipAddress: args.context.ipAddress,
                userAgent: args.context.userAgent,
                metadata: {deviceId: args.context.deviceId}
            });

            // return info to be used for further ops
            return {
                evictedSessionIds,
                sessionId: session.id,
                tokenFamilyId: session.tokenFamilyId,
                refreshToken: refresh.refreshToken,
                refreshTokenExpiresAt: refresh.refreshTokenExpiresAt,
            }
        });

        // After commit: an entry written inside the transaction would survive a
        // rollback and lock the user out of a session that is still live.
        await this.denylist.revoke(result.evictedSessionIds);
        // create access token
        const token = await this.tokenService.generateAccessToken({
            userId: args.userId,
            sessionId: result.sessionId,
            tokenFamilyId: result.tokenFamilyId,
            emailVerified: args.emailVerified,
            authMethod: args.authMethod,
        });

        // return issued session
        return {
            sessionId: result.sessionId,
            tokenFamilyId: result.tokenFamilyId,
            accessToken: token.accessToken,
            expiresIn: token.expiresIn,
            refreshToken: result.refreshToken,
            refreshTokenExpiresAt: result.refreshTokenExpiresAt,
        }
    }

    /**
     * Exchanges a refresh token for a new token pair, rotating the refresh token.
     *
     * Every decision happens inside ONE transaction that RETURNS an outcome rather
     * than throwing: the rejection paths write the lazy expiry sweep and the family
     * revocation, and a throw would roll those back — leaving a stolen token live.
     * The 401 is raised after the transaction has committed.
     */
    async rotateRefreshToken(rawToken: string, context: AuthContext): Promise<IssuedSession> {
        // get grace seconds from config
        const graceSeconds = this.config.getOrThrow<number>('auth.session.refreshReuseGraceSeconds');

        const now = new Date();

        // generate token hash from rawtoken
        const tokenHash = generateTokenHash(rawToken);

        const outcome = await this.prisma.$transaction<RotationOutcome>(async (tx) => {
            // read stored refresh token
            const stored = await tx.sessionRefreshToken.findUnique({
                where: { tokenHash },
                select: {
                    id: true,
                    usedAt: true,
                    revokedAt: true,
                    expiresAt: true,
                    session: {
                        select: {
                            id: true,
                            userId: true,
                            tokenFamilyId: true,
                            authMethod: true,
                            expiresAt: true,
                            revokedAt: true,
                            user: { select: { status: true } },
                        },
                    },
                },
            });

            // Unknown token: no writes, and no hint to the caller that it was unknown.
            if (!stored) {
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.TOKEN_NOT_FOUND };
            }

            const session = stored.session;

            // Already dead — nothing left to revoke, and not a theft signal.
            if (session.revokedAt) {
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.SESSION_REVOKED };
            }

            // Absolute lifetime reached. Swept lazily here so expired sessions do not
            // need a background job to be marked; this write must commit.
            if (session.expiresAt <= now) {
                await tx.session.updateMany({
                    where: { id: session.id, revokedAt: null },
                    data: { revokedAt: now, revocationReason: SessionRevocationReason.EXPIRED },
                });
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.SESSION_EXPIRED };
            }

            // Re-checked on every refresh: otherwise a suspended user keeps renewing
            // for the remaining 30 days of their session.
            if (session.user.status !== UserStatus.ACTIVE) {
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.USER_NOT_ACTIVE };
            }

            if (stored.revokedAt) {
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.TOKEN_REVOKED };
            }

            // Idle timeout: the refresh token's own lifetime, shorter than the session's.
            if (stored.expiresAt <= now) {
                return { kind: 'REJECTED', reason: REFRESH_FAILURE_REASON.TOKEN_EXPIRED };
            }

            let graceReplay = false;

            // If stored token is already consumed
            if (stored.usedAt) {
                if (!this.isWithinGrace(stored.usedAt, now, graceSeconds)) {
                    const revokedSessionIds = await this.revokeTokenFamily(
                        tx, session, stored.id, stored.usedAt, now, context,
                    );
                    return {
                        kind: 'REJECTED',
                        reason: REFRESH_FAILURE_REASON.TOKEN_REUSE,
                        revokedSessionIds,
                    };
                }
                // Benign double-submit: two in-flight requests from the same client.
                graceReplay = true;
            } 
            // If stored token is not consumed
            else {
                // The single-use guarantee: whoever flips usedAt from null wins. Under
                // Read Committed the loser's UPDATE waits for the winner to commit,
                // re-checks the WHERE, and matches zero rows.
                const consumed = await tx.sessionRefreshToken.updateMany({
                    where: { id: stored.id, usedAt: null },
                    data: { usedAt: now },
                });

                if (consumed.count === 0) {
                    const winner = await tx.sessionRefreshToken.findUnique({
                        where: { id: stored.id },
                        select: { usedAt: true },
                    });

                    if (!winner?.usedAt || !this.isWithinGrace(winner.usedAt, now, graceSeconds)) {
                        const revokedSessionIds = await this.revokeTokenFamily(
                            tx, session, stored.id, winner?.usedAt ?? null, now, context,
                        );
                        return {
                            kind: 'REJECTED',
                            reason: REFRESH_FAILURE_REASON.TOKEN_REUSE,
                            revokedSessionIds,
                        };
                    }
                    graceReplay = true;
                }
            }

            // A grace replay mints a second child of the same parent rather than
            // re-issuing the first child: only its hash was stored, so the original
            // raw token is unrecoverable by design. Both children are valid and tied
            // to this session; the client keeps whichever response lands last.
            const refresh = await this.createRefreshToken(tx, session.id, session.expiresAt, now);

            await tx.session.update({
                where: { id: session.id },
                data: {
                    lastUsedAt: now,
                    lastRefreshedAt: now,
                    ipAddress: normalizeIpAddress(context.ipAddress),
                    userAgent: context.userAgent,
                },
            });

            // Read fresh rather than trusting the old token's claim, so verifying an
            // email propagates into the next access token instead of staying stale
            // for the life of the session.
            const primaryEmail = await tx.userEmail.findFirst({
                where: { userId: session.userId, isPrimary: true },
                select: { isVerified: true },
            });

            await logAuditEvent({
                tx,
                userId: session.userId,
                sessionId: session.id,
                eventType: AuthEventType.TOKEN_REFRESH,
                authMethod: session.authMethod,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                metadata: { deviceId: context.deviceId, graceReplay },
            });

            return {
                kind: 'ROTATED',
                userId: session.userId,
                sessionId: session.id,
                tokenFamilyId: session.tokenFamilyId,
                authMethod: session.authMethod,
                emailVerified: primaryEmail?.isVerified ?? false,
                refreshToken: refresh.refreshToken,
                refreshTokenExpiresAt: refresh.refreshTokenExpiresAt,
                graceReplay,
            };
        });

        if (outcome.kind === 'REJECTED') {
            await this.denylist.revoke(outcome.revokedSessionIds ?? []);

            // One message for every rejection. Telling the caller whether a token was
            // unknown, expired or reused is reconnaissance for someone probing a
            // stolen token; the distinction lives in the audit log only.
            throw new UnauthorizedException(GENERIC_REFRESH_FAILURE);
        }

        const token = await this.tokenService.generateAccessToken({
            userId: outcome.userId,
            sessionId: outcome.sessionId,
            tokenFamilyId: outcome.tokenFamilyId,
            emailVerified: outcome.emailVerified,
            authMethod: outcome.authMethod,
        });

        return {
            sessionId: outcome.sessionId,
            tokenFamilyId: outcome.tokenFamilyId,
            accessToken: token.accessToken,
            expiresIn: token.expiresIn,
            refreshToken: outcome.refreshToken,
            refreshTokenExpiresAt: outcome.refreshTokenExpiresAt,
        };
    }

    private isWithinGrace(usedAt: Date, now: Date, graceSeconds: number): boolean {
        return now.getTime() - usedAt.getTime() <= graceSeconds * 1000;
    }

    /**
     * Creates one refresh token row and returns the raw value, which is the only
     * moment it exists — the database keeps just its hash. Shared by login and
     * rotation so the clamp and the hashing cannot drift apart between them.
     */
    private async createRefreshToken(
        tx: Prisma.TransactionClient,
        sessionId: string,
        sessionExpiresAt: Date,
        now: Date,
    ): Promise<{ refreshToken: string; refreshTokenExpiresAt: Date }> {
        const refreshTtl = this.config.getOrThrow<number>('auth.session.refreshTtlSeconds');

        const refreshToken = generateRawToken();
        // Clamped to the session: a refresh token must never outlive the session it
        // belongs to, or the absolute lifetime is not actually absolute.
        const refreshTokenExpiresAt = new Date(
            Math.min(now.getTime() + refreshTtl * 1000, sessionExpiresAt.getTime()),
        );

        await tx.sessionRefreshToken.create({
            data: {
                sessionId,
                tokenHash: generateTokenHash(refreshToken),
                expiresAt: refreshTokenExpiresAt,
            },
        });

        return { refreshToken, refreshTokenExpiresAt };
    }

    /**
     * A used token replayed outside the grace window means two parties hold it.
     * Assume theft and revoke the whole family, not just this session.
     */
    private async revokeTokenFamily(
        tx: Prisma.TransactionClient,
        session: { id: string; userId: string; tokenFamilyId: string; authMethod: AuthMethod },
        presentedTokenId: string,
        presentedTokenUsedAt: Date | null,
        now: Date,
        context: AuthContext,
    ): Promise<string[]> {
        await tx.session.updateMany({
            where: {
                userId: session.userId,
                tokenFamilyId: session.tokenFamilyId,
                revokedAt: null,
            },
            data: { revokedAt: now, revocationReason: SessionRevocationReason.TOKEN_REUSE },
        });

        const familySessions = await tx.session.findMany({
            where: { userId: session.userId, tokenFamilyId: session.tokenFamilyId },
            select: { id: true },
        });

        await tx.sessionRefreshToken.updateMany({
            where: {
                sessionId: { in: familySessions.map((familySession) => familySession.id) },
                revokedAt: null,
            },
            data: { revokedAt: now },
        });

        await logAuditEvent({
            tx,
            userId: session.userId,
            sessionId: session.id,
            eventType: AuthEventType.TOKEN_REUSE_DETECTED,
            authMethod: session.authMethod,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            metadata: {
                deviceId: context.deviceId,
                tokenFamilyId: session.tokenFamilyId,
                presentedTokenId,
                presentedTokenUsedAt: presentedTokenUsedAt?.toISOString() ?? null,
                revokedSessions: familySessions.length,
            },
        });

        return familySessions.map((familySession) => familySession.id);
    }

    /**
     * Revokes one session and every refresh token under it.
     *
     * Idempotent by design: logging out twice, or a retried request, must succeed
     * rather than 400. The `revokedAt: null` guard is what makes the second call a
     * no-op, and a no-op writes no audit event — a logout that did not happen
     * should not be recorded as one.
     *
     * Note the access token issued for this session stays valid until it expires
     * (auth.jwt.accessTtlSeconds). Revocation is immediate for refresh, eventual
     * for access; closing that gap needs the denylist behind
     * auth.session.denylistEnabled.
     */
    async revokeSession(sessionId: string, context: AuthContext): Promise<void> {
        const now = new Date();

        const wasRevoked = await this.prisma.$transaction(async (tx) => {
            const session = await tx.session.findUnique({
                where: { id: sessionId },
                select: { userId: true, authMethod: true },
            });

            if (!session) {
                return false;
            }

            const revoked = await tx.session.updateMany({
                where: { id: sessionId, revokedAt: null },
                data: { revokedAt: now, revocationReason: SessionRevocationReason.LOGOUT },
            });

            // Already revoked: nothing changed, so record nothing.
            if (revoked.count === 0) {
                return false;
            }

            // A session may legitimately have no unrevoked tokens left, so the count
            // here is not a reason to skip the audit event.
            await tx.sessionRefreshToken.updateMany({
                where: { sessionId, revokedAt: null },
                data: { revokedAt: now },
            });

            await logAuditEvent({
                tx,
                userId: session.userId,
                sessionId,
                eventType: AuthEventType.LOGOUT,
                authMethod: session.authMethod,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                metadata: { deviceId: context.deviceId },
            });

            return true;
        });

        if (wasRevoked) {
            await this.denylist.revoke([sessionId]);
        }
    }

    /**
     * Logout path for a client holding only the refresh cookie — which is the normal
     * case, since the access token may well have expired by the time someone clicks
     * log out. Resolving then revoking is safe without a shared transaction because
     * revocation is idempotent.
     */
    async revokeSessionByRefreshToken(rawToken: string, context: AuthContext): Promise<void> {
        const stored = await this.prisma.sessionRefreshToken.findUnique({
            where: { tokenHash: generateTokenHash(rawToken) },
            select: { sessionId: true },
        });

        if (!stored) {
            return;
        }

        await this.revokeSession(stored.sessionId, context);
    }

    /**
     * Revokes every active session for a user. Writes ONE audit event carrying the
     * count rather than one per session: this is a single user action.
     */
    async revokeAllSessions(
        userId: string,
        initiatingSessionId: string | undefined,
        context: AuthContext,
    ): Promise<number> {
        const now = new Date();

        // Ids are read first so the exact set revoked here is known: needed for the
        // denylist, and it keeps the token update from touching sessions that were
        // already revoked earlier.
        const revokedSessionIds = await this.prisma.$transaction(async (tx) => {
            const activeSessions = await tx.session.findMany({
                where: { userId, revokedAt: null },
                select: { id: true },
            });

            if (activeSessions.length === 0) {
                return [];
            }

            const sessionIds = activeSessions.map((session) => session.id);

            await tx.session.updateMany({
                where: { id: { in: sessionIds } },
                data: { revokedAt: now, revocationReason: SessionRevocationReason.LOGOUT_ALL },
            });

            await tx.sessionRefreshToken.updateMany({
                where: { sessionId: { in: sessionIds }, revokedAt: null },
                data: { revokedAt: now },
            });

            await logAuditEvent({
                tx,
                userId,
                sessionId: initiatingSessionId,
                eventType: AuthEventType.LOGOUT_ALL,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                metadata: {
                    deviceId: context.deviceId,
                    revokedCount: sessionIds.length,
                    initiatingSessionId: initiatingSessionId ?? null,
                },
            });

            return sessionIds;
        });

        await this.denylist.revoke(revokedSessionIds);

        return revokedSessionIds.length;
    }
}

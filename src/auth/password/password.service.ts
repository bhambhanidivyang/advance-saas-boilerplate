import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthEventType, SessionRevocationReason, UserStatus } from 'src/generated/prisma/client';
import { logAuditEvent } from 'src/common/audit/log-auth-event';
import { runUnitOfWork } from 'src/common/prisma/unit-of-work';
import { SessionService } from '../session/session.service';
import { hashPassword, verifyPassword } from './password-hash.util';
import { ChangePasswordArgs, ChangePasswordResult } from './password.interface';
import { CLEARED_LOCKOUT_STATE } from './password-lockout.constants';

/**
 * The password credential lifecycle: changing it now, resetting it next.
 *
 * Not an authentication mechanism. Nothing here produces an AuthenticationResult —
 * the caller of change-password is already authenticated. Authentication answers
 * "who is this?"; this service manages the proof itself.
 */
@Injectable()
export class PasswordService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly sessionService: SessionService,
    ) {}

    async changePassword(args: ChangePasswordArgs): Promise<ChangePasswordResult> {
        const { userId, sessionId, currentPassword, newPassword, context } = args;
        const now = new Date();

        const session = await this.prisma.session.findUnique({
            where: { id: sessionId },
            select: {
                userId: true,
                expiresAt: true,
                revokedAt: true,
                user: { select: { status: true, deletedAt: true, passwordHash: true } },
            },
        });

        // Re-checked against the database even though the guard verified the access
        // token: the guard is stateless, so a session revoked in the last few minutes
        // still carries a valid token. A credential change must not run on one.
        if (
            !session ||
            session.userId !== userId ||
            session.revokedAt ||
            session.expiresAt <= now ||
            session.user.status !== UserStatus.ACTIVE ||
            session.user.deletedAt
        ) {
            throw new UnauthorizedException({
                message: 'Session is no longer active',
                code: 'SESSION_REVOKED',
            });
        }

        const { passwordHash } = session.user;

        // An account created through an external provider has no password to change.
        // Setting a first password is a different flow with its own verification.
        if (!passwordHash) {
            throw new ForbiddenException({
                message: 'This account has no password to change',
                code: 'NO_PASSWORD_CREDENTIAL',
            });
        }

        // Re-authentication. A valid access token proves possession of a credential,
        // not that the person is at the keyboard now, so a credential change demands
        // fresh proof.
        //
        // 403 rather than 401 on purpose: clients treat 401 as "my session died, go
        // refresh", which is wrong here — the session is fine, the input is not.
        //
        // Not counted toward the lockout counter: that counter exists to stop
        // unauthenticated guessing, and counting here would let anything able to send
        // requests as this user (an XSS, say) lock the real owner out.
        if (!(await verifyPassword(currentPassword, passwordHash))) {
            throw new ForbiddenException({
                message: 'Current password is incorrect',
                code: 'INVALID_CURRENT_PASSWORD',
            });
        }

        if (newPassword === currentPassword) {
            throw new BadRequestException({
                message: 'New password must be different from the current password',
                code: 'PASSWORD_UNCHANGED',
            });
        }

        // argon2 is deliberately CPU-bound; never hold a transaction open across it.
        const newPasswordHash = await hashPassword(newPassword);

        // One unit of work: the credential, every other session, and this session's
        // refresh token change together or not at all.
        return runUnitOfWork(this.prisma, async (uow) => {
            await uow.tx.user.update({
                where: { id: userId },
                data: {
                    passwordHash: newPasswordHash,
                    passwordChangedAt: now,
                    mustChangePassword: false,
                    ...CLEARED_LOCKOUT_STATE,
                },
            });

            // Someone already holding a stolen refresh token for another device loses
            // it. The caller's own session is kept so they are not logged out of the
            // tab they just used. Denylisting happens after commit, queued by
            // revokeSessions itself.
            const revokedSessionIds = await this.sessionService.revokeSessions(
                uow,
                { userId, id: { not: sessionId } },
                SessionRevocationReason.PASSWORD_CHANGED,
                now,
            );

            // The surviving session keeps working, but any refresh token issued before
            // the change is retired.
            const reissued = await this.sessionService.reissueRefreshToken(
                uow,
                sessionId,
                session.expiresAt,
                now,
            );

            await logAuditEvent({
                tx: uow.tx,
                userId,
                sessionId,
                eventType: AuthEventType.PASSWORD_CHANGED,
                ipAddress: context.ipAddress,
                userAgent: context.userAgent,
                metadata: {
                    deviceId: context.deviceId,
                    revokedOtherSessions: revokedSessionIds.length,
                },
            });

            return { ...reissued, revokedSessions: revokedSessionIds.length };
        });
    }
}

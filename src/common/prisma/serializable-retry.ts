import { Logger } from 'nestjs-pino';
import { Prisma } from 'src/generated/prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

export interface SerializableRetryOptions {
    maxRetries?: number;
    logCode: string;
    logMessage: string;
}

/**
 * Runs `fn` in a Serializable transaction, retrying on Postgres serialization
 * failures (Prisma P2034).
 *
 * Note this only converts lost races into retries — single-use guarantees must
 * still come from the queries themselves (e.g. `update where { usedAt: null }`).
 */
export async function withSerializableRetry<T>(
    prisma: PrismaService,
    logger: Logger,
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
    options: SerializableRetryOptions,
): Promise<T> {
    const { maxRetries = 3, logCode, logMessage } = options;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await prisma.$transaction(fn, {
                isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
            });
        } catch (error) {
            if (
                error instanceof Prisma.PrismaClientKnownRequestError &&
                error.code === 'P2034' &&
                attempt < maxRetries - 1
            ) {
                logger.warn({ code: logCode, message: logMessage, attempt: attempt + 1 });
                continue;
            }
            throw error;
        }
    }

    throw new Error('Unreachable');
}

import { Prisma } from 'src/generated/prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

/**
 * A database transaction plus the side effects that must wait for it to commit.
 *
 * Some effects cannot be rolled back — a Redis write, an email, a published event.
 * Performed inside the transaction, they would survive a rollback and act on a
 * change that never happened. Code running in the transaction queues them with
 * afterCommit() instead, which also means it never has to return data out of the
 * transaction just so a caller can perform the effect later.
 */
export interface UnitOfWork {
    tx: Prisma.TransactionClient;
    afterCommit(effect: () => Promise<void>): void;
}

/**
 * Runs `work` in one transaction, then runs its queued effects in order once the
 * transaction has committed. If the transaction fails, the effects are discarded.
 *
 * Effects run after the commit is final, so they should handle their own failures:
 * one that throws surfaces as an error even though the data change already landed.
 */
export async function runUnitOfWork<T>(
    prisma: PrismaService,
    work: (uow: UnitOfWork) => Promise<T>,
): Promise<T> {
    const effects: Array<() => Promise<void>> = [];

    const result = await prisma.$transaction((tx) =>
        work({
            tx,
            afterCommit: (effect) => {
                effects.push(effect);
            },
        }),
    );

    for (const effect of effects) {
        await effect();
    }

    return result;
}

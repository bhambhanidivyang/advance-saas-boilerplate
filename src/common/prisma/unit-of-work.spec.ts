import { PrismaService } from 'src/prisma/prisma.service';
import { runUnitOfWork } from './unit-of-work';

describe('runUnitOfWork', () => {
    const tx = { marker: 'tx' };
    let events: string[];
    let prisma: { $transaction: jest.Mock };

    beforeEach(() => {
        events = [];
        prisma = {
            $transaction: jest.fn(async (work: (client: typeof tx) => Promise<unknown>) => {
                const result = await work(tx);
                events.push('commit');
                return result;
            }),
        };
    });

    it('runs queued effects only after the transaction commits', async () => {
        const result = await runUnitOfWork(prisma as unknown as PrismaService, async (uow) => {
            expect(uow.tx).toBe(tx);
            uow.afterCommit(async () => {
                events.push('effect');
            });
            events.push('work');
            return 'done';
        });

        expect(result).toBe('done');
        expect(events).toEqual(['work', 'commit', 'effect']);
    });

    // The reason the queue exists: an effect that cannot be rolled back must never
    // act on a change that was rolled back.
    it('discards queued effects when the transaction fails', async () => {
        const effect = jest.fn();

        await expect(
            runUnitOfWork(prisma as unknown as PrismaService, async (uow) => {
                uow.afterCommit(effect);
                throw new Error('write failed');
            }),
        ).rejects.toThrow('write failed');

        expect(effect).not.toHaveBeenCalled();
    });

    it('runs effects in the order they were queued', async () => {
        await runUnitOfWork(prisma as unknown as PrismaService, async (uow) => {
            uow.afterCommit(async () => {
                events.push('first');
            });
            uow.afterCommit(async () => {
                events.push('second');
            });
        });

        expect(events).toEqual(['commit', 'first', 'second']);
    });
});

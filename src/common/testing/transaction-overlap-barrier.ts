import { PrismaService } from 'src/prisma/prisma.service';

const BARRIER_TIMEOUT_MS = 10_000;

/**
 * Holds the first N $transaction calls until they have all arrived, then
 * releases them together so the database work actually overlaps.
 * Later retries (P2034) are not gated.
 *
 * Test-only helper. Shared by the integration specs that need genuine
 * concurrency against a real MVCC engine, which mocks cannot reproduce.
 */
export function installTransactionOverlapBarrier(
  prisma: PrismaService,
  overlappingCalls: number,
) {
  const originalTransaction = prisma.$transaction.bind(prisma);
  let firstWaveArrivals = 0;
  let firstWaveReleased = false;
  const waiting: Array<() => void> = [];
  let transactionCalls = 0;

  const spy = jest
    .spyOn(prisma, '$transaction')
    .mockImplementation((...args: unknown[]) => {
      transactionCalls += 1;

      const run = () =>
        (originalTransaction as (...inner: unknown[]) => Promise<unknown>)(
          ...args,
        );

      if (firstWaveReleased) {
        return run();
      }

      firstWaveArrivals += 1;
      if (firstWaveArrivals < overlappingCalls) {
        return Promise.race([
          new Promise<unknown>((resolve, reject) => {
            const timer = setTimeout(() => {
              reject(
                new Error(
                  `Concurrency barrier timed out after ${BARRIER_TIMEOUT_MS}ms`,
                ),
              );
            }, BARRIER_TIMEOUT_MS);

            waiting.push(() => {
              clearTimeout(timer);
              resolve(run());
            });
          }),
        ]);
      }

      firstWaveReleased = true;
      waiting.forEach((release) => release());
      return run();
    });

  return {
    getTransactionCalls: () => transactionCalls,
    restore: () => spy.mockRestore(),
  };
}

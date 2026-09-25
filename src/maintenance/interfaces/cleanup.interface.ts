/** Rows removed by one cleanup run, per table. */
export interface CleanupResult {
    deletedRefreshTokens: number;
    deletedUserTokens: number;
    deletedAuthNonces: number;
}

/** The repeatable cleanup job carries no payload: what to delete is configuration. */
export type CleanupJob = Record<string, never>;

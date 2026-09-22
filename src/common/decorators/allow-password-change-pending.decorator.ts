import { SetMetadata } from '@nestjs/common';

export const ALLOW_PASSWORD_CHANGE_PENDING = 'allowPasswordChangePending';

/**
 * Marks a route as reachable by a user who still has to change their password.
 *
 * Only the routes that let them resolve or escape that state qualify: changing the
 * password, and logging out. Everything else stays blocked, otherwise "must change
 * password" means nothing.
 */
export const AllowPasswordChangePending = () => SetMetadata(ALLOW_PASSWORD_CHANGE_PENDING, true);

import { applyDecorators } from '@nestjs/common';
import { IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { isNotCommonPassword } from './is-not-common-password.decorator';
import { isNotBreachedPassword } from './is-not-breached.decorator';

/**
 * The single password policy. Registration, change-password and (later) reset all
 * apply this, so a credential can never be set through a route with a weaker rule
 * than registration's.
 *
 * Only for a field holding a NEW password. Never apply it to one holding an
 * existing password (login, "current password"): policy governs what may be
 * created, and enforcing it on verification locks out anyone whose password
 * predates a policy change.
 *
 * Deliberately not named IsStrongPassword — class-validator exports a decorator by
 * that name, and an editor auto-import would silently pick the wrong one.
 */
export function MeetsPasswordPolicy(): PropertyDecorator {
    return applyDecorators(
        IsString({ message: 'Password must be a string.' }),
        IsNotEmpty({ message: 'Password is required.' }),
        MinLength(8, { message: 'Password must be at least 8 characters long.' }),
        MaxLength(128, { message: 'Password must not exceed 128 characters.' }),
        Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, {
            message:
                'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
        }),
        isNotCommonPassword({
            message: 'This password is on a common blocklist and cannot be used.',
        }),
        isNotBreachedPassword({
            message: 'This password has been exposed in a global data breach. Please pick a different one.',
        }),
    ) as PropertyDecorator;
}

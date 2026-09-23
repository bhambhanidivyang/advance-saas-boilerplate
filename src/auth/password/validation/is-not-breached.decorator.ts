import { ConfigService } from "@nestjs/config";
import { registerDecorator, ValidationArguments, ValidationOptions, ValidatorConstraint, ValidatorConstraintInterface } from "class-validator";
import { createHash } from "crypto";

@ValidatorConstraint({ name: 'isNotBreachedPassword', async: true })
export class IsNotBreachedValidatorConstraint implements ValidatorConstraintInterface {
    async validate(password: any, validationArguments?: ValidationArguments): Promise<boolean> {
        if (process.env.ENABLE_HIBP_CHECK !== 'true') return true;
        if (typeof password !== 'string') return false;
        // 1. Calculate SHA-1 hash of the password (uppercase hex string)
        const sha1Hash = createHash('sha1').update(password).digest('hex').toUpperCase();

        // 2. Extract 5-character prefix and remaining suffix
        const prefix = sha1Hash.substring(0,5);
        const suffix = sha1Hash.substring(5);

        // 3. Query HIBP range API
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: {
            'Add-Padding': 'true'
            }
        })

        if (!response.ok) {
            // Fail-open: If HIBP API has downtime/error, don't block registration
            return true;
        }

        // 4. Parse the text response body (ReadableStream to string)
        const bodyText = await response.text();

        // 5. Split line by line and check if our suffix exists
        const lines = bodyText.split(/\r?\n/);

        const isBreached = lines.some((line) => {
            const [hashSuffix, countStr] = line.split(':');
            return hashSuffix === suffix && parseInt(countStr,10) > 0;
        })

        return !isBreached;
        
    }

    defaultMessage(validationArguments?: ValidationArguments): string {
        return 'This password is known to be breached. Please pick another password.'    
    }
}

export function isNotBreachedPassword (validationOptions: ValidationOptions) {
    return function (object: object, propertyName: string) {
        registerDecorator({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            validator: IsNotBreachedValidatorConstraint
        })
    }
}
import { registerDecorator, ValidationArguments, ValidationOptions, ValidatorConstraint, ValidatorConstraintInterface } from "class-validator";
import { isCommonPassword } from "src/auth/password/validation/common-passwords.utils";

@ValidatorConstraint({ name: 'isNotCommonPassword', async: false })
export class IsNotCommonPasswordConstraint implements ValidatorConstraintInterface {
    async validate(password: any, validationArguments?: ValidationArguments): Promise<boolean> {
        if (process.env.ENABLE_COMMON_PASSWORD_CHECK !== 'true') return true;
        if (typeof password !== 'string') return false;

        return !isCommonPassword(password);
    }

    defaultMessage(validationArguments?: ValidationArguments): string {
        return 'This password is too common. Please enter a strong password.'
    }
}

export function isNotCommonPassword(validationOptions: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            target: object.constructor,
            propertyName,
            options: validationOptions,
            validator: IsNotCommonPasswordConstraint
        })
    }
}
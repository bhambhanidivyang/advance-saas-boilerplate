import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { AuthenticatedRequest, AuthenticatedUser } from "src/auth/interfaces/authenticated-request.interface";

export const CurrentUser = createParamDecorator((data: keyof AuthenticatedUser | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    return data ? request.user?.[data] : request.user;
})
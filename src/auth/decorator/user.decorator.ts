import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Role } from '@prisma/client';

export interface JwtPayload {
  id: string;
  role: Role;
  exp: number;
}

export const UserDecorator = createParamDecorator(
  (_data, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    return request.user;
  },
);

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../decorator/user.decorator';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private readonly jwt: JwtService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get('roles', context.getHandler());

    if (!roles) {
      return false;
    }

    const request = context.switchToHttp().getRequest();

    const accessTokenCookie = request.cookies.accessToken;

    const user: JwtPayload = this.jwt.decode(accessTokenCookie) as JwtPayload;

    return roles.some((role: Role): boolean => role == user?.role);
  }
}

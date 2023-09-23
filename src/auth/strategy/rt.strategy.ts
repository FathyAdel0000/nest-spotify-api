import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { User } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../decorator/user.decorator';

@Injectable()
export class RtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh-token',
) {
  constructor(
    configService: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([RtStrategy.extractJWT]),
      secretOrKey: configService.get('REFRESH_TOKEN_SECRET'),
    });
  }

  private static extractJWT(req: Request): string | null {
    if (req.cookies && 'refreshToken' in req.cookies) {
      return req.cookies.refreshToken;
    }
    return null;
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    const user: User = await this.prisma.user.findUnique({
      where: { id: payload.id },
    });
    if (!user) {
      throw new ForbiddenException('Token is not valid!');
    }
    return payload;
  }
}

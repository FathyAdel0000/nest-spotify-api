import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { User } from '@prisma/client';
import * as process from 'process';
import { response } from 'express';
import { Profile } from 'passport';
import { CommonService } from '../../common/common.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly prisma: PrismaService,
    private readonly commonService: CommonService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:8000/api/auth/google/redirect',
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { name, emails, photos } = profile;

    const user: User = await this.prisma.user.findUnique({
      where: { email: emails[0].value },
    });

    if (!user) {
      const createdUser: User = await this.prisma.user.create({
        data: {
          username: profile.displayName,
          email: emails[0].value,
          photo: photos[0].value,
          confirmed: true,
        },
      });

      const accessToken: string = await this.commonService.signAccessToken(
        createdUser.id,
        createdUser.role,
      );

      const refreshToken: string = await this.commonService.signRefreshToken(
        createdUser.id,
        createdUser.role,
      );

      await this.commonService.updateRefreshToken(createdUser.id, refreshToken);
      await this.commonService.signCookies(response, accessToken, refreshToken);

      done(null, createdUser);
    }

    done(null, user);
  }
}

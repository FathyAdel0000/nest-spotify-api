import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateSignupDto } from './dto/create-signup-dto';
import { UserResponse } from './dto/user-response';
import { Role, Singer, User } from '@prisma/client';
import { hash, verify } from 'argon2';
import { CommonService } from '../common/common.service';
import { Request, Response } from 'express';
import { UploadService } from '../upload/upload.service';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './decorator/user.decorator';
import { CreateLoginDto } from './dto/create-login-dto';
import { ResetPasswordDto } from './dto/reset-password-dto';
import { SelectedUserDataType } from 'src/interfaces/user-interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly commonService: CommonService,
    private readonly uploadService: UploadService,
    private readonly mailerService: MailerService,
  ) {}

  private selectedUserData: SelectedUserDataType = {
    id: true,
    username: true,
    email: true,
    photoName: true,
    confirmed: true,
    role: true,
    singer: true,
    createdAt: true,
    updatedAt: true,
  };

  async signup(
    signupData: CreateSignupDto,
    response: Response,
    file: Express.Multer.File,
  ): Promise<UserResponse> {
    const { email, password } = signupData;

    const user: User = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (user) {
      throw new ForbiddenException('Email already taken!');
    }

    if (file) {
      await this.uploadService.upload(file.originalname, file.buffer);
    }

    const createdUser: UserResponse = await this.prisma.user.create({
      data: {
        ...signupData,
        password: await hash(password),
        email: email.toLowerCase(),
        photoName: file ? file.originalname : null,
        role: Role.USER,
      },
      select: this.selectedUserData,
    });

    const createdSinger: Singer = await this.prisma.singer.create({
      data: {
        name: createdUser.username,
        userId: createdUser.id,
        photoName: createdUser.photoName,
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

    await this.commonService.signCookies(response, accessToken, refreshToken);
    await this.commonService.updateRefreshToken(createdUser.id, refreshToken);

    const link: string = `http://localhost:3000/api/auth/confirm-email/${accessToken}`;

    await this.mailerService.sendMail({
      from: this.config.getOrThrow('NODEMAILER_EMAIL'),
      to: createdUser.email,
      subject: 'Confirm your email',
      html: `
        <h1>Please confirm your email</h1>
        <b></b>
        <h4>${link}</h4>
      `,
    });
    response.send({ ...createdUser, singer: createdSinger });
    return { ...createdUser, singer: createdSinger };
  }

  async confirmEmail(token: string): Promise<string> {
    const decodedUser: JwtPayload = this.jwt.decode(token) as JwtPayload;
    const user: User = await this.commonService.findUserById(decodedUser.id);
    if (Date.now() >= decodedUser.exp * 1000) {
      throw new ForbiddenException('Token is expired!');
    }
    if (!user) {
      throw new ForbiddenException('Token is not valid');
    }
    await this.commonService.findUserById(decodedUser.id);
    await this.prisma.user.update({
      where: { id: decodedUser.id },
      data: { confirmed: true },
    });
    return 'Email Confirmed Successfully!';
  }

  async resendConfirmationEmail(decodedUser: JwtPayload): Promise<string> {
    const user: User = await this.commonService.findUserById(decodedUser.id);
    const accessToken: string = await this.commonService.signAccessToken(
      user.id,
      user.role,
    );
    const link: string = `http://localhost:3000/api/auth/confirm-email/${accessToken}`;
    await this.mailerService.sendMail({
      from: this.config.getOrThrow('NODEMAILER_EMAIL'),
      to: user.email,
      subject: 'Confirm your email',
      html: `
        <h1>Please confirm your email</h1>
        <b></b>
        <h4>${link}</h4>
      `,
    });
    return 'Resend Confirmation Successfully!';
  }

  async login(
    loginData: CreateLoginDto,
    response: Response,
  ): Promise<UserResponse> {
    const { email, password } = loginData;
    const user: User = await this.commonService.findUserByEmail(email);

    if (!user.confirmed) {
      throw new ForbiddenException('User is not confirmed!');
    }

    const isValidPassword: boolean = await verify(user.password, password);
    if (!isValidPassword) {
      throw new ForbiddenException('Password is not valid!');
    }

    const accessToken: string = await this.commonService.signAccessToken(
      user.id,
      user.role,
    );
    const refreshToken: string = await this.commonService.signRefreshToken(
      user.id,
      user.role,
    );

    await this.commonService.signCookies(response, accessToken, refreshToken);
    await this.commonService.updateRefreshToken(user.id, refreshToken);

    const loggedInUser: UserResponse = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: this.selectedUserData,
    });

    response.send(loggedInUser);

    return loggedInUser;
  }

  async googleLogin(): Promise<string> {
    return 'Google authentication';
  }

  async handleRedirect(): Promise<string> {
    return 'Login with google successfully!';
  }

  async handleRefreshToken(
    request: Request,
    response: Response,
    decodedUser: JwtPayload,
  ): Promise<string> {
    const user: User = await this.commonService.findUserById(decodedUser.id);
    const refreshTokenCookie = request.cookies.refreshToken;

    const isValidRefreshToken: boolean = await verify(
      user.refreshToken,
      refreshTokenCookie,
    );

    if (!isValidRefreshToken) {
      throw new ForbiddenException('Token is not valid!');
    }

    const accessToken: string = await this.commonService.signAccessToken(
      user.id,
      user.role,
    );
    const refreshToken: string = await this.commonService.signRefreshToken(
      user.id,
      user.role,
    );

    await this.commonService.signCookies(response, accessToken, refreshToken);
    await this.commonService.updateRefreshToken(user.id, refreshToken);

    response.send('Handle Refresh Token successfully');

    return 'Handle Refresh Token Successfully';
  }

  async forgotPassword(decodedUser: JwtPayload) {
    const user: User = await this.commonService.findUserById(decodedUser.id);
    const accessToken: string = await this.commonService.signAccessToken(
      user.id,
      user.role,
    );
    const link: string = `http://localhost:3000/api/auth/reset-password/${accessToken}`;
    await this.mailerService.sendMail({
      from: this.config.getOrThrow('NODEMAILER_EMAIL'),
      to: user.email,
      subject: 'Reset Password',
      html: `
        <h1>Reset your password</h1>
        <b></b>
        <h4>${link}</h4>
      `,
    });
    return 'Please check your email to reset password!';
  }

  async resetPassword(
    resetPasswordData: ResetPasswordDto,
    token: string,
  ): Promise<string> {
    const decodedUser: JwtPayload = this.jwt.decode(token) as JwtPayload;
    const user: User = await this.commonService.findUserById(decodedUser.id);
    if (Date.now() >= decodedUser.exp * 1000) {
      throw new ForbiddenException('Token is expired!');
    }
    if (!user) {
      throw new ForbiddenException('Token is not valid');
    }
    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: await hash(resetPasswordData.password) },
    });
    return 'Reset Password succesfully!';
  }

  async logout(response: Response, decodedUser: JwtPayload): Promise<void> {
    const user: User = await this.commonService.findUserById(decodedUser.id);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: null },
    });
    response.clearCookie('accessToken');
    response.clearCookie('refreshToken');
    response.end();
  }
}

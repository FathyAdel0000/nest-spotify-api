import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Put,
  Req,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateSignupDto } from './dto/create-signup-dto';
import { UserResponse } from './dto/user-response';
import { Request, Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { AtGuard } from './guard/at.guard';
import { CreateLoginDto } from './dto/create-login-dto';
import { JwtPayload, UserDecorator } from './decorator/user.decorator';
import { GoogleGuard } from './guard/google.guard';
import { RtGuard } from './guard/rt.guard';
import { ResetPasswordDto } from './dto/reset-password-dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @UseInterceptors(FileInterceptor('file'))
  async signup(
    @Body() signupData: CreateSignupDto,
    @Res() response: Response,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<UserResponse> {
    return this.authService.signup(signupData, response, file);
  }

  @Post('confirm-email/:token')
  @UseGuards(AtGuard)
  async confirmEmail(@Param('token') token: string): Promise<string> {
    return this.authService.confirmEmail(token);
  }

  @Post('resend-confirmation-email')
  @UseGuards(AtGuard)
  async resendConfirmationEmail(
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<string> {
    return this.authService.resendConfirmationEmail(decodedUser);
  }

  @Post('login')
  async login(
    @Body() loginData: CreateLoginDto,
    @Res() response: Response,
  ): Promise<UserResponse> {
    return this.authService.login(loginData, response);
  }

  @Get('login/google')
  @UseGuards(GoogleGuard)
  async googleLogin(): Promise<string> {
    return this.authService.googleLogin();
  }

  @Get('google/redirect')
  @UseGuards(GoogleGuard)
  async handleRedirect(): Promise<string> {
    return this.authService.handleRedirect();
  }

  @Get('refresh-token')
  @UseGuards(RtGuard)
  async handleRefreshToken(
    @Req() request: Request,
    @Res() response: Response,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<string> {
    return this.authService.handleRefreshToken(request, response, decodedUser);
  }

  @Post('forgot-password')
  @UseGuards(AtGuard)
  async forgotPassword(
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<string> {
    return this.authService.forgotPassword(decodedUser);
  }

  @Put('reset-password/:token')
  @UseGuards(AtGuard)
  async resetPassword(
    @Body() resetPasswordData: ResetPasswordDto,
    @Param('token') token: string,
  ): Promise<string> {
    return this.authService.resetPassword(resetPasswordData, token);
  }

  @Delete('logout')
  @HttpCode(204)
  @UseGuards(AtGuard)
  async logout(
    @Res() response: Response,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<void> {
    return this.authService.logout(response, decodedUser);
  }
}

import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseIntPipe,
  Put,
  Query,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { Role } from '@prisma/client';
import { UserResponse } from 'src/auth/dto/user-response';
import { UpdateUserDto } from './dto/update-user-dto';
import { AtGuard } from 'src/auth/guard/at.guard';
import { RoleGuard } from 'src/auth/guard/role.guard';
import { Roles } from 'src/auth/decorator/roles.decorator';
import { JwtPayload, UserDecorator } from 'src/auth/decorator/user.decorator';
import { Response } from 'express';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  @UseGuards(RoleGuard)
  @Roles(Role.ADMIN)
  async getAll(
    @Query('page', ParseIntPipe) page: number,
    @Query('size', ParseIntPipe) size: number,
  ): Promise<UserResponse[]> {
    return this.userService.getAll(page, size);
  }

  @Get(':userId')
  @UseGuards(AtGuard)
  async getOne(@Param('userId') userId: string): Promise<UserResponse> {
    return this.userService.getOne(userId);
  }

  @Put(':userId')
  @UseInterceptors(FileInterceptor('file'))
  @UseGuards(AtGuard)
  async update(
    @Param('userId') userId: string,
    @Body() userData: UpdateUserDto,
    @UploadedFile() file: Express.Multer.File,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<UserResponse> {
    return this.userService.update(userId, userData, file, decodedUser);
  }

  @Put('reset-role/:userId')
  @UseGuards(RoleGuard)
  @Roles(Role.ADMIN)
  async resetRole(
    @Param('userId') userId: string,
    @Res() response: Response,
  ): Promise<void> {
    return this.userService.resetRole(userId, response);
  }

  @Delete(':userId')
  @HttpCode(204)
  @UseGuards(AtGuard)
  async delete(
    @Param('userId') userId: string,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<void> {
    return this.userService.delete(userId, decodedUser);
  }
}

import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserResponse } from '../auth/dto/user-response';
import { UpdateUserDto } from './dto/update-user-dto';
import { CommonService } from '../common/common.service';
import { Role, User } from '@prisma/client';
import { hash } from 'argon2';
import { JwtPayload } from 'src/auth/decorator/user.decorator';
import { UploadService } from '../upload/upload.service';
import { SelectedUserDataType } from 'src/interfaces/user-interface';
import { Response } from 'express';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly commonService: CommonService,
    private readonly uploadService: UploadService,
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

  async getAll(page: number, size: number): Promise<UserResponse[]> {
    return await this.prisma.user.findMany({
      select: this.selectedUserData,
      skip: page * size || 0,
      take: size || 0,
    });
  }

  async getOne(userId: string): Promise<UserResponse> {
    const user: UserResponse = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.selectedUserData,
    });
    if (!user) {
      throw new NotFoundException('User not found!');
    }
    return user;
  }

  async update(
    userId: string,
    userData: UpdateUserDto,
    file: Express.Multer.File,
    decodedUser: JwtPayload,
  ): Promise<UserResponse> {
    if (decodedUser.id !== userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }

    const user: User = await this.commonService.findUserById(userId);

    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }

    const hashedPassword: string = userData.password
      ? await hash(userData.password)
      : user.password;

    return await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...userData,
        password: hashedPassword,
        photoName: file ? file.originalname : null,
      },
      select: this.selectedUserData,
    });
  }

  async resetRole(userId: string, response: Response): Promise<void> {
    const user: UserResponse = await this.getOne(userId);
    if (user.role == Role.ADMIN) {
      throw new ForbiddenException('User is already admin!');
    }
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        role: Role.ADMIN,
      },
      select: this.selectedUserData,
    });
    response.send('Reset role successfully!');
  }

  async delete(userId: string, decodedUser: JwtPayload): Promise<void> {
    if (decodedUser.id !== userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    await this.commonService.findUserById(userId);
    await this.prisma.user.delete({
      where: { id: userId },
    });
  }
}

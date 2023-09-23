import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SingerResponse } from './dto/singer-response';
import { Role } from '@prisma/client';
import { JwtPayload } from '../auth/decorator/user.decorator';
import { UpdateSingerDto } from './dto/update-singer-dto';
import { UploadService } from '../upload/upload.service';
import { CreateSingerAlbumDto } from '../singer-album/dto/create-singer-album-dto';
import { SingerAlbumResponse } from '../singer-album/dto/singer-album-response';
import { SelectedSingerData } from 'src/interfaces/singer-interface';
import { SelectedSingerAlbumData } from 'src/interfaces/singer-album-interface';

@Injectable()
export class SingerService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly uploadService: UploadService,
  ) {}

  private selectedSingerData: SelectedSingerData = {
    id: true,
    name: true,
    info: true,
    type: true,
    userId: true,
    photoName: true,
    createdAt: true,
    updatedAt: true,
  };

  private selectedSingerAlbumData: SelectedSingerAlbumData = {
    id: true,
    name: true,
    photoName: true,
    userId: true,
  };

  async getAll(page: number, size: number): Promise<SingerResponse[]> {
    return await this.prisma.singer.findMany({
      select: this.selectedSingerData,
      skip: page * size || 0,
      take: size || 0,
    });
  }

  async getOne(singerId: string): Promise<SingerResponse> {
    const singer: SingerResponse = await this.prisma.singer.findUnique({
      where: { id: singerId },
      select: this.selectedSingerData,
    });
    if (!singer) {
      throw new NotFoundException('Singer not found!');
    }
    return singer;
  }

  async update(
    singerId: string,
    singerData: UpdateSingerDto,
    file: Express.Multer.File,
    decodedUser: JwtPayload,
  ): Promise<SingerResponse> {
    const singer: SingerResponse = await this.getOne(singerId);
    if (decodedUser.id !== singer.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }
    await this.getOne(singerId);
    return await this.prisma.singer.update({
      where: { id: singerId },
      data: { ...singerData, photoName: file ? file.originalname : null },
      select: this.selectedSingerData,
    });
  }

  async delete(singerId: string, decodedUser: JwtPayload): Promise<void> {
    const singer: SingerResponse = await this.getOne(singerId);
    if (decodedUser.id !== singer.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    await this.getOne(singerId);
    await this.prisma.singer.delete({ where: { id: singerId } });
  }

  async createSingerAlbum(
    singerAlbumData: CreateSingerAlbumDto,
    singerId: string,
    decodedUser: JwtPayload,
    file: Express.Multer.File,
  ): Promise<SingerAlbumResponse> {
    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }
    return await this.prisma.singerAlbum.create({
      data: {
        ...singerAlbumData,
        userId: decodedUser.id,
        singerId,
        photoName: file ? file.originalname : null,
      },
      select: this.selectedSingerAlbumData,
    });
  }
}

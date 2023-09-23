import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtPayload } from '../auth/decorator/user.decorator';
import { UploadService } from '../upload/upload.service';
import { Role } from '@prisma/client';
import { SelectedPlaylistData } from '../interfaces/playlist-interface';
import { PlaylistResponse } from './dto/playlist-response';
import { UpdatePlaylistDto } from './dto/update-playlist-dto';
import { CreatePlaylistDto } from './dto/create-playlist-dto';

@Injectable()
export class PlaylistService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly uploadService: UploadService,
  ) {}

  private selectedPlaylistData: SelectedPlaylistData = {
    id: true,
    name: true,
    photoName: true,
    userId: true,
    createdAt: true,
    updatedAt: true,
  };

  async getAll(page: number, size: number): Promise<PlaylistResponse[]> {
    return await this.prisma.playlist.findMany({
      skip: page * size,
      take: size,
      select: this.selectedPlaylistData,
    });
  }

  async getOne(playlistId: string): Promise<PlaylistResponse> {
    const playlist: PlaylistResponse = await this.prisma.playlist.findUnique({
      where: {
        id: playlistId,
      },
      select: this.selectedPlaylistData,
    });
    if (!playlist) {
      throw new NotFoundException('Playlist not found!');
    }
    return playlist;
  }

  async create(
    playlistData: CreatePlaylistDto,
    decodedUser: JwtPayload,
    file: Express.Multer.File,
  ): Promise<PlaylistResponse> {
    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }
    return await this.prisma.playlist.create({
      data: {
        ...playlistData,
        userId: decodedUser.id,
        photoName: file ? file.originalname : null,
      },
      select: this.selectedPlaylistData,
    });
  }

  async update(
    playlistData: UpdatePlaylistDto,
    playlistId: string,
    decodedUser: JwtPayload,
    file: Express.Multer.File,
  ): Promise<PlaylistResponse> {
    const playlist: PlaylistResponse = await this.getOne(playlistId);
    if (decodedUser.id !== playlist.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }
    return await this.prisma.playlist.update({
      where: { id: playlistId },
      data: { ...playlistData, photoName: file ? file.originalname : null },
      select: this.selectedPlaylistData,
    });
  }

  async delete(playlistId: string, decodedUser: JwtPayload): Promise<void> {
    const playlist: PlaylistResponse = await this.getOne(playlistId);
    if (decodedUser.id !== playlist.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    await this.prisma.playlist.delete({
      where: { id: playlistId },
    });
  }
}

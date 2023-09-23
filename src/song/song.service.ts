import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SongResponse } from './dto/song-response-dto';
import { SelectedSongData } from '../interfaces/song-interface';
import { UpdateSongDto } from './dto/update-song-dto';
import { JwtPayload } from '../auth/decorator/user.decorator';
import { UploadService } from '../upload/upload.service';
import { Role, SongsOnPlaylists } from '@prisma/client';

@Injectable()
export class SongService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly uploadService: UploadService,
  ) {}

  private selectedSongData: SelectedSongData = {
    id: true,
    name: true,
    description: true,
    artist: true,
    type: true,
    language: true,
    rate: true,
    photoName: true,
    userId: true,
    createdAt: true,
    updatedAt: true,
  };

  async getAll(page: number, size: number): Promise<SongResponse[]> {
    return await this.prisma.song.findMany({
      skip: page * size,
      take: size,
      select: this.selectedSongData,
    });
  }

  async getOne(songId: string): Promise<SongResponse> {
    const song: SongResponse = await this.prisma.song.findUnique({
      where: {
        id: songId,
      },
      select: this.selectedSongData,
    });
    if (!song) {
      throw new NotFoundException('Song not found!');
    }
    return song;
  }

  async update(
    songData: UpdateSongDto,
    songId: string,
    decodedUser: JwtPayload,
    file: Express.Multer.File,
  ): Promise<SongResponse> {
    const song: SongResponse = await this.getOne(songId);
    if (decodedUser.id !== song.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    if (file) {
      this.uploadService.upload(file.originalname, file.buffer);
    }
    return await this.prisma.song.update({
      where: { id: songId },
      data: { ...songData, photoName: file ? file.originalname : null },
      select: this.selectedSongData,
    });
  }

  async delete(songId: string, decodedUser: JwtPayload): Promise<void> {
    const song: SongResponse = await this.getOne(songId);
    if (decodedUser.id !== song.userId || decodedUser.role !== Role.ADMIN) {
      throw new UnauthorizedException('Unauthorized user!');
    }
    await this.prisma.song.delete({
      where: { id: songId },
    });
  }

  async pushSongToPlaylist(
    songId: string,
    playlistId: string,
  ): Promise<SongsOnPlaylists> {
    return await this.prisma.songsOnPlaylists.create({
      data: {
        songId,
        playlistId,
      },
    });
  }
}

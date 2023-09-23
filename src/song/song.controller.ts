import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { SongService } from './song.service';
import { SongResponse } from './dto/song-response-dto';
import { RoleGuard } from '../auth/guard/role.guard';
import { Roles } from '../auth/decorator/roles.decorator';
import { Role, SongsOnPlaylists } from '@prisma/client';
import { AtGuard } from '../auth/guard/at.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtPayload, UserDecorator } from '../auth/decorator/user.decorator';
import { SingerAlbumResponse } from '../singer-album/dto/singer-album-response';
import { UpdateSongDto } from './dto/update-song-dto';

@Controller('songs')
export class SongController {
  constructor(private readonly songService: SongService) {}

  @Get()
  @UseGuards(RoleGuard)
  @Roles(Role.ADMIN)
  async getAll(
    @Query('page', ParseIntPipe) page: number,
    @Query('size', ParseIntPipe) size: number,
  ): Promise<SongResponse[]> {
    return this.songService.getAll(page, size);
  }

  @Get(':songId')
  @UseGuards(AtGuard)
  async getOne(@Param('songId') songId: string): Promise<SongResponse> {
    return this.songService.getOne(songId);
  }

  @Put(':songId')
  @UseGuards(AtGuard)
  @UseInterceptors(FileInterceptor('file'))
  async update(
    @Body() songData: UpdateSongDto,
    @Param('songId') songId: string,
    @UserDecorator() decodedUser: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<SingerAlbumResponse> {
    return this.songService.update(songData, songId, decodedUser, file);
  }

  @Delete(':songId')
  @UseGuards(AtGuard)
  @HttpCode(204)
  async Delete(
    @Param('songId') songId: string,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<void> {
    return this.songService.delete(songId, decodedUser);
  }

  @Post(':songId/playlists/:playlistId')
  @UseGuards(AtGuard)
  async pushSongToPlaylist(
    @Param('songId') songId: string,
    @Param('playlistId') playlistId: string,
  ): Promise<SongsOnPlaylists> {
    return this.songService.pushSongToPlaylist(songId, playlistId);
  }
}

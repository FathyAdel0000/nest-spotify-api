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
import { SingerAlbumService } from './singer-album.service';
import { RoleGuard } from '../auth/guard/role.guard';
import { Roles } from '../auth/decorator/roles.decorator';
import { Role } from '@prisma/client';
import { SingerAlbumResponse } from './dto/singer-album-response';
import { AtGuard } from '../auth/guard/at.guard';
import { JwtPayload, UserDecorator } from '../auth/decorator/user.decorator';
import { FileInterceptor } from '@nestjs/platform-express';
import { UpdateSingerAlbumDto } from './dto/update-singer-album-dto';
import { CreateSongDto } from '../song/dto/create-song-dto';
import { SongResponse } from '../song/dto/song-response-dto';

@Controller('singer-albums')
export class SingerAlbumController {
  constructor(private readonly singerAlbumService: SingerAlbumService) {}

  @Get()
  @UseGuards(RoleGuard)
  @Roles(Role.ADMIN)
  async getAll(
    @Query('page', ParseIntPipe) page: number,
    @Query('size', ParseIntPipe) size: number,
  ): Promise<SingerAlbumResponse[]> {
    return this.singerAlbumService.getAll(page, size);
  }

  @Get(':singerAlbumId')
  @UseGuards(AtGuard)
  async getOne(
    @Param('singerAlbumId') singerAlbumId: string,
  ): Promise<SingerAlbumResponse> {
    return this.singerAlbumService.getOne(singerAlbumId);
  }

  @Put(':singerAlbumId')
  @UseGuards(AtGuard)
  @UseInterceptors(FileInterceptor('file'))
  async update(
    @Body() singerAlbumData: UpdateSingerAlbumDto,
    @Param('singerAlbumId') singerAlbumId: string,
    @UserDecorator() decodedUser: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<SingerAlbumResponse> {
    return this.singerAlbumService.update(
      singerAlbumData,
      singerAlbumId,
      decodedUser,
      file,
    );
  }

  @Delete(':singerAlbumId')
  @UseGuards(AtGuard)
  @HttpCode(204)
  async delete(
    @Param('singerAlbumId') singerAlbumId: string,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<void> {
    return this.singerAlbumService.delete(singerAlbumId, decodedUser);
  }

  @Post(':singerAlbumId/new-song')
  @UseGuards(AtGuard)
  @UseInterceptors(FileInterceptor('file'))
  async createSong(
    @Body() songData: CreateSongDto,
    @Param('singerAlbumId') singerAlbumId: string,
    @UserDecorator() decodedUser: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<SongResponse> {
    return this.singerAlbumService.createSong(
      songData,
      singerAlbumId,
      decodedUser,
      file,
    );
  }
}

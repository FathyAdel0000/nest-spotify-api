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
import { RoleGuard } from '../auth/guard/role.guard';
import { Roles } from '../auth/decorator/roles.decorator';
import { Role } from '@prisma/client';
import { AtGuard } from '../auth/guard/at.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtPayload, UserDecorator } from '../auth/decorator/user.decorator';
import { PlaylistResponse } from './dto/playlist-response';
import { UpdatePlaylistDto } from './dto/update-playlist-dto';
import { PlaylistService } from './playlist.service';
import { CreatePlaylistDto } from './dto/create-playlist-dto';

@Controller('playlists')
export class PlaylistController {
  constructor(private readonly playlistService: PlaylistService) {}

  @Get()
  @UseGuards(RoleGuard)
  @Roles(Role.ADMIN)
  async getAll(
    @Query('page', ParseIntPipe) page: number,
    @Query('size', ParseIntPipe) size: number,
  ): Promise<PlaylistResponse[]> {
    return this.playlistService.getAll(page, size);
  }

  @Get(':playlistId')
  @UseGuards(AtGuard)
  async getOne(
    @Param('playlistId') playlistId: string,
  ): Promise<PlaylistResponse> {
    return this.playlistService.getOne(playlistId);
  }

  @Post()
  @UseGuards(AtGuard)
  @UseInterceptors(FileInterceptor('file'))
  async create(
    @Body() playlistData: CreatePlaylistDto,
    @UserDecorator() decodedUser: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<PlaylistResponse> {
    return this.playlistService.create(playlistData, decodedUser, file);
  }

  @Put(':playlistId')
  @UseGuards(AtGuard)
  @UseInterceptors(FileInterceptor('file'))
  async update(
    @Body() playlistData: UpdatePlaylistDto,
    @Param('playlistId') playlistId: string,
    @UserDecorator() decodedUser: JwtPayload,
    @UploadedFile() file: Express.Multer.File,
  ): Promise<PlaylistResponse> {
    return this.playlistService.update(
      playlistData,
      playlistId,
      decodedUser,
      file,
    );
  }

  @Delete(':playlistId')
  @UseGuards(AtGuard)
  @HttpCode(204)
  async Delete(
    @Param('playlistId') playlistId: string,
    @UserDecorator() decodedUser: JwtPayload,
  ): Promise<void> {
    return this.playlistService.delete(playlistId, decodedUser);
  }
}

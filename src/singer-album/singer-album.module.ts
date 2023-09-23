import { Module } from '@nestjs/common';
import { SingerAlbumService } from './singer-album.service';
import { SingerAlbumController } from './singer-album.controller';

@Module({
  controllers: [SingerAlbumController],
  providers: [SingerAlbumService],
})
export class SingerAlbumModule {}

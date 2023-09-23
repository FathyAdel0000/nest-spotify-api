import { Module } from '@nestjs/common';
import { SingerService } from './singer.service';
import { SingerController } from './singer.controller';

@Module({
  controllers: [SingerController],
  providers: [SingerService],
})
export class SingerModule {}

import { IsEnum, IsNotEmpty, IsNumber, IsString } from 'class-validator';
import { SongType } from '@prisma/client';

export class CreateSongDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsString()
  artist: string;

  @IsNotEmpty()
  @IsEnum(SongType)
  type: SongType;

  @IsNotEmpty()
  @IsString()
  language: string;

  @IsNotEmpty()
  @IsNumber()
  rate: number;
}

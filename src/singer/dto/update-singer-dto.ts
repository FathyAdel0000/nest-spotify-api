import { IsEnum, IsOptional, IsString } from 'class-validator';
import { SingerType } from '@prisma/client';

export class UpdateSingerDto {
  @IsOptional()
  @IsString()
  name: string;

  @IsOptional()
  info: string;

  @IsOptional()
  @IsEnum(SingerType)
  type: SingerType;
}

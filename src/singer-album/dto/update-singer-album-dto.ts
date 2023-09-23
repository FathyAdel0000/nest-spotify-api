import { PartialType } from '@nestjs/mapped-types';
import { CreateSingerAlbumDto } from './create-singer-album-dto';

export class UpdateSingerAlbumDto extends PartialType(CreateSingerAlbumDto) {}

import { SongType } from '@prisma/client';

export class SongResponse {
  id: string;
  name: string;
  description: string;
  artist: string;
  type: SongType;
  language: string;
  rate: number;
  userId: string;
  photoName: string;
  createdAt: Date;
  updatedAt: Date;
}

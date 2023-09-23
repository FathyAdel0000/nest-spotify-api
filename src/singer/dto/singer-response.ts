import { SingerType } from '@prisma/client';

export class SingerResponse {
  id: string;
  name: string;
  info: string;
  type: SingerType;
  photoName: string;
  userId: string;
  createdAt: Date;
  updatedAt: Date;
}

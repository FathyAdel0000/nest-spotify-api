import { Role, Singer } from '@prisma/client';

export class UserResponse {
  id: string;
  username: string;
  email: string;
  photoName: string;
  confirmed: boolean;
  role: Role;
  singer: Singer;
  createdAt: Date;
  updatedAt: Date;
}

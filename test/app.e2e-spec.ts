import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from './../src/app.module';
import { Role } from '@prisma/client';
import * as request from 'supertest';
import * as process from 'process';
import * as cookieParser from 'cookie-parser';
import { PrismaService } from '../src/prisma/prisma.service';

//user data
interface UserData {
  userId: string;
  singerId: string;
  singerAlbumId: string;
  songId: string;
  playlistId: string;
  username: string;
  email: string;
  accessToken: string;
  refreshToken: string;
  productKey: string;
}

export const userData: UserData = {
  userId: '',
  singerId: '',
  singerAlbumId: '',
  songId: '',
  playlistId: '',
  username: '',
  email: '',
  accessToken: '',
  refreshToken: '',
  productKey: process.env.PRODUCT_KEY_STRING,
};

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService = new PrismaService();
  beforeEach(async (): Promise<void> => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
    await app.init();
  });
  const splitToken = (token: string) => {
    const splitted: string = token.split(';')[0];
    const tokenString: string = splitted.split('=')[1];
    return tokenString;
  };
  const setCookie = (response: request.Response): void => {
    const cookies = response.headers['set-cookie'];
    userData.accessToken = cookies[0];
    userData.refreshToken = cookies[1];
  };

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });

  it('/auth/signup (POST)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .post('/auth/signup')
      .expect(201)
      .send({
        username: 'fathy adel',
        email: process.env.TEST_EMAIL,
        password: 'stefan123@ME',
      });
    userData.userId = response.body.id;
    userData.username = response.body.username;
    userData.email = response.body.email;
    userData.singerId = response.body.singer.id;

    setCookie(response);
  });

  it('/auth/confirm-email/:token (POST)', async (): Promise<void> => {
    const accessToken: string = splitToken(userData.accessToken);
    await request(app.getHttpServer())
      .post(`/auth/confirm-email/${accessToken}`)
      .set('cookie', userData.accessToken)
      .expect(201);
  });

  it('/auth/login (POST)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .post('/auth/login')
      .expect(201)
      .send({
        email: process.env.TEST_EMAIL,
        password: 'stefan123@ME',
      });
    await prisma.user.update({
      where: { id: userData.userId },
      data: {
        role: Role.ADMIN,
      },
    });
    setCookie(response);
  });

  it('/auth/resend-confirmation-email (POST)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .post('/auth/resend-confirmation-email')
      .expect(201)
      .set('cookie', userData.accessToken);
  });

  it('/auth/refresh-token (GET)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .get('/auth/refresh-token')
      .set('cookie', userData.refreshToken)
      .expect(200);
    setCookie(response);
  });

  it('/auth/forgot-password (POST)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .post('/auth/forgot-password')
      .set('cookie', userData.accessToken)
      .expect(201);
  });

  it('/auth/reset-password (PUT)', async (): Promise<void> => {
    const accessToken: string = splitToken(userData.accessToken);
    await request(app.getHttpServer())
      .put(`/auth/reset-password/${accessToken}`)
      .send({ password: 'stefan123@ME' })
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/auth/logout (DELETE)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .delete(`/auth/logout`)
      .set('cookie', userData.accessToken)
      .expect(204);
  });

  it('/users (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/users`)
      .query({
        page: 0,
        size: 1,
      })
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/users/:id (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/users/${userData.userId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/users/:id (PUT)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .put(`/users/${userData.userId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singers (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/singers`)
      .query({
        page: 0,
        size: 1,
      })
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singers/:singerId (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/singers/${userData.singerId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singers/:singerId (PUT)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .put(`/singers/${userData.singerId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singers/:singerId/new-singer-album (POST)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .post(`/singers/${userData.singerId}/new-singer-album`)
      .send({ name: 'stefan butler album song' })
      .set('cookie', userData.accessToken)
      .expect(201);
    userData.singerAlbumId = response.body.id;
  });

  it('/singer-albums (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/singer-albums`)
      .set('cookie', userData.accessToken)
      .query({
        page: 0,
        size: 1,
      })
      .expect(200);
  });

  it('/singer-albums/:singerAlbumId (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/singer-albums/${userData.singerAlbumId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singer-albums/:singerAlbumId (PUT)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .put(`/singer-albums/${userData.singerAlbumId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/singer-albums/:singerAlbumId/new-song (POST)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .post(`/singer-albums/${userData.singerAlbumId}/new-song`)
      .send({
        name: 'stefan butler song',
        description: 'stefan butler description',
        artist: 'stefan butler',
        type: 'POP',
        language: 'english',
        rate: 15,
      })
      .set('cookie', userData.accessToken)
      .expect(201);

    userData.songId = response.body.id;
  });

  it('/songs (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/songs`)
      .set('cookie', userData.accessToken)
      .query({
        page: 0,
        size: 1,
      })
      .expect(200);
  });

  it('/songs/:songId (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/songs/${userData.songId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/songs/:songId (PUT)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .put(`/songs/${userData.songId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/playlists (POST)', async (): Promise<void> => {
    const response: request.Response = await request(app.getHttpServer())
      .post(`/playlists`)
      .send({
        name: 'stefan butler playlist',
      })
      .set('cookie', userData.accessToken)
      .expect(201);
    userData.playlistId = response.body.id;
  });

  it('/playlists (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/playlists`)
      .query({
        page: 0,
        size: 1,
      })
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/playlists/:playlistId (GET)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .get(`/playlists/${userData.playlistId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/playlists/:playlistId (PUT)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .put(`/playlists/${userData.playlistId}`)
      .set('cookie', userData.accessToken)
      .expect(200);
  });

  it('/songs/:songId/playlists/:playlistId (POST)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .post(`/songs/${userData.songId}/playlists/${userData.playlistId}`)
      .set('cookie', userData.accessToken)
      .expect(201);
  });

  it('/playlists/:playlistId (DELETE)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .delete(`/playlists/${userData.playlistId}`)
      .set('cookie', userData.accessToken)
      .expect(204);
  });

  it('/songs/:songId (DELETE)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .delete(`/songs/${userData.songId}`)
      .set('cookie', userData.accessToken)
      .expect(204);
  });

  it('/singer-albums/:singerAlbumId (DELETE)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .delete(`/singer-albums/${userData.singerAlbumId}`)
      .set('cookie', userData.accessToken)
      .expect(204);
  });

  it('/users/:id (DELETE)', async (): Promise<void> => {
    await request(app.getHttpServer())
      .delete(`/users/${userData.userId}`)
      .set('cookie', userData.accessToken)
      .expect(204);
  });
});

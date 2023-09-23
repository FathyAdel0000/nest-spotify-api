/*
  Warnings:

  - The primary key for the `Playlist` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `Singer` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `SingerAlbum` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `Song` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `SongsOnPlaylists` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `User` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- DropForeignKey
ALTER TABLE "Playlist" DROP CONSTRAINT "Playlist_userId_fkey";

-- DropForeignKey
ALTER TABLE "Singer" DROP CONSTRAINT "Singer_userId_fkey";

-- DropForeignKey
ALTER TABLE "SingerAlbum" DROP CONSTRAINT "SingerAlbum_singerId_fkey";

-- DropForeignKey
ALTER TABLE "SingerAlbum" DROP CONSTRAINT "SingerAlbum_userId_fkey";

-- DropForeignKey
ALTER TABLE "Song" DROP CONSTRAINT "Song_singerAlbumId_fkey";

-- DropForeignKey
ALTER TABLE "Song" DROP CONSTRAINT "Song_userId_fkey";

-- DropForeignKey
ALTER TABLE "SongsOnPlaylists" DROP CONSTRAINT "SongsOnPlaylists_playlistId_fkey";

-- DropForeignKey
ALTER TABLE "SongsOnPlaylists" DROP CONSTRAINT "SongsOnPlaylists_songId_fkey";

-- AlterTable
ALTER TABLE "Playlist" DROP CONSTRAINT "Playlist_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ADD CONSTRAINT "Playlist_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Playlist_id_seq";

-- AlterTable
ALTER TABLE "Singer" DROP CONSTRAINT "Singer_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ADD CONSTRAINT "Singer_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Singer_id_seq";

-- AlterTable
ALTER TABLE "SingerAlbum" DROP CONSTRAINT "SingerAlbum_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ALTER COLUMN "singerId" SET DATA TYPE TEXT,
ADD CONSTRAINT "SingerAlbum_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "SingerAlbum_id_seq";

-- AlterTable
ALTER TABLE "Song" DROP CONSTRAINT "Song_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ALTER COLUMN "singerAlbumId" SET DATA TYPE TEXT,
ADD CONSTRAINT "Song_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Song_id_seq";

-- AlterTable
ALTER TABLE "SongsOnPlaylists" DROP CONSTRAINT "SongsOnPlaylists_pkey",
ALTER COLUMN "songId" SET DATA TYPE TEXT,
ALTER COLUMN "playlistId" SET DATA TYPE TEXT,
ADD CONSTRAINT "SongsOnPlaylists_pkey" PRIMARY KEY ("songId", "playlistId");

-- AlterTable
ALTER TABLE "User" DROP CONSTRAINT "User_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "User_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "User_id_seq";

-- AddForeignKey
ALTER TABLE "Singer" ADD CONSTRAINT "Singer_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SingerAlbum" ADD CONSTRAINT "SingerAlbum_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SingerAlbum" ADD CONSTRAINT "SingerAlbum_singerId_fkey" FOREIGN KEY ("singerId") REFERENCES "Singer"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Song" ADD CONSTRAINT "Song_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Song" ADD CONSTRAINT "Song_singerAlbumId_fkey" FOREIGN KEY ("singerAlbumId") REFERENCES "SingerAlbum"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Playlist" ADD CONSTRAINT "Playlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SongsOnPlaylists" ADD CONSTRAINT "SongsOnPlaylists_songId_fkey" FOREIGN KEY ("songId") REFERENCES "Song"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SongsOnPlaylists" ADD CONSTRAINT "SongsOnPlaylists_playlistId_fkey" FOREIGN KEY ("playlistId") REFERENCES "Playlist"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

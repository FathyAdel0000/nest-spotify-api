-- DropForeignKey
ALTER TABLE "Playlist" DROP CONSTRAINT "Playlist_userId_fkey";

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

-- AddForeignKey
ALTER TABLE "SingerAlbum" ADD CONSTRAINT "SingerAlbum_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SingerAlbum" ADD CONSTRAINT "SingerAlbum_singerId_fkey" FOREIGN KEY ("singerId") REFERENCES "Singer"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Song" ADD CONSTRAINT "Song_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Song" ADD CONSTRAINT "Song_singerAlbumId_fkey" FOREIGN KEY ("singerAlbumId") REFERENCES "SingerAlbum"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Playlist" ADD CONSTRAINT "Playlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SongsOnPlaylists" ADD CONSTRAINT "SongsOnPlaylists_songId_fkey" FOREIGN KEY ("songId") REFERENCES "Song"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SongsOnPlaylists" ADD CONSTRAINT "SongsOnPlaylists_playlistId_fkey" FOREIGN KEY ("playlistId") REFERENCES "Playlist"("id") ON DELETE CASCADE ON UPDATE CASCADE;

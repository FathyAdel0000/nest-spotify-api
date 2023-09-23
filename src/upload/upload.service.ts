import {
  DeleteObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { fromIni } from '@aws-sdk/credential-providers';
import { HttpRequest } from '@smithy/protocol-http';
import { S3RequestPresigner } from '@aws-sdk/s3-request-presigner';
import { parseUrl } from '@smithy/url-parser';
import { formatUrl } from '@aws-sdk/util-format-url';
import { Hash } from '@smithy/hash-node';

@Injectable()
export class UploadService {
  constructor(private readonly config: ConfigService) {}

  private readonly s3Client: S3Client = new S3Client({
    region: this.config.getOrThrow('AWS_REGION'),
    credentials: {
      secretAccessKey: this.config.getOrThrow('AWS_SECRET_ACCESS_KEY'),
      accessKeyId: this.config.getOrThrow('AWS_ACCESS_KEY'),
    },
  });

  createPresignedUrlWithoutClient = async (
    region: string,
    bucket: string,
    key: string,
  ): Promise<string> => {
    const url = parseUrl(`https://${bucket}.s3.${region}.amazonaws.com/${key}`);
    const presigner = new S3RequestPresigner({
      credentials: fromIni(),
      region,
      sha256: Hash.bind(null, 'sha256'),
    });
    const signedUrlObject = await presigner.presign(new HttpRequest(url));
    return formatUrl(signedUrlObject);
  };

  async upload(filename: string, file: Buffer): Promise<void> {
    const bucket = this.config.getOrThrow('AWS_BUCKET_NAME');
    const response = await this.s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: filename,
        Body: file,
      }),
    );
    if (response.$metadata.httpStatusCode !== 200) {
      throw new BadRequestException('Invalid credentials!');
    }
  }

  async delete(filename: string): Promise<void> {
    await this.s3Client.send(
      new DeleteObjectCommand({
        Bucket: this.config.getOrThrow('AWS_BUCKET_NAME'),
        Key: filename,
      }),
    );
  }

  async getPresignedUrl(fileName: string): Promise<string> {
    const bucket = this.config.getOrThrow('AWS_BUCKET_NAME');
    const region = this.config.getOrThrow('AWS_REGION');
    return await this.createPresignedUrlWithoutClient(region, bucket, fileName);
  }
}

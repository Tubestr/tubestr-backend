import { env } from './config';

export function getBlobUrl(sha256: string): string {
  return `${env.blossom.publicUrl}/${sha256}`;
}

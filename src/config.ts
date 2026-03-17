import { config as loadEnv } from 'dotenv';

loadEnv();

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function toNumber(input: string, fallback: number): number {
  const parsed = Number(input);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const env = {
  port: toNumber(process.env.PORT ?? '8080', 8080),
  host: process.env.HOST ?? '0.0.0.0',
  nodeEnv: process.env.NODE_ENV ?? 'production',
  nip98ChallengeTtlSeconds: toNumber(process.env.NIP98_CHALLENGE_TTL_SECONDS ?? '300', 300),
  databaseUrl: requireEnv('DATABASE_URL'),
  blossom: {
    serverUrl: requireEnv('BLOSSOM_SERVER_URL'),
    publicUrl: requireEnv('BLOSSOM_PUBLIC_URL'),
  },
  freeTrial: {
    enabled: (process.env.FREE_TRIAL_MODE ?? 'false').toLowerCase() === 'true',
    days: toNumber(process.env.FREE_TRIAL_DAYS ?? '30', 30)
  },
  apple: {
    issuerId: process.env.APPLE_ISSUER_ID,
    keyId: process.env.APPLE_KEY_ID,
    privateKey: process.env.APPLE_PRIVATE_KEY_BASE64 ? Buffer.from(process.env.APPLE_PRIVATE_KEY_BASE64, 'base64').toString('utf8') : undefined,
    environment: process.env.APPLE_ENVIRONMENT ?? 'Production'
  },
  google: {
    projectId: process.env.GOOGLE_PROJECT_ID,
    clientEmail: process.env.GOOGLE_CLIENT_EMAIL,
    privateKey: process.env.GOOGLE_PRIVATE_KEY_BASE64 ? Buffer.from(process.env.GOOGLE_PRIVATE_KEY_BASE64, 'base64').toString('utf8') : undefined
  },
  moderation: {
    moderatorNpub: process.env.MODERATOR_NPUB,
    moderatorPublicKey: process.env.MODERATOR_PUBLIC_KEY
  }
};

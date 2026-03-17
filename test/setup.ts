import { execSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import path from 'node:path';

process.env.NODE_ENV = process.env.NODE_ENV ?? 'test';
process.env.PORT = process.env.PORT ?? '0';
process.env.DATABASE_URL = process.env.DATABASE_URL ?? 'file:./prisma/test.db';
process.env.BLOSSOM_SERVER_URL = process.env.BLOSSOM_SERVER_URL ?? 'http://localhost:3000';
process.env.BLOSSOM_PUBLIC_URL = process.env.BLOSSOM_PUBLIC_URL ?? 'http://localhost:3000';
process.env.NIP98_CHALLENGE_TTL_SECONDS =
  process.env.NIP98_CHALLENGE_TTL_SECONDS ?? '300';
process.env.APPLE_ENVIRONMENT = process.env.APPLE_ENVIRONMENT ?? 'Sandbox';
process.env.FREE_TRIAL_MODE = process.env.FREE_TRIAL_MODE ?? 'false';
process.env.FREE_TRIAL_DAYS = process.env.FREE_TRIAL_DAYS ?? '30';

declare global {
  // eslint-disable-next-line no-var
  var __TEST_DB_PREPARED__: boolean | undefined;
}

if (!globalThis.__TEST_DB_PREPARED__) {
  const dbFile = path.resolve(__dirname, '../prisma/test.db');
  if (existsSync(dbFile)) {
    rmSync(dbFile);
  }

  execSync('npx prisma migrate deploy', {
    stdio: 'inherit',
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL
    }
  });

  globalThis.__TEST_DB_PREPARED__ = true;
}

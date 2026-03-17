/*
  Warnings:

  - You are about to drop the column `objectKey` on the `Upload` table. All the data in the column will be lost.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Upload" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "npub" TEXT NOT NULL,
    "sha256" TEXT,
    "status" TEXT NOT NULL,
    "sizeBytes" BIGINT NOT NULL,
    "contentType" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Upload_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_Upload" ("contentType", "createdAt", "id", "npub", "sizeBytes", "status") SELECT "contentType", "createdAt", "id", "npub", "sizeBytes", "status" FROM "Upload";
DROP TABLE "Upload";
ALTER TABLE "new_Upload" RENAME TO "Upload";
CREATE UNIQUE INDEX "Upload_sha256_key" ON "Upload"("sha256");
CREATE INDEX "Upload_npub_idx" ON "Upload"("npub");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

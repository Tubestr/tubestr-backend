CREATE TABLE IF NOT EXISTS "User" (
    "npub" TEXT NOT NULL PRIMARY KEY,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "Entitlement" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "npub" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "productId" TEXT NOT NULL,
    "originalTxId" TEXT,
    "purchaseToken" TEXT,
    "status" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "quotaBytes" BIGINT NOT NULL,
    "egressBytesMon" BIGINT NOT NULL DEFAULT 0,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Entitlement_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS "Entitlement_npub_platform_idx" ON "Entitlement"("npub", "platform");
CREATE UNIQUE INDEX IF NOT EXISTS "Entitlement_npub_productId_key" ON "Entitlement"("npub", "productId");

CREATE TABLE IF NOT EXISTS "Usage" (
    "npub" TEXT NOT NULL PRIMARY KEY,
    "storedBytes" BIGINT NOT NULL DEFAULT 0,
    "egressBytesMon" BIGINT NOT NULL DEFAULT 0,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Usage_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS "Upload" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "npub" TEXT NOT NULL,
    "sha256" TEXT,
    "status" TEXT NOT NULL,
    "sizeBytes" BIGINT NOT NULL,
    "contentType" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Upload_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS "Upload_sha256_key" ON "Upload"("sha256");
CREATE INDEX IF NOT EXISTS "Upload_npub_idx" ON "Upload"("npub");

CREATE TABLE IF NOT EXISTS "ApplePurchase" (
    "originalTxId" TEXT NOT NULL PRIMARY KEY,
    "npub" TEXT NOT NULL,
    "appAccountToken" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ApplePurchase_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS "GooglePurchase" (
    "purchaseToken" TEXT NOT NULL PRIMARY KEY,
    "npub" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "subscriptionId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "GooglePurchase_npub_fkey" FOREIGN KEY ("npub") REFERENCES "User" ("npub") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS "service_config" (
    "id" INTEGER NOT NULL PRIMARY KEY CHECK ("id" = 1),
    "service_secret_key_hex" TEXT,
    "service_public_key_hex" TEXT,
    "version" TEXT,
    "generated_at" DATETIME,
    "updated_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "relay_checkpoints" (
    "stream_key" TEXT NOT NULL PRIMARY KEY,
    "last_created_at" BIGINT NOT NULL DEFAULT 0,
    "last_event_id" TEXT,
    "updated_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "enrolled_groups" (
    "mls_group_id_hex" TEXT NOT NULL PRIMARY KEY,
    "nostr_group_id_hex" TEXT NOT NULL,
    "group_name" TEXT NOT NULL,
    "group_description" TEXT NOT NULL,
    "group_relays_json" TEXT NOT NULL,
    "welcomer_pubkey_hex" TEXT NOT NULL,
    "wrapper_event_id" TEXT NOT NULL,
    "member_count" INTEGER NOT NULL DEFAULT 0,
    "enrolled_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "raw_intake_events" (
    "event_id" TEXT NOT NULL PRIMARY KEY,
    "kind" INTEGER NOT NULL,
    "wrapper_event_id" TEXT,
    "mls_group_id_hex" TEXT,
    "source_relay_url" TEXT,
    "event_json" TEXT NOT NULL,
    "received_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS "raw_intake_events_group_idx" ON "raw_intake_events"("mls_group_id_hex");

CREATE TABLE IF NOT EXISTS "moderation_cases" (
    "report_id" TEXT NOT NULL PRIMARY KEY,
    "mls_group_id_hex" TEXT NOT NULL,
    "sender_parent_pubkey" TEXT NOT NULL,
    "video_id" TEXT NOT NULL,
    "subject_child_id" TEXT NOT NULL,
    "reporter_child_id" TEXT,
    "blob_hash" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "note" TEXT,
    "level" INTEGER NOT NULL,
    "recipient_type" TEXT NOT NULL,
    "ts" BIGINT NOT NULL,
    "raw_event_id" TEXT,
    "raw_wrapper_event_id" TEXT,
    "received_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" TEXT NOT NULL DEFAULT 'new'
);

CREATE INDEX IF NOT EXISTS "moderation_cases_status_idx" ON "moderation_cases"("status");
CREATE INDEX IF NOT EXISTS "moderation_cases_group_idx" ON "moderation_cases"("mls_group_id_hex");
CREATE INDEX IF NOT EXISTS "moderation_cases_received_at_idx" ON "moderation_cases"("received_at");

CREATE TABLE IF NOT EXISTS "case_status_history" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "report_id" TEXT NOT NULL,
    "from_status" TEXT,
    "to_status" TEXT NOT NULL,
    "changed_by" TEXT,
    "note" TEXT,
    "changed_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "case_status_history_report_id_fkey" FOREIGN KEY ("report_id") REFERENCES "moderation_cases" ("report_id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS "case_status_history_report_id_idx" ON "case_status_history"("report_id");

CREATE TABLE IF NOT EXISTS "BetaFunnelEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "source" TEXT NOT NULL,
    "eventName" TEXT NOT NULL,
    "platform" TEXT,
    "familyHash" TEXT,
    "sessionId" TEXT,
    "contextJson" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS "BetaFunnelEvent_eventName_createdAt_idx" ON "BetaFunnelEvent"("eventName", "createdAt");
CREATE INDEX IF NOT EXISTS "BetaFunnelEvent_familyHash_eventName_idx" ON "BetaFunnelEvent"("familyHash", "eventName");
CREATE INDEX IF NOT EXISTS "BetaFunnelEvent_source_createdAt_idx" ON "BetaFunnelEvent"("source", "createdAt");

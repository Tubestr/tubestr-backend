-- CreateTable
CREATE TABLE "BetaFunnelEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "source" TEXT NOT NULL,
    "eventName" TEXT NOT NULL,
    "platform" TEXT,
    "familyHash" TEXT,
    "sessionId" TEXT,
    "contextJson" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "BetaFunnelEvent_eventName_createdAt_idx" ON "BetaFunnelEvent"("eventName", "createdAt");

-- CreateIndex
CREATE INDEX "BetaFunnelEvent_familyHash_eventName_idx" ON "BetaFunnelEvent"("familyHash", "eventName");

-- CreateIndex
CREATE INDEX "BetaFunnelEvent_source_createdAt_idx" ON "BetaFunnelEvent"("source", "createdAt");

import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { nip19 } from "nostr-tools";
import cors from "@fastify/cors";
import sensible from "@fastify/sensible";
import { createHash, randomBytes } from "crypto";
import { env } from "./config";
import { verifyNip98 } from "./nip98";
import { prisma } from "./prisma";
import { getBlobUrl } from "./blossom";
import {
  getEntitlementForNpub,
  upsertAppleNotification,
  upsertGoogleNotification,
} from "./subs";

declare module "fastify" {
  interface FastifyRequest {
    npub?: string;
  }
}

type ChallengeStore = Map<string, { exp: number }>;

interface BuildResult {
  app: FastifyInstance;
  cleanupInterval: NodeJS.Timeout;
}

const betaFunnelSources = new Set(["app", "marketing"]);

function hashFamilyNpub(npub: string): string {
  return createHash("sha256").update(`beta-funnel:${npub}`).digest("hex");
}

export async function buildServer(): Promise<BuildResult> {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });
  await app.register(sensible);

  const challenges: ChallengeStore = new Map();
  const cleanupInterval = setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, entry] of challenges.entries()) {
      if (entry.exp < now) challenges.delete(key);
    }
  }, 60_000);
  cleanupInterval.unref();

  const requireAuth = (req: FastifyRequest) => {
    if (!req.npub) {
      throw app.httpErrors.unauthorized("NIP-98 authentication required");
    }
  };

  app.addHook("preHandler", async (req) => {
    const path = req.routeOptions?.url ?? req.url ?? "";
    if (path.startsWith("/auth") || path.startsWith("/webhooks")) return;

    const result = await verifyNip98({ req, challenges });
    if (result?.npub) {
      req.npub = result.npub;
    }
  });

  app.get("/health", async () => ({ ok: true }));

  app.post("/auth/challenge", async () => {
    const challenge = randomBytes(24).toString("hex");
    const ttl = env.nip98ChallengeTtlSeconds;
    const exp = Math.floor(Date.now() / 1000) + ttl;
    challenges.set(challenge, { exp });

    return {
      challenge,
      expires_at: new Date(exp * 1000).toISOString(),
    };
  });

  app.get("/entitlement", async (req) => {
    requireAuth(req);
    const npub = req.npub!;

    await prisma.user.upsert({
      where: { npub },
      update: {},
      create: { npub },
    });

    const entitlement = await getEntitlementForNpub(npub);
    const usage = await prisma.usage.findUnique({ where: { npub } });

    return {
      plan: entitlement?.productId ?? null,
      status: entitlement?.status ?? "none",
      expires_at: entitlement?.expiresAt?.toISOString() ?? null,
      quota_bytes: entitlement?.quotaBytes?.toString() ?? "0",
      used_bytes: usage?.storedBytes?.toString() ?? "0",
    };
  });

  app.delete("/account", async (req) => {
    requireAuth(req);
    const npub = req.npub!;

    const deleted = await prisma.$transaction(async (tx) => {
      const [applePurchases, googlePurchases, uploads, entitlements] =
        await Promise.all([
          tx.applePurchase.deleteMany({ where: { npub } }),
          tx.googlePurchase.deleteMany({ where: { npub } }),
          tx.upload.deleteMany({ where: { npub } }),
          tx.entitlement.deleteMany({ where: { npub } }),
        ]);
      const usage = await tx.usage.deleteMany({ where: { npub } });
      const user = await tx.user.deleteMany({ where: { npub } });

      return {
        apple_purchases: applePurchases.count,
        google_purchases: googlePurchases.count,
        uploads: uploads.count,
        entitlements: entitlements.count,
        usage: usage.count,
        users: user.count,
      };
    });

    return {
      ok: true,
      npub,
      deleted,
    };
  });

  app.get("/safety/moderator-key", async (req, reply) => {
    requireAuth(req);

    let configuredNpub = env.moderation.moderatorNpub?.toLowerCase();
    const hex = env.moderation.moderatorPublicKey?.toLowerCase();

    if (!configuredNpub && hex) {
      try {
        configuredNpub = nip19.npubEncode(hex).toLowerCase();
      } catch {
        // fall through to error below
      }
    }

    if (!configuredNpub) {
      throw app.httpErrors.internalServerError("Moderator key not configured");
    }

    reply.header("Cache-Control", "public, max-age=3600");
    return { npub: configuredNpub };
  });

  interface UploadAuthorizeBody {
    filename?: string;
    content_type?: string;
    size_bytes?: number;
  }

  app.post<{ Body: UploadAuthorizeBody }>("/upload/authorize", async (req) => {
    requireAuth(req);

    const { filename, content_type, size_bytes } = req.body ?? {};
    if (!filename || !content_type || typeof size_bytes !== "number") {
      throw app.httpErrors.badRequest(
        "filename, content_type, and size_bytes are required",
      );
    }

    const entitlement = await getEntitlementForNpub(req.npub!);
    if (
      !entitlement ||
      ["expired", "canceled", "paused"].includes(entitlement.status)
    ) {
      throw app.httpErrors.paymentRequired("No active subscription");
    }

    const upload = await prisma.upload.create({
      data: {
        npub: req.npub!,
        status: "pending",
        sizeBytes: BigInt(size_bytes),
        contentType: content_type,
      },
    });

    await prisma.usage.upsert({
      where: { npub: req.npub! },
      update: {
        storedBytes: { increment: BigInt(size_bytes) },
      },
      create: {
        npub: req.npub!,
        storedBytes: BigInt(size_bytes),
        egressBytesMon: BigInt(0),
      },
    });

    return { upload_id: upload.id, blossom_url: env.blossom.publicUrl };
  });

  interface UploadCompleteBody {
    upload_id?: string;
    sha256?: string;
    size_bytes?: number;
  }

  app.post<{ Body: UploadCompleteBody }>("/upload/complete", async (req) => {
    requireAuth(req);

    const { upload_id, sha256, size_bytes } = req.body ?? {};
    if (!upload_id || !sha256) {
      throw app.httpErrors.badRequest("upload_id and sha256 are required");
    }
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw app.httpErrors.badRequest(
        "sha256 must be a 64-character hex string",
      );
    }

    const upload = await prisma.upload.findUnique({ where: { id: upload_id } });
    if (!upload || upload.npub !== req.npub) {
      throw app.httpErrors.notFound("Upload not found");
    }
    if (upload.status !== "pending") {
      throw app.httpErrors.conflict("Upload already completed");
    }

    await prisma.upload.update({
      where: { id: upload_id },
      data: {
        sha256,
        status: "uploaded",
        ...(typeof size_bytes === "number"
          ? { sizeBytes: BigInt(size_bytes) }
          : {}),
      },
    });

    return { url: getBlobUrl(sha256) };
  });

  interface DownloadUrlBody {
    sha256?: string;
  }

  app.post<{ Body: DownloadUrlBody }>("/download/url", async (req) => {
    requireAuth(req);
    const { sha256 } = req.body ?? {};
    if (!sha256) {
      throw app.httpErrors.badRequest("sha256 is required");
    }

    return { url: getBlobUrl(sha256) };
  });

  app.post("/webhooks/appstore", async (req) => {
    await upsertAppleNotification(req.body);
    return { ok: true };
  });

  app.post("/webhooks/play", async (req) => {
    await upsertGoogleNotification(req.body);
    return { ok: true };
  });

  interface BetaFunnelEventBody {
    source?: string;
    event_name?: string;
    platform?: string;
    session_id?: string;
    context?: unknown;
  }

  app.post<{ Body: BetaFunnelEventBody }>(
    "/beta/funnel-events",
    async (req) => {
      const source = req.body?.source?.trim().toLowerCase();
      const eventName = req.body?.event_name?.trim();
      const platform = req.body?.platform?.trim().toLowerCase() || null;
      const sessionId = req.body?.session_id?.trim() || null;

      if (!source || !betaFunnelSources.has(source)) {
        throw app.httpErrors.badRequest(
          "source must be one of: app, marketing",
        );
      }
      if (!eventName) {
        throw app.httpErrors.badRequest("event_name is required");
      }

      const context =
        req.body?.context == null ? null : JSON.stringify(req.body.context);
      const familyHash = req.npub ? hashFamilyNpub(req.npub) : null;

      const event = await prisma.betaFunnelEvent.create({
        data: {
          source,
          eventName,
          platform,
          familyHash,
          sessionId,
          contextJson: context,
        },
      });

      return { ok: true, id: event.id };
    },
  );

  app.get("/beta/funnel-summary", async (req) => {
    const daysRaw = (req.query as { days?: string } | undefined)?.days;
    const days = Math.min(Math.max(Number(daysRaw ?? "7") || 7, 1), 90);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const events = await prisma.betaFunnelEvent.findMany({
      where: { createdAt: { gte: since } },
      orderBy: [{ createdAt: "asc" }],
    });

    const byEvent = new Map<
      string,
      {
        source: string;
        total: number;
        uniqueFamilies: Set<string>;
      }
    >();

    for (const event of events) {
      const bucket = byEvent.get(event.eventName) ?? {
        source: event.source,
        total: 0,
        uniqueFamilies: new Set<string>(),
      };
      bucket.total += 1;
      if (event.familyHash) {
        bucket.uniqueFamilies.add(event.familyHash);
      }
      byEvent.set(event.eventName, bucket);
    }

    return {
      window_days: days,
      since: since.toISOString(),
      totals: events.length,
      events: Array.from(byEvent.entries())
        .map(([eventName, bucket]) => ({
          event_name: eventName,
          source: bucket.source,
          total: bucket.total,
          unique_families: bucket.uniqueFamilies.size,
        }))
        .sort((a, b) => a.event_name.localeCompare(b.event_name)),
    };
  });

  return { app, cleanupInterval };
}

async function main() {
  const { app, cleanupInterval } = await buildServer();

  const closeSignals: NodeJS.Signals[] = ["SIGINT", "SIGTERM"];
  for (const signal of closeSignals) {
    process.on(signal, async () => {
      app.log.info({ signal }, "Shutting down");
      clearInterval(cleanupInterval);
      await app.close();
      await prisma.$disconnect();
      process.exit(0);
    });
  }

  try {
    await app.listen({ port: env.port, host: env.host });
  } catch (err) {
    app.log.error(err);
    clearInterval(cleanupInterval);
    await app.close();
    await prisma.$disconnect();
    process.exit(1);
  }
}

void main();

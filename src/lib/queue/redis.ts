import IORedis from "ioredis";

export function isRedisConfigured(): boolean {
  if (process.env.REDIS_URL) return true;
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) return true;
  return false;
}

function buildRedisUrl(): string | null {
  // 1. If caller already set a full Redis URL, use it directly.
  if (process.env.REDIS_URL) return process.env.REDIS_URL;

  // 2. Derive from Upstash REST credentials.
  const restUrl = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (restUrl && token) {
    const host = restUrl.replace(/^https?:\/\//, "");
    return `rediss://default:${token}@${host}:6379`;
  }

  return null;
}

let _redis: IORedis | null = null;

/**
 * Returns the shared ioredis instance, creating it on first call.
 * BullMQ re-uses this connection for all queue/worker operations.
 * Returns null if Redis is not configured in the current environment.
 */
export function getRedisConnection(): IORedis | null {
  if (_redis) return _redis;

  const url = buildRedisUrl();
  if (!url) return null;

  try {
    _redis = new IORedis(url, {
      maxRetriesPerRequest: null, // Required by BullMQ
      enableReadyCheck: false, // Required by BullMQ on Upstash
      tls: url.startsWith("rediss://") ? {} : undefined,
      lazyConnect: true,
    });

    _redis.on("error", (err) => {
      // Log but don't crash — BullMQ handles reconnection internally.
      console.error("[Redis] connection error:", err.message);
    });

    return _redis;
  } catch (err: any) {
    console.error("[Redis] Failed to initialize connection:", err.message);
    return null;
  }
}

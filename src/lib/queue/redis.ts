

import IORedis from "ioredis";

function buildRedisUrl(): string {
  // 1. If caller already set a full Redis URL, use it directly.
  if (process.env.REDIS_URL) return process.env.REDIS_URL;

  // 2. Derive from Upstash REST credentials.
  const restUrl = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (restUrl && token) {

    const host = restUrl.replace(/^https?:\/\//, "");
    return `rediss://default:${token}@${host}:6379`;
  }

  throw new Error(
    "Redis is not configured. Set REDIS_URL or UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN in your .env"
  );
}

let _redis: IORedis | null = null;

/**
 * Returns the shared ioredis instance, creating it on first call.
 * BullMQ re-uses this connection for all queue/worker operations.
 */
export function getRedisConnection(): IORedis {
  if (_redis) return _redis;

  const url = buildRedisUrl();

  _redis = new IORedis(url, {
    maxRetriesPerRequest: null, // Required by BullMQ
    enableReadyCheck: false, // Required by BullMQ on Upstash
    tls: url.startsWith("rediss://") ? {} : undefined,
  });

  _redis.on("error", (err) => {
    // Log but don't crash — BullMQ handles reconnection internally.
    console.error("[Redis] connection error:", err.message);
  });

  return _redis;
}

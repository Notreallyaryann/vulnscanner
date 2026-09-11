/**
 * src/instrumentation.ts
 *
 * Next.js 15 Instrumentation Hook.
 *
 * The `register()` function is called ONCE when the Next.js server process
 * starts (before the first request is handled). This is the correct place to
 * boot long-lived singleton resources like BullMQ workers.
 *
 * Docs: https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 *
 * NOTE: This file MUST live at src/instrumentation.ts (or instrumentation.ts
 * at the project root) and is auto-discovered by Next.js — no import needed.
 */

export async function register() {
  // Only start workers in the Node.js runtime (not in the Edge runtime or
  // during the build phase where `window` / native modules are unavailable).
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Graceful degradation: if Redis is not configured, skip workers entirely
    // so the rest of the app still works (falls back to setTimeout behaviour).
    const hasRedis =
      process.env.REDIS_URL ||
      (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);

    if (!hasRedis) {
      console.warn(
        "[BullMQ] No Redis configuration found — workers not started. " +
        "Set UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN in .env to enable the job queue."
      );
      return;
    }

    try {
      const { startWorkers } = await import("./lib/queue/worker");
      startWorkers();
      console.log("[BullMQ] Job queue workers registered via instrumentation hook.");
    } catch (err: any) {
      // Log but don't crash the server if the queue fails to start.
      console.error("[BullMQ] Failed to start workers:", err?.message ?? err);
    }
  }
}

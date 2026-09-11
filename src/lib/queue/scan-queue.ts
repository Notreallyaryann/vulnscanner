import { Queue } from "bullmq";
import { getRedisConnection, isRedisConfigured } from "./redis";

// ── Job payload types ──────────────────────────────────────────────────────────

export interface DastScanJobData {
  scanId: string;
  targetUrl: string;
  customAuth?: {
    email?: string;
    password?: string;
  };
}

export interface GitHubScanJobData {
  scanId: string;
  repoFullName: string;
  branch: string;
  accessToken: string;
  enableLLM: boolean;
  email?: string;
}

// ── Lazy queue instances ───────────────────────────────────────────────────────

let _scanQueue: Queue<DastScanJobData> | null = null;
let _githubScanQueue: Queue<GitHubScanJobData> | null = null;

export function getScanQueue(): Queue<DastScanJobData> | null {
  if (_scanQueue) return _scanQueue;
  const connection = getRedisConnection();
  if (!connection) return null;

  try {
    _scanQueue = new Queue<DastScanJobData>("dast-scan", {
      connection,
      defaultJobOptions: {
        attempts: 2,           // Try once, retry once on unexpected failure
        backoff: {
          type: "exponential",
          delay: 5_000,       // 5 s initial backoff
        },
        removeOnComplete: { count: 100 },  // Keep last 100 completed jobs for inspection
        removeOnFail: { count: 50 },  // Keep last 50 failed jobs for debugging
      },
    });
    return _scanQueue;
  } catch (err: any) {
    console.error("[BullMQ] Failed to initialize scanQueue:", err.message);
    return null;
  }
}

export function getGitHubScanQueue(): Queue<GitHubScanJobData> | null {
  if (_githubScanQueue) return _githubScanQueue;
  const connection = getRedisConnection();
  if (!connection) return null;

  try {
    _githubScanQueue = new Queue<GitHubScanJobData>("github-scan", {
      connection,
      defaultJobOptions: {
        attempts: 2,
        backoff: {
          type: "exponential",
          delay: 5_000,
        },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 50 },
      },
    });
    return _githubScanQueue;
  } catch (err: any) {
    console.error("[BullMQ] Failed to initialize githubScanQueue:", err.message);
    return null;
  }
}

// ── Safe Dispatchers (BullMQ with automatic in-process fallback) ────────────────

/**
 * Enqueues a DAST scan job. If Redis is configured, pushes to BullMQ.
 * Otherwise, falls back to direct async execution in the current process.
 */
export async function enqueueDastScan(data: DastScanJobData): Promise<void> {
  const queue = getScanQueue();
  if (queue) {
    try {
      await queue.add("dast-scan", data);
      console.log(`[BullMQ] Enqueued DAST scan job for ${data.scanId}`);
      return;
    } catch (err: any) {
      console.warn(`[BullMQ] Failed to add to queue, falling back to in-process execution:`, err.message);
    }
  }

  // Fallback: run in-process via setTimeout
  setTimeout(async () => {
    try {
      const { runVulnerabilityScan } = await import("../scanner");
      await runVulnerabilityScan(data.scanId, data.targetUrl, data.customAuth);
    } catch (err) {
      console.error(`[Scanner fallback] Scan failed for ${data.scanId}:`, err);
    }
  }, 0);
}

/**
 * Enqueues a GitHub scan job. If Redis is configured, pushes to BullMQ.
 * Otherwise, falls back to direct async execution in the current process.
 */
export async function enqueueGitHubScan(data: GitHubScanJobData): Promise<void> {
  const queue = getGitHubScanQueue();
  if (queue) {
    try {
      await queue.add("github-scan", data);
      console.log(`[BullMQ] Enqueued GitHub scan job for ${data.scanId}`);
      return;
    } catch (err: any) {
      console.warn(`[BullMQ] Failed to add to queue, falling back to in-process execution:`, err.message);
    }
  }

  // Fallback: run in-process via setTimeout
  setTimeout(async () => {
    try {
      const { runGitHubScan } = await import("../github-scanner");
      await runGitHubScan(
        data.scanId,
        data.repoFullName,
        data.branch,
        data.accessToken,
        data.enableLLM,
        data.email
      );
    } catch (err) {
      console.error(`[GitHub scanner fallback] Scan failed for ${data.scanId}:`, err);
    }
  }, 0);
}

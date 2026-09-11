

import { Worker, type Job } from "bullmq";
import { getRedisConnection } from "./redis";
import { type DastScanJobData, type GitHubScanJobData } from "./scan-queue";
import { prisma } from "../prisma";

const CONCURRENCY = Number(process.env.SCAN_CONCURRENCY ?? 2);

// ── DAST Worker ────────────────────────────────────────────────────────────────

let dastWorker: Worker | null = null;

function createDastWorker(): Worker<DastScanJobData> {
  // Lazy import to avoid circular dependency at module init time.
  const worker = new Worker<DastScanJobData>(
    "dast-scan",
    async (job: Job<DastScanJobData>) => {
      const { runVulnerabilityScan } = await import("../scanner");
      const { scanId, targetUrl, customAuth } = job.data;

      console.log(`[BullMQ] DAST job ${job.id} started — scanId: ${scanId}`);

      await runVulnerabilityScan(scanId, targetUrl, customAuth);

      console.log(`[BullMQ] DAST job ${job.id} completed — scanId: ${scanId}`);
    },
    {
      connection: getRedisConnection(),
      concurrency: CONCURRENCY,
    }
  );

  worker.on("failed", async (job, err) => {
    const scanId = job?.data?.scanId;
    console.error(`[BullMQ] DAST job ${job?.id} failed (scanId: ${scanId}):`, err.message);

    // If all retry attempts are exhausted, mark the scan as FAILED in the DB
    // so the UI doesn't show it stuck in SCANNING / PENDING forever.
    if (job && job.attemptsMade >= (job.opts.attempts ?? 1)) {
      try {
        await prisma.scan.update({
          where: { id: scanId },
          data: { status: "FAILED", completedAt: new Date() },
        });
        console.warn(`[BullMQ] Marked scan ${scanId} as FAILED after all retries exhausted.`);
      } catch (dbErr) {
        console.error(`[BullMQ] Could not update scan ${scanId} status to FAILED:`, dbErr);
      }
    }
  });

  worker.on("error", (err) => {
    console.error("[BullMQ] DAST worker error:", err.message);
  });

  return worker;
}

// ── GitHub Scan Worker ─────────────────────────────────────────────────────────

let githubWorker: Worker | null = null;

function createGitHubWorker(): Worker<GitHubScanJobData> {
  const worker = new Worker<GitHubScanJobData>(
    "github-scan",
    async (job: Job<GitHubScanJobData>) => {
      const { runGitHubScan } = await import("../github-scanner");
      const { scanId, repoFullName, branch, accessToken, enableLLM, email } = job.data;

      console.log(`[BullMQ] GitHub job ${job.id} started — scanId: ${scanId}, repo: ${repoFullName}`);

      await runGitHubScan(scanId, repoFullName, branch, accessToken, enableLLM, email);

      console.log(`[BullMQ] GitHub job ${job.id} completed — scanId: ${scanId}`);
    },
    {
      connection: getRedisConnection(),
      concurrency: CONCURRENCY,
    }
  );

  worker.on("failed", async (job, err) => {
    const scanId = job?.data?.scanId;
    console.error(`[BullMQ] GitHub job ${job?.id} failed (scanId: ${scanId}):`, err.message);

    if (job && job.attemptsMade >= (job.opts.attempts ?? 1)) {
      try {
        await prisma.gitHubScan.update({
          where: { id: scanId },
          data: { status: "FAILED", completedAt: new Date() },
        });
        console.warn(`[BullMQ] Marked GitHub scan ${scanId} as FAILED after all retries exhausted.`);
      } catch (dbErr) {
        console.error(`[BullMQ] Could not update GitHub scan ${scanId} status to FAILED:`, dbErr);
      }
    }
  });

  worker.on("error", (err) => {
    console.error("[BullMQ] GitHub worker error:", err.message);
  });

  return worker;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Starts both BullMQ workers. Safe to call multiple times — subsequent calls
 * are no-ops if workers are already running.
 */
export function startWorkers(): void {
  if (!dastWorker) {
    dastWorker = createDastWorker();
    console.log(`[BullMQ] DAST worker started (concurrency: ${CONCURRENCY})`);
  }
  if (!githubWorker) {
    githubWorker = createGitHubWorker();
    console.log(`[BullMQ] GitHub worker started (concurrency: ${CONCURRENCY})`);
  }
}

/**
 * Gracefully shuts down both workers.
 * Call this in process teardown / tests.
 */
export async function stopWorkers(): Promise<void> {
  await Promise.all([
    dastWorker?.close(),
    githubWorker?.close(),
  ]);
  dastWorker = null;
  githubWorker = null;
  console.log("[BullMQ] Workers stopped.");
}


import { Queue } from "bullmq";
import { getRedisConnection } from "./redis";

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

// ── Queue instances ────────────────────────────────────────────────────────────

/** Queue for DAST (Dynamic Application Security Testing) web scans. */
export const scanQueue = new Queue<DastScanJobData>("dast-scan", {
  connection: getRedisConnection(),
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

/** Queue for GitHub repository SAST/SCA scans. */
export const githubScanQueue = new Queue<GitHubScanJobData>("github-scan", {
  connection: getRedisConnection(),
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

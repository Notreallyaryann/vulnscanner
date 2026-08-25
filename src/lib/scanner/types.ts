import pLimit from "p-limit";

// Global type augmentation: allows `next: { revalidate }` in native fetch() calls
// without needing @ts-ignore on every probe file.
declare global {
  interface RequestInit {
    next?: { revalidate?: number | false; tags?: string[] };
  }
}


export interface PendingFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
  // ── False-positive reduction fields ──
  confidence?: number;         // 0.0 – 1.0: how certain we are this is real
  validationSteps?: string[];  // proof trail: each step that confirmed the finding
  isVerified?: boolean;        // true = multiple independent signals confirmed it
}

export interface AuthSession {
  cookies: string;
  bearerToken: string;
  csrfToken: string;
  userId: string;
  userId2: string;
  cookies2: string;
  bearerToken2: string;
}

export const EMPTY_SESSION: AuthSession = {
  cookies: "",
  bearerToken: "",
  csrfToken: "",
  userId: "",
  userId2: "",
  cookies2: "",
  bearerToken2: "",
};

export const FETCH_HEADERS = {
  "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/3.0; Security-Audit)",
  Accept: "text/html,application/xhtml+xml,*/*;q=0.9",
  "Accept-Language": "en-US,en;q=0.9",
};

/**
 * Confidence levels used across probes.
 */
export const CONFIDENCE = {
  DETERMINISTIC: 0.99,
  DUAL_VERIFIED: 0.95,
  TIMING_VERIFIED: 0.90,
  EXEC_VERIFIED: 0.93,
  SINGLE_PAYLOAD: 0.55,
  PASSIVE_SIGNAL: 0.20,
} as const;

/** Build a verified finding (dual-payload or multi-step confirmed). */
export function verifiedFinding(
  base: Omit<PendingFinding, "confidence" | "validationSteps" | "isVerified">,
  steps: string[],
  confidence: number = CONFIDENCE.DUAL_VERIFIED
): PendingFinding {
  return { ...base, confidence, validationSteps: steps, isVerified: true };
}

/** Build an unverified (passive/single-event) finding. */
export function passiveFinding(
  base: Omit<PendingFinding, "confidence" | "validationSteps" | "isVerified">,
  steps: string[],
  confidence: number = CONFIDENCE.PASSIVE_SIGNAL
): PendingFinding {
  return { ...base, confidence, validationSteps: steps, isVerified: false };
}

export function safeUrlJoin(base: string, path: string): string | null {
  try {
    return new URL(path, base).toString();
  } catch {
    return null;
  }
}


export const PROBE_CONCURRENCY = 3;
export const PROBE_DELAY_MS = 150;

export async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Throttled Probe Dispatcher.
 */
export async function throttledProbes<T>(
  items: T[],
  probeFn: (item: T) => Promise<PendingFinding | null | (PendingFinding | null)[]>,
  concurrency = PROBE_CONCURRENCY,
  delayMs = PROBE_DELAY_MS
): Promise<PendingFinding[]> {
  const limit = pLimit(concurrency);
  const results: PendingFinding[] = [];

  await Promise.all(
    items.map((item) =>
      limit(async () => {
        try {
          const res = await probeFn(item);
          if (res) {
            if (Array.isArray(res)) {
              results.push(...res.filter((f): f is PendingFinding => Boolean(f)));
            } else {
              results.push(res);
            }
          }
        } catch {
          // Swallow individual probe failure
        }
        if (delayMs > 0) {
          await sleep(delayMs);
        }
      })
    )
  );

  return results;
}

export interface FormTarget {
  actionUrl: string;
  method: "GET" | "POST";
  fields: string[];
}

export interface JsApiEndpoint {
  url: string;
  method?: string;
  sourceJsUrl?: string;
}

import { chromium, Browser, BrowserContext } from "playwright";

// ─── Chromium launch args safe for both local and server/Docker environments ─

const CHROMIUM_ARGS = [
  "--no-sandbox",
  "--disable-dev-shm-usage",
  "--disable-setuid-sandbox",
  "--disable-gpu",
  "--no-first-run",
  "--no-zygote",
  "--single-process",
  "--disable-background-networking",
  "--disable-extensions",
  "--disable-sync",
  "--disable-translate",
  "--metrics-recording-only",
  "--safebrowsing-disable-auto-update",
];

// ─── Per-scan browser state ──────────────────────────────────────────────────

interface PoolEntry {
  browser: Browser;
  refCount: number;
  createdAt: number;
}

const pool = new Map<string, PoolEntry>();

/**
 * Acquire a shared Chromium Browser instance for a given scan.
 * Multiple callers within the same scan share the same browser.
 * The browser is only closed when `releaseBrowser()` is called
 * AND all acquirers have released.
 *
 * On Vercel (no local Chromium), returns null so callers can
 * fall back to static fetch.
 */
export async function acquireBrowser(scanId: string): Promise<Browser | null> {
  // Vercel / serverless — no Playwright available
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) {
    return null;
  }

  const existing = pool.get(scanId);
  if (existing) {
    existing.refCount++;
    return existing.browser;
  }

  let browser: Browser;
  try {
    const pw = await import("playwright");
    browser = await pw.chromium.launch({
      headless: true,
      args: CHROMIUM_ARGS,
    });
  } catch {
    return null; // Playwright not installed
  }

  pool.set(scanId, { browser, refCount: 1, createdAt: Date.now() });
  return browser;
}

/**
 * Decrement the reference count for a scan's browser.
 * When refCount hits 0, the browser is closed.
 */
export async function releaseBrowser(scanId: string): Promise<void> {
  const entry = pool.get(scanId);
  if (!entry) return;

  entry.refCount--;
  if (entry.refCount <= 0) {
    pool.delete(scanId);
    await entry.browser.close().catch(() => {});
  }
}

/**
 * Force-close a scan's browser (used on scan cancellation / error).
 */
export async function destroyBrowser(scanId: string): Promise<void> {
  const entry = pool.get(scanId);
  if (!entry) return;
  pool.delete(scanId);
  await entry.browser.close().catch(() => {});
}

/**
 * Create an authenticated BrowserContext within a shared browser.
 *
 * Injects:
 * - Auth cookies (if session.cookies is non-empty)
 * - Authorization Bearer header (if session.bearerToken is non-empty)
 * - DOM XSS sink instrumentation script
 */
export async function createAuthContext(
  browser: Browser,
  targetUrl: string,
  session?: { cookies: string; bearerToken: string },
): Promise<BrowserContext> {
  const extraHeaders: Record<string, string> = {
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
  };

  if (session?.bearerToken) {
    extraHeaders["Authorization"] = `Bearer ${session.bearerToken}`;
  }

  const context = await browser.newContext({
    userAgent:
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 VulnScanner/3.0",
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
    extraHTTPHeaders: extraHeaders,
  });

  // Inject auth cookies into the context
  if (session?.cookies) {
    const parsedUrl = new URL(targetUrl);
    const cookiePairs = session.cookies.split(";").map((c) => c.trim()).filter(Boolean);
    const cookieObjects: Array<{
      name: string;
      value: string;
      domain: string;
      path: string;
      httpOnly: boolean;
      secure: boolean;
      sameSite: "Lax";
    }> = [];

    for (const pair of cookiePairs) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx < 1) continue;
      const name = pair.slice(0, eqIdx).trim();
      const value = pair.slice(eqIdx + 1).trim();
      cookieObjects.push({
        name,
        value,
        domain: parsedUrl.hostname,
        path: "/",
        httpOnly: false,
        secure: parsedUrl.protocol === "https:",
        sameSite: "Lax",
      });
    }

    if (cookieObjects.length > 0) {
      await context.addCookies(cookieObjects);
    }
  }

  // Instrument DOM XSS sink monitoring before any page scripts run
  await context.addInitScript(() => {
    (window as any).__domXssSinkLogs = [];
    const trackSink = (sinkName: string, val: any) => {
      try {
        const str = String(val);
        if (
          str.includes("vulnscan") ||
          str.includes("alert(") ||
          str.includes("<img") ||
          str.includes("<script")
        ) {
          (window as any).__domXssSinkLogs.push({
            sink: sinkName,
            payloadSnippet: str.slice(0, 200),
          });
        }
      } catch {}
    };

    try {
      const origEval = window.eval;
      window.eval = function (code: string) {
        trackSink("eval", code);
        return origEval.apply(this, arguments as any);
      };
    } catch {}
  });

  return context;
}

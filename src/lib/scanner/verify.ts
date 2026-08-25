import { acquireBrowser, releaseBrowser } from "../browser-pool";
import { AuthSession, EMPTY_SESSION } from "./types";
import { authedFetch } from "./session";
import { SQL_ERROR_PATTERNS_ACTIVE, SQLI_PAYLOADS, XSS_PAYLOADS } from "./payloads";

/**
 * Fisher-Yates shuffle — returns a new array with elements in random order.
 */
export function shuffleArray<T>(arr: T[]): T[] {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

/**
 * Open `testUrl` in the configured headless browser and check whether the
 * XSS payload actually *executes* (not merely appears in the HTML source).
 */
export async function browserVerifyXssExecution(
  testUrl: string,
  log: (m: string) => void,
  scanId: string
): Promise<boolean> {
  // Path A: external browser service
  const serviceUrl = process.env.BROWSER_SERVICE_URL;
  if (serviceUrl) {
    try {
      const resp = await fetch(`${serviceUrl.replace(/\/$/, "")}/xss-verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: testUrl }),
        signal: AbortSignal.timeout(20000),
      });
      if (resp.ok) {
        const data = (await resp.json()) as { fired?: boolean };
        if (data.fired) {
          log(`🧪  Browser XSS execution confirmed via browser service: ${testUrl}`);
          return true;
        }
      }
    } catch {
      /* fall through to Playwright */
    }
  }

  // Path B: Vercel — no local browser
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) return false;

  // Path C: local Playwright pool
  const slotId = `xss-verify-${scanId}-${Date.now()}`;
  const browser = await acquireBrowser(slotId);
  if (!browser) return false;

  try {
    const context = await browser.newContext({
      javaScriptEnabled: true,
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();

    // Instrument BEFORE navigation so the patch runs before any inline script
    await page.addInitScript(() => {
      (window as any).__XSS_FIRED__ = false;
      const mark = () => {
        (window as any).__XSS_FIRED__ = true;
      };
      (window as any).alert = mark;
      (window as any).confirm = mark;
      (window as any).prompt = mark;
      window.addEventListener("error", () => mark());
    });

    try {
      await page.goto(testUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {
      /* timeout — still check the flag */
    }

    // Give async handlers time to fire
    await page.waitForTimeout(1500).catch(() => {});

    const fired: boolean = await page
      .evaluate(() => !!(window as any).__XSS_FIRED__)
      .catch(() => false);

    await context.close();

    if (fired) log(`🧪  Browser XSS execution confirmed via Playwright: ${testUrl}`);
    return fired;
  } catch {
    return false;
  } finally {
    await releaseBrowser(slotId);
  }
}

export async function confirmSQLiHit(
  url: string,
  param: string,
  triggeringPayload: string,
  isForm = false,
  formFields?: string[],
  method?: "GET" | "POST",
  session: AuthSession = EMPTY_SESSION
): Promise<boolean> {
  const confirmPayloads = SQLI_PAYLOADS.filter((p) => p !== triggeringPayload).slice(0, 3);
  for (const confirmPayload of confirmPayloads) {
    try {
      let body = "";
      let fetchUrl = url;
      if (isForm && formFields) {
        const fd = new URLSearchParams();
        for (const f of formFields) fd.set(f, f === param ? confirmPayload : "confirm_test");
        if (method === "POST") {
          const resp = await authedFetch(
            url,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: fd.toString(),
            },
            8000,
            false,
            session
          );
          if (!resp) continue;
          body = await resp.text();
        } else {
          const u = new URL(url);
          for (const [k, v] of fd) u.searchParams.set(k, v);
          fetchUrl = u.toString();
        }
      } else {
        const u = new URL(url);
        u.searchParams.set(param, confirmPayload);
        fetchUrl = u.toString();
      }
      if (!body) {
        const resp = await authedFetch(fetchUrl, {}, 8000, false, session);
        if (!resp) continue;
        body = await resp.text();
      }
      if (SQL_ERROR_PATTERNS_ACTIVE.some((p) => p.test(body))) return true;
    } catch {
      /* try next */
    }
  }
  return false;
}

export async function confirmXSSHit(
  url: string,
  param: string,
  triggeringPayload: string,
  session: AuthSession = EMPTY_SESSION
): Promise<boolean> {
  const pool = shuffleArray(XSS_PAYLOADS.filter((p) => p !== triggeringPayload));
  const confirmPayloads = pool.slice(0, 2);
  for (const payload of confirmPayloads) {
    try {
      const u = new URL(url);
      u.searchParams.set(param, payload);
      const resp = await authedFetch(u.toString(), {}, 8000, false, session);
      if (!resp) continue;
      const body = await resp.text();
      const htmlEncodedForms = [
        payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"),
        payload.replace(/"/g, "&quot;"),
        payload.replace(/'/g, "&#x27;"),
        payload.replace(/'/g, "&#39;"),
      ];
      const isEncoded = htmlEncodedForms.some((enc) => body.includes(enc));
      if (body.includes(payload) && !isEncoded) return true;
    } catch {
      /* try next */
    }
  }
  return false;
}

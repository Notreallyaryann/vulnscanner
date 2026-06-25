import { chromium, Browser } from "playwright";


export interface BrowserResult {
  /** Fully rendered HTML after JS hydration */
  html: string;
  /** Framework/tech signals detected via runtime JS evaluation */
  runtimeFrameworks: string[];
  /** Additional same-origin links discovered client-side (SPA routes) */
  discoveredLinks: string[];
  /** API or background endpoints intercepted during page execution (fetch/XHR) */
  interceptedRequests: string[];
}

// ─── Chromium launch args safe for both local and server/Docker environments ─

const CHROMIUM_ARGS = [
  "--no-sandbox",                  // Required in Docker / CI environments
  "--disable-dev-shm-usage",       // Prevents /dev/shm OOM crashes in containers
  "--disable-setuid-sandbox",
  "--disable-gpu",                 // Not needed for headless scanning
  "--no-first-run",
  "--no-zygote",
  "--single-process",              // Lower memory footprint during scans
  "--disable-background-networking",
  "--disable-extensions",
  "--disable-sync",
  "--disable-translate",
  "--metrics-recording-only",
  "--safebrowsing-disable-auto-update",
];

// ─── Main export: render a URL and return structured results ─────────────────


export async function renderWithBrowser(
  url: string,
  log: (msg: string) => void,
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
        // Set a timeout to prevent hanging the scan
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

  // ─── Case 3: Local environment, no service URL. Run Playwright locally ─────
  let browser: Browser | null = null;
  try {
    log(`🌐  Playwright (Local): Launching headless Chromium for ${url}`);

    // Dynamically import playwright to prevent loading it on Vercel/serverless environments
    let playwrightModule;
    try {
      playwrightModule = await import("playwright");
    } catch (importErr: any) {
      log(`⚠️  Playwright (Local): Failed to load module — ${importErr?.message ?? String(importErr)}`);
      return null;
    }

    browser = await playwrightModule.chromium.launch({
      headless: true,
      args: CHROMIUM_ARGS,
    });

    const context = await browser.newContext({
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 VulnScanner/3.0",
      ignoreHTTPSErrors: true,
      // Broad viewport to trigger desktop-mode renders (avoids mobile-only code paths)
      viewport: { width: 1440, height: 900 },
      // Accept all content types so we don't miss API JSON responses in the DOM
      extraHTTPHeaders: {
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });

    const page = await context.newPage();

    const parsedBase = new URL(url);
    const baseHostname = parsedBase.hostname;
    const interceptedRequests: string[] = [];

    // Intercept background API / Fetch / XHR requests
    page.on("request", (request) => {
      const resourceType = request.resourceType();
      const urlStr = request.url();
      if (resourceType === "fetch" || resourceType === "xhr" || urlStr.includes("/api/")) {
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

    // Stage 1: Navigate — use domcontentloaded for initial paint
    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      });
    } catch {
      log(`⚠️  Playwright: Navigation timed out for ${url}, proceeding with partial render`);
    }

    // Stage 2: Wait for SPA hydration — networkidle with generous timeout
    // If the app has WebSockets or polling, this will time out; that is OK.
    try {
      await page.waitForLoadState("networkidle", { timeout: 10000 });
    } catch {
      // App has persistent network connections — still usable
    }

    // Stage 3: Let deferred JS finish (React lazy-loading, route transitions)
    // This is a real wait, NOT a fixed sleep — uses requestAnimationFrame heuristic
    await page.waitForFunction(() => document.readyState === "complete", {
      timeout: 5000,
    }).catch(() => { });

    // Stage 4: Extract rendered HTML (the full hydrated DOM)
    const html = await page.content();
    log(
      `✅  Playwright: Rendered ${(html.length / 1024).toFixed(1)} KB of hydrated DOM`,
    );

    // Stage 5: Detect frameworks via runtime JS evaluation
    // These signals ONLY exist at runtime — invisible to static fetch()
    const runtimeFrameworks = await page
      .evaluate(() => {
        const detected: string[] = [];
        const w = window as any;

        if (w.__NEXT_DATA__ || w.next) detected.push("Next.js");
        if (w.__nuxt__ || w.$nuxt || w.__NUXT__) detected.push("Nuxt.js");
        if (w.angular || document.querySelector("[ng-version]")) detected.push("Angular");
        if (w.__VUE__ || w.Vue) detected.push("Vue.js");
        if (w.React || w.__REACT_DEVTOOLS_GLOBAL_HOOK__) detected.push("React");
        if (w.__remix_server_manifest__ || w.__remixContext) detected.push("Remix");
        if (w.__gatsby) detected.push("Gatsby");
        if (w.__sveltekit_dev || document.querySelector("[data-sveltekit-preload-data]"))
          detected.push("SvelteKit");
        if (document.querySelector("astro-page") || w.__astro_hmr)
          detected.push("Astro");
        if (w.htmx) detected.push("HTMX");
        if (w.Alpine) detected.push("Alpine.js");
        if (w.Ember) detected.push("Ember.js");
        if (w.Backbone) detected.push("Backbone.js");
        if (w.jQuery || w.$?.fn?.jquery) detected.push("jQuery");
        return detected;
      })
      .catch(() => [] as string[]);

    if (runtimeFrameworks.length > 0) {
      log(`🧬  Playwright: Runtime frameworks detected: ${runtimeFrameworks.join(", ")}`);
    }

    // Stage 6: Extract client-side discovered links for SPA route coverage
    // Playwright sees the full rendered anchor tags that fetch() would miss
    const discoveredLinks = await page
      .evaluate(
        (baseHostname: string) => {
          return Array.from(document.querySelectorAll("a[href]"))
            .map((a) => (a as HTMLAnchorElement).href)
            .filter((href) => {
              try {
                const u = new URL(href);
                return (
                  u.hostname === baseHostname &&
                  !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(
                    u.pathname,
                  )
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

    log(`🔗  Playwright: Found ${discoveredLinks.length} client-side links`);
    if (interceptedRequests.length > 0) {
      log(`📡  Playwright: Intercepted ${interceptedRequests.length} background API request(s)`);
    }

    return { html, runtimeFrameworks, discoveredLinks, interceptedRequests };
  } catch (error: any) {
    log(`⚠️  Playwright: Browser rendering failed — ${error?.message ?? String(error)}`);
    log(`↩️  Playwright: Falling back to static HTTP fetch results`);
    return null;
  } finally {
    if (browser) {
      await browser.close().catch(() => { });
    }
  }
}

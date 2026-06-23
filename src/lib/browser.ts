import { chromium, Browser } from "playwright";

// ─── Result type returned from browser rendering ───────────────────────────

export interface BrowserResult {
  /** Fully rendered HTML after JS hydration */
  html: string;
  /** Framework/tech signals detected via runtime JS evaluation */
  runtimeFrameworks: string[];
  /** Additional same-origin links discovered client-side (SPA routes) */
  discoveredLinks: string[];
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

/**
 * Industry-grade Playwright renderer.
 *
 * Strategy:
 *   1. Navigate with `domcontentloaded` (fast) to get the shell immediately.
 *   2. Wait for `networkidle` with a generous timeout to let SPAs hydrate.
 *   3. If networkidle times out (background polling / WebSockets), we still
 *      proceed with whatever has rendered — we do NOT block the scan.
 *   4. Evaluate runtime JS to detect frameworks that don't leave static traces.
 *   5. Extract client-side discovered anchor links for SPA route coverage.
 *
 * Falls back to `null` gracefully on any error so the scanner always continues.
 */
export async function renderWithBrowser(
  url: string,
  log: (msg: string) => void,
): Promise<BrowserResult | null> {
  let browser: Browser | null = null;
  try {
    log(`🌐  Playwright: Launching headless Chromium for ${url}`);

    browser = await chromium.launch({
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
    }).catch(() => {});

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

        if (w.__NEXT_DATA__ || w.next)                          detected.push("Next.js");
        if (w.__nuxt__ || w.$nuxt || w.__NUXT__)               detected.push("Nuxt.js");
        if (w.angular || document.querySelector("[ng-version]")) detected.push("Angular");
        if (w.__VUE__ || w.Vue)                                 detected.push("Vue.js");
        if (w.React || w.__REACT_DEVTOOLS_GLOBAL_HOOK__)        detected.push("React");
        if (w.__remix_server_manifest__ || w.__remixContext)    detected.push("Remix");
        if (w.__gatsby)                                          detected.push("Gatsby");
        if (w.__sveltekit_dev || document.querySelector("[data-sveltekit-preload-data]"))
                                                                 detected.push("SvelteKit");
        if (document.querySelector("astro-page") || w.__astro_hmr)
                                                                 detected.push("Astro");
        if (w.htmx)                                              detected.push("HTMX");
        if (w.Alpine)                                            detected.push("Alpine.js");
        if (w.Ember)                                             detected.push("Ember.js");
        if (w.Backbone)                                          detected.push("Backbone.js");
        if (w.jQuery || w.$?.fn?.jquery)                        detected.push("jQuery");
        return detected;
      })
      .catch(() => [] as string[]);

    if (runtimeFrameworks.length > 0) {
      log(`🧬  Playwright: Runtime frameworks detected: ${runtimeFrameworks.join(", ")}`);
    }

    // Stage 6: Extract client-side discovered links for SPA route coverage
    // Playwright sees the full rendered anchor tags that fetch() would miss
    const parsedBase = new URL(url);
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
        parsedBase.hostname,
      )
      .catch(() => [] as string[]);

    log(`🔗  Playwright: Found ${discoveredLinks.length} client-side links`);

    return { html, runtimeFrameworks, discoveredLinks };
  } catch (error: any) {
    log(`⚠️  Playwright: Browser rendering failed — ${error?.message ?? String(error)}`);
    log(`↩️  Playwright: Falling back to static HTTP fetch results`);
    return null;
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

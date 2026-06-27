const express = require("express");
const { chromium } = require("playwright");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;

// ─── Chromium launch args safe for Docker and server environments ─────────────
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

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "healthy" });
});

// Render endpoint
app.post("/render", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required in request body" });
  }

  console.log(`🌐 Received render request for: ${url}`);
  let browser = null;

  try {
    browser = await chromium.launch({
      headless: true,
      args: CHROMIUM_ARGS,
    });

    const context = await browser.newContext({
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 VulnScanner/3.0",
      ignoreHTTPSErrors: true,
      viewport: { width: 1440, height: 900 },
      extraHTTPHeaders: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });

    const page = await context.newPage();
    const parsedBase = new URL(url);
    const baseHostname = parsedBase.hostname;
    const interceptedRequests = [];

    // Intercept background API / Fetch / XHR requests
    page.on("request", (request) => {
      const resourceType = request.resourceType();
      const urlStr = request.url();
      if (resourceType === "fetch" || resourceType === "xhr" || urlStr.includes("/api/") || urlStr.includes("/_next/data/")) {
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
        timeout: 15000,
      });
    } catch (err) {
      console.warn(`⚠️ Navigation timed out for ${url}, proceeding with partial render`);
    }

    // Stage 2: Wait for SPA hydration — networkidle with generous timeout
    try {
      await page.waitForLoadState("networkidle", { timeout: 8000 });
    } catch (err) {
      // App has persistent network connections — still usable
    }

    // Stage 3: Let deferred JS finish
    await page.waitForFunction(() => document.readyState === "complete", {
      timeout: 3000,
    }).catch(() => {});

    // Stage 4: Extract rendered HTML
    const html = await page.content();

    // Stage 5: Detect frameworks via runtime JS evaluation
    const runtimeFrameworks = await page
      .evaluate(() => {
        const detected = [];
        const w = window;
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
      .catch(() => []);

    // Stage 6: Extract client-side discovered links for SPA route coverage
    const discoveredLinks = await page
      .evaluate((baseHost) => {
        return Array.from(document.querySelectorAll("a[href]"))
          .map((a) => a.href)
          .filter((href) => {
            try {
              const u = new URL(href);
              return (
                u.hostname === baseHost &&
                !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(u.pathname)
              );
            } catch {
              return false;
            }
          })
          .slice(0, 50);
      }, baseHostname)
      .catch(() => []);

    console.log(`✅ Rendered ${(html.length / 1024).toFixed(1)} KB for ${url}`);
    res.status(200).json({
      html,
      runtimeFrameworks,
      discoveredLinks,
      interceptedRequests,
    });
  } catch (error) {
    console.error(`❌ Browser rendering failed:`, error);
    res.status(500).json({ error: error.message || "Rendering failed" });
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Browser rendering service listening on port ${PORT}`);
});

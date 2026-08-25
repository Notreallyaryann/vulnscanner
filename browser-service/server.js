const express = require("express");
const { chromium } = require("playwright");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3003;

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

// ── Keep-Alive / Anti-Sleep Configuration ─────────────────────────────────────
const KEEP_ALIVE_ENABLED = process.env.ENABLE_KEEP_ALIVE === "true";
const SELF_PING_INTERVAL_MS = parseInt(process.env.SELF_PING_INTERVAL_MS || "600000", 10); // 10 minutes default

const pingStats = {
  enabled: KEEP_ALIVE_ENABLED,
  pingCount: 0,
  lastPingTime: null,
  lastPingStatus: null,
  targetUrl: null,
};

function startKeepAliveLoop() {
  if (!KEEP_ALIVE_ENABLED) {
    console.log("ℹ️  Keep-Alive self-ping auto wake up is DISABLED by default (prevents exhausting Render free tier hours)");
    return;
  }

  const targetHost =
    process.env.SELF_PING_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    `http://localhost:${PORT}`;

  const cleanTargetHost = targetHost.replace(/\/$/, "");
  const pingEndpoint = `${cleanTargetHost}/health`;
  pingStats.targetUrl = pingEndpoint;

  console.log(`⏰ Starting Anti-Sleep Keep-Alive loop (pinging ${pingEndpoint} every ${SELF_PING_INTERVAL_MS / 1000}s)`);

  setInterval(async () => {
    try {
      pingStats.lastPingTime = new Date().toISOString();
      const response = await fetch(pingEndpoint, {
        method: "GET",
        headers: { "User-Agent": "Render-KeepAlive-Ping/1.0" },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        pingStats.pingCount++;
        pingStats.lastPingStatus = `OK (${response.status})`;
        console.log(`📡 [Keep-Alive Ping #${pingStats.pingCount}] Successfully pinged ${pingEndpoint} — service state reset`);
      } else {
        pingStats.lastPingStatus = `HTTP Error ${response.status}`;
        console.warn(`⚠️ [Keep-Alive Ping] Ping to ${pingEndpoint} returned status ${response.status}`);
      }
    } catch (err) {
      pingStats.lastPingStatus = `Error: ${err.message}`;
      console.error(`❌ [Keep-Alive Ping] Ping failed:`, err.message);
    }
  }, SELF_PING_INTERVAL_MS);
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    service: "browser-microservice",
    uptimeSeconds: Math.floor(process.uptime()),
    keepAlive: pingStats,
    timestamp: new Date().toISOString(),
  });
});

// Root path handler
app.get("/", (req, res) => {
  res.status(200).send("Browser Playwright Rendering Microservice is online.");
});

// URL patterns that are noise — NOT real API endpoints worth scanning
// Defined once at module level (not per-request) for performance
const NOISE_URL_PATTERNS = [
  /\/cdn-cgi\//i,              // Cloudflare challenge platform
  /\/beacon(\.js)?/i,          // Analytics beacons
  /\/collect(\?|$)/i,          // Tracking collection endpoints
  /\/analytics(\.js)?/i,       // Analytics scripts
  /\/gtm(\.js)?\?/i,           // Google Tag Manager
  /\/gtag(\.js)?\?/i,          // Google Analytics gtag
  /\/fbevents\.js/i,           // Facebook Pixel
  /\/sentry\.(io|js)/i,        // Sentry error reporting
  /\/sockjs-node/i,            // Webpack hot reload
  /\/_next\/webpack-hmr/i,     // Next.js HMR websocket
  /\/socket\.io\/\?/i,         // Socket.io polling noise
];

// Render endpoint
app.post("/render", async (req, res) => {
  const { url } = req.body;

  // Bug fix #1: validate URL format before passing to Playwright
  // An invalid URL would crash `new URL(url)` below and return a 500
  if (!url) {
    return res.status(400).json({ error: "URL is required in request body" });
  }
  let parsedBase;
  try {
    parsedBase = new URL(url);
  } catch {
    return res.status(400).json({ error: `Invalid URL: ${url}` });
  }

  console.log(`🌐 Received render request for: ${url}`);

  // Bug fix #2: browser and context tracked separately so context is always closed
  // even if page operations fail — prevents Playwright context/browser leaks
  let browser = null;
  let context = null;

  try {
    browser = await chromium.launch({
      headless: true,
      args: CHROMIUM_ARGS,
    });

    context = await browser.newContext({
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
    const baseHostname = parsedBase.hostname;
    const interceptedRequests = [];

    // Bug fix #3: page.on("request") fires BEFORE page.goto() is called,
    // so we register the listener immediately after creating the page (correct).
    // However the original code used `urlStr.includes("/api/")` which also
    // catches strings like "/capabilities" — restrict to actual resource types only
    // and rely on the noise filter + same-origin check for /api/ paths.
    page.on("request", (request) => {
      const resourceType = request.resourceType();
      const urlStr = request.url();

      // Only capture fetch/xhr and /_next/data/ data fetches
      const isApiLike =
        resourceType === "fetch" ||
        resourceType === "xhr" ||
        urlStr.includes("/_next/data/");

      if (!isApiLike) return;

      try {
        // Skip noise URLs (Cloudflare challenge platform, analytics, HMR, etc.)
        if (NOISE_URL_PATTERNS.some((pattern) => pattern.test(urlStr))) return;

        const reqUrl = new URL(urlStr);
        const baseParts = baseHostname.split(".");
        const reqParts = reqUrl.hostname.split(".");

        // Allow same host OR any subdomain sharing the same apex (e.g. api.example.com)
        const isSameOrSub =
          reqUrl.hostname === baseHostname ||
          (reqParts.length >= 2 &&
            baseParts.length >= 2 &&
            reqUrl.hostname.endsWith(baseParts.slice(-2).join(".")));

        if (isSameOrSub) {
          // Deduplicate by hostname+pathname (ignore dynamic query params/tokens)
          const canonicalKey = `${reqUrl.hostname}${reqUrl.pathname}`;
          const alreadySeen = interceptedRequests.some((existing) => {
            try {
              const e = new URL(existing);
              return e.hostname + e.pathname === canonicalKey;
            } catch {
              return false;
            }
          });
          if (!alreadySeen) {
            // Store clean URL — strip dynamic query tokens for readability
            const cleanUrl = `${reqUrl.protocol}//${reqUrl.hostname}${reqUrl.pathname}`;
            interceptedRequests.push(cleanUrl);
          }
        }
      } catch {
        // Ignore unparseable URLs
      }
    });

    // Stage 1: Navigate — use domcontentloaded for initial paint
    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 15000,
      });
    } catch (err) {
      console.warn(`⚠️ Navigation timed out or failed for ${url}: ${err.message}. Proceeding with partial render.`);
    }

    // Stage 2: Wait for SPA hydration — networkidle with generous timeout
    try {
      await page.waitForLoadState("networkidle", { timeout: 8000 });
    } catch {
      // App has persistent network connections (WebSocket, SSE) — still usable
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

        // Next.js
        if (
          w.__NEXT_DATA__ ||
          w.next ||
          w.__NEXT_P ||
          document.querySelector("script[src*='/_next/']") ||
          document.querySelector("next-route-announcer, [data-next-page]")
        ) {
          detected.push("Next.js");
        }

        // Nuxt.js
        if (w.__nuxt__ || w.$nuxt || w.__NUXT__ || document.querySelector("script[src*='/_nuxt/']")) {
          detected.push("Nuxt.js");
        }

        // Angular (v1, v2-v18+)
        if (
          w.angular ||
          w.ng ||
          w.getAllAngularRootElements ||
          document.querySelector("[ng-version], [ng-app], [ng-server-context], [ng-component], app-root, router-outlet, [ng-reflect-model], [_nghost-c0], [_ngcontent-c0]") ||
          document.querySelector("script[src*='angular'], script[src*='main-es'], script[src*='polyfills']")
        ) {
          detected.push("Angular");
        }

        // Vue.js
        if (
          w.__VUE__ ||
          w.Vue ||
          w.__vue__ ||
          document.querySelector("[data-v-], [v-cloak], [v-is]") ||
          document.querySelector("script[src*='vue']")
        ) {
          detected.push("Vue.js");
        }

        // React (including React 17/18/19 DOM fiber inspection)
        const hasReactFiber = () => {
          try {
            const els = [
              document.body,
              document.getElementById("root"),
              document.getElementById("__next"),
              document.querySelector("main"),
              document.querySelector("div"),
            ].filter(Boolean);
            return els.some(
              (el) =>
                el &&
                Object.keys(el).some(
                  (k) => k.startsWith("__react") || k.startsWith("_react")
                )
            );
          } catch {
            return false;
          }
        };
        if (
          w.React ||
          w.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
          document.querySelector("[data-reactroot], [data-reactid], [data-react-checksum]") ||
          hasReactFiber() ||
          document.querySelector("script[src*='react']")
        ) {
          detected.push("React");
        }

        // Django
        if (
          document.querySelector("input[name='csrfmiddlewaretoken']") ||
          document.cookie.includes("csrftoken") ||
          document.querySelector("a[href*='/admin/login']")
        ) {
          detected.push("Django");
        }

        // FastAPI
        if (document.querySelector("a[href*='/docs'], a[href*='/redoc'], a[href*='/openapi.json']")) {
          detected.push("FastAPI");
        }

        // Remix
        if (w.__remix_server_manifest__ || w.__remixContext) detected.push("Remix");

        // Gatsby
        if (w.__gatsby) detected.push("Gatsby");

        // Svelte / SvelteKit
        if (
          w.__svelte ||
          w.__sveltekit_dev ||
          document.querySelector("[data-sveltekit-preload-data], [class*='svelte-']") ||
          document.querySelector("script[src*='_app/immutable']")
        ) {
          detected.push("SvelteKit");
        }

        // Astro
        if (document.querySelector("astro-page") || w.__astro_hmr) detected.push("Astro");

        // HTMX, Alpine, Ember, Backbone, jQuery
        if (w.htmx) detected.push("HTMX");
        if (w.Alpine) detected.push("Alpine.js");
        if (w.Ember) detected.push("Ember.js");
        if (w.Backbone) detected.push("Backbone.js");
        // Bug fix #4: w.$?.fn?.jquery uses optional chaining which is valid in modern Node,
        // but w.$ could be jQuery OR many other things (Zepto, cash-dom, prototype).
        // Check jquery property specifically to avoid false positives.
        if (w.jQuery || (w.$ && w.$.fn && w.$.fn.jquery)) detected.push("jQuery");

        // PHP / Laravel
        if (document.querySelector("input[name='_token']") || document.cookie.includes("laravel_session")) {
          detected.push("Laravel");
        }

        // Spring / Java
        if (document.cookie.includes("JSESSIONID")) detected.push("Spring");

        // ASP.NET
        if (
          document.querySelector("input[name='__VIEWSTATE']") ||
          document.cookie.includes("ASP.NET")
        ) {
          detected.push("ASP.NET");
        }

        return Array.from(new Set(detected));
      })
      .catch(() => []);

    // Stage 6: Extract client-side discovered links for SPA route coverage
    const discoveredLinks = await page
      .evaluate((baseHost) => {
        const links = new Set();
        document
          .querySelectorAll("a[href], [routerlink], [to], [data-href], [ng-reflect-router-link]")
          .forEach((el) => {
            const val =
              el.getAttribute("href") ||
              el.getAttribute("routerlink") ||
              el.getAttribute("to") ||
              el.getAttribute("data-href") ||
              el.getAttribute("ng-reflect-router-link");
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
                // Bug fix #5: relative paths like "about" should resolve relative to current
                // page URL, not blindly prepend /#/ which breaks non-hash-router SPAs.
                // Try both — the engine will de-dupe and discard invalid ones.
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
                u.hostname === baseHost &&
                // Bug fix #6: also filter out .webp, .ttf, .eot, .xml, .txt asset extensions
                !/\.(css|js|png|jpg|jpeg|gif|ico|webp|woff|woff2|ttf|eot|svg|pdf|xml|txt|map)$/i.test(
                  u.pathname
                )
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
    console.error(`❌ Browser rendering failed for ${url}:`, error);
    res.status(500).json({ error: error.message || "Rendering failed" });
  } finally {
    // Bug fix #2 (continued): always close context first, then browser
    // Closing browser alone without closing context can leave dangling page processes
    if (context) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Browser rendering service listening on port ${PORT}`);
  startKeepAliveLoop();
});

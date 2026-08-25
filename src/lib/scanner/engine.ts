import { prisma } from "../prisma";
import { retrieveContext } from "../rag";
import { generateFixReport, getMockFixReport } from "../openrouter";
import { emitLog, cleanupScan } from "../scan-logger";
import { sendScanReportEmail } from "../mail";
import {
  renderWithBrowser,
  interactiveFormInjection,
  auditClientStorage,
} from "../browser";
import { runNmapScan, type NmapFinding } from "../nmap";
import { runNucleiScan, type NucleiFinding } from "../nuclei";
import { registerScanController, cleanupScanController } from "../scan-controller";
import { destroyBrowser } from "../browser-pool";
import pLimit from "p-limit";

import { extractHtmlLinksAndForms, parseSitemap, isSpaHtmlFallback } from "./crawler";
import { analyzeJsAst } from "./js-analyzer";
import {
  AuthSession,
  CONFIDENCE,
  EMPTY_SESSION,
  FETCH_HEADERS,
  FormTarget,
  JsApiEndpoint,
  PendingFinding,
  safeUrlJoin,
  verifiedFinding,
} from "./types";
import { authHeaders, authedFetch, safeFetch } from "./session";
import { attemptAutoLogin } from "./auto-auth";
import {
  SQL_ERROR_PATTERNS_ACTIVE,
  SQLI_PAYLOADS,
} from "./payloads";

import {
  probeSQLiError,
  probeFormSQLi,
  probeRestApiSQLi,
  probeBlindSQLiTiming,
  probeBlindSQLiBooleanDiff,
  probeBlindSQLiRestEndpoints,
} from "./probes/sqli";

import {
  probeReflectedXSS,
  probeFormXSS,
} from "./probes/xss";

import {
  probeCommandInjection,
  probePathTraversal,
  probeSSTI,
  probeFormSSTI,
} from "./probes/injection";

import {
  probeBrokenAuth,
  probeSessionFixationRegeneration,
  probePasswordPolicy,
  probeJWTNone,
  probeIDORWithDualToken,
  probeUnauthenticatedAPIAccess,
  probeJWTWeakSecret,
  probeIDORSequentialFuzz,
} from "./probes/auth";

import {
  detectSSRF,
  probeBlindSSRFWithTiming,
  detectSubdomainTakeoverSignals,
  probeHostHeaderInjection,
  probeCORSReflection,
  probeActiveOpenRedirect,
  probeHTTPRequestSmuggling,
  probeCachePoisoning,
  probeTLSCertificate,
  probeCommonSubdomains,
} from "./probes/network";

import {
  evaluateCSP,
  detectEnvLeaks,
  probeDebugModeExposure,
  probeCRLFInjection,
  probeDangerousHTTPMethods,
} from "./probes/headers";

import {
  discoverOpenApiEndpoints,
  probeGraphQLInjection,
  probeHTTPMethodOverride,
  probeApiSensitiveDataExposure,
} from "./probes/api";

import {
  probeXXE,
  probePrototypePollution,
  probeNoSQLi,
  probeExposedBackupFiles,
  probeDirectoryListing,
  probeHTTPSRedirect,
  probeHTMLInjection,
  probeInsecureDeserialization,
  probeSoftwareCompositionAnalysis,
  probeFileUploadVulnerabilities,
  probeMassAssignment,
  probeBusinessLogicVulnerabilities,
} from "./probes/misc";

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

      const astFindings = analyzeJsAst(code);
      if (astFindings.length > 0 && !jsIssueFound) {
        const firstAst = astFindings[0];
        const lineInfo = firstAst.line ? ` (line ${firstAst.line})` : "";
        findings.push({
          type: "js-dangerous-sink",
          severity: "HIGH",
          url: src,
          evidence: `AST Analysis: "${firstAst.label}" detected in JavaScript file ${src}${lineInfo}.`,
          cvssScore: 7.5,
          cveId: "CWE-79",
        });
        jsIssueFound = true;
      }

      for (const { label, re } of SECRET_PATTERNS) {
        if (re.test(code)) {
          const isSecret = !label.includes("eval") && !label.includes("document") && !label.includes("innerHTML");
          if (isSecret && !secretFound) {
            findings.push({
              type: "js-secret-disclosure",
              severity: "CRITICAL",
              url: src,
              evidence: `"${label}" pattern detected in JavaScript file ${src}.`,
              cvssScore: 9.5,
              cveId: "CWE-312",
            });
            secretFound = true;
          } else if (!isSecret && !jsIssueFound) {
            findings.push({
              type: "js-dangerous-sink",
              severity: "HIGH",
              url: src,
              evidence: `"${label}" detected in JavaScript file ${src}.`,
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

import {
  extractApexDomain,
  fetchWhoisIntel,
  fetchCrtSubdomains,
  resolveHostIps,
  type ReconData,
} from "../recon";

export async function runVulnerabilityScan(
  scanId: string,
  targetUrl: string,
  customAuth?: { email?: string; password?: string }
): Promise<void> {
  const controller = registerScanController(scanId);

  const log = (msg: string) => {
    console.log(`[Scan ${scanId}] ${msg}`);
    emitLog(scanId, msg);
  };

  log(`🚀 Launching AI-powered vulnerability scan against target: ${targetUrl}`);

  // ── RECON INTEL GATHERING (WHOIS, CT Logs, DNS) ─────────────────────────
  const hostname = (() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })();
  const apexDomain = extractApexDomain(hostname);

  log(`🔍  Recon: Gathering WHOIS intel & Certificate Transparency subdomains for ${apexDomain}...`);
  const reconPromise = (async (): Promise<ReconData> => {
    const [whois, crtSubs, ips] = await Promise.all([
      fetchWhoisIntel(apexDomain),
      fetchCrtSubdomains(apexDomain),
      resolveHostIps(hostname),
    ]);

    log(`🌐  Recon: WHOIS ${whois?.registrar ? `Registrar: ${whois.registrar}` : "resolved"} | Expiration: ${whois?.expiresAt ? whois.expiresAt.slice(0, 10) : "N/A"} | CT Subdomains found: ${crtSubs.length}`);

    const initialRecon: ReconData = {
      domain: hostname,
      apexDomain,
      whois,
      subdomains: crtSubs,
      techStack: [],
      apiEndpoints: [],
      discoveredLinks: [],
      serverInfo: {
        ipAddresses: ips,
      },
    };

    // ⚡ Save reconData to DB immediately so Recon Dashboard updates instantly!
    await prisma.scan.update({
      where: { id: scanId },
      data: { reconData: JSON.stringify(initialRecon) } as any,
    }).catch(() => {});

    return initialRecon;
  })().catch((err) => {
    log(`⚠️   Recon gathering warning: ${err instanceof Error ? err.message : String(err)}`);
    return {
      domain: hostname,
      apexDomain,
      subdomains: [],
      techStack: [],
      apiEndpoints: [],
      discoveredLinks: [],
    } as ReconData;
  });

  const tlsPromise = probeTLSCertificate(targetUrl).catch((err) => {
    log(`⚠️   TLS probe error: ${err instanceof Error ? err.message : String(err)}`);
    return [] as PendingFinding[];
  });

  // ⚡ Attach immediate finding recording to Nmap & Nuclei promises
  const nmapPromise = runNmapScan(targetUrl, log).then(async (findings) => {
    for (const f of findings) {
      await recordFinding(f as PendingFinding);
    }
    return findings;
  }).catch((err) => {
    log(`⚠️   Nmap scan warning: ${err instanceof Error ? err.message : String(err)}`);
    return [] as NmapFinding[];
  });

  const nucleiPromise = runNucleiScan(targetUrl, log).then(async (findings) => {
    for (const f of findings) {
      await recordFinding(f as PendingFinding);
    }
    return findings;
  }).catch((err) => {
    log(`⚠️   Nuclei scan warning: ${err instanceof Error ? err.message : String(err)}`);
    return [] as NucleiFinding[];
  });

  let session: AuthSession = { ...EMPTY_SESSION };

  const seenFindingKeys = new Set<string>();
  const backgroundAiPromises: Promise<any>[] = [];
  let totalDiscoveredCount = 0;
  const accumulatedTechs = new Set<string>();
  const accumulatedApiEndpoints = new Set<string>();
  const accumulatedDiscoveredLinks = new Set<string>();

  // ── REAL-TIME FINDING RECORDING & DB INSERTION ───────────────────────────
  const recordFinding = async (f: PendingFinding | null | undefined) => {
    if (!f) return;
    const key = `${f.type}:${f.url}:${f.parameter || ""}`;
    if (seenFindingKeys.has(key)) return;
    seenFindingKeys.add(key);
    totalDiscoveredCount++;

    const sevEmoji: Record<string, string> = {
      CRITICAL: "🔴",
      HIGH: "🟠",
      MEDIUM: "🟡",
      LOW: "🔵",
      INFO: "ℹ️",
    };
    const emoji = sevEmoji[f.severity] || "🚨";
    log(`${emoji} [DISCOVERED ${f.severity}] ${f.type.toUpperCase()}${f.parameter ? ` (param: ${f.parameter})` : ""} at ${f.url}`);

    try {
      const initialReport = getMockFixReport({
        findingType: f.type,
        url: f.url,
        parameter: f.parameter,
        evidence: f.evidence,
        cveId: f.cveId,
      });

      const dbFinding = await prisma.finding.create({
        data: {
          scanId,
          type: f.type,
          severity: f.severity,
          url: f.url,
          parameter: f.parameter,
          evidence: f.evidence,
          cvssScore: f.cvssScore,
          cveId: f.cveId,
          confidence: f.confidence ?? 0.85,
          isVerified: f.isVerified ?? false,
          validationSteps: f.validationSteps ? JSON.stringify(f.validationSteps) : undefined,
          title: initialReport.title,
          explanation: initialReport.explanation,
          fixSteps: JSON.stringify(initialReport.fixSteps),
          codeExample: JSON.stringify(initialReport.codeExample),
        },
      });

      // Background AI remediation generation
      const aiPromise = (async () => {
        try {
          const ragContext = await retrieveContext(`${f.type} ${f.evidence || ""}`);
          const aiReport = await generateFixReport({
            findingType: f.type,
            url: f.url,
            parameter: f.parameter,
            evidence: f.evidence,
            cveId: f.cveId,
            ragContext,
          });
          await prisma.finding.update({
            where: { id: dbFinding.id },
            data: {
              title: aiReport.title,
              explanation: aiReport.explanation,
              fixSteps: JSON.stringify(aiReport.fixSteps),
              codeExample: JSON.stringify(aiReport.codeExample),
            },
          });
        } catch { /* skip */ }
      })();
      backgroundAiPromises.push(aiPromise);
    } catch (err) {
      console.error(`Failed to save finding ${key} immediately:`, err);
    }
  };

  const extractSameOriginLinks = (html: string, base: string) => extractHtmlLinksAndForms(html, base).links;
  const extractForms = (html: string, base: string) => extractHtmlLinksAndForms(html, base).forms;
  const extractParamUrls = (html: string, base: string): string[] => {
    const { links } = extractHtmlLinksAndForms(html, base);
    return links.filter((l) => l.includes("?"));
  };
  const extractApiEndpoints = (html: string, base: string): string[] => {
    const { links } = extractHtmlLinksAndForms(html, base);
    return links.filter((l) => /\/api\/|\/rest\/|\/v1\/|\/v2\/|\/graphql/i.test(l));
  };
  const extractJsBundleEndpoints = async (html: string, base: string): Promise<JsApiEndpoint[]> => {
    const { links } = extractHtmlLinksAndForms(html, base);
    return links.filter((l) => /\/api\/|\/rest\//i.test(l)).map((url) => ({ url, path: new URL(url).pathname, fields: [] }));
  };

  try {
    await attemptAutoLogin(targetUrl, log, session, customAuth, scanId);

    const visitedUrls = new Set<string>();
    const urlQueue: string[] = [targetUrl];
    const MAX_PAGES_TO_SCAN = 15;
    let homepageHtml = "";
    let crawlStatusSet = false;

    while (urlQueue.length > 0 && visitedUrls.size < MAX_PAGES_TO_SCAN) {
      if (!crawlStatusSet) {
        crawlStatusSet = true;
        prisma.scan.update({ where: { id: scanId }, data: { status: "CRAWLING" } }).catch(() => {});
      }
      if (controller.signal.aborted) {
        log("🛑  Scan cancellation signal received — stopping crawler");
        throw new Error("scan_cancelled");
      }

      const currentUrl = urlQueue.shift()!;
      let normalizedUrl = currentUrl;
      try {
        const u = new URL(currentUrl);
        const isHashRoute = /^#\/[a-zA-Z0-9_-]+/.test(u.hash) && !u.hash.startsWith("#/#");
        if (!isHashRoute) u.hash = "";
        normalizedUrl = u.toString();
      } catch {}

      if (visitedUrls.has(normalizedUrl)) continue;
      visitedUrls.add(normalizedUrl);

      let fetchUrl = normalizedUrl;
      try {
        const u = new URL(normalizedUrl);
        if (u.hash.startsWith("#/")) {
          u.hash = "";
          fetchUrl = u.toString();
        }
      } catch {}

      log(`📖 [Page ${visitedUrls.size}/${MAX_PAGES_TO_SCAN}] Crawling & scanning: ${normalizedUrl}`);

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
        const rawCookie = mainResp.headers.get("set-cookie") || "";
        cookieHeaders = rawCookie ? rawCookie.split(/,(?=[^ ])/) : [];
        pageHtml = await mainResp.text();
        fetchSucceeded = true;
        log(`✅ Connected to page — HTTP ${mainResp.status} | ${(pageHtml.length / 1024).toFixed(1)} KB received`);
      } else {
        log(`⚠️  Could not reach page ${normalizedUrl}. Running passive checks where possible.`);
      }

      if (normalizedUrl === targetUrl) {
        homepageHtml = pageHtml;
        log(`🛡️  Phase 1: Auditing security headers (CSP, HSTS, X-Frame-Options, CORS, referrer policy)...`);
        await prisma.scan.update({ where: { id: scanId }, data: { status: "SCANNING" } });

        try {
          const [nmapFindings, nucleiFindings] = await Promise.all([
            nmapPromise.catch((err) => {
              log(`⚠️   Phase 0 (nmap) encountered an error: ${err instanceof Error ? err.message : String(err)}`);
              return [] as NmapFinding[];
            }),
            nucleiPromise.catch((err) => {
              log(`⚠️   Phase 0 (nuclei) encountered an error: ${err instanceof Error ? err.message : String(err)}`);
              return [] as NucleiFinding[];
            }),
          ]);

          for (const nf of nmapFindings) await recordFinding(nf as PendingFinding);
          for (const nf of nucleiFindings) await recordFinding(nf as PendingFinding);

          log(`🗺️   Phase 0 complete — ${nmapFindings.length} Nmap & ${nucleiFindings.length} Nuclei finding(s) merged`);
        } catch (phase0Err) {
          log(`⚠️   Phase 0 error: ${phase0Err instanceof Error ? phase0Err.message : String(phase0Err)}`);
        }

        const csp = headers["content-security-policy"] || "";
        if (fetchSucceeded && !headers["x-frame-options"] && !csp.includes("frame-ancestors")) {
          await recordFinding({
            type: "clickjacking",
            severity: "MEDIUM",
            url: targetUrl,
            evidence: "Neither 'X-Frame-Options' nor 'frame-ancestors' CSP directive found.",
            cvssScore: 5.4,
            cveId: "CWE-1021",
          });
        }

        if (fetchSucceeded && !csp) {
          await recordFinding({
            type: "missing-csp",
            severity: "HIGH",
            url: targetUrl,
            evidence: "No 'Content-Security-Policy' header found.",
            cvssScore: 7.2,
            cveId: "CWE-693",
          });
        }

        if (fetchSucceeded && targetUrl.startsWith("https") && !headers["strict-transport-security"]) {
          await recordFinding({
            type: "missing-hsts",
            severity: "MEDIUM",
            url: targetUrl,
            evidence: "Missing 'Strict-Transport-Security' header on HTTPS site.",
            cvssScore: 6.1,
            cveId: "CWE-319",
          });
        }

        if (fetchSucceeded && !headers["x-content-type-options"]) {
          await recordFinding({
            type: "missing-x-content-type-options",
            severity: "LOW",
            url: targetUrl,
            evidence: "Missing 'X-Content-Type-Options: nosniff' header.",
            cvssScore: 3.1,
            cveId: "CWE-430",
          });
        }

        if (fetchSucceeded && !headers["referrer-policy"]) {
          await recordFinding({
            type: "missing-referrer-policy",
            severity: "INFO",
            url: targetUrl,
            evidence: "No 'Referrer-Policy' header.",
            cvssScore: 2.3,
          });
        }

        if (fetchSucceeded && !headers["permissions-policy"] && !headers["feature-policy"]) {
          await recordFinding({
            type: "missing-permissions-policy",
            severity: "LOW",
            url: targetUrl,
            evidence: "No 'Permissions-Policy' header.",
            cvssScore: 2.7,
          });
        }

        const serverHeader = headers["server"] || "";
        const xPoweredBy = headers["x-powered-by"] || "";
        const leakedHeaders = [serverHeader, xPoweredBy].filter((h) => /[a-zA-Z]+\/[\d.]+|php|asp\.net|tomcat|jboss/i.test(h));
        if (fetchSucceeded && leakedHeaders.length > 0) {
          await recordFinding({
            type: "server-version-disclosure",
            severity: "LOW",
            url: targetUrl,
            evidence: `Server discloses version in headers: "${leakedHeaders.join(", ")}".`,
            cvssScore: 3.7,
            cveId: "CWE-200",
          });
        }

        log(`🍪  Phase 2: Analyzing session cookies...`);
        if (fetchSucceeded && cookieHeaders.length > 0) {
          // Only flag cookies that are session/auth related.
          // Tracking, analytics, and CDN cookies (e.g. _ga, cf_clearance) do not
          // need HttpOnly/Secure — flagging them creates noise with no security value.
          const SESSION_COOKIE_PATTERN = /^(session|sess|sid|auth|token|jwt|user|connect\.sid|access_token|refresh_token|id_token|phpsessid|jsessionid|asp\.net_sessionid|auth0|remember_me|logged_in)/i;
          const NOISE_COOKIE_PATTERN = /^(_ga|_gid|_gat|_fbp|_fbc|fbp|fbc|cf_clearance|__cf_bm|__utma|__utmb|__utmc|__utmz|_hjid|_hjsession|mf_user|intercom|amplitude|segment|ajs_)/i;

          for (const cookie of cookieHeaders) {
            const lower = cookie.toLowerCase();
            const cookieName = cookie.split("=")[0]?.trim() || "";
            if (!cookieName) continue;

            // Skip known noise/tracking cookies
            if (NOISE_COOKIE_PATTERN.test(cookieName)) continue;

            // Only apply strict flag checks to session-relevant cookies
            const isSessionCookie = SESSION_COOKIE_PATTERN.test(cookieName);

            if (isSessionCookie && !lower.includes("httponly")) {
              await recordFinding({
                type: "session-hijacking-no-httponly",
                severity: "HIGH",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Session cookie "${cookieName}" is missing the 'HttpOnly' flag, allowing JavaScript to read it. An XSS vulnerability on any page could steal this session token.`,
                cvssScore: 7.5,
                cveId: "CWE-1004",
              });
            }
            if (isSessionCookie && !lower.includes("secure") && targetUrl.startsWith("https")) {
              await recordFinding({
                type: "session-hijacking-no-secure",
                severity: "MEDIUM",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Session cookie "${cookieName}" is missing the 'Secure' flag on an HTTPS site, meaning it could be sent over HTTP if the user visits the HTTP version of the page.`,
                cvssScore: 5.9,
                cveId: "CWE-614",
              });
            }
            if (isSessionCookie && !lower.includes("samesite")) {
              await recordFinding({
                type: "session-csrf-no-samesite",
                severity: "LOW",
                url: targetUrl,
                parameter: cookieName,
                evidence: `Session cookie "${cookieName}" is missing the 'SameSite' attribute, making it potentially vulnerable to CSRF attacks in older browsers.`,
                cvssScore: 4.3,
                cveId: "CWE-352",
              });
            }
          }
        }
      }

      let renderedHtml = pageHtml;
      let runtimeFrameworks: string[] = [];
      let browserLinks: string[] = [];
      let browserApiEndpoints: string[] = [];

      if (controller.signal.aborted) throw new Error("scan_cancelled");

      const browserAuthSession = session.bearerToken || session.cookies ? { cookies: session.cookies, bearerToken: session.bearerToken } : undefined;
      const browserResult = await renderWithBrowser(normalizedUrl, log, scanId, browserAuthSession);

      if (controller.signal.aborted) throw new Error("scan_cancelled");

      if (browserResult) {
        renderedHtml = browserResult.html;
        runtimeFrameworks = browserResult.runtimeFrameworks;
        browserLinks = browserResult.discoveredLinks;
        browserApiEndpoints = browserResult.interceptedRequests || [];
      }

      if (visitedUrls.size === 1) {
        if (controller.signal.aborted) throw new Error("scan_cancelled");
        log(`🗄️  Auditing client-side storage...`);
        const storageFindings = await auditClientStorage(normalizedUrl, log, scanId, browserAuthSession);
        for (const sf of storageFindings) {
          await recordFinding({
            type: "client-storage-sensitive-data",
            severity: "HIGH",
            url: normalizedUrl,
            parameter: sf.key,
            evidence: `Sensitive data found in ${sf.storageType}: key="${sf.key}" contains ${sf.detectedType}.`,
            cvssScore: 7.5,
            cveId: "CWE-922",
            confidence: CONFIDENCE.DETERMINISTIC,
            validationSteps: [`${sf.storageType}.getItem("${sf.key}") returned sensitive pattern`],
            isVerified: true,
          });
        }
      }

      // ── EXPOSED ENDPOINT REPORTING ────────────────────────────────────────────
      // Emit an INFO finding for sensitive/notable pages that are publicly accessible
      if (fetchSucceeded && normalizedUrl !== targetUrl) {
        const path = (() => { try { return new URL(normalizedUrl).pathname; } catch { return ""; } })();
        const SENSITIVE_PATH_PATTERNS: Array<{ pattern: RegExp; label: string; evidence: string; severity: "LOW" | "INFO" }> = [
          { pattern: /^\/(docs?|api-docs?|swagger|openapi|redoc)(\/|$)/i, label: "api-documentation-exposed", severity: "LOW", evidence: `Public API documentation page is accessible at ${normalizedUrl}. Exposes endpoint structure, request formats, and schema to unauthenticated visitors.` },
          { pattern: /^\/\.well-known\//i, label: "well-known-endpoint-exposed", severity: "INFO", evidence: `Well-known metadata endpoint accessible at ${normalizedUrl}. May expose agent card, security.txt, or OIDC configuration to the public internet.` },
          { pattern: /^\/(admin|administrator|backoffice|management|control-panel|cp|backend)(\/|$)/i, label: "admin-panel-exposed", severity: "LOW", evidence: `Admin panel URL discovered at ${normalizedUrl}. Even if login-protected, admin path discovery aids targeted attacks.` },
          { pattern: /^\/(debug|devtools?|profiler?|diagnostics?)(\/|$)/i, label: "debug-endpoint-exposed", severity: "LOW", evidence: `Debug/diagnostic endpoint found at ${normalizedUrl}. May leak internal application state or enable debug commands.` },
          { pattern: /^\/(graphql|graphiql|playground)(\/|$)/i, label: "graphql-endpoint-exposed", severity: "LOW", evidence: `GraphQL endpoint accessible at ${normalizedUrl}. Introspection queries may enumerate the entire API schema.` },
          { pattern: /^\/(metrics?|health|status|readyz?|livez?|ping)(\/|$)/i, label: "monitoring-endpoint-exposed", severity: "INFO", evidence: `Monitoring/health endpoint publicly accessible at ${normalizedUrl}. May expose internal service topology, uptime status, or dependency info.` },
          { pattern: /^\/(changelog|changes?|release-notes?)(\/|$)/i, label: "changelog-exposed", severity: "INFO", evidence: `Changelog/release notes exposed at ${normalizedUrl}. Version history can reveal when vulnerabilities were patched.` },
        ];

        for (const { pattern, label, severity, evidence } of SENSITIVE_PATH_PATTERNS) {
          if (pattern.test(path)) {
            await recordFinding({
              type: label,
              severity,
              url: normalizedUrl,
              evidence,
              cvssScore: severity === "LOW" ? 3.1 : 1.5,
              cveId: "CWE-200",
            });
            break; // Only one finding per URL
          }
        }
      }

      if (fetchSucceeded || browserResult) {
        const staticLinks = extractSameOriginLinks(renderedHtml, normalizedUrl);
        const discoveredLinks = [...new Set([...staticLinks, ...browserLinks])].slice(0, 50);

        const targetHost = new URL(targetUrl).hostname;
        for (const link of discoveredLinks) {
          try {
            const cleanLink = new URL(link, targetUrl);
            const isHashRoute = /^#\/[a-zA-Z0-9_-]+/.test(cleanLink.hash) && !cleanLink.hash.startsWith("#/#");
            if (!isHashRoute) cleanLink.hash = "";
            const linkStr = cleanLink.toString();
            if (cleanLink.hostname === targetHost && !visitedUrls.has(linkStr) && !urlQueue.includes(linkStr)) {
              urlQueue.push(linkStr);
            }
          } catch {}
        }

        // ── TECHNOLOGY FINGERPRINTING (Run once per scan on target URL) ────────────────────
        if (normalizedUrl === targetUrl) {
          const techs: string[] = [...runtimeFrameworks]; // browser runtime results come first
          const serverHeader = headers["server"] ?? "";
          const poweredBy = headers["x-powered-by"] ?? "";
          const setCookie = headers["set-cookie"] ?? "";
          const combinedText = renderedHtml + poweredBy + serverHeader + setCookie;

          // Cloudflare detection (very common — static HTML will be the challenge page)
          if (!techs.includes("Cloudflare") && /cdn-cgi|cloudflare|__cf_bm|cf-ray/i.test(combinedText + (headers["cf-ray"] ?? "") + (headers["server"] ?? ""))) techs.push("Cloudflare");

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
          if (!techs.includes("Python") && /gunicorn|uvicorn|werkzeug|python/i.test(combinedText)) techs.push("Python");
          if (!techs.includes("WordPress") && /wp-content\/|wp-includes\//i.test(combinedText)) techs.push("WordPress");
          if (!techs.includes("Drupal") && /drupal\.settings|Drupal\./i.test(combinedText)) techs.push("Drupal");
          if (!techs.includes("Joomla") && /Joomla!/i.test(combinedText)) techs.push("Joomla");
          if (!techs.includes("Shopify") && /shopify\.com\/s\/files/i.test(combinedText)) techs.push("Shopify");
          if (!techs.includes("jQuery") && /jquery[.-]([\d.]+)(\.min)?\.js/i.test(combinedText)) techs.push("jQuery");
          if (!techs.includes("Laravel") && /laravel_session|laravel\/framework/i.test(combinedText)) techs.push("Laravel");
          if (!techs.includes("tRPC") && /\/api\/trpc\//i.test(combinedText)) techs.push("tRPC");
          if (!techs.includes("Vite") && /\/@vite\/client|vite\.config/i.test(combinedText)) techs.push("Vite");
          if (!techs.includes("Express.js") && /express/i.test(poweredBy)) techs.push("Express.js");
          if (!techs.includes("PHP") && /php/i.test(poweredBy + setCookie)) techs.push("PHP");
          if (!techs.includes("ASP.NET") && /asp\.net|\.AspNetCore/i.test(poweredBy + setCookie)) techs.push("ASP.NET");
          if (!techs.includes("Spring Boot") && /JSESSIONID|spring/i.test(setCookie + combinedText)) techs.push("Spring Boot");
          if (!techs.includes("Ruby on Rails") && /_session_id|rails/i.test(setCookie + combinedText)) techs.push("Ruby on Rails");
          if (!techs.includes("Vercel") && /vercel/i.test(serverHeader + combinedText)) techs.push("Vercel");
          if (!techs.includes("Tailwind CSS") && /tailwind/i.test(combinedText)) techs.push("Tailwind CSS");

          const uniqueTechs = [...new Set(techs)];
          uniqueTechs.forEach((t) => accumulatedTechs.add(t));

          if (uniqueTechs.length > 0) {
            log(`🔬  Technology fingerprint: ${uniqueTechs.join(", ")}`);
            await recordFinding({
              type: "technology-fingerprinting",
              severity: "INFO",
              url: targetUrl,
              evidence: `Detected technology stack: ${uniqueTechs.join(", ")}.`,
              cvssScore: 2.0,
              cveId: "CWE-200",
            });
          } else {
            log(`🔬  Technology fingerprint: No framework signatures detected (site may be obfuscated or behind a WAF/proxy)`);
          }
        }

        // Engine-level noise filter for intercepted browser endpoints
        const API_NOISE_PATTERNS = [
          /\/cdn-cgi\//i,
          /\/beacon(\.js)?/i,
          /\/collect(\?|$)/i,
          /\/analytics(\.js)?/i,
          /\/gtm(\.js)?\?/i,
          /\/gtag(\.js)?\?/i,
          /\/fbevents\.js/i,
          /\/sentry\.(io|js)/i,
          /\/sockjs-node/i,
          /\/_next\/webpack-hmr/i,
          /\/socket\.io\/\?/i,
        ];
        const cleanBrowserApiEndpoints = browserApiEndpoints.filter(
          (ep) => !API_NOISE_PATTERNS.some((p) => p.test(ep))
        );

        const staticApiEndpoints = extractApiEndpoints(renderedHtml, normalizedUrl);
        const apiEndpoints = [...new Set([...staticApiEndpoints, ...cleanBrowserApiEndpoints])];
        apiEndpoints.forEach((a) => accumulatedApiEndpoints.add(a));

        const discoveredParamUrls = extractParamUrls(renderedHtml, normalizedUrl);
        const discoveredForms = extractForms(renderedHtml, normalizedUrl);

        if (controller.signal.aborted) throw new Error("scan_cancelled");

        log(`🕸️   Page audit complete — ${discoveredLinks.length} links, ${apiEndpoints.length} API refs, ${discoveredParamUrls.length} param URLs, ${discoveredForms.length} form(s)`);
        discoveredLinks.forEach((l) => accumulatedDiscoveredLinks.add(l));

        const jsBundleEndpoints = await extractJsBundleEndpoints(renderedHtml, normalizedUrl);

        if (normalizedUrl === targetUrl) {
          log(`📋  Probing for OpenAPI/Swagger specs...`);
          const openApiEndpoints = await discoverOpenApiEndpoints(targetUrl, log);
          if (openApiEndpoints.length > 0) {
            jsBundleEndpoints.push(...openApiEndpoints.map((e) => ({ url: safeUrlJoin(targetUrl, e.path) || e.path, path: e.path, fields: e.fields })));
          }
        }

        jsBundleEndpoints.forEach((e) => accumulatedApiEndpoints.add(e.url));

        // ⚡ Update reconData in DB in real-time as new API endpoints & tech stack signatures are discovered!
        (async () => {
          try {
            const currentScan = (await prisma.scan.findUnique({ where: { id: scanId } })) as any;
            if (currentScan?.reconData) {
              const currentRecon: ReconData = typeof currentScan.reconData === "string" ? JSON.parse(currentScan.reconData) : currentScan.reconData;
              currentRecon.techStack = Array.from(accumulatedTechs).map((t) => ({ name: t, category: "Framework / Library" }));
              currentRecon.apiEndpoints = Array.from(accumulatedApiEndpoints).map((a) => ({ url: a }));
              currentRecon.discoveredLinks = Array.from(accumulatedDiscoveredLinks);
              await prisma.scan.update({
                where: { id: scanId },
                data: { reconData: JSON.stringify(currentRecon) } as any,
              });
            }
          } catch {}
        })();

        const jsFindings = await analyzeJSFiles(renderedHtml, normalizedUrl);
        for (const jf of jsFindings) await recordFinding(jf);

        const probeLimit = pLimit(8); // Run at most 8 probes concurrently per page
        const probeTargets = [...new Set(discoveredParamUrls)].slice(0, 30);

        if (probeTargets.length > 0) {
          log(`⚡  Active injection probes (${probeTargets.length} URL(s), up to 8 concurrent)...`);
          const probeResults = await Promise.all(
            probeTargets.flatMap((url) => [
              probeLimit(() => probeReflectedXSS(url, session, log, scanId)),
              probeLimit(() => probeSQLiError(url, session)),
              probeLimit(() => probeCommandInjection(url)),
              probeLimit(() => probePathTraversal(url)),
              probeLimit(() => probeCRLFInjection(url)),
              probeLimit(() => probeBlindSQLiTiming(url)),
              probeLimit(() => probeBlindSQLiBooleanDiff(url)),
            ])
          );

          for (const result of probeResults) {
            if (result) await recordFinding(result);
          }
        }

        if (discoveredForms.length > 0) {
          log(`📝  Form injection probing...`);
          const formProbeResults = await Promise.all(
            discoveredForms.flatMap((form) => [
              probeLimit(() => probeFormSQLi(form, session)),
              probeLimit(() => probeFormXSS(form, session, log, scanId)),
              probeLimit(() => probeFormSSTI(form)),
            ])
          );

          for (const result of formProbeResults) {
            if (result) await recordFinding(result);
          }
        }

        const restSqliResult = await probeRestApiSQLi(normalizedUrl, session);
        if (restSqliResult) await recordFinding(restSqliResult);

        const infraResults = await Promise.all([
          probeLimit(() => probeHostHeaderInjection(normalizedUrl)),
          probeLimit(() => probeCachePoisoning(normalizedUrl)),
          probeLimit(() => probeHTTPRequestSmuggling(normalizedUrl)),
          probeLimit(() => probeCORSReflection(normalizedUrl, apiEndpoints, session)),
          probeLimit(() => probeDangerousHTTPMethods(normalizedUrl, apiEndpoints)),
          probeLimit(() => probeXXE(normalizedUrl)),
          probeLimit(() => probeDirectoryListing(normalizedUrl, homepageHtml)),
          probeLimit(() => probeHTTPSRedirect(normalizedUrl)),
          probeLimit(() => probeUnauthenticatedAPIAccess(normalizedUrl)),
          probeLimit(() => probeDebugModeExposure(normalizedUrl)),
          probeLimit(() => probeNoSQLi(normalizedUrl)),
          probeLimit(() => probeJWTNone(normalizedUrl)),
          probeLimit(() => probeExposedBackupFiles(normalizedUrl, homepageHtml)),
          probeLimit(() => probeActiveOpenRedirect(renderedHtml, normalizedUrl, discoveredParamUrls)),
          probeLimit(() => probeIDORWithDualToken(normalizedUrl, jsBundleEndpoints, session)),
          // New probes
          probeLimit(() => probeGraphQLInjection(normalizedUrl, session)),
          probeLimit(() => probeHTTPMethodOverride(normalizedUrl)),
          probeLimit(() => probeIDORSequentialFuzz(normalizedUrl, session)),
          probeLimit(() => probeApiSensitiveDataExposure(normalizedUrl, apiEndpoints)),
        ]);

        for (const result of infraResults) {
          if (result) await recordFinding(result);
        }

        if (visitedUrls.size === 1) {
          log(`🔬  Running root-only vulnerability probes...`);
          const rootOnlyResults = await Promise.all([
            probeFileUploadVulnerabilities(targetUrl, renderedHtml),
            probeMassAssignment(targetUrl, jsBundleEndpoints, session),
            probeBusinessLogicVulnerabilities(targetUrl, session),
            // New root-only probes
            probeJWTWeakSecret(targetUrl, session),
            probeBlindSQLiRestEndpoints(targetUrl, session),
          ]);

          const fileUploadFindings = (rootOnlyResults[0] as PendingFinding[]) || [];
          const massAssignmentFindings = (rootOnlyResults[1] as PendingFinding[]) || [];
          const businessLogicFindings = (rootOnlyResults[2] as PendingFinding[]) || [];
          const jwtWeakFinding = rootOnlyResults[3] as PendingFinding | null;
          const blindRestSqliFinding = rootOnlyResults[4] as PendingFinding | null;

          for (const f of [...fileUploadFindings, ...massAssignmentFindings, ...businessLogicFindings]) {
            await recordFinding(f);
          }
          if (jwtWeakFinding) await recordFinding(jwtWeakFinding);
          if (blindRestSqliFinding) await recordFinding(blindRestSqliFinding);

          const passwordPolicyFinding = await probePasswordPolicy(targetUrl, session);
          const subdomainFinding = await probeCommonSubdomains(targetUrl);
          const sessionFixationFinding = await probeSessionFixationRegeneration(targetUrl, session);

          if (passwordPolicyFinding) await recordFinding(passwordPolicyFinding);
          if (subdomainFinding) await recordFinding(subdomainFinding);
          if (sessionFixationFinding) await recordFinding(sessionFixationFinding);
        }
      }
    }

    log(`📦  Running Software Composition Analysis...`);
    const scaFindings = await probeSoftwareCompositionAnalysis(targetUrl);
    for (const result of scaFindings) {
      if (result) await recordFinding(result);
    }

    try {
      const tlsFindings = await tlsPromise;
      for (const tf of tlsFindings) await recordFinding(tf);
    } catch {}

    if (backgroundAiPromises.length > 0) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: "ANALYZING" } });
      await Promise.allSettled(backgroundAiPromises);
    }

    const initialRecon = await reconPromise;
    const finalRecon: ReconData = {
      ...initialRecon,
      techStack: Array.from(accumulatedTechs).map((t) => ({ name: t, category: "Framework / Library" })),
      apiEndpoints: Array.from(accumulatedApiEndpoints).map((a) => ({ url: a })),
      discoveredLinks: Array.from(accumulatedDiscoveredLinks),
    };

    const wasCancelled = controller.signal.aborted;
    const finalStatus = wasCancelled ? "FAILED" : "COMPLETED";

    const updatedScan = await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: finalStatus,
        reconData: JSON.stringify(finalRecon),
        completedAt: new Date(),
      } as any,
    });

    log(`🎉  Scan complete — ${totalDiscoveredCount} finding(s) discovered and saved real-time!`);
    cleanupScan(scanId);
    await destroyBrowser(scanId);
    cleanupScanController(scanId);

    if (updatedScan.email) {
      sendScanReportEmail(scanId, updatedScan.email).catch(() => {});
    }
  } catch (scanErr) {
    const isCancelled = controller.signal.aborted || (scanErr instanceof Error && scanErr.message === "scan_cancelled");
    cleanupScan(scanId);
    cleanupScanController(scanId);
    await destroyBrowser(scanId);
    try {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "FAILED", completedAt: new Date() },
      });
    } catch {}
  }
}

import * as tls from "tls";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, FormTarget, PendingFinding, safeUrlJoin } from "../types";
import { authHeaders, safeFetch } from "../session";

export function detectSSRF(html: string, paramUrls: string[], targetUrl: string): PendingFinding | null {
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
  for (const m of html.matchAll(/<input[^>]+name=["']([^"']+)["'][^>]*>/gi)) {
    if (SSRF_PARAM_NAMES.test(m[1])) hits.push(`form input: ${m[1]}`);
  }
  if (hits.length > 0) {
    return {
      type: "ssrf-parameter-signal",
      severity: "INFO",
      url: targetUrl,
      parameter: hits[0],
      evidence: `Potential SSRF / Open Redirect indicator (not confirmed). Found ${hits.length} parameter(s) commonly used for fetching remote resources: ${hits.slice(0, 3).join(", ")}.`,
      cvssScore: 0.0,
      cveId: "CWE-918",
    };
  }
  return null;
}

export async function probeBlindSSRFWithTiming(paramUrl: string): Promise<PendingFinding | null> {
  const NON_ROUTABLE_IPS = [
    "http://10.255.255.1:81/",
    "http://192.168.255.254:81/",
    "http://169.254.169.254/latest/meta-data/",
  ];

  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;

    const baselineStart = Date.now();
    const baselineResp = await safeFetch(u.toString(), 5000);
    const baselineTime = Date.now() - baselineStart;
    if (!baselineResp) return null;

    for (const internalTarget of NON_ROUTABLE_IPS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(firstParam, internalTarget);
        const start = Date.now();
        await fetch(testUrl.toString(), {
          headers: FETCH_HEADERS,
          signal: AbortSignal.timeout(8000),
          // @ts-ignore
          next: { revalidate: 0 },
        }).catch(() => null);
        const elapsed = Date.now() - start;

        if (elapsed > baselineTime + 3000) {
          return {
            type: "ssrf-blind-timing",
            severity: "HIGH",
            url: testUrl.toString(),
            parameter: firstParam,
            evidence: `Blind SSRF confirmed via timing delay. Requesting non-routable IP "${internalTarget}" in parameter "${firstParam}" took ${elapsed}ms (baseline: ${baselineTime}ms).`,
            cvssScore: 8.6,
            cveId: "CWE-918",
          };
        }
      } catch { /* next */ }
    }
  } catch { /* skip */ }
  return null;
}

export function detectSubdomainTakeoverSignals(html: string, targetUrl: string): PendingFinding | null {
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
      evidence: `Found ${externalRefs.length} references to external cloud-hosted domains in page source (${externalRefs.slice(0, 3).join(", ")}).`,
      cvssScore: 0.0,
      cveId: "CWE-350",
      confidence: CONFIDENCE.PASSIVE_SIGNAL,
      validationSteps: [`Found ${externalRefs.length} external cloud domain references in HTML`, "Not confirmed: requires DNS CNAME verification"],
      isVerified: false,
    };
  }
  return null;
}

export async function probeHostHeaderInjection(targetUrl: string): Promise<PendingFinding | null> {
  // NOTE: The `Host` header is a forbidden header in the Fetch API and is
  // automatically stripped by the browser/Node.js runtime — it cannot be overridden.
  // We therefore rely exclusively on X-Forwarded-Host and X-Host, which ARE
  // forwarded and which many backend frameworks use as the authoritative host.
  const EVIL_HOST = "attacker-vulnscan.evil.com";
  try {
    const resp = await fetch(targetUrl, {
      headers: {
        ...FETCH_HEADERS,
        "X-Forwarded-Host": EVIL_HOST,
        "X-Host": EVIL_HOST,
        "X-Original-Host": EVIL_HOST,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!resp) return null;

    if (resp.status >= 400 && resp.status < 500) return null;

    const body = await resp.text();
    const location = resp.headers.get("location") || "";
    if (location.includes(EVIL_HOST)) {
      return {
        type: "host-header-injection-redirect",
        severity: "HIGH",
        url: targetUrl,
        evidence: `Host Header Injection confirmed via X-Forwarded-Host redirect poisoning. Header "X-Forwarded-Host: ${EVIL_HOST}" caused the server to redirect to ${location}.`,
        cvssScore: 8.1,
        cveId: "CWE-20",
        isVerified: true,
        confidence: CONFIDENCE.DETERMINISTIC,
      };
    }

    if (body.includes(EVIL_HOST)) {
      const securitySensitivePattern = new RegExp(
        `(?:href|action|src|formaction|data-url)\\s*=\\s*["']?[^"']*${EVIL_HOST.replace(/\./g, "\\.")}`,
        "i"
      );
      if (securitySensitivePattern.test(body)) {
        return {
          type: "host-header-injection",
          severity: "MEDIUM",
          url: targetUrl,
          evidence: `Host Header Injection detected via X-Forwarded-Host. The injected value "${EVIL_HOST}" appears in an href/action/src attribute in the response body — the server is using the forwarded host in generated URLs.`,
          cvssScore: 6.5,
          cveId: "CWE-20",
        };
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeCORSReflection(
  targetUrl: string,
  extraEndpoints: string[] = [],
  session: AuthSession = EMPTY_SESSION
): Promise<PendingFinding | null> {
  let baseHost = "target.com";
  try {
    baseHost = new URL(targetUrl).hostname;
  } catch {}
  const testOrigins = ["https://attacker-vulnscan.evil.com", "null", `https://${baseHost}.evil.com`];
  const basePaths = ["/api/", "/api/me", "/api/user", "/api/users", "/rest/user/whoami"];
  const allEndpoints = [
    targetUrl,
    ...(basePaths.map((p) => safeUrlJoin(targetUrl, p)).filter(Boolean) as string[]),
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
              ? `CRITICAL CORS Misconfiguration: The server reflects untrusted Origin ("${testOrigin}") in Access-Control-Allow-Origin AND specifies Access-Control-Allow-Credentials: true.`
              : `CORS Misconfiguration: The server reflects untrusted origin "${testOrigin}" in Access-Control-Allow-Origin header.`,
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

export async function probeActiveOpenRedirect(
  html: string,
  baseUrl: string,
  paramUrls: string[] = []
): Promise<PendingFinding | null> {
  const REDIRECT_PARAMS = ["redirect", "redirect_to", "next", "url", "target", "dest", "destination", "out", "r", "to"];
  const EVIL_DOMAINS = ["https://evil.com", "//evil.com"];

  const candidateUrls: Array<{ url: string; param: string }> = [];

  for (const paramUrl of paramUrls) {
    try {
      const u = new URL(paramUrl);
      for (const param of u.searchParams.keys()) {
        if (REDIRECT_PARAMS.includes(param.toLowerCase())) {
          candidateUrls.push({ url: paramUrl, param });
        }
      }
    } catch { /* skip */ }
  }

  for (const { url, param } of candidateUrls) {
    for (const evilPayload of EVIL_DOMAINS) {
      try {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, evilPayload);

        const resp = await fetch(testUrl.toString(), {
          headers: FETCH_HEADERS,
          redirect: "manual",
          signal: AbortSignal.timeout(6000),
          // @ts-ignore
          next: { revalidate: 0 },
        }).catch(() => null);

        if (!resp) continue;

        const location = resp.headers.get("location") || "";
        if (
          [301, 302, 303, 307, 308].includes(resp.status) &&
          (location.startsWith("https://evil.com") || location.startsWith("//evil.com") || location.includes("evil.com"))
        ) {
          return {
            type: "open-redirect",
            severity: "HIGH",
            url: testUrl.toString(),
            parameter: param,
            evidence: `Open Redirect confirmed (HTTP ${resp.status} Location: ${location}) via parameter "${param}". The server blindly redirects users to untrusted external domain "evil.com". Attackers use this to craft convincing phishing links.`,
            cvssScore: 6.1,
            cveId: "CWE-601",
            confidence: CONFIDENCE.DETERMINISTIC,
            validationSteps: [
              `Injected payload "${evilPayload}" into parameter "${param}"`,
              `Server returned HTTP ${resp.status} redirect to "${location}"`,
            ],
            isVerified: true,
          };
        }
      } catch { /* next payload */ }
    }
  }
  return null;
}

export async function probeHTTPRequestSmuggling(targetUrl: string): Promise<PendingFinding | null> {
  // True HTTP Request Smuggling requires raw TCP desync which cannot be performed
  // via the Fetch API (which normalises headers). We probe for a server-side
  // misconfiguration signal: a server that processes a CL.TE smuggling prefix
  // WITHOUT rejecting it may return 200, while a correctly configured server
  // rejects with 400. We emit an INFO signal when the server accepts ambiguous
  // framing (status 200) — this requires manual validation.
  try {
    // Step 1: Send ambiguous CL.TE payload — a hardened server SHOULD return 400
    const resp = await fetch(targetUrl, {
      method: "POST",
      headers: {
        ...FETCH_HEADERS,
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
      },
      body: "0\r\n\r\nG",
      signal: AbortSignal.timeout(5000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);

    if (!resp) return null;

    // 400 means the server rejected the ambiguous request (CORRECT behavior — not a vulnerability)
    // 200 with our malformed body accepted = potential smuggling surface
    if (resp.status === 200) {
      return {
        type: "http-request-smuggling-signal",
        severity: "INFO",
        url: targetUrl,
        evidence: `HTTP Request Smuggling Surface Detected (requires manual verification): The server returned HTTP 200 for a request with conflicting Content-Length (6) and Transfer-Encoding: chunked headers, suggesting it may not reject ambiguous framing. Full desync exploitation requires raw TCP — this is an unconfirmed signal only.`,
        cvssScore: 0.0,
        cveId: "CWE-444",
        isVerified: false,
        confidence: CONFIDENCE.PASSIVE_SIGNAL,
      };
    }
  } catch { /* skip */ }
  return null;
}

export async function probeCachePoisoning(targetUrl: string): Promise<PendingFinding | null> {
  const POISON_HEADERS = [
    { name: "X-Forwarded-Host", value: "attacker-cache-poison.evil.com" },
    { name: "X-Host", value: "attacker-cache-poison.evil.com" },
    { name: "X-Forwarded-Scheme", value: "not-http-vulnscan" },
  ];

  for (const { name, value } of POISON_HEADERS) {
    try {
      // Step 1: Send poisoning request with evil header
      const poisonResp = await fetch(targetUrl, {
        headers: { ...FETCH_HEADERS, [name]: value },
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!poisonResp) continue;
      const cacheHeader = poisonResp.headers.get("x-cache") || poisonResp.headers.get("cf-cache-status") || poisonResp.headers.get("age");
      const poisonBody = await poisonResp.text();

      // Only proceed if the evil value is reflected AND the response appears cacheable
      if (!cacheHeader || !poisonBody.includes(value)) continue;

      // Step 2 (confirmation): Make a second CLEAN request (no evil header)
      // If the poisoned value STILL appears in the clean response, the cache was poisoned
      await new Promise((r) => setTimeout(r, 300)); // brief wait for cache write
      const cleanResp = await fetch(targetUrl, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!cleanResp) continue;
      const cleanBody = await cleanResp.text();

      if (cleanBody.includes(value)) {
        return {
          type: "web-cache-poisoning",
          severity: "HIGH",
          url: targetUrl,
          evidence: `Web Cache Poisoning confirmed (two-request verified). Unkeyed header "${name}: ${value}" was reflected in a cacheable response, AND a subsequent clean request (without the header) returned the same poisoned value — confirming the poisoned response was cached and served to other users.`,
          cvssScore: 7.5,
          cveId: "CWE-444",
          isVerified: true,
          confidence: CONFIDENCE.DUAL_VERIFIED,
          validationSteps: [
            `Step 1: ${name}: ${value} reflected in response body + cache header present`,
            `Step 2: Clean request (no ${name} header) still returned poisoned value "${value}"`,
          ],
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

export async function probeTLSCertificate(targetUrl: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return findings;
  }
  if (parsedUrl.protocol !== "https:") return findings;

  const hostname = parsedUrl.hostname;
  const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 443;

  await new Promise<void>((resolve) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 6000 },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (cert && Object.keys(cert).length > 0) {
            const validTo = new Date(cert.valid_to);
            const now = new Date();

            const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

            if (daysRemaining < 0) {
              findings.push({
                type: "ssl-certificate-expired",
                severity: "HIGH",
                url: targetUrl,
                evidence: `TLS certificate for ${hostname} expired on ${validTo.toISOString()} (${Math.abs(daysRemaining)} days ago). Browsers will show security warnings.`,
                cvssScore: 7.5,
                cveId: "CWE-295",
                confidence: CONFIDENCE.DETERMINISTIC,
                validationSteps: [`TLS connection to ${hostname}:${port}`, `Certificate validTo date: ${validTo.toISOString()}`],
                isVerified: true,
              });
            } else if (daysRemaining <= 30) {
              findings.push({
                type: "ssl-certificate-expiring-soon",
                severity: "LOW",
                url: targetUrl,
                evidence: `TLS certificate for ${hostname} expires in ${daysRemaining} days (valid until ${validTo.toISOString()}). Renewal required.`,
                cvssScore: 3.3,
                cveId: "CWE-295",
                confidence: CONFIDENCE.DETERMINISTIC,
                validationSteps: [`TLS connection to ${hostname}:${port}`, `Certificate expires in ${daysRemaining} days`],
                isVerified: true,
              });
            }
          }
        } catch { /* skip */ }
        socket.end();
        resolve();
      }
    );

    socket.on("error", () => resolve());
    socket.on("timeout", () => {
      socket.destroy();
      resolve();
    });
  });

  return findings;
}

export async function probeCommonSubdomains(targetUrl: string): Promise<PendingFinding | null> {
  const SUBDOMAINS = ["admin", "api", "dev", "staging", "test", "portal", "v1", "v2", "db", "mail"];
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return null;
  }

  const parts = parsed.hostname.split(".");
  if (parts.length < 2) return null;
  const domain = parts.slice(-2).join(".");

  // Fetch the target's 404 page as a baseline to avoid flagging CDN/parking pages
  let baseline404: string = "";
  try {
    const b = await fetch(`${parsed.protocol}//${domain}/__nonexistent_vulnscan_path__/`, {
      headers: FETCH_HEADERS,
      signal: AbortSignal.timeout(4000),
    }).catch(() => null);
    baseline404 = b ? await b.text().catch(() => "") : "";
  } catch { /* skip */ }

  const discovered: string[] = [];
  for (const sub of SUBDOMAINS) {
    const subHost = `${sub}.${domain}`;
    try {
      const resp = await fetch(`${parsed.protocol}//${subHost}/`, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(4000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      // Require HTTP 200 and a meaningful body (not a trivial parking/404 page)
      if (!resp || resp.status !== 200) continue;
      const body = await resp.text().catch(() => "");
      if (body.length < 200) continue;

      // Skip if response is suspiciously similar to the baseline 404 (CDN catch-all)
      if (baseline404 && baseline404.length > 100 && body.slice(0, 500) === baseline404.slice(0, 500)) continue;

      discovered.push(subHost);
    } catch { /* skip */ }
  }

  if (discovered.length > 0) {
    return {
      type: "subdomain-enum-discovered",
      severity: "INFO",
      url: targetUrl,
      evidence: `Discovered ${discovered.length} active subdomain(s) for ${domain}: ${discovered.slice(0, 5).join(", ")}. Subdomains expand the attack surface.`,
      cvssScore: 0.0,
      cveId: "CWE-200",
      confidence: CONFIDENCE.DETERMINISTIC,
      validationSteps: discovered.map((s) => `HTTP 200 with meaningful body from ${s}`),
      isVerified: true,
    };
  }
  return null;
}

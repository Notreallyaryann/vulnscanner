import { CONFIDENCE, FETCH_HEADERS, PendingFinding } from "../types";
import { safeFetch } from "../session";

export function evaluateCSP(cspValue: string, url: string): PendingFinding[] {
  const results: PendingFinding[] = [];
  const weaknesses: string[] = [];

  if (/unsafe-inline/i.test(cspValue)) weaknesses.push("'unsafe-inline' allowed in script-src (allows inline <script> execution)");
  if (/unsafe-eval/i.test(cspValue)) weaknesses.push("'unsafe-eval' allowed in script-src (allows eval() / setTimeout strings)");
  if (/\*\s*(;|$)/.test(cspValue)) weaknesses.push("wildcard (*) in default-src or script-src allows scripts from any origin");
  if (/data:/i.test(cspValue)) weaknesses.push("'data:' URI allowed — attackers can load scripts via data: URIs");
  if (!/default-src|script-src/i.test(cspValue)) weaknesses.push("no default-src or script-src directive — browsers apply no script restriction");

  if (weaknesses.length > 0) {
    results.push({
      type: "weak-csp",
      severity: "MEDIUM",
      url,
      evidence: `Content-Security-Policy header is present but contains dangerous directives: ${weaknesses.join("; ")}.`,
      cvssScore: 5.8,
      cveId: "CWE-693",
    });
  }
  return results;
}

export function detectEnvLeaks(html: string, targetUrl: string): PendingFinding | null {
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
        evidence: `"${label}" detected in the page HTML/JS source: "${match[0].substring(0, 80)}".`,
        cvssScore: 9.5,
        cveId: "CWE-312",
      };
    }
  }
  return null;
}

export async function probeDebugModeExposure(targetUrl: string): Promise<PendingFinding | null> {
  const DEBUG_PATHS = [
    "/_ah/admin", "/admin/debug", "/debug", "/__debug__/",
    "/_profiler/open", "/telescope", "/horizon", "/_ignition/health-check",
    "/_framework/staticfiles/", "/elmah.axd", "/trace.axd", "/dump", "/?debug=1",
    "/__debugger__", "/console", "/docs", "/redoc", "/openapi.json", "/swagger.json",
    "/__nextjs_original-stack", "/@vite/client",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings",
  ];
  const DEBUG_MARKERS = [
    /Traceback \(most recent call last\)/i,
    /Werkzeug Powered Traceback|Interactive Console/i,
    /swagger-ui|redoc-container|openapi: 3\./i,
    /Laravel.*whoops|Whoops.*Laravel/i,
    /Symfony.*exception.*details/i,
    /DEBUG.*=.*True|DJANGO_DEBUG|Technical500Response/i,
    /__nextjs_original-stack/i,
    /"_links":\s*\{"self":\s*\{"href":\s*".*actuator"/i,
    /Application has thrown an uncaught exception|stack trace/i,
    /at\s+[\w.]+\([\w./]+:\d+:\d+\)/,
    /xdebug-error|Xdebug v[\d.]+/i,
  ];

  for (const path of DEBUG_PATHS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const resp = await safeFetch(url, 4000);
      if (!resp || (resp.status !== 200 && resp.status !== 500)) continue;
      const body = await resp.text();
      const hit = DEBUG_MARKERS.find((p) => p.test(body));
      if (hit) {
        return {
          type: "debug-mode-exposed",
          severity: path.includes("/docs") || path.includes("/openapi.json") ? "MEDIUM" : "HIGH",
          url,
          evidence: `Debug/development mode or API documentation is exposed in production at ${url}.`,
          cvssScore: path.includes("/docs") || path.includes("/openapi.json") ? 5.3 : 7.5,
          cveId: "CWE-215",
        };
      }
    } catch { /* next path */ }
  }
  return null;
}

export async function probeCRLFInjection(paramUrl: string): Promise<PendingFinding | null> {
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
              evidence: `CRLF Injection (HTTP Response Splitting) confirmed. Injecting CRLF characters into parameter "${param}" caused the server to emit an injected HTTP header "${headerName}: ${headerVal}".`,
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

export async function probeDangerousHTTPMethods(targetUrl: string, apiPaths: string[]): Promise<PendingFinding | null> {
  const targets = [
    targetUrl,
    ...(apiPaths.map((p) => {
      try {
        return new URL(p, targetUrl).toString();
      } catch {
        return "";
      }
    }).filter(Boolean)),
  ].slice(0, 5);

  for (const url of targets) {
    try {
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
            evidence: `HTTP TRACE method is enabled at ${url}. TRACE reflects all request headers back in response body.`,
            cvssScore: 6.3,
            cveId: "CWE-16",
          };
        }
      }

      const optResp = await fetch(url, {
        method: "OPTIONS",
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      if (optResp) {
        const allowed = optResp.headers.get("allow") || optResp.headers.get("access-control-allow-methods") || "";
        const dangerous = ["TRACE", "CONNECT"].filter((m) => allowed.toUpperCase().includes(m));
        if (dangerous.length > 0) {
          return {
            type: "dangerous-http-methods",
            severity: "MEDIUM",
            url,
            evidence: `HTTP OPTIONS response reveals genuinely dangerous methods: ${dangerous.join(", ")}. Allow header: "${allowed}".`,
            cvssScore: 6.3,
            cveId: "CWE-16",
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

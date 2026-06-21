import { prisma } from "./prisma";
import { retrieveContext } from "./rag";
import { generateFixReport } from "./cerebras";

interface PendingFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
}

const FETCH_HEADERS = {
  "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/2.0; Security-Audit)",
  Accept: "text/html,application/xhtml+xml,*/*;q=0.9",
  "Accept-Language": "en-US,en;q=0.9",
};

// ─── Crawler & Extraction Helpers ─────────────────────────────────────────────

/** Describes a parsed HTML form with its action URL, HTTP method, and input field names. */
interface FormTarget {
  actionUrl: string;
  method: "GET" | "POST";
  fields: string[]; // all injectable input field names
}

/**
 * Parse all same-origin HTML forms from a page.
 * Extracts action URL, method (default POST), and all text-like input field names.
 * This enables submitting injection payloads directly to form fields — not just URL params.
 * Capped at 8 forms to avoid excessive probing.
 */
function extractForms(html: string, baseUrl: string): FormTarget[] {
  const base = new URL(baseUrl);
  const forms: FormTarget[] = [];
  const INJECTABLE_TYPES = /^(text|search|email|number|tel|url|hidden|password|)$/i;

  for (const formMatch of html.matchAll(/<form(\s[^>]*)?>([\s\S]*?)<\/form>/gi)) {
    try {
      const attrs = formMatch[1] ?? "";
      const body  = formMatch[2] ?? "";

      // Resolve action URL (default to current page)
      const actionMatch = attrs.match(/action=["']([^"']+)["']/i);
      const rawAction   = actionMatch ? actionMatch[1].trim() : baseUrl;
      const actionUrl   = new URL(rawAction, baseUrl);
      if (actionUrl.hostname !== base.hostname) continue; // skip cross-origin forms

      // Method (default GET if not specified, but POST is far more common for data forms)
      const methodMatch = attrs.match(/method=["']?(get|post)["']?/i);
      const method: "GET" | "POST" = methodMatch
        ? (methodMatch[1].toUpperCase() as "GET" | "POST")
        : "POST";

      // Collect all injectable input field names
      const fields: string[] = [];
      for (const inputMatch of body.matchAll(/<input(\s[^>]*)?\/?>|<textarea(\s[^>]*)?>/gi)) {
        const inputAttrs = inputMatch[1] ?? inputMatch[2] ?? "";
        const typeMatch  = inputAttrs.match(/type=["']?([^"'\s>]+)["']?/i);
        const nameMatch  = inputAttrs.match(/name=["']([^"']+)["']/i);
        if (!nameMatch) continue;
        const fieldType = typeMatch ? typeMatch[1] : "";
        // Inject into any text-like field (including password for default-creds testing)
        if (INJECTABLE_TYPES.test(fieldType)) {
          fields.push(nameMatch[1]);
        }
      }
      // Also grab <select> and <textarea> names
      for (const selMatch of body.matchAll(/<(?:select|textarea)(\s[^>]*)?>/gi)) {
        const selAttrs  = selMatch[1] ?? "";
        const nameMatch = selAttrs.match(/name=["']([^"']+)["']/i);
        if (nameMatch) fields.push(nameMatch[1]);
      }

      if (fields.length > 0) {
        forms.push({ actionUrl: actionUrl.toString(), method, fields });
      }
    } catch { /* skip malformed */ }
  }
  return forms.slice(0, 8);
}

/** Extract same-origin links from HTML, excluding static assets. Capped at 30. */
function extractSameOriginLinks(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const links = new Set<string>();
  for (const m of html.matchAll(/(?:href|action)=["']([^"'#][^"']*)["']/gi)) {
    try {
      const u = new URL(m[1], baseUrl);
      if (
        u.hostname === base.hostname &&
        !/\.(css|js|png|jpg|gif|ico|woff|woff2|svg|pdf|map)$/i.test(u.pathname)
      ) links.add(u.href);
    } catch { /* skip malformed */ }
  }
  return [...links].slice(0, 30);
}

/** Extract same-origin URLs that carry query params (for active injection tests). Capped at 10. */
function extractParamUrls(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const out = new Set<string>();
  for (const m of html.matchAll(/(?:href|action)=["']([^"']*\?[^"'&][^"']*)["']/gi)) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname && [...u.searchParams.keys()].length > 0)
        out.add(u.href);
    } catch { /* skip */ }
  }
  return [...out].slice(0, 10);
}

/** Extract API/REST/GraphQL path references from inline HTML & scripts. Capped at 20. */
function extractApiEndpoints(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const out = new Set<string>();
  const pats = [
    /["'`](\/api\/[^\s"'`?#]{3,80})/g,
    /["'`](\/rest\/[^\s"'`?#]{3,80})/g,
    /["'`](\/v\d+\/[^\s"'`?#]{3,80})/g,
    /["'`](\/graphql[^\s"'`?#]{0,40})/gi,
  ];
  for (const pat of pats)
    for (const m of html.matchAll(pat)) {
      try { new URL(m[1], baseUrl); out.add(m[1]); } catch { /* skip */ }
    }
  return [...out].slice(0, 20);
}

/** Parse sitemap.xml and return same-origin URLs. Capped at 25. */
function parseSitemap(xml: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const urls: string[] = [];
  for (const m of xml.matchAll(/<loc>(https?:\/\/[^<]+)<\/loc>/gi)) {
    try {
      const u = new URL(m[1].trim());
      if (u.hostname === base.hostname) urls.push(u.href);
    } catch { /* skip */ }
  }
  return urls.slice(0, 25);
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
];

// Multiple SQLi payloads: error-based, boolean-based, UNION-based
const SQLI_PAYLOADS = [
  "'",                           // basic single quote — triggers syntax errors
  "'--",                         // comment out rest of query
  "' OR '1'='1",                 // boolean always-true
  "' OR '1'='1'--",              // boolean with comment
  "1' AND 1=1--",                // numeric context boolean
  "' UNION SELECT NULL--",       // UNION-based (1 column)
  "' UNION SELECT NULL,NULL--",  // UNION-based (2 columns)
  "; DROP TABLE users--",        // stacked query (rare but detectable)
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

/**
 * Inject SQLi payloads into a URL query parameter and detect SQL error signatures.
 * Tests multiple payloads and all parameters in the URL.
 */
async function probeSQLiError(paramUrl: string): Promise<PendingFinding | null> {
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
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;
          const body = await resp.text();
          const hit = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(body));
          if (hit) {
            return {
              type: "sql-injection-reflected",
              severity: "CRITICAL",
              url: testUrl.toString(),
              parameter: param,
              evidence: `SQL Injection confirmed via URL parameter. Injecting payload "${payload}" into query parameter "${param}" triggered a database error in the HTTP response. This confirms the application builds SQL queries from raw user input without parameterization. An attacker can enumerate tables, extract data, and potentially gain full database control.`,
              cvssScore: 9.8,
              cveId: "CWE-89",
            };
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Submit SQLi payloads to every input field in an HTML form via POST/GET.
 * This catches injection in search boxes, login fields, registration forms, etc.
 * Returns the first confirmed finding.
 */
async function probeFormSQLi(form: FormTarget): Promise<PendingFinding | null> {
  // Skip pure password-only forms (login) — handled by broken-auth probe
  const nonPasswordFields = form.fields.filter((f) => !/^pass(word)?|pwd|secret$/i.test(f));
  if (nonPasswordFields.length === 0) return null;

  for (const field of nonPasswordFields) {
    for (const payload of SQLI_PAYLOADS) {
      try {
        // Build a body with the payload in the target field; fill other fields with "test"
        const formData = new URLSearchParams();
        for (const f of form.fields) {
          formData.set(f, f === field ? payload : "test");
        }

        let resp: Response | null = null;
        if (form.method === "POST") {
          resp = await fetch(form.actionUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "User-Agent": FETCH_HEADERS["User-Agent"],
            },
            body: formData.toString(),
            redirect: "follow",
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
        } else {
          // GET — append fields as query params
          const getUrl = new URL(form.actionUrl);
          for (const [k, v] of formData) getUrl.searchParams.set(k, v);
          resp = await safeFetch(getUrl.toString(), 6000);
        }

        if (!resp) continue;
        const body = await resp.text();
        const hit = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(body));
        if (hit) {
          return {
            type: "sql-injection-form",
            severity: "CRITICAL",
            url: form.actionUrl,
            parameter: field,
            evidence: `SQL Injection confirmed via form field submission. Submitting payload "${payload}" in form field "${field}" (${form.method} to ${form.actionUrl}) returned a database error. The application passes form input directly into SQL queries without sanitization. An attacker can dump the entire database, bypass authentication, and escalate privileges.`,
            cvssScore: 9.8,
            cveId: "CWE-89",
          };
        }
      } catch { /* next */ }
    }
  }
  return null;
}

/**
 * Reflect XSS payloads via URL query parameter and check for unencoded reflection in the response.
 * Tests multiple payloads across all URL parameters.
 */
async function probeReflectedXSS(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params) {
      for (const payload of XSS_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;
          const body = await resp.text();
          // Unencoded reflection = XSS; HTML-encoded = safe
          const reflected = body.includes(payload) &&
            !body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
          if (reflected) {
            return {
              type: "reflected-xss",
              severity: "HIGH",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Reflected XSS confirmed via URL parameter. The payload "${payload.substring(0, 60)}" injected into query parameter "${param}" appears unencoded in the HTTP response. An attacker can craft a malicious link that, when clicked by an authenticated user, executes arbitrary JavaScript in their browser — enabling session theft, keylogging, or account takeover.`,
              cvssScore: 7.4,
              cveId: "CWE-79",
            };
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

/**
 * Submit XSS payloads to every input field in an HTML form and check for unencoded reflection.
 * Catches stored/reflected XSS in search forms, comment boxes, profile fields, etc.
 */
async function probeFormXSS(form: FormTarget): Promise<PendingFinding | null> {
  for (const field of form.fields) {
    for (const payload of XSS_PAYLOADS) {
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) {
          formData.set(f, f === field ? payload : "test");
        }

        let resp: Response | null = null;
        if (form.method === "POST") {
          resp = await fetch(form.actionUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "User-Agent": FETCH_HEADERS["User-Agent"],
            },
            body: formData.toString(),
            redirect: "follow",
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
        } else {
          const getUrl = new URL(form.actionUrl);
          for (const [k, v] of formData) getUrl.searchParams.set(k, v);
          resp = await safeFetch(getUrl.toString(), 6000);
        }

        if (!resp) continue;
        const body = await resp.text();
        const reflected = body.includes(payload) &&
          !body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
        if (reflected) {
          return {
            type: "reflected-xss-form",
            severity: "HIGH",
            url: form.actionUrl,
            parameter: field,
            evidence: `Reflected XSS confirmed via form input. The payload "${payload.substring(0, 60)}" submitted in form field "${field}" (${form.method} to ${form.actionUrl}) is reflected back in the HTTP response without HTML-encoding. An attacker can inject malicious scripts via this form, leading to session hijacking, credential theft, or malware delivery.`,
            cvssScore: 7.4,
            cveId: "CWE-79",
          };
        }
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
      if (resp.status === 200 || resp.status === 400) {
        const text = await resp.text();
        if (text.includes("__schema") || text.includes("queryType")) {
          return {
            type: "graphql-introspection-enabled",
            severity: "MEDIUM",
            url,
            evidence: `GraphQL introspection is enabled at ${url}. Any visitor can query the full API schema — all types, fields, mutations, and queries — giving attackers a complete blueprint of the backend for targeted exploitation.`,
            cvssScore: 5.3,
            cveId: "CWE-200",
          };
        }
      }
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

      if (isRedirect || (hasAuthCookie && noErrorInBody)) {
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
      type: "ssrf-parameter-detected",
      severity: "HIGH",
      url: targetUrl,
      parameter: hits[0],
      evidence: `Found ${hits.length} parameter(s) that accept URLs or remote paths: ${hits.slice(0, 3).join(", ")}. If the server fetches these URLs without validation, an attacker can make the server send requests to internal services (metadata APIs, databases, internal admin panels), leading to SSRF.`,
      cvssScore: 8.6,
      cveId: "CWE-918",
    };
  }
  return null;
}

/** Inject shell metacharacters into params and look for error signatures (blind command injection indicator). */
async function probeCommandInjection(paramUrl: string): Promise<PendingFinding | null> {
  const PAYLOADS = ["; ls", "| whoami", "& dir", "`id`", "$(id)"];
  const CMD_ERROR_PATTERNS = [
    /sh:\s+\d+:.*not found/i, /command not found/i, /Permission denied/i,
    /No such file or directory/i, /cannot find/i, /is not recognized/i,
    /root:x:0:0/i, /uid=\d+\(/, /Volume Serial Number/i,
  ];
  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    const origVal = u.searchParams.get(firstParam) ?? "";
    u.searchParams.set(firstParam, origVal + PAYLOADS[0]);
    const resp = await safeFetch(u.toString(), 5000);
    if (!resp) return null;
    const body = await resp.text();
    const hit = CMD_ERROR_PATTERNS.find((p) => p.test(body));
    if (hit) {
      return {
        type: "command-injection",
        severity: "CRITICAL",
        url: u.toString(),
        parameter: firstParam,
        evidence: `Injecting shell metacharacters into parameter "${firstParam}" produced an OS-level error or command output in the HTTP response. This indicates the server is passing user input to a shell command, allowing an attacker to execute arbitrary OS commands and potentially gain full server access.`,
        cvssScore: 9.8,
        cveId: "CWE-78",
      };
    }
  } catch { /* skip */ }
  return null;
}

/** Probe path traversal (LFI) by injecting ../ sequences into the first param of URLs. */
async function probePathTraversal(paramUrl: string): Promise<PendingFinding | null> {
  const TRAVERSAL_PAYLOAD = "../../../etc/passwd";
  const LFI_PATTERNS = [/root:x:0:0/, /bin\/bash/, /daemon:x/, /nobody:x/];
  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    u.searchParams.set(firstParam, TRAVERSAL_PAYLOAD);
    const resp = await safeFetch(u.toString(), 5000);
    if (!resp) return null;
    const body = await resp.text();
    const hit = LFI_PATTERNS.find((p) => p.test(body));
    if (hit) {
      return {
        type: "path-traversal-lfi",
        severity: "CRITICAL",
        url: u.toString(),
        parameter: firstParam,
        evidence: `Injecting path traversal sequences into parameter "${firstParam}" caused the server to return local file content (e.g., /etc/passwd). An attacker can read sensitive server files, credentials, and private keys.`,
        cvssScore: 9.1,
        cveId: "CWE-22",
      };
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
      severity: "MEDIUM",
      url: targetUrl,
      evidence: `Found ${externalRefs.length} references to external cloud-hosted domains in page source (${externalRefs.slice(0, 3).join(", ")}). If any CNAMEs are unclaimed, an attacker can register the resource and serve malicious content from your domain.`,
      cvssScore: 6.4,
      cveId: "CWE-350",
    };
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

export async function runVulnerabilityScan(scanId: string, targetUrl: string) {
  console.log(`🚀 Starting passive security scan [${scanId}] for: ${targetUrl}`);

  try {
    await prisma.scan.update({ where: { id: scanId }, data: { status: "CRAWLING" } });

    // ── Fetch main page ────────────────────────────────────────────────────────
    const mainResp = await safeFetch(targetUrl);
    const headers: Record<string, string> = {};
    let pageHtml = "";
    let cookieHeaders: string[] = [];
    let fetchSucceeded = false;

    if (mainResp) {
      mainResp.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
      // Collect ALL Set-Cookie headers (they come comma-joined from fetch)
      const rawCookie = mainResp.headers.get("set-cookie") || "";
      cookieHeaders = rawCookie ? rawCookie.split(/,(?=[^ ])/) : [];
      pageHtml = await mainResp.text();
      fetchSucceeded = true;
      console.log(`✅ Fetched main page (HTTP ${mainResp.status}), ${pageHtml.length} bytes`);
    } else {
      console.warn("⚠️ Could not reach target. Running header-only checks.");
    }

    await prisma.scan.update({ where: { id: scanId }, data: { status: "SCANNING" } });

    const findings: PendingFinding[] = [];

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION A: SECURITY HEADER CHECKS
    // ══════════════════════════════════════════════════════════════════════════

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

    // A7 – Server version disclosure (fingerprinting for CVE targeting)
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

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION B: COOKIE & SESSION SECURITY (Session Hijacking)
    // ══════════════════════════════════════════════════════════════════════════

    if (fetchSucceeded && cookieHeaders.length > 0) {
      for (const cookie of cookieHeaders) {
        const lower = cookie.toLowerCase();
        const cookieName = cookie.split("=")[0]?.trim() || "session";

        // B1 – Missing HttpOnly flag (XSS can steal the cookie)
        if (!lower.includes("httponly")) {
          findings.push({
            type: "session-hijacking-no-httponly",
            severity: "HIGH",
            url: targetUrl,
            parameter: cookieName,
            evidence: `Cookie "${cookieName}" is missing the 'HttpOnly' flag. JavaScript on the page (including XSS payloads) can read this cookie via document.cookie and send it to an attacker's server.`,
            cvssScore: 7.5,
            cveId: "CWE-1004",
          });
          break;
        }

        // B2 – Missing Secure flag (cookie sent over HTTP)
        if (!lower.includes("secure")) {
          findings.push({
            type: "session-hijacking-no-secure",
            severity: "MEDIUM",
            url: targetUrl,
            parameter: cookieName,
            evidence: `Cookie "${cookieName}" is missing the 'Secure' flag. The browser will transmit this cookie over unencrypted HTTP connections, exposing it to network eavesdroppers.`,
            cvssScore: 5.9,
            cveId: "CWE-614",
          });
          break;
        }

        // B3 – Missing SameSite flag (CSRF via cookies)
        if (!lower.includes("samesite")) {
          findings.push({
            type: "csrf-via-cookie-samesite",
            severity: "MEDIUM",
            url: targetUrl,
            parameter: cookieName,
            evidence: `Cookie "${cookieName}" has no 'SameSite' attribute. Cross-site requests (from a malicious page) will automatically include this cookie, enabling CSRF attacks.`,
            cvssScore: 6.1,
            cveId: "CWE-352",
          });
          break;
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION C: CSRF DETECTION (Form-level)
    // ══════════════════════════════════════════════════════════════════════════

    if (fetchSucceeded && pageHtml) {
      // C1 – HTML forms without CSRF tokens
      const formMatches = [...pageHtml.matchAll(/<form[^>]*method=["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi)];
      const csrfTokenPatterns = /csrf|_token|authenticity_token|__requestverificationtoken|nonce/i;

      for (const form of formMatches) {
        const formBody = form[1] || "";
        const hasToken = csrfTokenPatterns.test(formBody);
        if (!hasToken) {
          findings.push({
            type: "csrf-missing-token",
            severity: "HIGH",
            url: targetUrl,
            evidence:
              "A POST form was found on the page without a detectable CSRF token field. An attacker can trick authenticated users into submitting this form from a third-party site, performing actions on their behalf (e.g., change email, make purchase).",
            cvssScore: 8.0,
            cveId: "CWE-352",
          });
          break; // Report once per scan
        }
      }

      // ══════════════════════════════════════════════════════════════════════
      // SECTION D: XSS INDICATORS (Passive — no active injection)
      // ══════════════════════════════════════════════════════════════════════

      // D1 – dangerouslySetInnerHTML or document.write in source
      if (/dangerouslySetInnerHTML|document\.write\s*\(/.test(pageHtml)) {
        findings.push({
          type: "xss-unsafe-rendering",
          severity: "HIGH",
          url: targetUrl,
          evidence:
            "Source code contains 'dangerouslySetInnerHTML' or 'document.write()'. If user-controlled data is passed to these APIs without sanitization, attackers can inject arbitrary JavaScript into the page (Stored/Reflected XSS).",
          cvssScore: 8.2,
          cveId: "CWE-79",
        });
      }

      // D2 – Inline event handlers with dynamic content (eval, onclick with vars)
      if (/on(click|load|error|mouseover)\s*=\s*["'][^"']*\$\{|eval\s*\(/.test(pageHtml)) {
        findings.push({
          type: "xss-inline-event-handler",
          severity: "MEDIUM",
          url: targetUrl,
          evidence:
            "Inline event handlers (onclick, onload, onerror) or eval() were detected in the page source. Dynamically constructed event handlers are a classic XSS injection vector.",
          cvssScore: 6.5,
          cveId: "CWE-79",
        });
      }

      // ══════════════════════════════════════════════════════════════════════
      // SECTION E: SQL INJECTION INDICATORS (Error-based detection)
      // ══════════════════════════════════════════════════════════════════════

      // E1 – Database error messages visible in HTML response
      const sqlErrorPatterns = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /MySQLSyntaxErrorException/i,
        /valid MySQL result/i,
        /PostgreSQL.*ERROR/i,
        /PSQLException/i,
        /ORA-\d{4,}/i, // Oracle errors
        /Microsoft OLE DB.*SQL Server/i,
        /Unclosed quotation mark after the character string/i,
        /SQLiteException/i,
        /org\.hibernate\.exception/i,
        /You have an error in your SQL syntax/i,
        /ODBC SQL Server Driver/i,
        /Syntax error.*in query expression/i,
      ];
      const matchedSqlError = sqlErrorPatterns.find((p) => p.test(pageHtml));
      if (matchedSqlError) {
        findings.push({
          type: "sql-injection-error-disclosure",
          severity: "CRITICAL",
          url: targetUrl,
          evidence:
            "The server is leaking raw SQL error messages in its HTTP response. This confirms the application is building SQL queries with user input and reveals database type, query structure, and table names — critical intelligence for an attacker.",
          cvssScore: 9.8,
          cveId: "CWE-89",
        });
      }

      // E2 – Debug/stack trace exposure (also helps SQLi exploitation)
      if (/at\s+[\w.]+\([\w./]+:\d+:\d+\)|Traceback \(most recent call last\)|Stack trace:/i.test(pageHtml)) {
        findings.push({
          type: "stack-trace-disclosure",
          severity: "HIGH",
          url: targetUrl,
          evidence:
            "A full stack trace or exception dump was found in the HTTP response. Stack traces reveal internal file paths, function names, and framework versions that attackers use to pinpoint exploitable code paths.",
          cvssScore: 7.5,
          cveId: "CWE-209",
        });
      }

      // ══════════════════════════════════════════════════════════════════════
      // SECTION F: SENSITIVE DATA EXPOSURE
      // ══════════════════════════════════════════════════════════════════════

      // F1 – API keys / secrets leaked in HTML source
      const secretPatterns: Array<{ label: string; pattern: RegExp }> = [
        { label: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
        { label: "Generic API key", pattern: /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i },
        { label: "Bearer token", pattern: /bearer\s+[A-Za-z0-9\-._~+/]+=*/i },
        { label: "Private key header", pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
        { label: "Stripe secret key", pattern: /sk_(live|test)_[0-9a-zA-Z]{24}/ },
        { label: "SendGrid API key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
        { label: "Password in source", pattern: /password\s*[:=]\s*["'][^"']{6,}["']/i },
      ];
      for (const { label, pattern } of secretPatterns) {
        if (pattern.test(pageHtml)) {
          findings.push({
            type: "sensitive-data-exposure",
            severity: "CRITICAL",
            url: targetUrl,
            evidence: `Possible secret detected in HTML source: "${label}". Hardcoded credentials or API keys in client-facing HTML allow attackers to authenticate as the application, access third-party services, and escalate privileges.`,
            cvssScore: 9.5,
            cveId: "CWE-312",
          });
          break; // Report once
        }
      }

      // F2 – Password field transmitted over HTTP (plaintext credential theft)
      if (!targetUrl.startsWith("https://") && /<input[^>]+type=["']?password["']?/i.test(pageHtml)) {
        findings.push({
          type: "password-over-http",
          severity: "CRITICAL",
          url: targetUrl,
          evidence:
            "A password input field was found on a plain HTTP page. Credentials entered by users are transmitted in cleartext over the network and visible to anyone performing a passive network sniff.",
          cvssScore: 9.1,
          cveId: "CWE-319",
        });
      }

      // F3 – Mixed content (HTTPS page loads HTTP resources)
      if (targetUrl.startsWith("https://")) {
        const httpRefs = (pageHtml.match(/(?:src|href|action)=["']http:\/\//gi) || []).length;
        if (httpRefs > 0) {
          findings.push({
            type: "mixed-content",
            severity: "MEDIUM",
            url: targetUrl,
            evidence: `Found ${httpRefs} reference(s) to insecure HTTP resources (src/href/action) on an HTTPS page. Mixed content lets attackers intercept and tamper with the insecure resources, potentially injecting malicious scripts.`,
            cvssScore: 5.4,
            cveId: "CWE-311",
          });
        }
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION G: CORS MISCONFIGURATION
    // ══════════════════════════════════════════════════════════════════════════

    const corsOrigin = headers["access-control-allow-origin"] || "";
    const corsCredentials = (headers["access-control-allow-credentials"] || "").toLowerCase();
    if (fetchSucceeded) {
      if (corsOrigin === "*" && corsCredentials === "true") {
        findings.push({
          type: "cors-credentials-wildcard",
          severity: "CRITICAL",
          url: targetUrl,
          evidence:
            "'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. Any origin can make credentialed cross-origin requests, letting attackers read authenticated API responses from a victim's browser session.",
          cvssScore: 9.0,
          cveId: "CWE-942",
        });
      } else if (corsOrigin === "*") {
        findings.push({
          type: "cors-wildcard",
          severity: "LOW",
          url: targetUrl,
          evidence:
            "CORS wildcard ('Access-Control-Allow-Origin: *') is set. Any website can read JSON/API responses from this server — acceptable for public APIs but dangerous if responses contain user-specific data.",
          cvssScore: 3.5,
          cveId: "CWE-942",
        });
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION H: OPEN REDIRECT CHECK
    // ══════════════════════════════════════════════════════════════════════════

    if (fetchSucceeded) {
      // H1 – Redirect parameters in links (passive detection)
      const redirectParamPattern = /(?:href|action)=["'][^"']*[?&](?:redirect|url|next|return|goto|dest|destination|rurl|target)=(?:https?:\/\/|\/\/)/gi;
      if (redirectParamPattern.test(pageHtml)) {
        findings.push({
          type: "open-redirect",
          severity: "MEDIUM",
          url: targetUrl,
          evidence:
            "A link or form action was found containing a redirect parameter (e.g., ?redirect=, ?next=, ?url=) that accepts an absolute URL. Attackers craft phishing links that start on your trusted domain then redirect victims to a malicious site.",
          cvssScore: 6.1,
          cveId: "CWE-601",
        });
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION I: ROBOTS.TXT SENSITIVE PATH DISCLOSURE
    // ══════════════════════════════════════════════════════════════════════════

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
            evidence: `robots.txt discloses sensitive paths: ${exposed.join(", ")}. Listing internal paths in robots.txt is a common misunderstanding — it actually advertises hidden endpoints to attackers rather than hiding them.`,
            cvssScore: 2.3,
          });
        }
      }
    } catch {
      /* non-critical */
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SECTION J: PROBE COMMON SENSITIVE ENDPOINTS
    // ══════════════════════════════════════════════════════════════════════════

    // Helper to detect if an endpoint returns a soft-404 or a generic SPA fallback route
    const isSoft404OrSPARedirect = (endpointBody: string, homepageBody: string): boolean => {
      if (!homepageBody) return false;
      
      // Get the page title
      const getTitle = (html: string) => {
        const m = html.match(/<title>([^<]+)<\/title>/i);
        return m ? m[1].trim() : "";
      };
      
      const homeTitle = getTitle(homepageBody);
      const epTitle = getTitle(endpointBody);
      
      // If titles are identical and not empty, it's a SPA fallback/redirect (e.g. "ChatGPT" or "Juice Shop")
      if (homeTitle && epTitle && homeTitle === epTitle) {
        return true;
      }
      
      // If the body length is extremely similar and both contain typical SPA signatures
      const lenDiff = Math.abs(endpointBody.length - homepageBody.length);
      const threshold = homepageBody.length * 0.08; // 8% threshold
      if (lenDiff < threshold) {
        if (/__NEXT_DATA__|__nuxt|webpack|next\/static|react-root|#app|#root/i.test(endpointBody)) {
          return true;
        }
      }
      return false;
    };

    // ── Content-verified endpoint probing ──────────────────────────────────
    // Each entry has verify(body, contentType) that must return true before
    // a finding is reported. Eliminates false positives from soft-404s,
    // login redirects, and SPAs that return 200 for every route.
    const sensitiveEndpoints: Array<{
      path: string; label: string;
      severity: "CRITICAL" | "HIGH" | "MEDIUM"; cvssScore: number;
      verify: (body: string, ct: string) => boolean;
    }> = [
      { path: "/.env",            label: ".env file",            severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
      { path: "/.env.local",      label: ".env.local",           severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
      { path: "/.env.production", label: ".env.production",      severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD|JWT/i.test(b) },
      { path: "/.env.backup",     label: ".env.backup",          severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /^[A-Z_]+=.+/m.test(b) || /DATABASE_URL|API_KEY|SECRET|PASSWORD/i.test(b) },
      { path: "/.git/HEAD",   label: ".git repository (HEAD)", severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /^ref:\s+refs\/heads\//m.test(b) || /^[0-9a-f]{40}$/m.test(b.trim()) },
      { path: "/.git/config", label: ".git/config",             severity: "CRITICAL", cvssScore: 9.8,
        verify: (b) => /\[core\]/.test(b) || /\[remote/.test(b) },
      { path: "/.svn/entries", label: ".svn repository", severity: "CRITICAL", cvssScore: 9.0,
        verify: (b) => /^10$/m.test(b) || /svn\.apache\.org/i.test(b) },
      { path: "/.htaccess", label: ".htaccess file", severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /RewriteEngine|AuthType|Require|Allow from|Deny from/i.test(b) },
      { path: "/.htpasswd", label: ".htpasswd credentials", severity: "CRITICAL", cvssScore: 9.5,
        verify: (b) => /^[^:]+:\$[^\s]+$/m.test(b) || /^[^:]+:[a-zA-Z0-9./]{13}$/m.test(b) },
      { path: "/wp-admin",     label: "WordPress admin",  severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /wp-login|WordPress|wp-admin/i.test(b) },
      { path: "/wp-login.php", label: "WordPress login",  severity: "MEDIUM", cvssScore: 5.3,
        verify: (b) => /user_login|user_pass|wp-login/i.test(b) },
      { path: "/phpmyadmin", label: "phpMyAdmin",      severity: "HIGH", cvssScore: 8.0,
        verify: (b) => /phpMyAdmin|phpmyadmin|pma_/i.test(b) },
      { path: "/pma",        label: "phpMyAdmin (pma)", severity: "HIGH", cvssScore: 8.0,
        verify: (b) => /phpMyAdmin|phpmyadmin|pma_/i.test(b) },
      { path: "/phpinfo.php",   label: "phpinfo()",            severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /PHP Version|phpinfo\(\)|php\.ini/i.test(b) },
      { path: "/info.php",      label: "PHP info page",        severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /PHP Version|phpinfo\(\)|php\.ini/i.test(b) },
      { path: "/server-status", label: "Apache server-status", severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /Apache Server Status|requests currently being processed/i.test(b) },
      { path: "/_profiler",     label: "Symfony Profiler",     severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /Symfony|sf-toolbar|profiler/i.test(b) },
      { path: "/actuator/env",    label: "Spring Boot /env",    severity: "CRITICAL", cvssScore: 9.0,
        verify: (b, ct) => ct.includes("application/json") && /"propertySources"|"activeProfiles"/i.test(b) },
      { path: "/actuator/health", label: "Spring Boot /health", severity: "MEDIUM",   cvssScore: 5.3,
        verify: (b, ct) => ct.includes("application/json") && /"status"\s*:\s*"UP"/i.test(b) },
      { path: "/metrics", label: "Metrics endpoint", severity: "MEDIUM", cvssScore: 5.3,
        verify: (b) => /process_cpu_seconds|go_goroutines|http_requests_total/i.test(b) },
      { path: "/config.yml",   label: "config.yml",   severity: "HIGH", cvssScore: 7.5,
        verify: (b) => /^[a-z_]+:\s+.+/m.test(b) && /password|secret|key|database/i.test(b) },
      { path: "/config.json",  label: "config.json",  severity: "HIGH", cvssScore: 7.5,
        verify: (b, ct) => ct.includes("application/json") && /password|secret|apiKey|database/i.test(b) },
      { path: "/database.yml", label: "database.yml", severity: "CRITICAL", cvssScore: 9.0,
        verify: (b) => /adapter:|database:|username:|password:/i.test(b) },
      { path: "/backup.zip",    label: "Backup archive (.zip)",    severity: "HIGH", cvssScore: 8.0,
        verify: (_, ct) => ct.includes("application/zip") || ct.includes("octet-stream") },
      { path: "/backup.tar.gz", label: "Backup archive (.tar.gz)", severity: "HIGH", cvssScore: 8.0,
        verify: (_, ct) => ct.includes("gzip") || ct.includes("octet-stream") },
      { path: "/db.sql",   label: "SQL database dump", severity: "CRITICAL", cvssScore: 9.5,
        verify: (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
      { path: "/dump.sql", label: "SQL dump",          severity: "CRITICAL", cvssScore: 9.5,
        verify: (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
      { path: "/api/v1/users",     label: "User list API",       severity: "HIGH", cvssScore: 8.5,
        verify: (b, ct) => ct.includes("application/json") && /email|username|password/i.test(b) },
      { path: "/api/users",        label: "User list API",       severity: "HIGH", cvssScore: 8.5,
        verify: (b, ct) => ct.includes("application/json") && /email|username|password/i.test(b) },
      { path: "/api/admin",        label: "Admin API",           severity: "HIGH", cvssScore: 8.0,
        verify: (b, ct) => ct.includes("application/json") && b.length > 30 },
      { path: "/rest/user/whoami", label: "Identity disclosure", severity: "HIGH", cvssScore: 7.5,
        verify: (b, ct) => ct.includes("application/json") && /email|id|role/i.test(b) },
      { path: "/socket.io/",       label: "Socket.IO endpoint",  severity: "MEDIUM", cvssScore: 5.3,
        verify: (b) => /socket\.io|websocket|polling/i.test(b) },
    ];

    for (const endpoint of sensitiveEndpoints) {
      try {
        const endpointUrl = new URL(endpoint.path, targetUrl).toString();
        const resp = await safeFetch(endpointUrl, 5000);
        if (!resp || resp.status !== 200) continue;
        const body = await resp.text();
        const ct   = resp.headers.get("content-type") ?? "";
        
        // Hard-reject obvious soft-404s
        if (/<title>[^<]*(404|not found|page not found)[^<]*<\/title>/i.test(body)) continue;
        if (body.length < 20) continue;
        
        // Verify similarity with home page to eliminate false positives on SPAs (e.g. Next.js, React, Angular)
        if (pageHtml && isSoft404OrSPARedirect(body, pageHtml)) {
          continue;
        }

        // Only report when content fingerprint matches
        if (!endpoint.verify(body, ct)) continue;

        findings.push({
          type: "sensitive-endpoint-exposed",
          severity: endpoint.severity,
          url: endpointUrl,
          evidence: `"${endpoint.label}" at ${endpointUrl} confirmed exposed: HTTP 200 with matching content fingerprint (verified, not a soft-404 or redirect).`,
          cvssScore: endpoint.cvssScore,
          cveId: "CWE-538",
        });
      } catch { /* skip unreachable */ }
    }

    // SECTION K: RATE LIMITING / DoS / DDoS PROTECTION CHECK
    // ══════════════════════════════════════════════════════════════════════════

    if (fetchSucceeded) {
      // K1 – Check if any rate-limit headers are present on the main response
      const rateLimitHeaders = [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "retry-after",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
      ];
      const hasRateLimitHeaders = rateLimitHeaders.some((h) => headers[h]);

      // K2 – Send a small controlled burst (10 rapid requests) and check for 429
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
      } catch {
        /* burst probe failed – skip */
      }

      // K3 – Check for WAF / CDN protection indicators
      const wafHeaders = ["cf-ray", "x-sucuri-id", "x-cache", "x-amz-cf-id", "x-waf-event-info", "x-cdn"];
      const hasWafOrCdn = wafHeaders.some((h) => headers[h]);

      if (got429) {
        // ✅ Rate limiting IS working — report as INFO (good finding)
        findings.push({
          type: "rate-limit-active",
          severity: "INFO",
          url: targetUrl,
          evidence: `Rate limiting is active. The server responded with HTTP 429 (Too Many Requests) after ${got429AfterN} rapid requests in the burst probe. DoS/DDoS protection is functioning correctly for this endpoint.`,
          cvssScore: 0.0,
        });
      } else if (!hasRateLimitHeaders && !hasWafOrCdn) {
        // ❌ No rate limiting detected at all — HIGH risk
        findings.push({
          type: "missing-rate-limiting",
          severity: "HIGH",
          url: targetUrl,
          evidence: `No rate limiting detected. ${BURST_COUNT} rapid consecutive requests were sent and all received successful 2xx/3xx responses. No 'X-RateLimit-*', 'Retry-After', WAF headers (Cloudflare, Sucuri, AWS CloudFront), or HTTP 429 response was observed. The server appears vulnerable to DoS/DDoS attacks, credential stuffing, brute-force login, and API abuse.`,
          cvssScore: 7.5,
          cveId: "CWE-770",
        });
      } else if (!hasRateLimitHeaders && hasWafOrCdn) {
        // ⚠️ WAF/CDN present but no explicit rate-limit headers — MEDIUM
        findings.push({
          type: "rate-limit-unverified",
          severity: "MEDIUM",
          url: targetUrl,
          evidence: `A CDN or WAF proxy was detected (headers: ${wafHeaders.filter((h) => headers[h]).join(", ")}) but no explicit rate-limit response headers were present and the burst probe did not trigger a 429. Rate limiting may be configured at the CDN level but is not confirmed. Ensure rate limiting is explicitly enforced, especially on login, signup, and API endpoints.`,
          cvssScore: 4.3,
          cveId: "CWE-770",
        });
      } else if (hasRateLimitHeaders && !got429) {
        // ⚠️ Headers present but limit wasn't hit — LOW (headers are a good sign)
        findings.push({
          type: "rate-limit-headers-present",
          severity: "INFO",
          url: targetUrl,
          evidence: `Rate-limit response headers detected (${rateLimitHeaders.filter((h) => headers[h]).join(", ")}). The burst probe of ${BURST_COUNT} requests did not trigger a 429 — the limit is set higher than ${BURST_COUNT} req/window, or resets quickly. Verify the configured threshold is low enough to prevent brute-force and credential stuffing attacks.`,
          cvssScore: 1.5,
        });
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 2 – CRAWLING, FINGERPRINTING & ENDPOINT DISCOVERY
    // ══════════════════════════════════════════════════════════════════════════

    let discoveredParamUrls: string[] = [];
    let discoveredLinks: string[] = [];
    let discoveredForms: FormTarget[] = [];

    if (fetchSucceeded && pageHtml) {
      // ── L1: Crawl same-origin links ──────────────────────────────────────
      discoveredLinks = extractSameOriginLinks(pageHtml, targetUrl);
      const apiEndpoints = extractApiEndpoints(pageHtml, targetUrl);
      discoveredParamUrls = extractParamUrls(pageHtml, targetUrl);
      discoveredForms = extractForms(pageHtml, targetUrl);
      console.log(`🕸️  Crawled ${discoveredLinks.length} links, ${apiEndpoints.length} API refs, ${discoveredParamUrls.length} param URLs, ${discoveredForms.length} form(s)`);

      // ── L2: Technology fingerprinting ────────────────────────────────────
      const techs: string[] = [];
      if (/__NEXT_DATA__|_next\/static/.test(pageHtml)) techs.push("Next.js");
      if (/window\.__nuxt__|__NUXT__/.test(pageHtml)) techs.push("Nuxt.js");
      if (/ng-version=|angular\.js/i.test(pageHtml)) techs.push("Angular");
      if (/__VUE__|window\.__vue__/i.test(pageHtml)) techs.push("Vue.js");
      if (/wp-content\/|wp-includes\//i.test(pageHtml)) techs.push("WordPress");
      if (/drupal\.settings|Drupal\./i.test(pageHtml)) techs.push("Drupal");
      if (/Joomla!/i.test(pageHtml)) techs.push("Joomla");
      if (/shopify\.com\/s\/files/i.test(pageHtml)) techs.push("Shopify");
      if (/jquery[.-]([\d.]+)(\.min)?\.js/i.test(pageHtml)) techs.push("jQuery");
      if (/react(?:\.production|\.development)?\.min\.js/i.test(pageHtml)) techs.push("React");
      if (techs.length > 0) {
        findings.push({
          type: "technology-fingerprinting",
          severity: "INFO",
          url: targetUrl,
          evidence: `Detected technology stack: ${techs.join(", ")}. Technology fingerprinting allows attackers to look up known CVEs and version-specific exploits for each detected library or framework.`,
          cvssScore: 2.0,
          cveId: "CWE-200",
        });
      }

      // ── L3: IDOR signal detection ────────────────────────────────────────
      // Flag discovered URLs or API refs that contain sequential numeric IDs
      const idorPatterns = [
        /\/api\/[^/\s]+\/\d+/i, /\/rest\/[^/\s]+\/\d+/i,
        /\/users?\/\d+/i, /\/orders?\/\d+/i, /\/products?\/\d+/i,
        /[?&](?:id|user_id|order_id|product_id|account_id)=\d+/i,
      ];
      const idorUrls = [...discoveredLinks, ...apiEndpoints, ...discoveredParamUrls]
        .filter((u) => idorPatterns.some((p) => p.test(u)));
      if (idorUrls.length > 0) {
        findings.push({
          type: "idor-numeric-id",
          severity: "MEDIUM",
          url: idorUrls[0],
          evidence: `Discovered ${idorUrls.length} URL(s) using sequential numeric IDs (e.g. ${idorUrls[0]}). Sequential IDs are highly susceptible to Insecure Direct Object Reference (IDOR / BOLA) attacks — an attacker can enumerate adjacent IDs to access other users' data without authorisation.`,
          cvssScore: 6.5,
          cveId: "CWE-639",
        });
      }
    }

    // ── L4: Sitemap endpoint discovery ──────────────────────────────────────
    try {
      const sitemapUrl = new URL("/sitemap.xml", targetUrl).toString();
      const sitemapResp = await safeFetch(sitemapUrl, 5000);
      if (sitemapResp && sitemapResp.ok) {
        const sitemapXml = await sitemapResp.text();
        const sitemapUrls = parseSitemap(sitemapXml, targetUrl);
        if (sitemapUrls.length > 0) {
          // Merge new param URLs from sitemap
          for (const u of sitemapUrls) {
            if (/\?/.test(u)) discoveredParamUrls.push(u);
          }
          console.log(`🗺️  sitemap.xml: found ${sitemapUrls.length} additional URL(s)`);
        }
      }
    } catch { /* non-critical */ }

    // ── L5: security.txt check ──────────────────────────────────────────────
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
          evidence: "No security.txt file found at /.well-known/security.txt or /security.txt. RFC 9116 recommends this file to let researchers know how to report vulnerabilities responsibly.",
          cvssScore: 0.0,
        });
      }
    } catch { /* non-critical */ }

    // ── L6: JWT analysis (cookies) ──────────────────────────────────────────
    if (fetchSucceeded && cookieHeaders.length > 0) {
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
                url: targetUrl,
                parameter: name,
                evidence: `JWT in cookie "${name}" has alg:"none". This allows an attacker to forge arbitrary tokens by removing the signature, bypassing all authentication without knowing the secret key.`,
                cvssScore: 9.8,
                cveId: "CWE-345",
              });
            } else if (decoded.alg) {
              findings.push({
                type: "jwt-detected",
                severity: "INFO",
                url: targetUrl,
                parameter: name,
                evidence: `JWT token detected in cookie "${name}" using algorithm ${decoded.alg}. Ensure the signing secret has ≥256 bits of entropy and that the server rejects tokens with alg:none. Weak secrets can be brute-forced offline from any captured token.`,
                cvssScore: 3.5,
                cveId: "CWE-327",
              });
            }
          } catch { /* decode failed – not a valid JWT */ }
          break; // report once
        }
      }
    }

    // ── L7: GraphQL introspection ────────────────────────────────────────────
    const gqlFinding = await checkGraphQLIntrospection(targetUrl);
    if (gqlFinding) findings.push(gqlFinding);

    // ── L8: NEXT_PUBLIC_ / env variable leak detection ───────────────────────
    if (fetchSucceeded && pageHtml) {
      const envLeak = detectEnvLeaks(pageHtml, targetUrl);
      if (envLeak) findings.push(envLeak);
    }

    // ── L9: Session fixation / weak session token ────────────────────────────
    if (fetchSucceeded && cookieHeaders.length > 0) {
      const sessionFix = detectSessionFixation(cookieHeaders, targetUrl);
      if (sessionFix) findings.push(sessionFix);
    }

    // ── L10: Subdomain takeover signals ──────────────────────────────────────
    if (fetchSucceeded && pageHtml) {
      const takeoverSignal = detectSubdomainTakeoverSignals(pageHtml, targetUrl);
      if (takeoverSignal) findings.push(takeoverSignal);
    }

    // ── L11: SSRF parameter detection ────────────────────────────────────────
    if (fetchSucceeded && pageHtml) {
      const ssrfFinding = detectSSRF(pageHtml, discoveredParamUrls, targetUrl);
      if (ssrfFinding) findings.push(ssrfFinding);
    }

    // ── L12: JS file secrets and dangerous sinks ─────────────────────────────
    if (fetchSucceeded && pageHtml) {
      console.log(`🔬 Analyzing inline JS files for secrets and dangerous sinks...`);
      const jsFindings = await analyzeJSFiles(pageHtml, targetUrl);
      findings.push(...jsFindings);
    }

    // ── L13: Broken auth (login form detection + default credential probe) ────
    if (fetchSucceeded && pageHtml) {
      const loginForms = [...pageHtml.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
      for (const formMatch of loginForms.slice(0, 3)) {
        const formBody = formMatch[1] || "";
        const hasPasswordField = /type=["']?password["']?/i.test(formBody);
        if (!hasPasswordField) continue;
        // Extract form action from the full match (formMatch[0])
        const fullForm = formMatch[0];
        const actionMatch = fullForm.match(/action=["']([^"']+)["']/i);
        const formAction = actionMatch ? new URL(actionMatch[1], targetUrl).toString() : targetUrl;
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
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PHASE 3 – ACTIVE PAYLOAD PROBING (safe, non-destructive)
    // ══════════════════════════════════════════════════════════════════════════

    // De-duplicate param URLs and cap total active probes
    const probeTargets = [...new Set(discoveredParamUrls)].slice(0, 8);

    if (probeTargets.length > 0) {
      console.log(`⚡ Running active probes on ${probeTargets.length} parameterised URL(s)...`);

      // Run all probes concurrently per URL for speed
      const probeResults = await Promise.all(
        probeTargets.flatMap((url) => [
          probeReflectedXSS(url),
          probeSQLiError(url),
          probeCommandInjection(url),
          probePathTraversal(url),
        ])
      );

      let xssFound = false;
      let sqliFound = false;
      let cmdInjFound = false;
      let lfiFound = false;
      for (const result of probeResults) {
        if (!result) continue;
        if (result.type === "reflected-xss" && !xssFound) {
          findings.push(result); xssFound = true;
        } else if (result.type === "sql-injection-reflected" && !sqliFound) {
          findings.push(result); sqliFound = true;
        } else if (result.type === "command-injection" && !cmdInjFound) {
          findings.push(result); cmdInjFound = true;
        } else if (result.type === "path-traversal-lfi" && !lfiFound) {
          findings.push(result); lfiFound = true;
        }
      }
    }

    // ── PHASE 3b: FORM-BASED INJECTION PROBING ───────────────────────────────
    // Submit payloads directly to HTML form input fields via POST/GET
    if (discoveredForms.length > 0) {
      console.log(`📝 Running form injection probes on ${discoveredForms.length} form(s) (${discoveredForms.reduce((a, f) => a + f.fields.length, 0)} total fields)...`);

      const formProbeResults = await Promise.all(
        discoveredForms.flatMap((form) => [
          probeFormSQLi(form),
          probeFormXSS(form),
        ])
      );

      let formSqliFound = false;
      let formXssFound = false;
      for (const result of formProbeResults) {
        if (!result) continue;
        if (result.type === "sql-injection-form" && !formSqliFound) {
          findings.push(result); formSqliFound = true;
        } else if (result.type === "reflected-xss-form" && !formXssFound) {
          findings.push(result); formXssFound = true;
        }
      }
    }

    console.log(`🔍 Scan complete: ${findings.length} finding(s) identified (passive + active + form).`);

    // ══════════════════════════════════════════════════════════════════════════
    // ANALYZING PHASE – RAG + Cerebras AI per finding
    // ══════════════════════════════════════════════════════════════════════════

    await prisma.scan.update({ where: { id: scanId }, data: { status: "ANALYZING" } });

    for (const pending of findings) {
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

        await prisma.finding.create({
          data: {
            scanId,
            type: pending.type,
            severity: pending.severity,
            url: pending.url,
            parameter: pending.parameter ?? null,
            evidence: pending.evidence ?? null,
            cvssScore: pending.cvssScore,
            cveId: pending.cveId ?? null,
            title: report.title,
            explanation: report.explanation,
            fixSteps: stepsJson as any,
            codeExample: codeExampleJson as any,
          },
        });
      } catch (err) {
        console.error(`❌ Failed to process finding [${pending.type}]:`, err);
      }
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "COMPLETED", completedAt: new Date() },
    });

    console.log(`✅ Scan [${scanId}] complete — ${findings.length} finding(s) saved.`);
  } catch (scanErr) {
    console.error(`❌ Scan [${scanId}] failed:`, scanErr);
    await prisma.scan
      .update({ where: { id: scanId }, data: { status: "FAILED" } })
      .catch((e) => console.error("Failed to set FAILED status:", e));
  }
}

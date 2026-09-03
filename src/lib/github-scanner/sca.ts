/**
 * github-scanner/sca.ts
 * Software Composition Analysis (SCA) engine.
 * Parses package.json / lockfiles and queries the OSV.dev API for CVEs.
 */

import { PendingFinding, verifiedFinding, CONFIDENCE } from "../scanner/types";
import semver from "semver";
import pLimit from "p-limit";

// ── OSV.dev API types ──────────────────────────────────────────────────────────

interface OsvQuery {
  version: string;
  package: {
    name: string;
    ecosystem: "npm";
  };
}

interface OsvAffected {
  package?: {
    name: string;
    ecosystem: string;
  };
  ranges?: Array<{
    type: string;
    events?: Array<{ introduced?: string; fixed?: string }>;
  }>;
  versions?: string[];
  database_specific?: {
    source?: string;
  };
}

interface OsvVulnerabilityStub {
  id: string;
  modified?: string;
}

interface OsvVulnerabilityDetails {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: OsvAffected[];
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
    github_reviewed?: boolean;
    github_reviewed_at?: string;
  };
}

interface OsvBatchResult {
  results: Array<{ vulns?: OsvVulnerabilityStub[] }>;
}

// ── Package parser ─────────────────────────────────────────────────────────────

interface InstalledPackage {
  name: string;
  version: string;
  isDirect: boolean;
}

function parsePackageLockV2(content: string): InstalledPackage[] {
  try {
    const lock = JSON.parse(content);
    const packages: InstalledPackage[] = [];
    const pkgs = lock.packages as Record<string, { version?: string; dev?: boolean }> | undefined;
    if (!pkgs) return [];

    for (const [path, meta] of Object.entries(pkgs)) {
      if (!path || path === "") continue; // skip root
      const name = path.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
      if (meta.version) {
        packages.push({ name, version: meta.version, isDirect: !path.includes("node_modules/", 14) });
      }
    }
    return packages;
  } catch {
    return [];
  }
}

function parsePackageJson(content: string): InstalledPackage[] {
  try {
    const pkg = JSON.parse(content);
    const packages: InstalledPackage[] = [];
    for (const [name, versionRange] of Object.entries({
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    })) {
      const version = semver.minVersion(String(versionRange))?.version;
      if (version) {
        packages.push({ name, version, isDirect: true });
      }
    }
    return packages;
  } catch {
    return [];
  }
}

export function extractPackages(filePath: string, content: string): InstalledPackage[] {
  if (filePath.endsWith("package-lock.json")) return parsePackageLockV2(content);
  if (filePath.endsWith("package.json") && !filePath.includes("node_modules")) {
    return parsePackageJson(content);
  }
  return [];
}

// ── OSV.dev batch query & detail hydration ────────────────────────────────────

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const OSV_CHUNK_SIZE = 100; // OSV batch limit

// In-memory cache for vulnerability details during scan
const vulnCache = new Map<string, OsvVulnerabilityDetails>();

async function queryOsvBatch(queries: OsvQuery[]): Promise<OsvBatchResult> {
  try {
    const res = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) {
      console.warn(`OSV API returned ${res.status}`);
      return { results: [] };
    }
    return (await res.json()) as OsvBatchResult;
  } catch (err) {
    console.warn("OSV query failed:", err);
    return { results: [] };
  }
}

async function fetchVulnDetails(vulnId: string): Promise<OsvVulnerabilityDetails | null> {
  if (vulnCache.has(vulnId)) {
    return vulnCache.get(vulnId)!;
  }
  try {
    const res = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(vulnId)}`);
    if (!res.ok) return null;
    const data = (await res.json()) as OsvVulnerabilityDetails;
    vulnCache.set(vulnId, data);
    return data;
  } catch {
    return null;
  }
}

function parseOsvSeverity(vuln: OsvVulnerabilityDetails): { cvss: number; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" } {
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev === "CRITICAL") return { cvss: 9.5, severity: "CRITICAL" };
  if (dbSev === "HIGH") return { cvss: 8.0, severity: "HIGH" };
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return { cvss: 5.5, severity: "MEDIUM" };
  if (dbSev === "LOW") return { cvss: 3.0, severity: "LOW" };

  // If numeric CVSS vector present
  if (vuln.severity && vuln.severity.length > 0) {
    for (const s of vuln.severity) {
      if (s.score) {
        const num = parseFloat(s.score);
        if (!isNaN(num) && num > 0 && num <= 10) {
          if (num >= 9.0) return { cvss: num, severity: "CRITICAL" };
          if (num >= 7.0) return { cvss: num, severity: "HIGH" };
          if (num >= 4.0) return { cvss: num, severity: "MEDIUM" };
          return { cvss: num, severity: "LOW" };
        }
      }
    }
  }

  return { cvss: 5.0, severity: "MEDIUM" };
}

function findFixedVersion(affected: OsvAffected[] | undefined, currentVersion: string): string | null {
  if (!affected) return null;
  let fallbackFixed: string | null = null;
  for (const aff of affected) {
    for (const r of (aff.ranges || [])) {
      let introduced = "0.0.0";
      for (const ev of (r.events || [])) {
        if (ev.introduced) introduced = ev.introduced;
        if (ev.fixed) {
          if (!fallbackFixed) fallbackFixed = ev.fixed;
          try {
            const parsedCurrent = semver.coerce(currentVersion)?.version;
            const parsedIntro = semver.coerce(introduced)?.version || "0.0.0";
            const parsedFixed = semver.coerce(ev.fixed)?.version || "999.999.999";
            if (parsedCurrent && semver.gte(parsedCurrent, parsedIntro) && semver.lt(parsedCurrent, parsedFixed)) {
              return ev.fixed;
            }
          } catch {
            // fallback
          }
        }
      }
    }
  }
  return fallbackFixed;
}

// ── Main SCA function ──────────────────────────────────────────────────────────

export async function scanDependenciesForCVEs(
  packages: InstalledPackage[],
  repoUrl: string
): Promise<PendingFinding[]> {
  if (packages.length === 0) return [];

  const findings: PendingFinding[] = [];
  const dedupedPackages = packages.filter(
    (p, i, arr) => arr.findIndex((q) => q.name === p.name && q.version === p.version) === i
  );

  // Split into chunks to stay within OSV batch limit
  for (let i = 0; i < dedupedPackages.length; i += OSV_CHUNK_SIZE) {
    const chunk = dedupedPackages.slice(i, i + OSV_CHUNK_SIZE);
    const queries: OsvQuery[] = chunk.map((p) => ({
      version: p.version,
      package: { name: p.name, ecosystem: "npm" },
    }));

    const batchResult = await queryOsvBatch(queries);

    // Collect all unique vuln IDs in this chunk to hydrate in parallel
    const allVulnIds = new Set<string>();
    for (const res of batchResult.results) {
      for (const v of res.vulns ?? []) {
        if (v.id) allVulnIds.add(v.id);
      }
    }

    const hydrateLimit = pLimit(10);
    await Promise.all(
      Array.from(allVulnIds).map((id) =>
        hydrateLimit(async () => {
          await fetchVulnDetails(id);
        })
      )
    );

    for (let j = 0; j < chunk.length; j++) {
      const pkg = chunk[j];
      const stubs = batchResult.results[j]?.vulns ?? [];

      for (const stub of stubs) {
        const details = vulnCache.get(stub.id) ?? { id: stub.id };
        const { cvss, severity } = parseOsvSeverity(details);
        const cveAlias = details.aliases?.find((a) => a.startsWith("CVE-"));
        const primaryId = cveAlias || details.id;
        const fixedVersion = findFixedVersion(details.affected, pkg.version);
        const advisorySummary = details.summary || `${pkg.name} Security Vulnerability (${primaryId})`;

        const evidence = `[${primaryId}] ${advisorySummary}${fixedVersion ? ` (Fixed in >= ${fixedVersion})` : ""}`;

        findings.push(
          verifiedFinding(
            {
              type: "sca-cve",
              severity,
              url: `${repoUrl}/blob/HEAD/package.json`,
              parameter: `${pkg.name}@${pkg.version}`,
              evidence,
              cvssScore: cvss,
              cveId: primaryId,
            },
            [
              `OSV / GitHub Advisory: ${details.id}${cveAlias ? ` (${cveAlias})` : ""}`,
              `Package: ${pkg.name}@${pkg.version}`,
              `Summary: ${advisorySummary}`,
              fixedVersion ? `Fixed in Version: >= ${fixedVersion}` : `Status: Known Vulnerability`,
              `Advisory: https://github.com/advisories/${details.id}`,
            ],
            CONFIDENCE.DETERMINISTIC
          )
        );
      }
    }
  }

  return findings;
}

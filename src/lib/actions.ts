"use server";

import { prisma } from "./prisma";
import { runVulnerabilityScan } from "./scanner";
import { retrieveContext, searchPastFindings } from "./rag";
import { answerFromContext } from "./openrouter";
import { getGitHubSession } from "./github-session";

/**
 * Initiates a new vulnerability scan.
 * Creates the DB record and fires the scanner engine asynchronously.
 */
export async function createScanAction(url: string, authEmail?: string, authPassword?: string): Promise<string> {
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
    cleanUrl = "https://" + cleanUrl;
  }

  try {
    new URL(cleanUrl);
  } catch {
    throw new Error("Invalid URL format. Please provide a valid address (e.g. example.com).");
  }

  const cleanAuthEmail = authEmail ? String(authEmail).trim() : null;
  const cleanAuthPassword = authPassword ? String(authPassword) : null;

  const scan = await prisma.scan.create({
    data: {
      targetUrl: cleanUrl,
      authEmail: cleanAuthEmail,
      authPassword: cleanAuthPassword,
      status: "PENDING",
    },
  });

  const customAuth = (cleanAuthEmail || cleanAuthPassword) ? {
    email: cleanAuthEmail || undefined,
    password: cleanAuthPassword || undefined,
  } : undefined;

  // Fire-and-forget background scan scheduled on the macro-task queue
  // This prevents Next.js from blocking the Server Action response.
  setTimeout(() => {
    runVulnerabilityScan(scan.id, cleanUrl, customAuth).catch((err) => {
      console.error(`Error executing background scan ${scan.id}:`, err);
    });
  }, 0);

  return scan.id;
}

/**
 * Fetches the user's scan history.
 */
export async function getScansAction() {
  try {
    return await prisma.scan.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        _count: {
          select: { findings: true },
        },
      },
    });
  } catch (error) {
    console.error("Failed to fetch scans:", error);
    return [];
  }
}

/**
 * Fetches a scan and its associated findings.
 * Skips the 'embedding' vector column to avoid Prisma driver issues.
 */
export async function getScanDetailsAction(scanId: string) {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
    });

    if (!scan) return null;

    const findings = await prisma.finding.findMany({
      where: { scanId },
      select: {
        id: true,
        type: true,
        severity: true,
        url: true,
        parameter: true,
        evidence: true,
        cvssScore: true,
        cveId: true,
        title: true,
        explanation: true,
        fixSteps: true,
        codeExample: true,
        createdAt: true,
      },
      orderBy: { cvssScore: "desc" },
    });

    const parsedFindings = findings.map((f) => {
      let parsedCodeExample = null;
      if (f.codeExample) {
        try {
          parsedCodeExample = typeof f.codeExample === "string" ? JSON.parse(f.codeExample) : f.codeExample;
        } catch {
          parsedCodeExample = f.codeExample;
        }
      }

      let parsedFixSteps = null;
      if (f.fixSteps) {
        try {
          parsedFixSteps = typeof f.fixSteps === "string" ? JSON.parse(f.fixSteps) : f.fixSteps;
        } catch {
          parsedFixSteps = f.fixSteps;
        }
      }

      return {
        ...f,
        codeExample: parsedCodeExample,
        fixSteps: parsedFixSteps,
      };
    });

    const scanObj = scan as any;
    let parsedRecon = null;
    if (scanObj.reconData) {
      try {
        parsedRecon = typeof scanObj.reconData === "string" ? JSON.parse(scanObj.reconData) : scanObj.reconData;
      } catch {
        parsedRecon = scanObj.reconData;
      }
    }

    return { ...scan, reconData: parsedRecon, findings: parsedFindings };
  } catch (error) {
    console.error(`Failed to fetch details for scan ${scanId}:`, error);
    return null;
  }
}

/**
 * Deletes a scan and all associated findings.
 */
export async function deleteScanAction(scanId: string): Promise<void> {
  try {
    await prisma.finding.deleteMany({ where: { scanId } });
    await prisma.scan.delete({ where: { id: scanId } });
  } catch (error) {
    console.error(`Failed to delete scan ${scanId}:`, error);
    throw new Error("Failed to delete scan.");
  }
}

/**
 * Queries the RAG system.
 * Hybrid search: OWASP/NVD guidelines + user's past findings.
 * Synthesizes results using Cerebras AI.
 */
export async function askRAGAction(query: string) {
  if (!query || query.trim() === "") {
    throw new Error("Query cannot be empty.");
  }

  try {
    const referenceContext = await retrieveContext(query, 3);
    const relatedFindings = await searchPastFindings(query, 3);

    let findingsContext = "No related past findings found.";
    if (relatedFindings.length > 0) {
      findingsContext = relatedFindings
        .map(
          (f) =>
            `- [${f.severity}] Vulnerability of type '${f.type}' was found on ${f.url} (Title: ${f.title}).`
        )
        .join("\n");
    }

    const combinedContext = `
=== OWASP / NVD / CWE GUIDELINES ===
${referenceContext}

=== PAST FINDINGS IN THIS SYSTEM ===
${findingsContext}
`;

    const answer = await answerFromContext(query, combinedContext);

    return {
      answer,
      sources: {
        guidelines: referenceContext !== "No relevant context found in knowledge base.",
        pastFindings: relatedFindings.map((f) => ({
          title: f.title,
          severity: f.severity,
          url: f.url,
          id: f.id,
        })),
      },
    };
  } catch (error) {
    console.error("RAG chatbot error:", error);
    throw new Error("Failed to process security query. Please check server logs.");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub Integration Actions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the current GitHub session (login + avatar) or null if not connected.
 */
export async function getGitHubSessionAction() {
  const session = await getGitHubSession();
  if (!session) return null;
  return { login: session.login, avatarUrl: session.avatarUrl, name: session.name };
}

/**
 * Fetches the authenticated user's GitHub repositories (up to 100, sorted by push date).
 */
export async function getGitHubReposAction() {
  const session = await getGitHubSession();
  if (!session) throw new Error("Not authenticated with GitHub");

  const res = await fetch(
    "https://api.github.com/user/repos?sort=pushed&per_page=100&affiliation=owner,collaborator",
    {
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: "application/vnd.github+json",
      },
    }
  );

  if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);

  const repos = await res.json();
  return (repos as any[]).map((r) => ({
    id: r.id as number,
    fullName: r.full_name as string,
    name: r.name as string,
    private: r.private as boolean,
    language: (r.language as string | null) ?? null,
    description: (r.description as string | null) ?? null,
    stargazersCount: (r.stargazers_count as number) ?? 0,
    pushedAt: (r.pushed_at as string) ?? null,
    defaultBranch: (r.default_branch as string) ?? "main",
  }));
}

/**
 * Fetches the list of branches for a given repository.
 */
export async function getRepoBranchesAction(repoFullName: string) {
  const session = await getGitHubSession();
  if (!session) throw new Error("Not authenticated with GitHub");

  const res = await fetch(
    `https://api.github.com/repos/${repoFullName}/branches?per_page=100`,
    {
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: "application/vnd.github+json",
      },
    }
  );

  if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);
  const branches = await res.json();
  return (branches as any[]).map((b) => b.name as string);
}

/**
 * Creates a new GitHub scan record and fires the background scan engine.
 */
export async function createGitHubScanAction(
  repoFullName: string,
  branch: string,
  enableLLM: boolean
): Promise<string> {
  const session = await getGitHubSession();
  if (!session) throw new Error("Not authenticated with GitHub");

  const { runGitHubScan } = await import("./github-scanner");

  const scan = await prisma.gitHubScan.create({
    data: {
      repoFullName,
      branch,
      enableLLM,
      status: "PENDING",
    },
  });

  setTimeout(() => {
    runGitHubScan(scan.id, repoFullName, branch, session.accessToken, enableLLM).catch(
      (err) => console.error(`GitHub scan ${scan.id} error:`, err)
    );
  }, 0);

  return scan.id;
}

/**
 * Fetches the list of all GitHub scans with finding counts.
 */
export async function getGitHubScansAction() {
  return prisma.gitHubScan.findMany({
    orderBy: { createdAt: "desc" },
    include: { _count: { select: { findings: true } } },
  });
}

/**
 * Fetches a single GitHub scan with all its findings.
 */
export async function getGitHubScanDetailsAction(scanId: string) {
  const scan = await prisma.gitHubScan.findUnique({ where: { id: scanId } });
  if (!scan) return null;

  const findings = await prisma.finding.findMany({
    where: { gitHubScanId: scanId },
    select: {
      id: true,
      type: true,
      severity: true,
      url: true,
      parameter: true,
      evidence: true,
      cvssScore: true,
      cveId: true,
      title: true,
      explanation: true,
      fixSteps: true,
      codeExample: true,
      confidence: true,
      isVerified: true,
      createdAt: true,
    },
    orderBy: { cvssScore: "desc" },
  });

  const parsedFindings = findings.map((f) => {
    let parsedCodeExample = null;
    let parsedFixSteps = null;
    if (f.codeExample) {
      try { parsedCodeExample = typeof f.codeExample === "string" ? JSON.parse(f.codeExample) : f.codeExample; } catch { parsedCodeExample = f.codeExample; }
    }
    if (f.fixSteps) {
      try { parsedFixSteps = typeof f.fixSteps === "string" ? JSON.parse(f.fixSteps) : f.fixSteps; } catch { parsedFixSteps = f.fixSteps; }
    }
    return { ...f, codeExample: parsedCodeExample, fixSteps: parsedFixSteps };
  });

  return { ...scan, findings: parsedFindings };
}


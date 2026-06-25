"use server";

import { prisma } from "./prisma";
import { runVulnerabilityScan } from "./scanner";
import { retrieveContext, searchPastFindings } from "./rag";
import { answerFromContext } from "./cerebras";

/**
 * Initiates a new vulnerability scan.
 * Creates the DB record and fires the scanner engine asynchronously.
 */
export async function createScanAction(url: string): Promise<string> {
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
    cleanUrl = "https://" + cleanUrl;
  }

  try {
    new URL(cleanUrl);
  } catch {
    throw new Error("Invalid URL format. Please provide a valid address (e.g. example.com).");
  }

  const scan = await prisma.scan.create({
    data: {
      targetUrl: cleanUrl,
      status: "PENDING",
    },
  });

  // Fire-and-forget background scan scheduled on the macro-task queue
  // This prevents Next.js from blocking the Server Action response.
  setTimeout(() => {
    runVulnerabilityScan(scan.id, cleanUrl).catch((err) => {
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

    return { ...scan, findings: parsedFindings };
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

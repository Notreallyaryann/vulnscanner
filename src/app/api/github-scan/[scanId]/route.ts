import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getGitHubSession } from "@/lib/github-session";

export const dynamic = "force-dynamic";

/**
 * GET /api/github-scan/[scanId]
 * Returns scan status + all associated findings.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const session = await getGitHubSession();
  if (!session) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { scanId } = await params;

  const scan = await prisma.gitHubScan.findUnique({ where: { id: scanId } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

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
    if (f.codeExample) {
      try {
        parsedCodeExample = typeof f.codeExample === "string"
          ? JSON.parse(f.codeExample)
          : f.codeExample;
      } catch {
        parsedCodeExample = f.codeExample;
      }
    }
    return { ...f, codeExample: parsedCodeExample };
  });

  return NextResponse.json({ ...scan, findings: parsedFindings });
}

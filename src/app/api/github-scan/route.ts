import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getGitHubSession } from "@/lib/github-session";
import { runGitHubScan } from "@/lib/github-scanner";

export const dynamic = "force-dynamic";

/**
 * POST /api/github-scan
 * Creates a new GitHub repo scan and fires it in the background.
 */
export async function POST(req: NextRequest) {
  const session = await getGitHubSession();
  if (!session) {
    return NextResponse.json({ error: "Not authenticated with GitHub" }, { status: 401 });
  }

  try {
    const { repoFullName, branch = "main", enableLLM = true } = await req.json();

    if (!repoFullName || typeof repoFullName !== "string") {
      return NextResponse.json({ error: "repoFullName is required" }, { status: 400 });
    }

    const scan = await prisma.gitHubScan.create({
      data: {
        repoFullName,
        branch: String(branch),
        enableLLM: Boolean(enableLLM),
        status: "PENDING",
      },
    });

    // Fire scan in background — don't await
    setTimeout(() => {
      runGitHubScan(
        scan.id,
        repoFullName,
        String(branch),
        session.accessToken,
        Boolean(enableLLM)
      ).catch((err) => {
        console.error(`GitHub scan ${scan.id} background error:`, err);
      });
    }, 0);

    return NextResponse.json({ scanId: scan.id });
  } catch (err: any) {
    console.error("GitHub scan creation failed:", err);
    return NextResponse.json({ error: err.message ?? "Internal Server Error" }, { status: 500 });
  }
}

/**
 * GET /api/github-scan
 * Returns a list of all GitHub scans (most recent first).
 */
export async function GET() {
  const session = await getGitHubSession();
  if (!session) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const scans = await prisma.gitHubScan.findMany({
    orderBy: { createdAt: "desc" },
    include: { _count: { select: { findings: true } } },
  });

  return NextResponse.json(scans);
}

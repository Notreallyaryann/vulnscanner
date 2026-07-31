import { NextRequest, NextResponse } from "next/server";
import { stopScan, isScanActive } from "@/lib/scan-controller";
import { prisma } from "@/lib/prisma";
import { emitLog } from "@/lib/scan-logger";

export const dynamic = "force-dynamic";

/**
 * POST /api/scan/[scanId]/stop
 *
 * Signals a running scan to cancel. The scanner checks the abort signal
 * at phase boundaries and will exit its main loop on the next iteration.
 * The scan status is updated to FAILED (cancelled) in the scanner itself.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const { scanId } = await params;

  // Verify the scan exists
  const scan = await prisma.scan.findUnique({ where: { id: scanId } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Already in a terminal state — nothing to stop
  if (scan.status === "COMPLETED" || scan.status === "FAILED") {
    return NextResponse.json(
      { error: "Scan has already finished and cannot be stopped." },
      { status: 409 }
    );
  }

  const isActive = isScanActive(scanId);

  if (!isActive) {
    // The scan may have just completed between our check above and here.
    // Update status to FAILED to ensure consistency.
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "FAILED", completedAt: new Date() },
    });
    return NextResponse.json(
      { error: "Scan is not currently active." },
      { status: 404 }
    );
  }

  // Send the abort signal — the scanner will pick it up on the next phase check
  stopScan(scanId);
  emitLog(scanId, "🛑  Scan stop requested by user — finishing current probe and exiting...");

  return NextResponse.json({ success: true, message: "Scan stop signal sent successfully." });
}

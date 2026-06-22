/**
 * GET /api/scan-logs/[scanId]
 * Server-Sent Events (SSE) endpoint — streams real-time scan log lines to the browser.
 *
 * The client opens an EventSource connection. The server:
 *  1. Immediately flushes all buffered log lines (catch-up for late joins / reconnects).
 *  2. Pushes new lines as they are emitted by the scanner engine.
 *  3. Sends a final "done" event when the scan finishes and closes the stream.
 */

import { NextRequest } from "next/server";
import { getBufferedLogs, subscribe } from "@/lib/scan-logger";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";
export const runtime  = "nodejs"; // EventEmitter requires Node runtime

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const { scanId } = await params;

  const encoder = new TextEncoder();

  /** Format a single SSE data line */
  const sseMsg = (event: string, data: string) =>
    `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

  const stream = new ReadableStream({
    async start(controller) {
      const enqueue = (text: string) => {
        try { controller.enqueue(encoder.encode(text)); } catch { /* closed */ }
      };

      // 1. Send buffered history so late-joining clients see past logs
      const buffered = getBufferedLogs(scanId);
      for (const entry of buffered) {
        enqueue(sseMsg("log", entry.msg));
      }

      // 2. Check if scan is already completed (no live events needed)
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        select: { status: true },
      }).catch(() => null);

      if (scan?.status === "COMPLETED" || scan?.status === "FAILED") {
        enqueue(sseMsg("done", scan.status));
        controller.close();
        return;
      }

      // 3. Subscribe to live log events
      let isClosed = false;
      const unsubscribe = subscribe(scanId, (entry) => {
        if (isClosed) return;
        enqueue(sseMsg("log", entry.msg));
      });

      // 4. Poll DB every 2 s to detect scan completion and send "done" event
      const poll = setInterval(async () => {
        try {
          const s = await prisma.scan.findUnique({
            where: { id: scanId },
            select: { status: true },
          });
          if (s?.status === "COMPLETED" || s?.status === "FAILED") {
            enqueue(sseMsg("done", s.status));
            cleanup();
          }
        } catch { /* ignore */ }
      }, 2000);

      const cleanup = () => {
        if (isClosed) return;
        isClosed = true;
        clearInterval(poll);
        unsubscribe();
        try { controller.close(); } catch { /* already closed */ }
      };

      // Clean up if the client disconnects
      _req.signal.addEventListener("abort", cleanup);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type":  "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection:      "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

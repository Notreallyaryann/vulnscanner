

export interface ScanLogEntry {
  ts: number;   // Unix ms
  msg: string;
}

const MAX_LINES = 1000;

// Buffer: scanId → array of log entries
const logBuffer = new Map<string, ScanLogEntry[]>();

// Subscribers: scanId → set of callback functions
type Subscriber = (entry: ScanLogEntry) => void;
const subscribers = new Map<string, Set<Subscriber>>();

/** Called by scanner.ts to push a new log line */
export function emitLog(scanId: string, msg: string): void {
  const entry: ScanLogEntry = { ts: Date.now(), msg };

  // Append to buffer
  if (!logBuffer.has(scanId)) logBuffer.set(scanId, []);
  const buf = logBuffer.get(scanId)!;
  buf.push(entry);
  if (buf.length > MAX_LINES) buf.shift();

  // Notify all live subscribers
  subscribers.get(scanId)?.forEach((cb) => cb(entry));
}

/** Returns a snapshot of all buffered lines for a scan (for reconnects) */
export function getBufferedLogs(scanId: string): ScanLogEntry[] {
  return logBuffer.get(scanId) ?? [];
}

/** Subscribe to live log events for a scan. Returns an unsubscribe function. */
export function subscribe(scanId: string, cb: Subscriber): () => void {
  if (!subscribers.has(scanId)) subscribers.set(scanId, new Set());
  subscribers.get(scanId)!.add(cb);
  return () => {
    subscribers.get(scanId)?.delete(cb);
    if (subscribers.get(scanId)?.size === 0) subscribers.delete(scanId);
  };
}

/** Called after scan completes to free memory */
export function cleanupScan(scanId: string): void {
  // Give clients 30 s to receive the tail before cleaning up
  setTimeout(() => {
    logBuffer.delete(scanId);
    subscribers.delete(scanId);
  }, 30_000);
}

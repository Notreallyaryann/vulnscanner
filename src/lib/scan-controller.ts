/**
 * scan-controller.ts
 * Per-scan AbortController registry.
 *
 * Allows the stop-scan API route to signal a running scan to cancel
 * without sharing global mutable state between concurrent scans.
 */

const scanControllers = new Map<string, AbortController>();

/**
 * Register a new AbortController for the given scan.
 * Called at the start of runVulnerabilityScan.
 * Returns the controller so the caller can read its signal.
 */
export function registerScanController(scanId: string): AbortController {
  const controller = new AbortController();
  scanControllers.set(scanId, controller);
  return controller;
}

/**
 * Signal a running scan to stop.
 * Returns true if the scan was found and the abort signal sent,
 * false if no active scan with that ID exists.
 */
export function stopScan(scanId: string): boolean {
  const controller = scanControllers.get(scanId);
  if (!controller || controller.signal.aborted) return false;
  controller.abort("scan_cancelled");
  return true;
}

/**
 * Check whether a scan is still actively running (controller registered
 * and not yet aborted).
 */
export function isScanActive(scanId: string): boolean {
  const controller = scanControllers.get(scanId);
  return !!controller && !controller.signal.aborted;
}

/**
 * Remove the controller entry once the scan finishes or is cleaned up.
 * Called at the end of runVulnerabilityScan (success or failure).
 */
export function cleanupScanController(scanId: string): void {
  scanControllers.delete(scanId);
}

import { buildPayloadTarget, PayloadFormat } from "../payloads";
import { ScannerFinding } from "./sqli";

const XSS_PAYLOADS = [
  "<vulnscanXSStag>",
  "<script>/*vulnscan*/</script>",
  `"><img src=x onerror=alert('vulnscan')>`,
  `" onmouseover="alert('vulnscan')"`,
  `';alert('vulnscan');//`,
  `</script><script>alert('vulnscan')</script>`,
  `<svg onload=alert('vulnscan')>`,
  `javascript:alert('vulnscan')`,
  `\${alert('vulnscan')}`,
];

export async function probeReflectedXSSMultiFormat(
  targetUrl: string,
  paramName: string,
  format: PayloadFormat = "URL_PARAM",
  fields: string[] = [paramName],
  authedFetch: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<ScannerFinding | null> {
  for (const payload of XSS_PAYLOADS) {
    try {
      const { fetchUrl, options } = buildPayloadTarget(targetUrl, format === "URL_PARAM" ? "GET" : "POST", paramName, payload, format, fields);
      const resp = await authedFetch(fetchUrl, options);
      if (!resp) continue;
      const text = await resp.text();

      const isRawReflected = text.includes(payload) && !text.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      if (isRawReflected) {
        return {
          type: "xss",
          severity: "HIGH",
          url: targetUrl,
          parameter: paramName,
          evidence: `Unescaped XSS payload '${payload}' reflected in server response for parameter '${paramName}' via ${format}.`,
          cvssScore: 7.2,
          cveId: "CWE-79",
          confidence: 0.90,
          validationSteps: [
            `Injected payload '${payload}' into parameter '${paramName}' via ${format}`,
            `Verified unescaped execution context in HTTP response body`,
          ],
          isVerified: true,
        };
      }
    } catch {}
  }
  return null;
}

/**
 * Analyzes DOM XSS sink execution logs captured by Playwright during JS hydration.
 */
export function analyzeDomXssEvents(
  url: string,
  events?: { sink: string; payloadSnippet: string }[]
): ScannerFinding | null {
  if (!events || events.length === 0) return null;
  const evt = events[0];

  return {
    type: "dom-xss",
    severity: "HIGH",
    url,
    evidence: `Client-side DOM XSS sink execution detected in browser context (${evt.sink}): "${evt.payloadSnippet}"`,
    cvssScore: 7.5,
    cveId: "CWE-79",
    confidence: 0.95,
    validationSteps: [
      `Headless browser evaluated client-side scripts on page ${url}`,
      `Captured untrusted input execution inside JavaScript sink '${evt.sink}'`,
    ],
    isVerified: true,
  };
}

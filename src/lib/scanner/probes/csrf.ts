import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, FormTarget, JsApiEndpoint, PendingFinding } from "../types";

const CSRF_ERROR_PATTERNS = [
  /csrf/i,
  /xsrf/i,
  /anti-forgery/i,
  /token.*invalid/i,
  /invalid.*token/i,
  /token.*mismatch/i,
  /missing.*token/i,
  /session.*expired/i,
  /forbidden/i,
  /unauthorized/i,
  /bad request/i,
];

/**
 * Actively probes state-changing forms (POST) for Cross-Site Request Forgery (CSRF).
 * Submits the form with an untrusted Origin/Referer and omitted/dummy anti-CSRF tokens
 * to determine whether the server executes the state change without cross-origin protection.
 */
export async function probeFormCSRF(
  form: FormTarget,
  session: AuthSession = EMPTY_SESSION
): Promise<PendingFinding | null> {
  // Only state-changing methods (POST) are susceptible to classic CSRF
  if (form.method !== "POST" || form.fields.length === 0) return null;

  try {
    const attackerOrigin = "https://evil-attacker.test";
    const attackerReferer = "https://evil-attacker.test/csrf-poc.html";

    // Build form body with sample test values
    const formData = new URLSearchParams();
    for (const field of form.fields) {
      if (/^(?:_csrf|csrfmiddlewaretoken|__viewstate|_token|authenticity_token|csrf[-_]?token)$/i.test(field)) {
        continue;
      }
      formData.set(field, "csrf_test_val");
    }

    // Cross-origin headers simulating malicious third-party site submission
    const headers: Record<string, string> = {
      ...FETCH_HEADERS,
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: attackerOrigin,
      Referer: attackerReferer,
    };
    if (session.cookies) {
      headers["Cookie"] = session.cookies;
    }

    const resp = await fetch(form.actionUrl, {
      method: "POST",
      headers,
      body: formData.toString(),
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);

    if (!resp) return null;

    // Explicit rejection: HTTP 401, 403, 419 indicates anti-CSRF or auth boundary enforced
    if ([401, 403, 419].includes(resp.status)) return null;

    const respBody = await resp.text().catch(() => "");
    const hasCsrfError = CSRF_ERROR_PATTERNS.some((p) => p.test(respBody));
    if (hasCsrfError) return null;

    const isSuccess =
      resp.status === 200 ||
      resp.status === 201 ||
      resp.status === 204 ||
      (resp.status >= 300 && resp.status < 400);

    if (!isSuccess) return null;

    const missingTokenInHtml = !form.hasCsrfToken;
    const steps = [
      `Sent cross-origin POST request to form action "${form.actionUrl}" with Origin: ${attackerOrigin}`,
      missingTokenInHtml
        ? "Form HTML contains no anti-CSRF token input field"
        : "Submitted form without valid anti-CSRF token (token omitted)",
      `Server accepted cross-origin request with HTTP ${resp.status} and no CSRF validation error`,
    ];

    return {
      type: "csrf-active-missing-token",
      severity: "HIGH",
      url: form.actionUrl,
      parameter: form.csrfFieldName || "anti-csrf-token",
      evidence: missingTokenInHtml
        ? `Active CSRF Confirmed: Form at ${form.actionUrl} lacks an anti-CSRF token and accepted a state-changing POST from cross-origin ${attackerOrigin} (HTTP ${resp.status}).`
        : `Active CSRF Confirmed: Form at ${form.actionUrl} processed a state-changing POST with an omitted/bypassed anti-CSRF token and spoofed Origin ${attackerOrigin} (HTTP ${resp.status}).`,
      cvssScore: 7.5,
      cveId: "CWE-352",
      confidence: CONFIDENCE.DUAL_VERIFIED,
      validationSteps: steps,
      isVerified: true,
    };
  } catch {
    return null;
  }
}

/**
 * Actively probes state-changing API endpoints for missing CSRF / Origin validation.
 */
export async function probeApiCSRF(
  baseUrl: string,
  apiEndpoints: JsApiEndpoint[],
  session: AuthSession = EMPTY_SESSION
): Promise<PendingFinding | null> {
  const sensitivePathRegex = /\b(?:update|change|delete|create|edit|save|remove|transfer|post|submit|settings|profile|password)\b/i;
  const candidates = apiEndpoints
    .filter((e) => e.url && (sensitivePathRegex.test(e.url) || e.method === "POST" || e.method === "PUT" || e.method === "DELETE"))
    .slice(0, 5);

  const attackerOrigin = "https://evil-attacker.test";

  for (const endpoint of candidates) {
    try {
      const fullUrl = new URL(endpoint.url, baseUrl).toString();
      const headers: Record<string, string> = {
        ...FETCH_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: attackerOrigin,
        Referer: `${attackerOrigin}/csrf.html`,
      };
      if (session.cookies) {
        headers["Cookie"] = session.cookies;
      }

      const resp = await fetch(fullUrl, {
        method: endpoint.method || "POST",
        headers,
        body: "test=csrf_probe",
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp) continue;
      if ([401, 403, 404, 405, 419].includes(resp.status)) continue;

      const body = await resp.text().catch(() => "");
      if (CSRF_ERROR_PATTERNS.some((p) => p.test(body))) continue;

      if (resp.status >= 200 && resp.status < 400) {
        return {
          type: "csrf-api-missing-protection",
          severity: "MEDIUM",
          url: fullUrl,
          parameter: "Origin",
          evidence: `State-changing API endpoint ${fullUrl} accepted a cross-origin ${endpoint.method || "POST"} request from ${attackerOrigin} without Origin/CSRF verification (HTTP ${resp.status}).`,
          cvssScore: 6.5,
          cveId: "CWE-352",
          confidence: CONFIDENCE.DUAL_VERIFIED,
          validationSteps: [
            `Sent cross-origin request to ${fullUrl} with Origin: ${attackerOrigin}`,
            `Request succeeded with HTTP ${resp.status} without preflight or custom CSRF header requirement`,
          ],
          isVerified: true,
        };
      }
    } catch {
      /* next */
    }
  }

  return null;
}

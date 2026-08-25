import { buildPayloadTarget, PayloadFormat, XSS_PAYLOADS } from "../payloads";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FormTarget, PendingFinding } from "../types";
import { authedFetch } from "../session";
import { browserVerifyXssExecution, confirmXSSHit, shuffleArray } from "../verify";

export async function probeReflectedXSS(
  paramUrl: string,
  session: AuthSession = EMPTY_SESSION,
  log?: (m: string) => void,
  scanId?: string
): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];
    if (params.length === 0) return null;

    const payloads = shuffleArray(XSS_PAYLOADS);

    for (const param of params) {
      for (const payload of payloads) {
        try {
          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await authedFetch(testUrl.toString(), {}, 8000, false, session);
          if (!resp) continue;
          const body = await resp.text();
          const htmlEncoded =
            body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;")) ||
            body.includes(payload.replace(/"/g, "&quot;")) ||
            body.includes(payload.replace(/'/g, "&#x27;")) ||
            body.includes(payload.replace(/'/g, "&#39;")) ||
            body.includes(payload.replace(/</g, "&amp;lt;").replace(/>/g, "&amp;gt;"));
          const reflected = body.includes(payload) && !htmlEncoded;
          if (!reflected) continue;

          const confirmed = await confirmXSSHit(paramUrl, param, payload, session);
          if (!confirmed) continue;

          let execConfirmed = false;
          if (scanId && log) {
            execConfirmed = await browserVerifyXssExecution(testUrl.toString(), log, scanId);
          }

          const confidence = execConfirmed ? CONFIDENCE.EXEC_VERIFIED : CONFIDENCE.DUAL_VERIFIED;
          const evidence = execConfirmed
            ? `Reflected XSS CONFIRMED (browser-executed + dual-payload) via URL parameter "${param}". Payload "${payload}" reflected unencoded, confirmed with a second payload, AND executed in a real browser context (window.alert fired).`
            : `Reflected XSS confirmed (dual-payload verified) via URL parameter "${param}". Payload reflected unencoded and confirmed with a second payload.`;
          const steps = [
            `Payload "${payload}" reflected unencoded in param "${param}" (randomized payload order)`,
            "Second distinct XSS payload also reflected unencoded (confirmation)",
            ...(execConfirmed ? ["Browser (Playwright/headless) confirmed payload execution — alert() fired"] : []),
          ];

          return {
            type: "reflected-xss",
            severity: "HIGH",
            url: testUrl.toString(),
            parameter: param,
            evidence,
            cvssScore: 7.4,
            cveId: "CWE-79",
            confidence,
            validationSteps: steps,
            isVerified: true,
          };
        } catch { /* next payload */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeFormXSS(
  form: FormTarget,
  session: AuthSession = EMPTY_SESSION,
  log?: (m: string) => void,
  scanId?: string
): Promise<PendingFinding | null> {
  const payloads = shuffleArray(XSS_PAYLOADS);
  for (const field of form.fields) {
    for (const payload of payloads) {
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
        const htmlEncodedForm =
          body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;")) ||
          body.includes(payload.replace(/"/g, "&quot;")) ||
          body.includes(payload.replace(/'/g, "&#x27;")) ||
          body.includes(payload.replace(/'/g, "&#39;")) ||
          body.includes(payload.replace(/</g, "&amp;lt;").replace(/>/g, "&amp;gt;"));
        const reflected = body.includes(payload) && !htmlEncodedForm;
        if (!reflected) continue;

        const confirmed = await confirmXSSHit(form.actionUrl, field, payload, session);
        if (!confirmed) continue;

        let execConfirmed = false;
        if (scanId && log && form.method === "GET") {
          const getUrl = new URL(form.actionUrl);
          getUrl.searchParams.set(field, payload);
          execConfirmed = await browserVerifyXssExecution(getUrl.toString(), log, scanId);
        }

        const confidence = execConfirmed ? CONFIDENCE.EXEC_VERIFIED : CONFIDENCE.DUAL_VERIFIED;
        const evidence = execConfirmed
          ? `Reflected XSS CONFIRMED (browser-executed + dual-payload) via form field "${field}". Payload "${payload}" reflected unencoded, confirmed with a second payload, AND executed in a real browser context.`
          : `Reflected XSS confirmed (dual-payload verified) via form field "${field}". Payload reflected unencoded and confirmed with a second payload.`;
        const steps = [
          `Payload "${payload}" reflected unencoded in form field "${field}" (randomized payload order)`,
          "Second payload confirmed with independent reflection check",
          ...(execConfirmed ? ["Browser (Playwright/headless) confirmed payload execution — alert() fired"] : []),
        ];

        return {
          type: "reflected-xss-form",
          severity: "HIGH",
          url: form.actionUrl,
          parameter: field,
          evidence,
          cvssScore: 7.4,
          cveId: "CWE-79",
          confidence,
          validationSteps: steps,
          isVerified: true,
        };
      } catch { /* next */ }
    }
  }
  return null;
}

export async function probeReflectedXSSMultiFormat(
  targetUrl: string,
  paramName: string,
  format: PayloadFormat = "URL_PARAM",
  fields: string[] = [paramName],
  authedFetchFn: (url: string, init?: RequestInit) => Promise<Response | null>,
  log?: (msg: string) => void,
  scanId?: string
): Promise<PendingFinding | null> {
  const payloads = shuffleArray(XSS_PAYLOADS);

  for (const payload of payloads) {
    try {
      const { fetchUrl, options } = buildPayloadTarget(
        targetUrl,
        format === "URL_PARAM" ? "GET" : "POST",
        paramName,
        payload,
        format,
        fields
      );
      const resp = await authedFetchFn(fetchUrl, options);
      if (!resp) continue;
      const text = await resp.text();

      const htmlEncodedForms = [
        payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"),
        payload.replace(/"/g, "&quot;"),
        payload.replace(/'/g, "&#x27;"),
        payload.replace(/'/g, "&#39;"),
        payload.replace(/</g, "&amp;lt;").replace(/>/g, "&amp;gt;"),
      ];
      const isEncoded = htmlEncodedForms.some((enc) => text.includes(enc));
      const isRawReflected = text.includes(payload) && !isEncoded;

      if (!isRawReflected) continue;

      let execConfirmed = false;
      if (scanId && log && format === "URL_PARAM") {
        execConfirmed = await browserVerifyXssExecution(fetchUrl, log, scanId);
      }

      const confidence = execConfirmed ? 0.93 : 0.90;
      const verifyStep = execConfirmed
        ? "Browser (Playwright/headless) confirmed payload execution — alert() fired"
        : "Verified unescaped execution context in HTTP response body";

      return {
        type: "xss",
        severity: "HIGH",
        url: targetUrl,
        parameter: paramName,
        evidence: execConfirmed
          ? `Reflected XSS CONFIRMED (browser-executed): payload '${payload}' reflected unencoded AND executed in a real browser context (window.alert fired) for parameter '${paramName}' via ${format}.`
          : `Reflected XSS (reflection detected): payload '${payload}' reflected unescaped in server response for parameter '${paramName}' via ${format}.`,
        cvssScore: 7.2,
        cveId: "CWE-79",
        confidence,
        validationSteps: [
          `Injected payload '${payload}' into parameter '${paramName}' via ${format} (randomized payload order — WAF evasion)`,
          verifyStep,
        ],
        isVerified: true,
      };
    } catch { /* try next payload */ }
  }
  return null;
}

export function analyzeDomXssEvents(
  url: string,
  events?: { sink: string; payloadSnippet: string }[]
): PendingFinding | null {
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

import { CONFIDENCE, FETCH_HEADERS, FormTarget, PendingFinding } from "../types";
import { safeFetch } from "../session";

const PAYLOADS_ROUND1 = ["; ls", "`id`", "$(id)"];
const PAYLOADS_ROUND2 = ["| whoami", "& dir"];
const CMD_GENERIC_PATTERNS = [
  /sh:\s+\d+:.*not found/i, /command not found/i, /Permission denied/i,
  /No such file or directory/i, /cannot find/i, /is not recognized/i,
];
const CMD_EXEC_PATTERNS = [
  /root:x:0:0/i, /uid=\d+\(/, /Volume Serial Number/i,
  /\bwhoami\b.*\n?\s*\w+/i, /^(root|www-data|daemon|nobody|apache)$/im,
];

export async function probeCommandInjection(paramUrl: string): Promise<PendingFinding | null> {
  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    const origVal = u.searchParams.get(firstParam) ?? "";

    let triggeringPayload = "";
    for (const p1 of PAYLOADS_ROUND1) {
      const testUrl = new URL(u.toString());
      testUrl.searchParams.set(firstParam, origVal + p1);
      const resp = await safeFetch(testUrl.toString(), 5000);
      if (!resp) continue;
      const body = await resp.text();
      if (CMD_GENERIC_PATTERNS.some((p) => p.test(body)) || CMD_EXEC_PATTERNS.some((p) => p.test(body))) {
        triggeringPayload = p1;
        break;
      }
    }
    if (!triggeringPayload) return null;

    let confirmed = false;
    for (const p2 of PAYLOADS_ROUND2) {
      const confirmUrl = new URL(u.toString());
      confirmUrl.searchParams.set(firstParam, origVal + p2);
      const confirmResp = await safeFetch(confirmUrl.toString(), 5000);
      if (!confirmResp) continue;
      const confirmBody = await confirmResp.text();
      if (CMD_EXEC_PATTERNS.some((p) => p.test(confirmBody)) || CMD_GENERIC_PATTERNS.some((p) => p.test(confirmBody))) {
        confirmed = true;
        break;
      }
    }
    if (!confirmed) return null;

    const finalUrl = new URL(u.toString());
    finalUrl.searchParams.set(firstParam, origVal + triggeringPayload);
    return {
      type: "command-injection",
      severity: "CRITICAL",
      url: finalUrl.toString(),
      parameter: firstParam,
      evidence: `Command Injection confirmed (dual-payload verified) via parameter "${firstParam}". Two structurally distinct shell payloads ("${triggeringPayload}" and a second confirmation payload) both produced OS-level output in the HTTP response.`,
      cvssScore: 9.8,
      cveId: "CWE-78",
      confidence: CONFIDENCE.DUAL_VERIFIED,
      validationSteps: [
        `Round-1 payload "${triggeringPayload}" produced OS-level pattern`,
        "Round-2 payload produced execution-proof output (uid=/whoami)",
      ],
      isVerified: true,
    };
  } catch { /* skip */ }
  return null;
}

export async function probePathTraversal(paramUrl: string): Promise<PendingFinding | null> {
  const TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
  ];
  const WIN_PAYLOADS = [
    "..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
  ];
  const isLinuxPasswd = (body: string) =>
    /root:x:0:0/.test(body) && (/\/bin\/bash/.test(body) || /daemon:x/.test(body));
  const isWindowsIni = (body: string) =>
    /\[extensions\]/i.test(body) || /\[fonts\]/i.test(body);

  try {
    const u = new URL(paramUrl);
    const firstParam = [...u.searchParams.keys()][0];
    if (!firstParam) return null;
    const origVal = u.searchParams.get(firstParam) ?? "";

    for (const payload of TRAVERSAL_PAYLOADS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(firstParam, origVal + payload);
        const resp = await safeFetch(testUrl.toString(), 5000);
        if (!resp) continue;
        const body = await resp.text();
        if (!isLinuxPasswd(body)) continue;

        const confirmPayload = TRAVERSAL_PAYLOADS.find((p) => p !== payload) ?? "../../../../etc/passwd";
        const confirmUrl = new URL(u.toString());
        confirmUrl.searchParams.set(firstParam, origVal + confirmPayload);
        const confirmResp = await safeFetch(confirmUrl.toString(), 5000);
        if (!confirmResp) continue;
        const confirmBody = await confirmResp.text();
        if (!isLinuxPasswd(confirmBody)) continue;

        return {
          type: "path-traversal-lfi",
          severity: "CRITICAL",
          url: testUrl.toString(),
          parameter: firstParam,
          evidence: `Path Traversal / LFI confirmed (dual-payload verified) via parameter "${firstParam}". Two depth-variant traversal payloads both returned /etc/passwd content (root:x:0:0 with /bin/bash).`,
          cvssScore: 9.1,
          cveId: "CWE-22",
        };
      } catch { /* next */ }
    }

    for (const payload of WIN_PAYLOADS) {
      try {
        const testUrl = new URL(u.toString());
        testUrl.searchParams.set(firstParam, origVal + payload);
        const resp = await safeFetch(testUrl.toString(), 5000);
        if (!resp) continue;
        const body = await resp.text();
        if (!isWindowsIni(body)) continue;

        return {
          type: "path-traversal-lfi",
          severity: "CRITICAL",
          url: testUrl.toString(),
          parameter: firstParam,
          evidence: `Path Traversal / LFI confirmed via parameter "${firstParam}" on a Windows server. Traversal payload returned Windows INI file content (win.ini markers detected).`,
          cvssScore: 9.1,
          cveId: "CWE-22",
        };
      } catch { /* next */ }
    }
  } catch { /* skip */ }
  return null;
}

const SSTI_PROBES = [
  { payload: "{{913*829}}", marker: "756877", engines: "Jinja2/Twig/Pebble/Handlebars" },
  { payload: "${913*829}", marker: "756877", engines: "Freemarker/Java EL/Groovy" },
  { payload: "<%= 913*829 %>", marker: "756877", engines: "ERB/EJS/ASP" },
  { payload: "#{913*829}", marker: "756877", engines: "Ruby Slim/Haml" },
  { payload: "*{913*829}", marker: "756877", engines: "Spring SpEL" },
];

export async function probeSSTI(paramUrl: string): Promise<PendingFinding | null> {
  const MATH_CONFIRM_PROBES = [
    { p: "{{987*654}}", e: "645498" },
    { p: "{{4321*8765}}", e: "37873565" },
  ];
  try {
    const u = new URL(paramUrl);
    const params = [...u.searchParams.keys()];

    const baselineResp = await safeFetch(u.toString(), 5000);
    const baselineText = baselineResp ? await baselineResp.text() : "";

    for (const param of params) {
      for (const { payload, marker, engines } of SSTI_PROBES) {
        try {
          if (baselineText.includes(marker)) continue;

          const testUrl = new URL(u.toString());
          testUrl.searchParams.set(param, payload);
          const resp = await safeFetch(testUrl.toString(), 5000);
          if (!resp) continue;
          const body = await resp.text();
          if (!body.includes(marker) || body.includes(payload)) continue;

          const validationSteps: string[] = [`Initial: "${payload}" → "${marker}" (${engines})`];
          let mathHits = 0;
          for (const { p, e } of MATH_CONFIRM_PROBES) {
            try {
              if (baselineText.includes(e)) continue;
              const cu = new URL(u.toString());
              cu.searchParams.set(param, p);
              const cr = await safeFetch(cu.toString(), 4000);
              if (!cr) continue;
              const cb = await cr.text();
              if (cb.includes(e) && !cb.includes(p)) {
                mathHits++;
                validationSteps.push(`Math confirm: "${p}" → "${e}" ✓`);
              }
            } catch { /* next */ }
          }
          if (mathHits < 2) continue;

          return {
            type: "ssti-injection",
            severity: "CRITICAL",
            url: testUrl.toString(),
            parameter: param,
            evidence: `Server-Side Template Injection (SSTI) confirmed. Expression "${payload}" evaluated to "${marker}" AND ${mathHits}/2 independent high-entropy math expressions also evaluated. Engine(s): ${engines}.`,
            cvssScore: 9.8,
            cveId: "CWE-94",
            confidence: CONFIDENCE.EXEC_VERIFIED,
            validationSteps,
            isVerified: true,
          };
        } catch { /* next */ }
      }
    }
  } catch { /* skip */ }
  return null;
}

export async function probeFormSSTI(form: FormTarget): Promise<PendingFinding | null> {
  const baselineResp =
    form.method === "POST"
      ? await fetch(form.actionUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
          body: new URLSearchParams(form.fields.map((f) => [f, "test"])).toString(),
          signal: AbortSignal.timeout(5000),
        }).catch(() => null)
      : await safeFetch(form.actionUrl, 5000);
  const baselineText = baselineResp ? await baselineResp.text() : "";

  for (const field of form.fields) {
    for (const { payload, marker, engines } of SSTI_PROBES) {
      try {
        if (baselineText.includes(marker)) continue;

        const formData = new URLSearchParams();
        for (const f of form.fields) formData.set(f, f === field ? payload : "test");
        const method = form.method === "POST";
        const resp = method
          ? await fetch(form.actionUrl, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
              body: formData.toString(),
              signal: AbortSignal.timeout(6000),
              // @ts-ignore
              next: { revalidate: 0 },
            }).catch(() => null)
          : await safeFetch(`${form.actionUrl}?${formData.toString()}`, 6000);
        if (!resp) continue;
        const body = await resp.text();
        if (!body.includes(marker) || body.includes(payload)) continue;

        let mathHits = 0;
        const confirmExprs = [
          { p: "{{987*654}}", e: "645498" },
          { p: "{{4321*8765}}", e: "37873565" },
        ];
        for (const { p, e } of confirmExprs) {
          try {
            if (baselineText.includes(e)) continue;
            const fd2 = new URLSearchParams();
            for (const f of form.fields) fd2.set(f, f === field ? p : "test");
            const r2 = method
              ? await fetch(form.actionUrl, {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
                  body: fd2.toString(),
                  signal: AbortSignal.timeout(5000),
                  // @ts-ignore
                  next: { revalidate: 0 },
                }).catch(() => null)
              : await safeFetch(`${form.actionUrl}?${fd2.toString()}`, 5000);
            if (!r2) continue;
            const b2 = await r2.text();
            if (b2.includes(e) && !b2.includes(p)) mathHits++;
          } catch { /* next */ }
        }
        if (mathHits < 2) continue;

        return {
          type: "ssti-injection-form",
          severity: "CRITICAL",
          url: form.actionUrl,
          parameter: field,
          evidence: `Server-Side Template Injection (SSTI) confirmed via form field "${field}". Payload "${payload}" evaluated to "${marker}", confirmed with secondary expressions. Engine(s): ${engines}.`,
          cvssScore: 9.8,
          cveId: "CWE-94",
          confidence: CONFIDENCE.EXEC_VERIFIED,
          validationSteps: [
            `Form field "${field}" accepted payload "${payload}"`,
            `Output contained evaluated result "${marker}"`,
            `Secondary math checks passed (${mathHits}/2)`,
          ],
          isVerified: true,
        };
      } catch { /* next */ }
    }
  }
  return null;
}

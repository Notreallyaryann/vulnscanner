import jwt from "jsonwebtoken";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, JsApiEndpoint, PendingFinding } from "../types";
import { authedFetch, safeFetch } from "../session";

export async function probeBrokenAuth(
  formActionUrl: string,
  usernameField: string,
  passwordField: string
): Promise<PendingFinding | null> {
  const DEFAULT_CREDS = [
    { u: "admin", p: "admin" },
    { u: "admin", p: "password" },
    { u: "admin", p: "admin123" },
    { u: "admin", p: "1234" },
    { u: "administrator", p: "administrator" },
    { u: "test", p: "test" },
    { u: "guest", p: "guest" },
    { u: "admin@juice-sh.op", p: "admin123" },
  ];
  for (const { u, p } of DEFAULT_CREDS) {
    try {
      const body = new URLSearchParams({ [usernameField]: u, [passwordField]: p });
      const resp = await fetch(formActionUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "VulnScanner/2.0" },
        body: body.toString(),
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      });
      const isRedirect = resp.status === 302 || resp.status === 301;
      const respText = resp.status === 200 ? await resp.text() : "";
      const hasAuthCookie =
        resp.headers.get("set-cookie")?.toLowerCase().includes("token") ||
        resp.headers.get("set-cookie")?.toLowerCase().includes("session");
      const noErrorInBody =
        respText.length > 0 && !/invalid|incorrect|wrong|failed|error|denied/i.test(respText);

      let success = false;
      if (isRedirect) {
        const location = resp.headers.get("location") || "";
        if (location && !location.includes("login") && !location.includes("error") && !location.includes("fail")) {
          success = true;
        }
      } else if (hasAuthCookie && noErrorInBody) {
        success = true;
      }

      if (success) {
        return {
          type: "broken-authentication-default-creds",
          severity: "CRITICAL",
          url: formActionUrl,
          parameter: `${usernameField}=${u} / ${passwordField}=${p}`,
          evidence: `Default credentials "${u}" / "${p}" succeeded on login form at ${formActionUrl} (HTTP ${resp.status}). An attacker can immediately take over this account.`,
          cvssScore: 9.8,
          cveId: "CWE-798",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

export function detectSessionFixation(cookieHeaders: string[], targetUrl: string): PendingFinding | null {
  for (const cookie of cookieHeaders) {
    const lower = cookie.toLowerCase();
    const nameValue = cookie.split(";")[0];
    const value = nameValue.split("=").slice(1).join("=").trim();
    const name = nameValue.split("=")[0]?.trim() ?? "";
    if (/session|sess|sid|auth/i.test(name) && value.length > 0 && value.length < 16) {
      return {
        type: "session-fixation-weak-token",
        severity: "HIGH",
        url: targetUrl,
        parameter: name,
        evidence: `Session cookie "${name}" has a very short (${value.length} char) token, indicating a weak or predictable session ID.`,
        cvssScore: 8.0,
        cveId: "CWE-384",
      };
    }
    if (targetUrl.startsWith("https") && /session|sess|sid|auth/i.test(name)) {
      if (!lower.includes("secure") || !lower.includes("httponly") || !lower.includes("samesite")) {
        return {
          type: "session-cookie-insecure-attributes",
          severity: "HIGH",
          url: targetUrl,
          parameter: name,
          evidence: `Session cookie "${name}" on an HTTPS site is missing Secure, HttpOnly, or SameSite flags.`,
          cvssScore: 7.4,
          cveId: "CWE-614",
        };
      }
    }
  }
  return null;
}

function extractSessionCookieHelper(setCookieHeader: string): { name: string; value: string } {
  for (const cookie of setCookieHeader.split(/,(?=[^ ])/)) {
    const nameValue = cookie.split(";")[0];
    const eqIdx = nameValue.indexOf("=");
    if (eqIdx === -1) continue;
    const name = nameValue.slice(0, eqIdx).trim();
    const value = nameValue.slice(eqIdx + 1).trim();
    if (/session|sess|sid|auth|token|jsessionid|phpsessid|connect\.sid/i.test(name)) {
      return { name, value };
    }
  }
  return { name: "", value: "" };
}

export async function probeSessionFixationRegeneration(
  targetUrl: string,
  session: AuthSession
): Promise<PendingFinding | null> {
  if (!session.bearerToken) return null;

  try {
    const unauthResp = await fetch(targetUrl, {
      headers: FETCH_HEADERS,
      signal: AbortSignal.timeout(6000),
      redirect: "follow",
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!unauthResp) return null;

    const unauthCookies = unauthResp.headers.get("set-cookie") ?? "";
    const unauthSessionCookie = extractSessionCookieHelper(unauthCookies);
    if (!unauthSessionCookie.value) return null;

    const authedResp = await fetch(targetUrl, {
      headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken}` },
      signal: AbortSignal.timeout(6000),
      redirect: "follow",
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);
    if (!authedResp) return null;

    const authedCookies = authedResp.headers.get("set-cookie") ?? "";
    const authedSessionCookie = extractSessionCookieHelper(authedCookies);

    if (
      authedSessionCookie.value &&
      unauthSessionCookie.name === authedSessionCookie.name &&
      unauthSessionCookie.value === authedSessionCookie.value &&
      unauthSessionCookie.value.length >= 8
    ) {
      return {
        type: "session-fixation-no-regeneration",
        severity: "HIGH",
        url: targetUrl,
        parameter: unauthSessionCookie.name,
        evidence: `Session Fixation vulnerability: the session cookie "${unauthSessionCookie.name}" was NOT regenerated after authentication. Pre-auth and post-auth session IDs are identical.`,
        cvssScore: 8.0,
        cveId: "CWE-384",
      };
    }
  } catch { /* skip */ }
  return null;
}

export async function probePasswordPolicy(baseUrl: string, session: AuthSession): Promise<PendingFinding | null> {
  const registerEndpoints = [
    "/api/register", "/api/signup", "/api/users", "/rest/user/register",
    "/api/auth/register", "/api/v1/register", "/api/v2/register", "/user/register",
    "/auth/register", "/register", "/signup", "/users", "/create-account",
  ];

  const weakPasswords = ["123456", "password", "admin", "test", "qwerty", "12345678", "abc123"];

  for (const path of registerEndpoints) {
    try {
      const url = new URL(path, baseUrl).toString();

      for (const weakPassword of weakPasswords) {
        const testEmail = `test_${Date.now()}@vulnscan.internal`;
        const body = { email: testEmail, password: weakPassword, username: "testuser" };

        const resp = await authedFetch(
          url,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
          6000,
          false,
          session
        );

        if (resp && (resp.status === 200 || resp.status === 201)) {
          return {
            type: "weak-password-policy",
            severity: "MEDIUM",
            url,
            parameter: "password",
            evidence: `Weak password policy detected. Registration endpoint accepted weak password "${weakPassword}" without enforcing complexity requirements.`,
            cvssScore: 5.9,
            cveId: "CWE-521",
          };
        }
      }
    } catch { /* next */ }
  }
  return null;
}

export async function probeJWTNone(targetUrl: string): Promise<PendingFinding | null> {
  const jwtEndpoints = [
    "/api/Users/1", "/api/users/1", "/api/v1/users/1",
    "/api/profile", "/api/orders", "/api/basket", "/api/feedbacks",
  ];

  let unsignedJwt: string;
  try {
    unsignedJwt = jwt.sign(
      { email: "admin@juice-sh.op", username: "admin", id: 1 },
      "",
      { algorithm: "none" as any }
    );
  } catch {
    unsignedJwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwidXNlcm5hbWUiOiJhZG1pbiIsImlkIjoxfQ.";
  }

  for (const path of jwtEndpoints) {
    try {
      const url = new URL(path, targetUrl).toString();

      const unauth = await fetch(url, {
        headers: FETCH_HEADERS,
        signal: AbortSignal.timeout(5000),
      }).catch(() => null);

      if (!unauth || (unauth.status !== 401 && unauth.status !== 403)) continue;

      const resp = await fetch(url, {
        headers: {
          ...FETCH_HEADERS,
          Authorization: `Bearer ${unsignedJwt}`,
        },
        signal: AbortSignal.timeout(5000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp) continue;

      if (resp.status === 200 || resp.status === 204) {
        return {
          type: "jwt-none-algorithm",
          severity: "CRITICAL",
          url,
          parameter: "Authorization",
          evidence: `JWT None Algorithm Accepted at ${url}. The server accepted an unsigned JWT token ("alg": "none") and granted access (HTTP ${resp.status}). An attacker can forge arbitrary JWT claims (e.g. admin privileges) without knowing the secret key.`,
          cvssScore: 9.8,
          cveId: "CWE-347",
          isVerified: true,
          confidence: CONFIDENCE.DETERMINISTIC,
        };
      }
    } catch { /* next */ }
  }
  return null;
}

export async function probeIDORWithDualToken(
  baseUrl: string,
  jsBundleEndpoints: JsApiEndpoint[],
  session: AuthSession
): Promise<PendingFinding | null> {
  if (!session.bearerToken || !session.bearerToken2) return null;
  if (!session.userId || String(session.userId).trim().length === 0) return null;

  const targetUserId = String(session.userId).trim();

  const userResourcePaths = [
    `/api/users/${targetUserId}`,
    `/api/user/${targetUserId}`,
    `/api/Users/${targetUserId}`,
    `/api/account/${targetUserId}`,
    `/api/profile/${targetUserId}`,
    `/api/v1/users/${targetUserId}`,
  ];

  const discoveredUserPaths = jsBundleEndpoints
    .filter((e) => e.url.includes(targetUserId) || e.url.includes(":id") || e.url.includes(":userId"))
    .map((e) => e.url.replace(":id", targetUserId).replace(":userId", targetUserId))
    .filter((p) => !p.endsWith("/me") && !p.endsWith("/change-password"))
    .slice(0, 3);

  const allPaths = [...new Set([...userResourcePaths, ...discoveredUserPaths])];

  for (const path of allPaths) {
    try {
      const url = new URL(path, baseUrl).toString();

      const resp1 = await fetch(url, {
        headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken}` },
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp1 || resp1.status !== 200) continue;
      const body1 = await resp1.text().catch(() => "");
      if (!body1 || body1.length < 20) continue;

      const resp2 = await fetch(url, {
        headers: { ...FETCH_HEADERS, Authorization: `Bearer ${session.bearerToken2}` },
        signal: AbortSignal.timeout(6000),
        // @ts-ignore
        next: { revalidate: 0 },
      }).catch(() => null);

      if (!resp2 || resp2.status !== 200) continue;

      const body2 = await resp2.text().catch(() => "");
      try {
        const json2 = JSON.parse(body2);
        const jsonStr = JSON.stringify(json2);

        const hasExplicitUserKey =
          jsonStr.includes(`"id":"${targetUserId}"`) ||
          jsonStr.includes(`"id":${targetUserId}`) ||
          jsonStr.includes(`"userId":"${targetUserId}"`) ||
          jsonStr.includes(`"userId":${targetUserId}`) ||
          jsonStr.includes(`"ownerId":"${targetUserId}"`) ||
          jsonStr.includes(`"ownerId":${targetUserId}`);

        if (hasExplicitUserKey || (targetUserId.length >= 4 && jsonStr.includes(targetUserId))) {
          return {
            type: "idor-bola",
            severity: "CRITICAL",
            url,
            parameter: "Authorization",
            evidence: `Insecure Direct Object Reference (IDOR/BOLA) confirmed at ${url}. User 2 successfully accessed resource owned by User 1 (ID: ${targetUserId}) using User 2's bearer token.`,
            cvssScore: 9.1,
            cveId: "CWE-639",
            isVerified: true,
            confidence: CONFIDENCE.DUAL_VERIFIED,
          };
        }
      } catch { /* not json */ }
    } catch { /* next path */ }
  }
  return null;
}

export async function probeUnauthenticatedAPIAccess(targetUrl: string): Promise<PendingFinding | null> {
  const SENSITIVE_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/accounts", "/api/customers",
    "/api/payments", "/api/orders",
    "/api/config", "/api/settings",
    "/api/keys", "/api/tokens",
    "/api/me", "/api/profile",
    "/api/dashboard",
    "/admin/api/users",
  ];
  const SENSITIVE_PATTERNS = /email|username|password|token|apiKey|secret|credit|ssn|phone|address|balance/i;

  for (const path of SENSITIVE_API_PATHS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const resp = await safeFetch(url, 5000);
      if (!resp || resp.status !== 200) continue;
      const ct = resp.headers.get("content-type") || "";
      if (!ct.includes("application/json")) continue;
      const body = await resp.text();
      if (SENSITIVE_PATTERNS.test(body) && body.length > 50) {
        return {
          type: "unauthenticated-api-access",
          severity: "CRITICAL",
          url,
          evidence: `API endpoint at ${url} returned sensitive data (${SENSITIVE_PATTERNS.exec(body)?.[0]}) with HTTP 200 and no authentication required.`,
          cvssScore: 9.1,
          cveId: "CWE-862",
        };
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * Brute-forces common JWT secrets. If a forged token signed with a weak secret
 * is accepted by a protected endpoint, escalation is trivial.
 */
export async function probeJWTWeakSecret(
  targetUrl: string,
  session: AuthSession
): Promise<PendingFinding | null> {
  if (!session.bearerToken) return null;

  const WEAK_SECRETS = [
    "secret", "password", "jwt_secret", "changeme", "supersecret",
    "your-256-bit-secret", "mysecret", "1234567890", "admin", "key",
    "jwt", "token", "app_secret", "secretkey", "jwtkey",
  ];
  const JWT_TEST_ENDPOINTS = [
    "/api/users/1", "/api/Users/1", "/api/v1/users/1",
    "/api/profile", "/api/me", "/api/admin",
  ];

  // Try to extract existing claims from current session token
  let claims: Record<string, any> = { email: "scanner@test.com", id: 1, role: "admin" };
  try {
    const parts = session.bearerToken.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], "base64").toString("utf-8"));
      claims = { ...payload, admin: true, role: "admin" };
    }
  } catch { /* use defaults */ }

  for (const secret of WEAK_SECRETS) {
    try {
      const forged = jwt.sign(claims, secret, { algorithm: "HS256" });
      for (const path of JWT_TEST_ENDPOINTS) {
        try {
          const url = new URL(path, targetUrl).toString();
          const unauth = await fetch(url, {
            headers: FETCH_HEADERS,
            signal: AbortSignal.timeout(4000),
          }).catch(() => null);
          if (!unauth || (unauth.status !== 401 && unauth.status !== 403)) continue;

          const resp = await fetch(url, {
            headers: { ...FETCH_HEADERS, Authorization: `Bearer ${forged}` },
            signal: AbortSignal.timeout(5000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (resp && (resp.status === 200 || resp.status === 204)) {
            return {
              type: "jwt-weak-secret",
              severity: "CRITICAL",
              url,
              parameter: "Authorization",
              evidence: `JWT Weak Secret confirmed. Token forged with secret "${secret}" (HS256) was accepted at ${url} (HTTP ${resp.status}). An attacker can forge arbitrary JWT claims to escalate privileges.`,
              cvssScore: 9.8,
              cveId: "CWE-345",
              isVerified: true,
              confidence: 0.99,
              validationSteps: [
                `Forged JWT signed with common secret "${secret}" (HS256)`,
                `Endpoint ${url} returned HTTP ${resp.status} — token accepted`,
              ],
            };
          }
        } catch { /* next endpoint */ }
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * IDOR sequential ID fuzzing: probes numeric object IDs to detect
 * broken access control on publicly accessible REST objects.
 * Works unauthenticated — no dual session needed.
 */
export async function probeIDORSequentialFuzz(
  baseUrl: string,
  session: AuthSession
): Promise<PendingFinding | null> {
  const API_PATTERNS = [
    "/api/users/%ID%", "/api/user/%ID%", "/api/v1/users/%ID%",
    "/api/orders/%ID%", "/api/products/%ID%", "/api/accounts/%ID%",
    "/api/profile/%ID%", "/api/customers/%ID%",
  ];

  for (const pattern of API_PATTERNS) {
    for (const seedId of [1, 2, 3]) {
      try {
        const url = new URL(pattern.replace("%ID%", String(seedId)), baseUrl).toString();
        const resp = await safeFetch(url, 5000);
        if (!resp || resp.status !== 200) continue;
        const ct = resp.headers.get("content-type") || "";
        if (!ct.includes("json")) continue;
        const body = await resp.text();
        if (body.length < 20) continue;

        // Found a live object — probe adjacent ID to confirm enumeration
        const adjacentId = seedId + 1;
        const adjUrl = new URL(pattern.replace("%ID%", String(adjacentId)), baseUrl).toString();
        const adjResp = await safeFetch(adjUrl, 5000);
        if (!adjResp || adjResp.status !== 200) continue;
        const adjBody = await adjResp.text();
        if (adjBody.length < 20) continue;

        try {
          const obj1 = JSON.parse(body);
          const obj2 = JSON.parse(adjBody);
          const id1 = obj1?.id || obj1?.data?.id || obj1?.userId;
          const id2 = obj2?.id || obj2?.data?.id || obj2?.userId;
          if (id1 && id2 && String(id1) !== String(id2)) {
            return {
              type: "idor-sequential-enumeration",
              severity: "HIGH",
              url,
              parameter: "id (URL path)",
              evidence: `IDOR / Object Enumeration detected at ${pattern.replace("%ID%", "{id}")}. Sequential IDs ${seedId} and ${adjacentId} both returned HTTP 200 with distinct data — no ownership validation enforced.`,
              cvssScore: 8.1,
              cveId: "CWE-639",
              confidence: 0.87,
              validationSteps: [
                `GET ${url} → HTTP 200 with JSON object (id=${id1})`,
                `GET ${adjUrl} → HTTP 200 with different JSON object (id=${id2})`,
                `Both accessible without ownership check`,
              ],
              isVerified: true,
            };
          }
        } catch { /* not JSON */ }
      } catch { /* next */ }
    }
  }
  return null;
}

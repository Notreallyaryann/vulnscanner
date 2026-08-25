import * as cheerio from "cheerio";
import { CookieJar } from "tough-cookie";
import { AuthSession, FETCH_HEADERS, safeUrlJoin } from "./types";
import { safeFetch } from "./session";
import { browserInteractiveLogin } from "../browser";

export async function attemptAutoRegister(targetUrl: string, log: (m: string) => void): Promise<void> {
  const REGISTER_PATHS = [
    "/api/auth/register", "/api/register", "/api/users",
    "/api/signup", "/api/auth/signup", "/register",
    "/rest/user/register", "/api/v1/auth/register", "/api/v1/users",
  ];
  const SCANNER_ACCOUNTS = [
    { email: "scanner_test_1@vulnscan.internal", password: "VulnScan@Test1!", name: "Scanner Test1", username: "scannertest1" },
    { email: "scanner_test_2@vulnscan.internal", password: "VulnScan@Test2!", name: "Scanner Test2", username: "scannertest2" },
  ];

  log("📝  Attempting auto-registration of scanner test accounts...");

  for (const path of REGISTER_PATHS) {
    const url = safeUrlJoin(targetUrl, path);
    if (!url) continue;

    // Probe endpoint liveness with a throwaway request
    const probe = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
      body: JSON.stringify({ email: "probe_check@probe.invalid", password: "probe123!" }),
      signal: AbortSignal.timeout(5000),
      // @ts-ignore
      next: { revalidate: 0 },
    }).catch(() => null);

    // Skip 404 (endpoint doesn't exist) and server errors
    if (!probe || probe.status === 404 || probe.status >= 502) {
      log(`ℹ️  Registration endpoint ${path} not available (status: ${probe?.status || 'no response'})`);
      continue;
    }

    log(`🔍  Found potential registration endpoint: ${path} (status: ${probe.status})`);
    let registeredAny = false;
    for (const account of SCANNER_ACCOUNTS) {
      try {
        // Try multiple common registration body shapes
        const bodies = [
          { email: account.email, password: account.password, name: account.name },
          { email: account.email, password: account.password, username: account.username },
          { email: account.email, password: account.password, passwordRepeat: account.password, securityQuestion: { id: 1 }, securityAnswer: "scanner" },
        ];
        for (const body of bodies) {
          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);
          if (!resp) continue;
          // 200/201 = created, 409/400 = already exists or duplicate — both are fine
          if (resp.status === 200 || resp.status === 201) {
            log(`✅  Registered test account: ${account.email}`);
            registeredAny = true;
            break;
          } else if (resp.status === 409 || resp.status === 422) {
            log(`ℹ️  Test account already exists: ${account.email}`);
            registeredAny = true;
            break;
          } else {
            log(`⚠️  Registration failed for ${account.email}: HTTP ${resp.status}`);
          }
        }
      } catch (err) {
        log(`⚠️  Registration error for ${account.email}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (registeredAny) {
      log(`✅  Registration successful via ${path}`);
      break; // Found the registration endpoint; done
    }
  }
}

export async function attemptAutoLogin(
  targetUrl: string,
  log: (m: string) => void,
  session: AuthSession,
  customAuth?: { email?: string; password?: string },
  scanId?: string
): Promise<void> {
  // Step 0: Try Playwright Browser Interactive Login for SPA / JS-rendered login forms
  if (customAuth?.email && customAuth?.password && scanId) {
    log(`🌐  Attempting Playwright SPA interactive login for ${customAuth.email}...`);
    const browserResult = await browserInteractiveLogin(targetUrl, log, scanId, customAuth);
    if (browserResult?.bearerToken || browserResult?.cookies) {
      if (browserResult.bearerToken) session.bearerToken = browserResult.bearerToken;
      if (browserResult.cookies) session.cookies = browserResult.cookies;
      if (browserResult.userId) session.userId = browserResult.userId;
      log(`✅  Auth session acquired via Playwright SPA interactive login!`);
      return;
    }
  }
  const REST_LOGIN_PATHS = [
    "/rest/user/login", "/api/auth/login", "/api/login",
    "/api/v1/auth/login", "/auth/login", "/login", "/admin/login",
    "/accounts/login", "/token", "/api/token", "/api/v1/login",
    "/api/auth/callback/credentials",
  ];
  const TEST_ACCOUNTS = [
    { email: "scanner_test_1@vulnscan.internal", username: "scannertest1", password: "VulnScan@Test1!", isUserProvided: false },
    { email: "scanner_test_2@vulnscan.internal", username: "scannertest2", password: "VulnScan@Test2!", isUserProvided: false },
    { email: "admin@juice-sh.op", username: "admin", password: "admin123", isUserProvided: false },
    { email: "test@test.com", username: "test", password: "test", isUserProvided: false },
    { email: "user@example.com", username: "user", password: "password", isUserProvided: false },
  ];

  const accountsToTry = [];
  if (customAuth?.email && customAuth?.password) {
    accountsToTry.push({
      email: customAuth.email,
      username: customAuth.email.includes("@") ? customAuth.email.split("@")[0] : customAuth.email,
      password: customAuth.password,
      isUserProvided: true,
    });
    log(`🔑  Target credentials provided by user: ${customAuth.email}. Prioritizing custom login...`);
  }
  accountsToTry.push(...TEST_ACCOUNTS);

  log("🔑  Attempting authenticated session acquisition...");

  // Register scanner test accounts only if custom auth is not supplied
  if (!customAuth?.email || !customAuth?.password) {
    await attemptAutoRegister(targetUrl, log);
  }

  // ── Step 1: HTML Login Form Discovery & Submission ────────────────────────
  const loginPagesToProbe = [
    targetUrl,
    safeUrlJoin(targetUrl, "/login"),
    safeUrlJoin(targetUrl, "/signin"),
    safeUrlJoin(targetUrl, "/auth/login"),
  ].filter(Boolean) as string[];

  for (const loginPageUrl of loginPagesToProbe) {
    if (session.bearerToken || session.cookies) break;
    try {
      const pageResp = await safeFetch(loginPageUrl, 5000);
      if (!pageResp || pageResp.status !== 200) continue;
      const html = await pageResp.text();
      const $ = cheerio.load(html);

      const forms = $("form").get();
      for (const formEl of forms) {
        if (session.bearerToken || session.cookies) break;
        const formActionRaw = $(formEl).attr("action") || loginPageUrl;
        const formAction = safeUrlJoin(loginPageUrl, formActionRaw) || loginPageUrl;

        const pwdInput = $(formEl).find("input[type='password'], input[name*='pass'], input[id*='pass']").first();
        if (!pwdInput.length) continue;
        const pwdName = pwdInput.attr("name") || pwdInput.attr("id") || "password";

        const userInput = $(formEl).find("input[type='email'], input[type='text'], input[name*='email'], input[name*='user'], input[name*='login']").first();
        const userName = userInput.attr("name") || userInput.attr("id") || "email";

        for (const creds of accountsToTry) {
          try {
            const formBody = new URLSearchParams({ [userName]: creds.email, [pwdName]: creds.password }).toString();
            const resp = await fetch(formAction, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
              body: formBody,
              signal: AbortSignal.timeout(6000),
              // @ts-ignore
              next: { revalidate: 0 },
            }).catch(() => null);

            if (!resp) continue;
            const text = await resp.text().catch(() => "");
            let json: any = null;
            try { json = JSON.parse(text); } catch { /* ignore */ }

            const token = json?.token || json?.data?.token || json?.access_token || json?.accessToken || json?.jwt;
            const userId = String(json?.data?.id || json?.id || json?.user?.id || json?.userId || "");
            const rawCookie = resp.headers.get("set-cookie") || "";

            if (token || rawCookie || resp.status === 302 || resp.status === 301) {
              if (token) session.bearerToken = token;
              if (rawCookie) {
                try {
                  const jar = new CookieJar();
                  const cookieStrings = rawCookie.split(/,(?=[^ ])/);
                  for (const cs of cookieStrings) {
                    await jar.setCookie(cs.trim(), formAction).catch(() => {});
                  }
                  session.cookies = await jar.getCookieString(formAction);
                } catch {
                  session.cookies = rawCookie.split(";")[0];
                }
              }
              if (userId) session.userId = userId;
              const sourceLabel = creds.isUserProvided ? "user-provided credentials" : `account ${creds.email}`;
              log(`✅  Auth session acquired via HTML form at ${formAction} using ${sourceLabel}`);
              break;
            }
          } catch { /* try next */ }
        }
      }
    } catch { /* try next login page */ }
  }

  // ── Step 2: REST Endpoint Probe (Fallback & Secondary Session Acquisition) ─
  for (const path of REST_LOGIN_PATHS) {
    const url = safeUrlJoin(targetUrl, path);
    if (!url) continue;

    let sessionsFilled = (session.bearerToken || session.cookies) ? 1 : 0;
    for (const creds of accountsToTry) {
      if (sessionsFilled >= 2) break;
      try {
        // Build payload variations: JSON body & Form-urlencoded body (for Django/FastAPI/OAuth2)
        const payloadConfigs = [
          {
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify({ email: creds.email, password: creds.password }),
          },
          {
            headers: { "Content-Type": "application/json", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: JSON.stringify({ username: creds.username, password: creds.password }),
          },
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: new URLSearchParams({ username: creds.username, password: creds.password, grant_type: "password" }).toString(),
          },
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": FETCH_HEADERS["User-Agent"] },
            body: new URLSearchParams({ email: creds.email, password: creds.password }).toString(),
          },
        ];

        for (const config of payloadConfigs) {
          const resp = await fetch(url, {
            method: "POST",
            headers: config.headers,
            body: config.body,
            signal: AbortSignal.timeout(6000),
            // @ts-ignore
            next: { revalidate: 0 },
          }).catch(() => null);

          if (!resp || (resp.status !== 200 && resp.status !== 201 && resp.status !== 302)) continue;

          const text = await resp.text().catch(() => "");
          let json: any = null;
          try { json = JSON.parse(text); } catch { /* text or redirect response */ }

          const token = json?.token || json?.data?.token || json?.authentication?.token ||
            json?.access_token || json?.accessToken || json?.jwt;
          const userId = String(json?.data?.id || json?.id || json?.user?.id || json?.userId || "");
          const rawCookie = resp.headers.get("set-cookie") || "";

          if (token || rawCookie) {
            const credLabel = creds.isUserProvided ? `user credentials (${creds.email})` : creds.email;
            if (sessionsFilled === 0) {
              if (token) session.bearerToken = token;
              if (rawCookie) {
                try {
                  const jar = new CookieJar();
                  const cookieStrings = rawCookie.split(/,(?=[^ ])/);
                  for (const cs of cookieStrings) {
                    await jar.setCookie(cs.trim(), url).catch(() => {});
                  }
                  session.cookies = await jar.getCookieString(url);
                } catch {
                  session.cookies = rawCookie.split(";")[0];
                }
              }
              if (userId) session.userId = userId;
              sessionsFilled++;
              log(`✅  Auth session 1 acquired (${credLabel}) via ${path}`);
              break;
            } else if (sessionsFilled === 1) {
              if (token) session.bearerToken2 = token;
              if (rawCookie) {
                try {
                  const jar = new CookieJar();
                  const cookieStrings = rawCookie.split(/,(?=[^ ])/);
                  for (const cs of cookieStrings) {
                    await jar.setCookie(cs.trim(), url).catch(() => {});
                  }
                  session.cookies2 = await jar.getCookieString(url);
                } catch {
                  session.cookies2 = rawCookie.split(";")[0];
                }
              }
              if (userId) session.userId2 = userId;
              sessionsFilled++;
              log(`✅  Auth session 2 acquired (${credLabel}) — for IDOR dual-token probing`);
              break;
            }
          }
        }
      } catch (err) {
        log(`⚠️  Login error for ${creds.email}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (sessionsFilled > 0) break;
  }
  if (!session.bearerToken && !session.cookies) {
    log("⚠️  Could not acquire an authenticated session — unauthenticated scan only");
  }
}

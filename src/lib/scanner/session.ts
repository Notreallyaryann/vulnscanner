import { AuthSession, EMPTY_SESSION, FETCH_HEADERS } from "./types";

export function authHeaders(session: AuthSession, useSecondSession = false): Record<string, string> {
  const token = useSecondSession ? session.bearerToken2 : session.bearerToken;
  const cookies = useSecondSession ? session.cookies2 : session.cookies;
  const extra: Record<string, string> = {};
  if (token) extra["Authorization"] = `Bearer ${token}`;
  if (cookies) extra["Cookie"] = cookies;
  if (session.csrfToken) extra["X-CSRF-Token"] = session.csrfToken;
  return extra;
}

/** fetch() wrapper that injects auth credentials automatically. */
export async function authedFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = 8000,
  useSecondSession = false,
  session: AuthSession = EMPTY_SESSION
): Promise<Response | null> {
  try {
    const headers: Record<string, string> = {
      ...FETCH_HEADERS,
      ...authHeaders(session, useSecondSession),
      ...((options.headers as Record<string, string>) || {}),
    };
    return await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      // @ts-ignore
      next: { revalidate: 0 },
    });
  } catch {
    return null;
  }
}

/** Robust fetch with default headers and timeout handling. */
export async function safeFetch(url: string, timeoutMs = 10000): Promise<Response | null> {
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: FETCH_HEADERS,
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      // @ts-ignore – Next.js cache bypass
      next: { revalidate: 0 },
    });
    return res;
  } catch {
    return null;
  }
}



import { cookies } from "next/headers";
import { createHmac } from "crypto";

const COOKIE_NAME = "vs_gh_session";
const SECRET = process.env.NEXTAUTH_SECRET || "fallback_secret_change_me";

// ── Payload stored inside the cookie ──────────────────────────────────────────
export interface GitHubSession {
  accessToken: string;
  login: string;
  avatarUrl: string;
  name: string | null;
}

// ── Signing helpers ────────────────────────────────────────────────────────────

function sign(payload: string): string {
  return createHmac("sha256", SECRET).update(payload).digest("base64url");
}

function encode(session: GitHubSession): string {
  const payload = Buffer.from(JSON.stringify(session)).toString("base64url");
  const sig = sign(payload);
  return `${payload}.${sig}`;
}

function decode(token: string): GitHubSession | null {
  try {
    const [payload, sig] = token.split(".");
    if (!payload || !sig) return null;
    if (sign(payload) !== sig) return null;
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/** Read and verify the GitHub session from cookies. Returns null if not logged in. */
export async function getGitHubSession(): Promise<GitHubSession | null> {
  const cookieStore = await cookies();
  const raw = cookieStore.get(COOKIE_NAME)?.value;
  if (!raw) return null;
  return decode(raw);
}

/** Write the GitHub session cookie (server-side only — call from API route). */
export function buildSessionCookie(session: GitHubSession): string {
  const value = encode(session);
  // 8 hours expiry
  const maxAge = 60 * 60 * 8;
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

/** Return a cookie header that clears the session. */
export function clearSessionCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

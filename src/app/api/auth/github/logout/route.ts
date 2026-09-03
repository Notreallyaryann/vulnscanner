import { NextResponse } from "next/server";
import { clearSessionCookie } from "@/lib/github-session";

export const dynamic = "force-dynamic";

/**
 * GET /api/auth/github/logout
 * Clears the GitHub session cookie and redirects to the home page.
 */
export async function GET() {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
  const response = NextResponse.redirect(`${appUrl}/`);
  response.headers.set("Set-Cookie", clearSessionCookie());
  return response;
}

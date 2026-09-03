import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/**
 * GET /api/auth/github
 * Redirects the user to GitHub's OAuth authorization page.
 */
export async function GET() {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

  if (!clientId || clientId === "your_github_oauth_client_id") {
    return new NextResponse(
      JSON.stringify({
        error: "GITHUB_CLIENT_ID is not configured. Please set it in your .env file.",
      }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  const redirectUri = `${appUrl}/api/auth/github/callback`;
  const scopes = "read:user repo";

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    allow_signup: "true",
  });

  const githubAuthUrl = `https://github.com/login/oauth/authorize?${params}`;
  return NextResponse.redirect(githubAuthUrl);
}

import { NextRequest, NextResponse } from "next/server";
import { buildSessionCookie } from "@/lib/github-session";

export const dynamic = "force-dynamic";

/**
 * GET /api/auth/github/callback
 * GitHub redirects here after the user authorizes the OAuth App.
 * Exchanges the `code` for an access token, builds a signed session
 * cookie, and redirects to the GitHub scan page.
 */
export async function GET(req: NextRequest) {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const error = searchParams.get("error");

  if (error || !code) {
    return NextResponse.redirect(`${appUrl}/github?error=oauth_denied`);
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return NextResponse.redirect(`${appUrl}/github?error=not_configured`);
  }

  try {
    // 1. Exchange code for access token
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: `${appUrl}/api/auth/github/callback`,
      }),
    });

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token as string;

    if (!accessToken) {
      console.error("GitHub token exchange failed:", tokenData);
      return NextResponse.redirect(`${appUrl}/github?error=token_exchange_failed`);
    }

    // 2. Fetch user profile
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
      },
    });

    if (!userRes.ok) {
      return NextResponse.redirect(`${appUrl}/github?error=user_fetch_failed`);
    }

    const user = await userRes.json();

    // 3. Build signed session cookie and redirect
    const cookieHeader = buildSessionCookie({
      accessToken,
      login: user.login as string,
      avatarUrl: user.avatar_url as string,
      name: (user.name as string | null) ?? null,
    });

    const response = NextResponse.redirect(`${appUrl}/github`);
    response.headers.set("Set-Cookie", cookieHeader);
    return response;
  } catch (err) {
    console.error("GitHub OAuth callback error:", err);
    return NextResponse.redirect(`${appUrl}/github?error=server_error`);
  }
}

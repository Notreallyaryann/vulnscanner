import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { runVulnerabilityScan } from "@/lib/scanner";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { url, email, authEmail, authPassword } = await req.json();

    if (!url) {
      return new NextResponse("URL is required", { status: 400 });
    }

    let cleanUrl = url.trim();
    if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
      cleanUrl = "https://" + cleanUrl;
    }

    try {
      new URL(cleanUrl);
    } catch {
      return new NextResponse("Invalid URL format", { status: 400 });
    }

    const cleanAuthEmail = authEmail ? String(authEmail).trim() : null;
    const cleanAuthPassword = authPassword ? String(authPassword) : null;

    // Create the scan record
    const scan = await prisma.scan.create({
      data: {
        targetUrl: cleanUrl,
        email: email ? String(email).trim() : null,
        authEmail: cleanAuthEmail,
        authPassword: cleanAuthPassword,
        status: "PENDING",
      },
    });

    const customAuth = (cleanAuthEmail || cleanAuthPassword) ? {
      email: cleanAuthEmail || undefined,
      password: cleanAuthPassword || undefined,
    } : undefined;

    // Fire the scan in the background on the Node event loop.
    setTimeout(() => {
      runVulnerabilityScan(scan.id, cleanUrl, customAuth).catch((err) => {
        console.error(`Error executing background scan ${scan.id}:`, err);
      });
    }, 0);

    return NextResponse.json({ scanId: scan.id });
  } catch (error: any) {
    console.error("API Scan creation failed:", error);
    return new NextResponse(error.message || "Internal Server Error", { status: 500 });
  }
}

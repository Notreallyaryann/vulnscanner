import { prisma } from "../src/lib/prisma";
import { storeKnowledgeChunk } from "../src/lib/rag";

const KNOWLEDGE_BASE = [
  {
    source: "owasp" as const,
    title: "SQL Injection (SQLi) - OWASP Top 10:2021-Injection",
    content: "SQL Injection occurs when user-supplied input is directly concatenated or interpolated into a SQL query string rather than using parameterized queries or prepared statements. Attackers exploit this to bypass authentication, read or modify sensitive database records, or execute administrative operations. Remediation: Always use parameterized APIs (like Prisma ORM, prepared statements, or ORM query builders) and never concatenate raw user input into SQL commands."
  },
  {
    source: "owasp" as const,
    title: "Cross-Site Scripting (XSS) - OWASP Top 10:2021-Injection",
    content: "Cross-Site Scripting occurs when an application includes untrusted data in a web page without proper validation or escaping. There are three main types: Stored XSS (payload saved in DB), Reflected XSS (payload reflected in query params), and DOM-based XSS (payload parsed in browser). Attackers exploit this to execute malicious scripts in the victim's browser, steal session cookies, or hijack user sessions. Remediation: Use context-aware HTML escaping, implement a strict Content Security Policy (CSP), and use safe React rendering (avoid dangerouslySetInnerHTML without sanitization)."
  },
  {
    source: "owasp" as const,
    title: "Cross-Site Request Forgery (CSRF) - OWASP Top 10:2021-Security Misconfiguration",
    content: "CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. If an application relies solely on session cookies, malicious sites can send POST requests on behalf of the user. Remediation: Implement anti-CSRF tokens for all state-changing requests, or rely on modern cookies configured with the SameSite=Lax or SameSite=Strict attribute."
  },
  {
    source: "owasp" as const,
    title: "Insecure Direct Object References (IDOR) - OWASP Top 10:2021-Broken Access Control",
    content: "IDOR is a type of access control vulnerability that occurs when an application uses user-supplied input to access database records directly (e.g. /api/invoice?id=123) without verifying if the requesting user has permission to access that specific record. Remediation: Perform thorough server-side authorization checks for every request, and use non-sequential random identifiers like UUIDs or CUIDs instead of auto-incrementing integer IDs."
  },
  {
    source: "owasp" as const,
    title: "Local File Inclusion (LFI) & Path Traversal",
    content: "Path Traversal (or LFI) allows attackers to read arbitrary files on the server running the application. This happens when the application takes a file path parameter (e.g., ?page=about.html) and concatenates it to a directory prefix without verifying that the resolved path stays within the intended directory, allowing relative path traversal sequences like '../'. Remediation: Avoid passing file path strings from user input directly. Instead, map inputs to a strict whitelist of files, or sanitize paths using path.resolve and verify they start with the allowed root directory."
  },
  {
    source: "owasp" as const,
    title: "Missing Security Headers - OWASP Top 10:2021-Security Misconfiguration",
    content: "Web servers should send headers to instruct browsers on security restrictions. Crucial headers include: Content-Security-Policy (CSP) to restrict scripts/resources; Strict-Transport-Security (HSTS) to enforce HTTPS; X-Frame-Options to prevent Clickjacking; and X-Content-Type-Options: nosniff to prevent MIME-sniffing. Remediation: Configure Next.js headers or reverse proxy config to send CSP, HSTS, X-Frame-Options, and X-Content-Type-Options."
  },
  {
    source: "owasp" as const,
    title: "Hardcoded Secrets and Credentials - OWASP Top 10:2021-Cryptographic Failures",
    content: "Applications should never store private keys, API keys, database credentials, or passwords in their source code repositories. If compromised, attackers can gain access to external APIs or database services. Remediation: Load configuration dynamically from environment variables (.env files locally, and environment secret managers in production), and use tools like git-secrets or Gitleaks in CI/CD pipelines to prevent committing secrets."
  },
  {
    source: "owasp" as const,
    title: "Open Redirect - OWASP Top 10:2021-Server-Side Request Forgery",
    content: "Open Redirect vulnerabilities occur when an application accepts a user-controlled input URL for redirection (e.g. /login?redirect=http://attacker.com) without validating if the destination URL is trusted. Attackers use this for phishing attacks, redirecting users to identical looking malicious sites. Remediation: Only allow redirection to relative paths (beginning with /) or validate destinations against a strict whitelist of allowed domains."
  },
  {
    source: "nvd" as const,
    title: "CVE-2024-34351: Next.js Server Actions Redirect SSRF / Open Redirect",
    content: "A vulnerability was identified in Next.js Server Actions where redirecting to user-controlled URLs could lead to SSRF or Open Redirect issues if not validated. Attackers could craft custom headers or hosts to redirect requests from the server to internal resources. Remediation: Update next to the latest patched version and restrict server action redirects to relative routes."
  }
];

async function main() {
  console.log("🌱 Starting database seeding...");

  // 0. Enable pgvector extension
  try {
    console.log("⚡ Enabling pgvector extension...");
    await prisma.$executeRawUnsafe("CREATE EXTENSION IF NOT EXISTS vector;");
    console.log("✅ pgvector extension enabled.");
  } catch (error) {
    console.warn("⚠️ Warning: Could not enable vector extension automatically. It might already be enabled or require administrative permissions:", error);
  }



  // 2. Clear previous knowledge chunks (optional, to prevent duplicates)
  console.log("🧹 Clearing old KnowledgeChunks...");
  await prisma.$executeRaw`DELETE FROM "KnowledgeChunk"`;

  // 3. Seed knowledge chunks with embeddings
  console.log(`📚 Seeding ${KNOWLEDGE_BASE.length} KnowledgeChunks (with embeddings)...`);
  for (const chunk of KNOWLEDGE_BASE) {
    try {
      console.log(`Vectorizing: "${chunk.title}"`);
      await storeKnowledgeChunk(chunk);
    } catch (error) {
      console.error(`❌ Failed to seed chunk "${chunk.title}":`, error);
    }
  }

  console.log("✅ Database seeding completed successfully!");
}

main()
  .catch((e) => {
    console.error("❌ Seeding failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

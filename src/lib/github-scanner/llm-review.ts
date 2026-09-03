/**
 * github-scanner/llm-review.ts
 * LLM Deep Code Review engine.
 * Sends high-priority source files to Llama 3.3 70B (via existing OpenRouter rotator)
 * for security vulnerabilities that regex/AST patterns cannot reliably detect.
 */

import pLimit from "p-limit";
import { reviewCodeForVulnerabilities, type LLMCodeFinding } from "../openrouter";
import { PendingFinding, verifiedFinding, passiveFinding, CONFIDENCE } from "../scanner/types";
import { getSkillContextForFile } from "./skills-loader";

// ── File prioritisation ────────────────────────────────────────────────────────

// Files matching these patterns are reviewed first
const HIGH_PRIORITY_PATTERNS = [
  /\/api\//,
  /\/route\.[tj]sx?$/,
  /auth/i,
  /middleware/i,
  /\/lib\//,
  /controller/i,
  /service/i,
  /handler/i,
  /permission/i,
  /role/i,
];

// Files matching these are skipped entirely (Frontend UI, static assets, docs, mocks)
const SKIP_PATTERNS = [
  /node_modules\//,
  /\.min\.js$/,
  /\.map$/,
  /dist\//,
  /\.next\//,
  /build\//,
  /\.d\.ts$/,
  /\.test\.[tj]sx?$/,
  /\.spec\.[tj]sx?$/,
  /__mocks__\//,
  /\.stories\.[tj]sx?$/,
  /migrations\//,
  /generated\//,
  // Frontend client components & pages (avoid LLM hallucinating backend flaws on UI)
  /(?:^|\/)(?:app|pages)\/(?:(?!api\/).)*\/page\.[tj]sx?$/,
  /(?:^|\/)(?:app|pages)\/(?:(?!api\/).)*\/layout\.[tj]sx?$/,
  /(?:^|\/)components\//,
  /(?:^|\/)docs\//,
  /Client\.[tj]sx?$/,
  /Modal\.[tj]sx?$/,
  /Button\.[tj]sx?$/,
];

const SUPPORTED_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go"]);

const EXT_TO_LANGUAGE: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".go": "go",
};

function getExt(path: string): string {
  const idx = path.lastIndexOf(".");
  return idx > -1 ? path.slice(idx) : "";
}

function isPriority(filePath: string): boolean {
  return HIGH_PRIORITY_PATTERNS.some((p) => p.test(filePath));
}

function shouldSkip(filePath: string): boolean {
  if (SKIP_PATTERNS.some((p) => p.test(filePath))) return true;
  const ext = getExt(filePath);
  return !SUPPORTED_EXTENSIONS.has(ext);
}

// ── False Positive Validator ───────────────────────────────────────────────────

function isFalsePositive(f: LLMCodeFinding, filePath: string): boolean {
  const text = `${f.type} ${f.explanation} ${f.evidence}`.toLowerCase();

  // 1. Reading process.env is standard best practice, not a vulnerability
  if (text.includes("process.env") && (text.includes("hardcoded") || text.includes("insecure") || text.includes("storage"))) {
    return true;
  }

  // 2. Native JSON parsing in JS is not deserialization RCE
  if ((text.includes("req.json") || text.includes("json.parse")) && text.includes("deserializ")) {
    return true;
  }

  // 3. Normal console logging is not an AppSec vulnerability
  if ((text.includes("console.error") || text.includes("console.log") || text.includes("console.warn")) && (text.includes("error handling") || text.includes("disclosure"))) {
    return true;
  }

  // 4. React state / UI variables
  if (text.includes("usestate") || text.includes("usesession") || text.includes("clipboard")) {
    return true;
  }

  // 5. Example placeholders
  if (text.includes("your_api_key_here") || text.includes("example.com")) {
    return true;
  }

  // 6. Generic missing rate limiting on internal helper functions
  if (text.includes("rate limit") && (filePath.includes("/lib/") || !filePath.includes("/api/auth") && !filePath.includes("/api/login"))) {
    return true;
  }

  // 7. Legitimate ownership queries
  if (text.includes("missing ownership") && (text.includes("userid") || text.includes("owner"))) {
    return true;
  }

  return false;
}

// ── Chunking ───────────────────────────────────────────────────────────────────

const MAX_CHUNK_LINES = 200;
const OVERLAP_LINES = 20; // overlap between chunks to avoid missing cross-line issues

function chunkCode(content: string): string[] {
  const lines = content.split("\n");
  if (lines.length <= MAX_CHUNK_LINES) return [content];

  const chunks: string[] = [];
  for (let i = 0; i < lines.length; i += MAX_CHUNK_LINES - OVERLAP_LINES) {
    chunks.push(lines.slice(i, i + MAX_CHUNK_LINES).join("\n"));
    if (i + MAX_CHUNK_LINES >= lines.length) break;
  }
  return chunks;
}

// ── Severity / CVSS mapping ────────────────────────────────────────────────────

const SEVERITY_CVSS: Record<string, number> = {
  CRITICAL: 9.0,
  HIGH: 7.5,
  MEDIUM: 5.0,
  LOW: 3.0,
  INFO: 1.0,
};

// ── LLM finding → PendingFinding converter ────────────────────────────────────

function llmFindingToPending(
  f: LLMCodeFinding,
  filePath: string,
  repoUrl: string,
  chunkOffset: number
): PendingFinding {
  const actualLine = f.line > 0 ? f.line + chunkOffset : 0;
  const lineRef = actualLine > 0 ? `#L${actualLine}` : "";
  const cvss = SEVERITY_CVSS[f.severity] ?? 5.0;

  return passiveFinding(
    {
      type: f.type,
      severity: f.severity,
      url: `${repoUrl}/blob/HEAD/${filePath}${lineRef}`,
      parameter: filePath,
      evidence: `[LLM Review] ${f.evidence ? `"${f.evidence.slice(0, 120)}" — ` : ""}${f.explanation}`,
      cvssScore: cvss,
    },
    [
      `LLM Deep Review flagged: ${f.type}`,
      `File: ${filePath}${actualLine > 0 ? `:${actualLine}` : ""}`,
      f.explanation,
    ],
    CONFIDENCE.PASSIVE_SIGNAL + 0.3 // LLM findings are less deterministic than regex
  );
}

// ── Main LLM review function ───────────────────────────────────────────────────

export interface FileContent {
  path: string;
  content: string;
}

/**
 * Run LLM deep security review across a list of source files.
 * Priority files are reviewed first; low-priority files follow.
 * Uses pLimit(2) to stay within OpenRouter rate limits without blocking DAST.
 */
export async function runLLMCodeReview(
  files: FileContent[],
  repoUrl: string,
  maxFiles = 30
): Promise<PendingFinding[]> {
  // Filter and sort files: priority first, then alphabetical
  const eligible = files
    .filter((f) => !shouldSkip(f.path))
    .sort((a, b) => {
      const aPrio = isPriority(a.path) ? 0 : 1;
      const bPrio = isPriority(b.path) ? 0 : 1;
      return aPrio - bPrio || a.path.localeCompare(b.path);
    })
    .slice(0, maxFiles);

  if (eligible.length === 0) return [];

  const limit = pLimit(2); // Max 2 parallel LLM calls
  const allFindings: PendingFinding[] = [];

  await Promise.all(
    eligible.map((file) =>
      limit(async () => {
        const ext = getExt(file.path);
        const language = EXT_TO_LANGUAGE[ext] ?? "text";
        const chunks = chunkCode(file.content);

        // Resolve file-specific skill context to guide the LLM review
        const skillContext = getSkillContextForFile(file.path);
        if (skillContext) {
          console.log(`    🛡️  Injecting skill context for: ${file.path}`);
        }

        for (let chunkIdx = 0; chunkIdx < chunks.length; chunkIdx++) {
          const chunkOffset = chunkIdx * (MAX_CHUNK_LINES - OVERLAP_LINES);
          try {
            const llmFindings = await reviewCodeForVulnerabilities(
              chunks[chunkIdx],
              file.path,
              language,
              skillContext || undefined
            );

            const validFindings = llmFindings.filter((f) => !isFalsePositive(f, file.path));

            for (const f of validFindings) {
              allFindings.push(llmFindingToPending(f, file.path, repoUrl, chunkOffset));
            }
          } catch (err) {
            // Non-fatal — skip this chunk if LLM errors out
            console.warn(`LLM review failed for ${file.path} chunk ${chunkIdx}:`, err);
          }
        }
      })
    )
  );

  return allFindings;
}

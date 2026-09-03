/**
 * github-scanner/secrets.ts
 * Regex-based secrets detection engine.
 * Scans source file contents for hardcoded credentials, API keys, and token leaks.
 */

import { PendingFinding, verifiedFinding, CONFIDENCE } from "../scanner/types";

// ── Secret pattern definitions ─────────────────────────────────────────────────

interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  cvssScore: number;
  cveId?: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // Cloud Provider Keys
  {
    id: "aws-access-key",
    label: "AWS Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-798",
  },
  {
    id: "aws-secret-key",
    label: "AWS Secret Access Key",
    regex: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|AWS_SECRET)['":\s=]+([A-Za-z0-9/+]{40})\b/gi,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-798",
  },
  // GitHub Tokens
  {
    id: "github-pat",
    label: "GitHub Personal Access Token",
    regex: /\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b/g,
    severity: "CRITICAL",
    cvssScore: 9.1,
    cveId: "CWE-798",
  },
  // Stripe
  {
    id: "stripe-secret",
    label: "Stripe Secret Key",
    regex: /\b(sk_live_[A-Za-z0-9]{24,})\b/g,
    severity: "CRITICAL",
    cvssScore: 9.1,
  },
  {
    id: "stripe-restricted",
    label: "Stripe Restricted Key",
    regex: /\b(rk_live_[A-Za-z0-9]{24,})\b/g,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  // OpenAI
  {
    id: "openai-key",
    label: "OpenAI API Key",
    regex: /\b(sk-[A-Za-z0-9]{48})\b/g,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  // Twilio
  {
    id: "twilio-sid",
    label: "Twilio Account SID",
    regex: /\b(AC[a-f0-9]{32})\b/g,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  {
    id: "twilio-token",
    label: "Twilio Auth Token",
    regex: /(?:twilio[_\-]?(?:auth[_\-]?)?token|TWILIO_AUTH_TOKEN)['":\s=]+([a-f0-9]{32})\b/gi,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  // SendGrid
  {
    id: "sendgrid-key",
    label: "SendGrid API Key",
    regex: /\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b/g,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  // Slack
  {
    id: "slack-token",
    label: "Slack Bot/App Token",
    regex: /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/g,
    severity: "HIGH",
    cvssScore: 7.5,
  },
  {
    id: "slack-webhook",
    label: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: "HIGH",
    cvssScore: 6.5,
  },
  // PEM Private Keys
  {
    id: "private-key-pem",
    label: "Private Key (PEM)",
    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----/g,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-321",
  },
  // Generic hardcoded passwords
  {
    id: "hardcoded-password",
    label: "Hardcoded Password in Assignment",
    regex: /(?:password|passwd|pwd|secret|api_?key|auth_?token)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-259",
  },
  // Database connection strings with creds
  {
    id: "db-connection-string",
    label: "Database Connection String with Credentials",
    regex: /(?:mongodb|mysql|postgres|postgresql|mssql|redis):\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    severity: "CRITICAL",
    cvssScore: 9.1,
    cveId: "CWE-522",
  },
  // JWT Secrets
  {
    id: "jwt-secret",
    label: "Hardcoded JWT Secret",
    regex: /(?:jwt[_\-]?secret|JWT_SECRET|token[_\-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-321",
  },
];

// ── Files to skip ──────────────────────────────────────────────────────────────
const SKIP_PATTERNS = [
  /node_modules\//,
  /\.min\.js$/,
  /\.map$/,
  /dist\//,
  /\.next\//,
  /build\//,
  /__tests__\//,
  /\.test\./,
  /\.spec\./,
];

// ── Main scanner function ──────────────────────────────────────────────────────

export interface SecretFinding {
  patternId: string;
  label: string;
  filePath: string;
  line: number;
  match: string;
  finding: PendingFinding;
}

/**
 * Scan a single file's content for hardcoded secrets.
 */
export function scanFileForSecrets(
  filePath: string,
  content: string,
  repoUrl: string
): SecretFinding[] {
  // Skip irrelevant files
  if (SKIP_PATTERNS.some((p) => p.test(filePath))) return [];

  const lines = content.split("\n");
  const results: SecretFinding[] = [];

  for (const pattern of SECRET_PATTERNS) {
    // Clone regex to reset lastIndex
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      let match: RegExpExecArray | null;

      while ((match = re.exec(line)) !== null) {
        const matchedValue = match[1] ?? match[0];
        // Skip very short matches (likely false positives) and placeholder strings
        if (matchedValue.length < 6) continue;
        if (/your[-_]?|changeme|placeholder|example|todo|fixme|xxx/i.test(matchedValue)) continue;
        // Skip matches that are all the same character (e.g. "aaaaaaa")
        if (/^(.)\1{5,}$/.test(matchedValue)) continue;

        const safeMatch = matchedValue.length > 12
          ? matchedValue.slice(0, 6) + "..." + matchedValue.slice(-4)
          : matchedValue.slice(0, 4) + "...";

        results.push({
          patternId: pattern.id,
          label: pattern.label,
          filePath,
          line: lineNum + 1,
          match: safeMatch,
          finding: verifiedFinding(
            {
              type: "secrets",
              severity: pattern.severity,
              url: `${repoUrl}/blob/HEAD/${filePath}#L${lineNum + 1}`,
              parameter: filePath,
              evidence: `[${pattern.label}] found at line ${lineNum + 1}: ${safeMatch}`,
              cvssScore: pattern.cvssScore,
              cveId: pattern.cveId,
            },
            [`Pattern matched: ${pattern.label}`, `File: ${filePath}:${lineNum + 1}`],
            CONFIDENCE.DETERMINISTIC
          ),
        });
      }
    }
  }

  return results;
}

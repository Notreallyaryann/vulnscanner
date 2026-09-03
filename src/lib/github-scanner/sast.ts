/**
 * github-scanner/sast.ts
 * Static Application Security Testing (SAST) engine.
 * Analyses JS/TS/JSX/TSX source code for dangerous patterns using
 * regex-based and simple structural analysis.
 */

import { PendingFinding, verifiedFinding, passiveFinding, CONFIDENCE } from "../scanner/types";

// ── SAST Pattern definitions ───────────────────────────────────────────────────

interface SASTPattern {
  id: string;
  type: string;
  label: string;
  regex: RegExp;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvssScore: number;
  cveId?: string;
  confidence: number;
  description: string;
}

const SAST_PATTERNS: SASTPattern[] = [
  // ── SQL Injection ─────────────────────────────────────────────────────────
  {
    id: "sqli-string-concat",
    type: "sqli",
    label: "SQL Injection via String Concatenation",
    regex: /(?:query|execute|raw|db\.run|db\.all|db\.get|prisma\.\$queryRawUnsafe|sequelize\.query|knex\.raw)\s*\(\s*[`'"].*(?:\$\{|'\s*\+\s*|"\s*\+\s*)/g,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-89",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "User input concatenated directly into SQL query string.",
  },
  {
    id: "sqli-template-literal",
    type: "sqli",
    label: "SQL Injection via Template Literal",
    // Must look like an actual SQL statement (e.g. SELECT ... FROM, DELETE FROM, etc.) within a query execution or backtick SQL
    regex: /(?:(?:db|client|pool|prisma)\.(?:query|raw|execute|\$queryRawUnsafe)|\bSQL\b)\s*\(\s*`\s*(?:SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO\s+[\s\S]+?\s+VALUES|UPDATE\s+[\s\S]+?\s+SET|DELETE\s+FROM\s+[\s\S]+?\s+WHERE)[\s\S]*?\$\{/gi,
    severity: "CRITICAL",
    cvssScore: 9.1,
    cveId: "CWE-89",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Unparameterised SQL with dynamic template literal interpolation.",
  },
  // ── Command Injection ─────────────────────────────────────────────────────
  {
    id: "cmdi-exec",
    type: "cmdi",
    label: "Command Injection via exec()/execSync()",
    regex: /(?:child_process\.)?(?:exec|execSync|execFile|spawn)\s*\(\s*(?:[`'"].*\$\{|`\s*\$\{[^}]*(?:req\.|params|body|query|args))/g,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-78",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Shell command built from user-controlled input.",
  },
  // ── Eval / Code Injection ─────────────────────────────────────────────────
  {
    id: "eval-call",
    type: "xss",
    label: "Dangerous eval() Usage",
    regex: /\beval\s*\(\s*(?!['"`][a-zA-Z0-9_-]+['"`]\s*\))/g,
    severity: "HIGH",
    cvssScore: 8.1,
    cveId: "CWE-95",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "eval() can execute arbitrary code. Avoid with user-controlled data.",
  },
  {
    id: "new-function",
    type: "xss",
    label: "new Function() Code Execution",
    regex: /new\s+Function\s*\([^)]*(?:req\.|params|body|query|input|\$\{)/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-95",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "new Function() with dynamic input is functionally equivalent to eval().",
  },
  // ── XSS / DOM Sinks ──────────────────────────────────────────────────────
  {
    id: "innerhtml-sink",
    type: "xss",
    label: "Dangerous innerHTML Assignment",
    regex: /\.innerHTML\s*=\s*(?!['"`]<\w+>['"`])(?:req\.|params|body|query|location|window\.name|document\.URL|\$\{|\+)/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-79",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "innerHTML assignment with dynamic user-controlled content is a DOM-XSS sink.",
  },
  {
    id: "document-write",
    type: "xss",
    label: "document.write() with Dynamic Content",
    regex: /document\.write\s*\([^)]*(?:req\.|location|params|query|\$\{)/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-79",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "document.write() with dynamic data is an XSS sink.",
  },
  // ── Path Traversal ────────────────────────────────────────────────────────
  {
    id: "path-traversal",
    type: "lfi",
    label: "Potential Path Traversal",
    regex: /(?:fs\.(?:readFile|writeFile|readFileSync|createReadStream))\s*\([^)]*(?:req\.(?:query|body|params)|params\.\w+|searchParams\.get)/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-22",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "File system operation using direct request-derived path without sanitization.",
  },
  // ── Hardcoded Crypto ──────────────────────────────────────────────────────
  {
    id: "hardcoded-crypto-key",
    type: "secrets",
    label: "Hardcoded Cryptographic Key in Code",
    regex: /(?:createCipher(?:iv)?|createDecipher(?:iv)?|createHmac)\s*\([^,]+,\s*['"][A-Za-z0-9+/]{16,}['"]/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-321",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Cryptographic operation uses a hardcoded secret key.",
  },
  // ── NoSQL Injection ───────────────────────────────────────────────────────
  {
    id: "nosql-injection",
    type: "nosqli",
    label: "NoSQL Injection Risk",
    // Only flag passing the whole unvalidated body directly or $where
    regex: /(?:\.(?:find|findOne|update|delete|deleteMany|updateMany))\s*\(\s*(?:req\.body|req\.query)\s*\)|\$where\s*:\s*(?:req\.|params|query|body)/g,
    severity: "HIGH",
    cvssScore: 8.1,
    cveId: "CWE-943",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Raw request body passed directly to MongoDB query object — NoSQL injection risk.",
  },
  // ── SSRF ─────────────────────────────────────────────────────────────────
  {
    id: "ssrf-fetch",
    type: "ssrf",
    label: "SSRF via Unvalidated User-Controlled URL",
    regex: /(?:axios\.(?:get|post)|fetch)\s*\(\s*(?:req\.(?:query|body)\.\w+|searchParams\.get\(['"][^'"]*url['"]\))/g,
    severity: "HIGH",
    cvssScore: 8.6,
    cveId: "CWE-918",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Outbound HTTP request made directly to a user-supplied URL — SSRF risk.",
  },
  // ── Insecure Randomness ───────────────────────────────────────────────────
  {
    id: "insecure-random",
    type: "crypto",
    label: "Insecure Math.random() for Security Purpose",
    regex: /(?:token|secret|salt|password|sessionKey|otp|csrf)\s*[:=]\s*.*Math\.random\(\)/gi,
    severity: "MEDIUM",
    cvssScore: 5.9,
    cveId: "CWE-338",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "Math.random() is predictable and unsafe for tokens/passwords/keys. Use crypto.randomBytes().",
  },
  // ── Hardcoded Admin Check ─────────────────────────────────────────────────
  {
    id: "hardcoded-admin-email",
    type: "auth",
    label: "Hardcoded Admin Bypass Check",
    regex: /(?:user\.email|user\.id|session\.user\.email)\s*(?:===?|==)\s*['"][^'"]+@[^'"]+['"]\s*&&.*(?:isAdmin|role\s*===\s*['"]admin['"])/gi,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-798",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Hardcoded user identity bypass for admin privileges.",
  },
  // ── Prototype Pollution ───────────────────────────────────────────────────
  {
    id: "prototype-pollution",
    type: "prototype_pollution",
    label: "Unsanitized Object Property / Prototype Pollution",
    regex: /(?:\[\s*['"`]__proto__['"`]\s*\]|\[\s*['"`]constructor['"`]\s*\]|\[\s*['"`]prototype['"`]\s*\]|target\[(?:key|prop|k)\]\s*=\s*source\[(?:key|prop|k)\])/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-1321",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "Modifying __proto__ or recursive object merging without key sanitation enables prototype pollution.",
  },
  // ── Insecure Deserialization ──────────────────────────────────────────────
  {
    id: "insecure-deserialization",
    type: "deserialization",
    label: "Insecure Object Deserialization",
    regex: /(?:node-serialize|serialize-to-js|pickle\.loads?|yaml\.unsafe_load|unserialize\s*\()/g,
    severity: "CRITICAL",
    cvssScore: 9.8,
    cveId: "CWE-502",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "Deserializing untrusted data with native serializers enables remote code execution.",
  },
  // ── Path Traversal ────────────────────────────────────────────────────────
  {
    id: "path-traversal-sink",
    type: "path_traversal",
    label: "Path Traversal via Dynamic Filesystem Call",
    regex: /(?:fs\.(?:readFile|readFileSync|createReadStream)|res\.sendFile)\s*\(\s*(?:path\.join\(|.*\+|`)[^)]*(?:req\.|params|query|filename)/g,
    severity: "HIGH",
    cvssScore: 7.5,
    cveId: "CWE-22",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "Dynamic file path constructed from user request without root directory boundary confinement.",
  },
  // ── Mass Assignment ───────────────────────────────────────────────────────
  {
    id: "mass-assignment-orm",
    type: "mass_assignment",
    label: "Mass Assignment via Raw Request Body in ORM",
    regex: /\.(?:create|update|updateMany|upsert)\s*\(\s*\{\s*(?:data|where\s*:\s*\{[^}]*\}\s*,\s*data)\s*:\s*req\.body\s*\}?\s*\)/g,
    severity: "HIGH",
    cvssScore: 7.3,
    cveId: "CWE-915",
    confidence: CONFIDENCE.SINGLE_PAYLOAD,
    description: "Passing raw req.body into database mutation allows modifying unprivileged or internal model fields.",
  },
  // ── Broken Crypto / Weak Hash ─────────────────────────────────────────────
  {
    id: "weak-crypto-hash",
    type: "crypto",
    label: "Weak Hash Function (MD5/SHA1)",
    regex: /crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
    severity: "MEDIUM",
    cvssScore: 5.3,
    cveId: "CWE-327",
    confidence: CONFIDENCE.DUAL_VERIFIED,
    description: "MD5 and SHA1 are cryptographically broken hash algorithms vulnerable to collision attacks.",
  },
];

// ── Files to scan ──────────────────────────────────────────────────────────────
const SUPPORTED_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
]);

const SKIP_PATTERNS = [
  /node_modules\//,
  /\.min\.js$/,
  /\.map$/,
  /dist\//,
  /\.next\//,
  /build\//,
  /\.d\.ts$/,
];

function getExt(path: string): string {
  const idx = path.lastIndexOf(".");
  return idx > -1 ? path.slice(idx) : "";
}

// ── Main scanner function ──────────────────────────────────────────────────────

export interface SASTFinding {
  patternId: string;
  type: string;
  label: string;
  filePath: string;
  line: number;
  finding: PendingFinding;
}

/**
 * Scan a single source file for SAST issues.
 */
export function scanFileForSAST(
  filePath: string,
  content: string,
  repoUrl: string
): SASTFinding[] {
  if (SKIP_PATTERNS.some((p) => p.test(filePath))) return [];
  if (!SUPPORTED_EXTENSIONS.has(getExt(filePath))) return [];

  const lines = content.split("\n");
  const results: SASTFinding[] = [];

  for (const pattern of SAST_PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      // Skip comment lines
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

      let match: RegExpExecArray | null;
      while ((match = re.exec(line)) !== null) {
        const evidence = match[0].slice(0, 120);
        const isVerified = pattern.confidence >= CONFIDENCE.DUAL_VERIFIED;
        const makeFinding = isVerified ? verifiedFinding : passiveFinding;

        results.push({
          patternId: pattern.id,
          type: pattern.type,
          label: pattern.label,
          filePath,
          line: lineNum + 1,
          finding: makeFinding(
            {
              type: pattern.type,
              severity: pattern.severity,
              url: `${repoUrl}/blob/HEAD/${filePath}#L${lineNum + 1}`,
              parameter: filePath,
              evidence: `[${pattern.label}] ${evidence} (line ${lineNum + 1})`,
              cvssScore: pattern.cvssScore,
              cveId: pattern.cveId,
            },
            [`SAST pattern matched: ${pattern.label}`, `File: ${filePath}:${lineNum + 1}`, pattern.description],
            pattern.confidence
          ),
        });
        // Only report once per line per pattern to avoid noise
        break;
      }
    }
  }

  return results;
}

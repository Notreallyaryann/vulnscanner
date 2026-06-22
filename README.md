# VulnScanner — AI-Augmented Web Vulnerability Scanner

<div align="center">

![VulnScanner](https://img.shields.io/badge/VulnScanner-v2.0-cyan?style=for-the-badge&logo=shield&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?style=for-the-badge&logo=typescript)
![pgvector](https://img.shields.io/badge/pgvector-RAG-green?style=for-the-badge&logo=postgresql)

**A full-stack, production-grade web security scanner with 20+ active exploit probes, real-time streaming logs, and AI-powered remediation via Retrieval-Augmented Generation.**

[Live Demo](#) · [Architecture](#architecture) · [Setup](#quick-start) · [Probes](#vulnerability-probes)

</div>

---

## What It Does

VulnScanner is a **genuine security engineering project** — not a tutorial clone. It autonomously audits a target URL through 12 scan phases, covering the **full OWASP Top 10 (2021)**, and uses a **Cerebras LLM + pgvector RAG pipeline** to generate actionable, code-level remediation for every finding.

### Highlights

| Capability | Details |
|---|---|
| **20+ Probe Types** | SQLi, XSS, SSTI, XXE, SSRF, CORS, Host Header, Prototype Pollution, Path Traversal, Command Injection, Blind Timing SQLi, and more |
| **Real-time Log Streaming** | Server-Sent Events (SSE) push live scan output to the dashboard terminal as each phase executes |
| **AI Remediation (RAG)** | pgvector semantic search over OWASP/CWE/NVD knowledge base → Cerebras LLM generates per-finding code fixes |
| **Multi-source Crawling** | Extracts same-origin links, HTML forms, API endpoints, and sitemap URLs for comprehensive coverage |
| **CVSS Scoring** | Every finding carries a CVSSv3 score, CWE ID, OWASP category, and attack simulation walkthrough |
| **Export Reports** | Download full scan results as structured JSON (`vulnscan-report-*.json`) or print as PDF |
| **Rate-limit Detection** | Sends burst of 10 requests and checks for 429 / WAF headers to detect DoS protection status |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (Next.js App Router)            │
│  Landing Page ──► Dashboard ◄── SSE EventSource            │
│                      │                                      │
│                 JSON Export  PDF Print                      │
└──────────────────────┬──────────────────────────────────────┘
                       │  Server Actions / API Routes
┌──────────────────────▼──────────────────────────────────────┐
│                   Next.js Server (Node.js)                  │
│                                                             │
│  actions.ts ──► scanner.ts ──► scan-logger.ts              │
│       │              │                │                     │
│  CRUD ops      20+ probes        emitLog()                  │
│       │              │                │                     │
│  prisma.ts     cerebras.ts    SSE Route: /api/scan-logs/    │
│       │              │         [scanId]                     │
│  PostgreSQL   Cerebras API                                  │
│  (pgvector)   (gpt-oss-120b)                                │
│                                                             │
│  rag.ts ──► embeddings.ts (@xenova/transformers)           │
│              MiniLM-L6-v2 (local, no API needed)           │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

- **SSE over WebSockets** — Server-Sent Events is simpler for one-directional streaming, works through proxies, and requires no extra infrastructure
- **In-memory log bus (`scan-logger.ts`)** — A `Map<scanId, Set<Subscriber>>` pub/sub bus decouples the scanner engine from the HTTP transport layer; logs are buffered for 30s so late-joining clients can catch up
- **Mock/offline fallback** — `cerebras.ts` includes a detailed mock mode when no API keys are configured, enabling local testing without external dependencies
- **Round-robin API key rotation** — Supports up to 5 Cerebras keys with automatic 429 retry on the next key
- **pgvector embeddings** — `@xenova/transformers` runs MiniLM-L6-v2 locally (no embedding API cost), storing 384-dim vectors for semantic finding search

---

## Vulnerability Probes

### Phase 1–5: Passive Checks
| Probe | OWASP | CVSS |
|---|---|---|
| Missing CSP / HSTS / X-Frame-Options / Referrer-Policy | A05 | 5.4–7.2 |
| Cookie missing HttpOnly / Secure / SameSite | A07 | 5.9–7.5 |
| CSRF missing anti-forgery token on POST forms | A04 | 8.0 |
| Sensitive endpoint exposure (.env, .git, phpinfo, actuators) | A01 | Up to 9.8 |
| Rate-limiting absent / burst probe (10 req burst + 429 check) | A04 | 7.5 |

### Phase 6–7: Crawl & Fingerprint
| Probe | OWASP | CVSS |
|---|---|---|
| Same-origin link crawler (30 URLs), sitemap parser | — | — |
| API endpoint discovery from inline scripts | — | — |
| IDOR detection via sequential numeric IDs in discovered URLs | A01 | 6.5 |
| JS file secrets (AWS keys, Stripe, OpenAI, private keys) | A02 | 9.5 |
| DOM-based XSS sink detection (eval, innerHTML, document.write) | A08 | 7.5 |

### Phase 8–10: Active Injection Probing
| Probe | OWASP | CVSS |
|---|---|---|
| **Reflected SQLi** — 8 payloads, all URL params | A03 | 9.8 |
| **Blind Time-Based SQLi** — MySQL/PostgreSQL/MSSQL SLEEP | A03 | 9.8 |
| **Form SQLi** — POST/GET form injection | A03 | 9.8 |
| **Reflected XSS** — 8 payloads, HTML/attribute/JS contexts | A03 | 7.4 |
| **Form XSS** — XSS via form field submission | A03 | 7.4 |
| **SSTI** — Jinja2, Twig, Freemarker, SpEL, ERB, Mako | A03 | 9.8 |
| **Path Traversal / LFI** — `../../../etc/passwd` | A03 | 9.1 |
| **Command Injection** — Shell metacharacters in params | A03 | 9.8 |
| **HTML Injection** — Content injection without JS | A03 | 5.4 |
| **Prototype Pollution** — `__proto__` / `constructor.prototype` | A03 | 8.0 |

### Phase 11: Infrastructure Checks
| Probe | OWASP | CVSS |
|---|---|---|
| **CORS Reflection** — Arbitrary origin reflected + credentials | A05 | Up to 9.6 |
| **Host Header Injection** — Password reset poisoning | A10 | 7.5–8.1 |
| **XXE Injection** — 10 XML-accepting endpoints | A03 | 9.1 |
| **Dangerous HTTP Methods** — OPTIONS, TRACE, PUT, DELETE | A05 | 6.3–6.5 |
| **Directory Listing** — 10 common paths | A01 | 5.3 |
| **Debug Mode Exposure** — Django/Laravel/Symfony debug pages | A05 | 7.5 |
| **Unauthenticated API Access** — Sensitive JSON endpoints | A01 | 9.1 |
| **GraphQL Introspection** — Schema exposure | A05 | 5.3 |

### Phase 12: AI RAG Analysis
- Vector search against local OWASP/CWE/NVD knowledge base
- Cerebras LLM generates: title, explanation, attack simulation, fix steps, vulnerable/fixed code diff, references

---

## Quick Start

### Prerequisites
- Node.js 20+
- PostgreSQL with `pgvector` extension (or use [Neon](https://neon.tech) — free tier works)
- Cerebras API key(s) — [get one free](https://cloud.cerebras.ai)

### 1. Clone & Install
```bash
git clone https://github.com/yourusername/vulnscanner
cd vulnscanner
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
```

Edit `.env`:
```env
# PostgreSQL (with pgvector)
DATABASE_URL="postgresql://user:pass@host/dbname?sslmode=require"
DIRECT_URL="postgresql://user:pass@host/dbname?sslmode=require"

# Cerebras API Keys (up to 5, round-robin rotated)
CEREBRAS_API_KEY_1="your-key-here"
CEREBRAS_API_KEY_2="optional-second-key"
```

### 3. Set Up Database
```bash
# Run migrations
npx prisma migrate deploy

# Enable pgvector
psql $DATABASE_URL -c 'CREATE EXTENSION IF NOT EXISTS vector;'

# Seed OWASP/CWE knowledge base
npx tsx prisma/seed.ts
```

### 4. Run
```bash
npm run dev
# Open http://localhost:3000
```

### 5. Test a Vulnerable App
Use [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) or `http://testphp.vulnweb.com` (intentionally vulnerable, safe to test against):
```bash
docker run -p 3001:3000 bkimminich/juice-shop
# Then scan: http://localhost:3001
```

---

## Running Tests
```bash
npm test
```

Tests cover: CSP evaluation, SQLi error detection, XSS reflection checking, environment variable leak detection, form field extraction, and SSRF parameter name matching.

---

## Project Structure
```
src/
├── app/
│   ├── page.tsx                  # Landing page with demo terminal
│   ├── dashboard/page.tsx        # Main dashboard + live log terminal
│   └── api/
│       └── scan-logs/[scanId]/   # SSE streaming endpoint
│           └── route.ts
└── lib/
    ├── scanner.ts                # 2,300+ line core scanner engine
    ├── scan-logger.ts            # In-memory SSE pub/sub log bus
    ├── cerebras.ts               # LLM client with key rotation + mock
    ├── rag.ts                    # pgvector semantic retrieval
    ├── embeddings.ts             # Local MiniLM-L6-v2 embeddings
    ├── actions.ts                # Next.js Server Actions
    └── __tests__/
        └── scanner.test.ts       # Unit tests for probe helpers

prisma/
├── schema.prisma                 # User, Scan, Finding, KnowledgeChunk
└── seed.ts                       # OWASP/CWE/NVD knowledge seeder
```

---

## Resume Bullet Points

> **AI-Augmented Vulnerability Scanner** · Next.js 15 · TypeScript · PostgreSQL/pgvector · Cerebras LLM
> - Built a 12-phase active security scanner with 20+ probe types covering the full OWASP Top 10 (2021), including blind time-based SQL injection, SSTI across 6 template engines, CORS reflection, XXE, host header injection, and prototype pollution
> - Engineered a real-time Server-Sent Events (SSE) log streaming system with an in-memory pub/sub bus, delivering live scan progress to the dashboard terminal with zero polling overhead
> - Integrated a full RAG pipeline: local MiniLM-L6-v2 embeddings stored in pgvector, semantic retrieval of OWASP/CWE/NVD knowledge, and Cerebras LLM (120B parameter) generating per-finding code-level remediation with CVSS scores and CWE mappings
> - Implemented round-robin API key rotation with automatic 429 retry, graceful offline fallback mode, and structured JSON report export

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router), React 19, Tailwind CSS v4 |
| Backend | Next.js Server Actions, SSE API routes, Node.js |
| Database | PostgreSQL + pgvector (Neon serverless) |
| ORM | Prisma 7 with Neon serverless adapter |
| Embeddings | `@xenova/transformers` — MiniLM-L6-v2 (runs locally) |
| LLM | Cerebras Cloud API (gpt-oss-120b / Llama 3.1 70B) |
| Icons | Lucide React |

---

## License

MIT — Use freely. Do not scan systems you do not own or have explicit written permission to test.

---

<div align="center">
Built with ♥ for security engineers who move fast.
</div>

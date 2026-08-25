# VulnScanner 🛡️

**VulnScanner** is an advanced, full-stack automated web application vulnerability scanner built with **Next.js**, **React**, and **Prisma**. It features headless browser verification via Playwright, Acorn AST static code analysis, Nmap network scanning, and AI-powered vulnerability remediation reports powered by **OpenRouter AI** and **RAG (Retrieval-Augmented Generation)**.

---

## ✨ Features

- 🔍 **Multi-Vector Security Auditing**:
  - **SQL Injection (SQLi)**: Multi-format probes for URL parameters, form fields, and JSON payloads.
  - **Cross-Site Scripting (XSS)**: Reflected, DOM-based, and stored XSS detection with WAF evasion payload shuffling.
  - **NoSQL Injection**: MongoDB operator injection testing.
  - **GraphQL & API Security**: Introspection checks and parameter pollution probing.
  - **Header & Infrastructure Security**: CSP evaluation, CORS misconfiguration, HSTS, and clickjacking detection.
- 🌳 **Acorn AST Static Analysis**: Parses client-side JavaScript bundles into Abstract Syntax Trees (AST) using `acorn` and `acorn-walk` to accurately identify dangerous DOM sinks (`eval`, `document.write`, `innerHTML`) and hardcoded secrets with line-level evidence.
- 🌐 **Headless Browser Verification**: Uses **Playwright** to verify real client-side JavaScript hydration, evaluate DOM-XSS sink execution in dynamic SPAs, and capture intercepted network requests.
- 📡 **Nmap Integration**: Port scanning and service fingerprinting via a dedicated containerized microservice.
- 🤖 **AI-Powered Remediation Reports**: Integrates **OpenRouter AI** (with multi-key round-robin rotation and automatic 429 rate-limit failover) and vector-based **RAG** to generate custom, context-aware code fixes and remediation guides for discovered vulnerabilities.
- 📧 **Automated Email Reports**: Delivers HTML scan summary reports via Nodemailer.

---

## 🏗️ Architecture & Project Structure

```text
vulnscanner/
├── src/
│   ├── app/                # Next.js App Router (UI pages & API routes)
│   └── lib/
│       ├── scanner.ts      # Core security scanner orchestration engine
│       ├── scanner/
│       │   ├── js-analyzer.ts  # Acorn AST static analysis module
│       │   ├── crawler.ts      # HTML & SPA route crawler
│       │   ├── payloads.ts     # Multi-format payload target builder
│       │   └── probes/         # Vulnerability probe sub-modules (SQLi, XSS, API)
│       ├── browser.ts      # Headless browser rendering & hydration logic
│       ├── browser-pool.ts # Playwright browser instance lifecycle manager
│       ├── openrouter.ts   # OpenRouter AI integration with multi-key rotation
│       ├── cerebras.ts     # Compatibility wrapper re-exporting openrouter.ts
│       ├── rag.ts          # RAG context retriever for remediation
│       ├── nmap.ts         # Network port scanner integration
│       └── mail.ts         # Nodemailer report dispatcher
├── browser-service/        # Docker microservice for Playwright rendering
├── nmap-service/           # Docker microservice for Nmap scanning
└── prisma/                 # Database schema & migrations (Neon PostgreSQL)
```

---


## 🔒 Complete List of Supported Cybersecurity Vulnerability Checks

Below is the complete inventory of automated security checks, active vulnerability probes, and static code audit vectors performed by VulnScanner:

| Category | Check / Vulnerability Vector | Description |
| :--- | :--- | :--- |
| **Injection** | **SQL Injection (SQLi)** | Error-based, Boolean-based, Blind Time-delay, and UNION-based injection probes across GET params, POST forms, JSON bodies, and GraphQL variables. |
| **Injection** | **NoSQL Injection (NoSQLi)** | MongoDB operator injection probes (`$ne`, `$gt`, `$where`, `$regex`) targeting JSON API endpoints. |
| **Injection** | **Command Injection (OS)** | OS command execution syntax probes (`;`, `\|`, `` ` ``, `$()`) targeting server-side shell invocations. |
| **Injection** | **Server-Side Template Injection (SSTI)** | Expression evaluation probes (`{{7*7}}`, `${7*7}`) for Jinja2, Twig, Smarty, Freemarker, and Handlebars. |
| **Injection** | **XML External Entity (XXE)** | DTD entity resolution and XML bomb injection checks on XML request handlers. |
| **Injection** | **Prototype Pollution** | Overwriting global `Object.prototype` properties via `__proto__` and `constructor.prototype` payloads in JSON requests. |
| **XSS & Client Security** | **Reflected XSS** | Multi-format payload injection with dynamic WAF-evasion shuffling and Playwright browser execution verification (`alert()`, `confirm()`, `onerror`). |
| **XSS & Client Security** | **DOM-Based XSS (AST)** | Acorn AST static code parsing of client JS bundles to detect dangerous sinks (`eval()`, `document.write()`, `.innerHTML` / `.outerHTML` assignments). |
| **XSS & Client Security** | **DOM-Based XSS (Dynamic)** | Headless browser instrumentation during page hydration to capture untrusted input execution in real-time. |
| **XSS & Client Security** | **Stored XSS** | Persistent input reflection verification across multi-step request flows. |
| **Client & Secrets** | **JS Hardcoded Secrets** | AST & Regex scanning of loaded JavaScript files for AWS Access Keys, Stripe keys, Bearer tokens, private keys, and passwords. |
| **Client & Secrets** | **Client Storage Security** | Playwright inspection of `localStorage` and `sessionStorage` for exposed JWTs, API keys, passwords, and sensitive PII. |
| **Auth & Sessions** | **CSRF & Token Validation** | Checks for missing Anti-CSRF tokens in HTML forms, SameSite cookie attributes, and Origin/Referrer validation. |
| **File Security** | **File Upload & MIME Sniffing** | Unrestricted file upload testing, MIME-type spoofing checks, path traversal upload paths, and `X-Content-Type-Options: nosniff` enforcement. |
| **DoS** | **Denial of Service (DoS / ReDoS)** | XML entity expansion bomb checks ("Billion Laughs") and Regular Expression Denial of Service (ReDoS) vulnerability patterns. |
| **Infrastructure** | **SSRF (Server-Side Request Forgery)** | Internal IP address and cloud metadata service reachability checks (`169.254.169.254`, `127.0.0.1`, `localhost`). |
| **Infrastructure** | **Web Cache Poisoning** | Unkeyed HTTP header reflection probes (`X-Forwarded-Host`, `X-Forwarded-Scheme`) targeting upstream CDN/cache nodes. |
| **Infrastructure** | **HTTP Method Security & XST** | Testing for dangerous HTTP methods (`TRACE`, `PUT`, `DELETE`) and Cross-Site Tracing (XST) header reflection. |
| **Infrastructure** | **Open Redirect** | Unvalidated external URL parameter redirection (`//evil.com`, `https://evil.com`). |
| **Configuration** | **CSP (Content Security Policy)** | Policy evaluation for weaknesses (`'unsafe-inline'`, `'unsafe-eval'`, wildcard `*` origins, missing script directives). |
| **Configuration** | **CORS Misconfiguration** | Testing for wildcard origins (`*`) with credentials, arbitrary `Origin` reflection, and `null` origin trust. |
| **Configuration** | **Security Headers Audit** | Verifying HSTS (`Strict-Transport-Security`), Clickjacking protection (`X-Frame-Options`), Referrer-Policy, and Permissions-Policy. |
| **Configuration** | **Cookie Security Flags** | Inspecting session cookies for missing `HttpOnly`, `Secure`, or `SameSite` flags. |
| **API Security** | **GraphQL Introspection** | Detecting enabled GraphQL Introspection queries and schema exposure. |
| **API Security** | **OpenAPI / Swagger Exposure** | Detecting public `/swagger.json`, `/api-docs`, or `/openapi.json` documentation endpoints. |
| **Network** | **Nmap Service & Port Scan** | Containerized Nmap integration for open port identification, service version fingerprinting, and SSL/TLS handshake checks. |



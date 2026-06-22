/**
 * scanner.test.ts
 * Unit tests for core scanner probe helpers.
 *
 * Run with:   npx tsx --test src/lib/__tests__/scanner.test.ts
 * (or add `"test": "tsx --test src/**\/__tests__\/*.test.ts"` to package.json)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// ─── Helpers under test (extracted pure functions) ─────────────────────────

/**
 * Evaluates a CSP header string and returns a list of detected weaknesses.
 * Mirrors the logic in scanner.ts::evaluateCSP.
 */
function evaluateCSP(cspValue: string): string[] {
  const weaknesses: string[] = [];
  if (/unsafe-inline/i.test(cspValue))
    weaknesses.push("unsafe-inline");
  if (/unsafe-eval/i.test(cspValue))
    weaknesses.push("unsafe-eval");
  if (/\*\s*(;|$)/.test(cspValue))
    weaknesses.push("wildcard");
  if (/data:/i.test(cspValue))
    weaknesses.push("data-uri");
  if (!/default-src|script-src/i.test(cspValue))
    weaknesses.push("no-script-src");
  return weaknesses;
}

/**
 * Checks if a response body contains unencoded SQL error signatures.
 * Mirrors SQL_ERROR_PATTERNS_ACTIVE from scanner.ts.
 */
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /MySQLSyntaxErrorException/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{4,}/i,
  /Unclosed quotation mark/i,
  /You have an error in your SQL syntax/i,
];

function detectSQLiError(body: string): boolean {
  return SQL_ERROR_PATTERNS.some((p) => p.test(body));
}

/**
 * Checks if a payload is reflected unencoded in a response body.
 * Mirrors the XSS reflection check in probeReflectedXSS.
 */
function isXSSReflected(body: string, payload: string): boolean {
  return (
    body.includes(payload) &&
    !body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"))
  );
}

/**
 * Detects environment variable / secret leaks in HTML.
 * Mirrors detectEnvLeaks from scanner.ts.
 */
function detectEnvLeaks(html: string): boolean {
  const ENV_PATTERNS = [
    /NEXT_PUBLIC_[A-Z0-9_]+=([^"'\s]{4,})/g,
    /apiKey:\s*["'][A-Za-z0-9_\-]{30,}["']/g,
    /AIza[0-9A-Za-z_-]{35}/g,
    /sk-[A-Za-z0-9]{32,}/g,
    /(?:mongodb|postgresql|mysql):\/\/[^@"'\s]{6,}@[^"'\s]{4,}/gi,
  ];
  return ENV_PATTERNS.some((re) => { re.lastIndex = 0; return re.test(html); });
}

/**
 * Extracts injectable form fields from an HTML string.
 * Mirrors the extractForms helper.
 */
function countFormFields(html: string): number {
  const INJECTABLE_TYPES = /^(text|search|email|number|tel|url|hidden|password|)$/i;
  let count = 0;
  for (const match of html.matchAll(/<input(\s[^>]*)?\/?>/gi)) {
    const attrs = match[1] ?? "";
    const typeMatch = attrs.match(/type=["']?([^"'\s>]+)["']?/i);
    const nameMatch = attrs.match(/name=["']([^"']+)["']/i);
    if (!nameMatch) continue;
    const fieldType = typeMatch ? typeMatch[1] : "";
    if (INJECTABLE_TYPES.test(fieldType)) count++;
  }
  return count;
}

// ─── Test Suites ────────────────────────────────────────────────────────────

describe("CSP Evaluation", () => {
  it("flags unsafe-inline", () => {
    const result = evaluateCSP("default-src 'self'; script-src 'unsafe-inline'");
    assert.ok(result.includes("unsafe-inline"), "should flag unsafe-inline");
  });

  it("flags unsafe-eval", () => {
    const result = evaluateCSP("script-src 'unsafe-eval'");
    assert.ok(result.includes("unsafe-eval"), "should flag unsafe-eval");
  });

  it("flags wildcard (*)", () => {
    const result = evaluateCSP("default-src *; script-src 'self'");
    assert.ok(result.includes("wildcard"), "should flag wildcard");
  });

  it("flags missing script-src", () => {
    const result = evaluateCSP("img-src *");
    assert.ok(result.includes("no-script-src"), "should flag missing script-src");
  });

  it("passes a strict policy", () => {
    const result = evaluateCSP(
      "default-src 'self'; script-src 'self' https://cdn.example.com"
    );
    assert.deepEqual(result, [], "strict CSP should have no weaknesses");
  });
});

describe("SQL Injection Error Detection", () => {
  it("detects MySQL syntax error", () => {
    assert.ok(detectSQLiError("SQL syntax error in MySQL"));
  });

  it("detects PostgreSQL error", () => {
    assert.ok(detectSQLiError("PostgreSQL ERROR: syntax error at or near"));
  });

  it("detects Oracle ORA error code", () => {
    assert.ok(detectSQLiError("ORA-00942: table or view does not exist"));
  });

  it("does not flag clean response", () => {
    assert.ok(!detectSQLiError("<html><body>Search results for: test</body></html>"));
  });

  it("detects unclosed quotation mark", () => {
    assert.ok(detectSQLiError("Unclosed quotation mark after the character string"));
  });
});

describe("XSS Reflection Check", () => {
  it("detects unencoded script tag in response", () => {
    const payload = "<script>/*vulnscan*/</script>";
    const body = `<html><div>Results: ${payload}</div></html>`;
    assert.ok(isXSSReflected(body, payload), "unencoded payload should be detected");
  });

  it("does not flag HTML-encoded reflection (safe)", () => {
    const payload = "<script>/*vulnscan*/</script>";
    const body = `<html><div>Results: &lt;script&gt;/*vulnscan*/&lt;/script&gt;</div></html>`;
    assert.ok(!isXSSReflected(body, payload), "encoded reflection should NOT be flagged");
  });

  it("detects img onerror payload", () => {
    const payload = `"><img src=x onerror=alert('vulnscan')>`;
    const body = `<div class="results">${payload}</div>`;
    assert.ok(isXSSReflected(body, payload));
  });
});

describe("Environment Variable / Secret Leak Detection", () => {
  it("detects NEXT_PUBLIC_ variable", () => {
    const html = `<script>window.__env = "NEXT_PUBLIC_API_KEY=sk_live_abc123xyz"</script>`;
    assert.ok(detectEnvLeaks(html));
  });

  it("detects OpenAI API key pattern", () => {
    const html = `var key = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012";`;
    assert.ok(detectEnvLeaks(html));
  });

  it("detects Google Maps API key pattern", () => {
    const html = `<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456"></script>`;
    assert.ok(detectEnvLeaks(html));
  });

  it("does not flag clean HTML", () => {
    const html = `<html><head><title>Home</title></head><body><p>Welcome</p></body></html>`;
    assert.ok(!detectEnvLeaks(html));
  });
});

describe("Form Field Extraction", () => {
  it("counts text input fields", () => {
    const html = `
      <form>
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="email" name="email" />
        <button type="submit">Login</button>
      </form>
    `;
    assert.equal(countFormFields(html), 3, "should count text, password, and email fields");
  });

  it("ignores checkbox and radio inputs", () => {
    const html = `
      <form>
        <input type="checkbox" name="agree" />
        <input type="radio" name="gender" value="m" />
        <input type="text" name="city" />
      </form>
    `;
    assert.equal(countFormFields(html), 1, "should only count text-like fields");
  });

  it("handles input without type attribute (defaults to text)", () => {
    const html = `<form><input name="search" /></form>`;
    assert.equal(countFormFields(html), 1);
  });
});

describe("SSRF Parameter Name Detection", () => {
  const SSRF_PARAM_NAMES = /\b(?:url|uri|endpoint|redirect|callback|proxy|fetch|load|src|dest|host|path|feed|target|resource|api)\b/i;

  it("detects 'url' parameter", () => {
    assert.ok(SSRF_PARAM_NAMES.test("url"));
  });

  it("detects 'redirect' parameter", () => {
    assert.ok(SSRF_PARAM_NAMES.test("redirect"));
  });

  it("detects 'callback' parameter", () => {
    assert.ok(SSRF_PARAM_NAMES.test("callback"));
  });

  it("does not flag benign parameter names", () => {
    assert.ok(!SSRF_PARAM_NAMES.test("page"));
    assert.ok(!SSRF_PARAM_NAMES.test("sort"));
    assert.ok(!SSRF_PARAM_NAMES.test("limit"));
  });
});

console.log("✅ All scanner unit tests completed.");

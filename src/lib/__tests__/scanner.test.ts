import test from "node:test";
import assert from "node:assert";
import { buildPayloadTarget } from "../scanner/payloads";
import { isSpaHtmlFallback } from "../scanner/crawler";
import { analyzeDomXssEvents } from "../scanner/probes/xss";
import { probeNoSQLiJson } from "../scanner/probes/api";

test("buildPayloadTarget generates valid JSON payload options", () => {
  const target = buildPayloadTarget("https://example.com/api/login", "POST", "username", "admin' OR 1=1--", "JSON_BODY", ["username", "password"]);
  assert.strictEqual(target.fetchUrl, "https://example.com/api/login");
  assert.strictEqual(target.options.method, "POST");
  assert.strictEqual((target.options.headers as any)["Content-Type"], "application/json");
  const parsed = JSON.parse(target.options.body as string);
  assert.strictEqual(parsed.username, "admin' OR 1=1--");
  assert.strictEqual(parsed.password, "test_value");
});

test("buildPayloadTarget generates valid GraphQL payload options", () => {
  const target = buildPayloadTarget("https://example.com/graphql", "POST", "searchQuery", "test_query", "GRAPHQL_VAR");
  assert.strictEqual(target.fetchUrl, "https://example.com/graphql");
  assert.strictEqual((target.options.headers as any)["Content-Type"], "application/json");
  const parsed = JSON.parse(target.options.body as string);
  assert.strictEqual(parsed.variables.searchQuery, "test_query");
});

test("isSpaHtmlFallback detects index.html SPA shells", () => {
  const mockResp = new Response("<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>", {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
  assert.strictEqual(isSpaHtmlFallback(mockResp, "<!DOCTYPE html><html>...</html>"), true);
});

test("analyzeDomXssEvents detects client-side sink execution", () => {
  const finding = analyzeDomXssEvents("https://example.com/search#test", [
    { sink: "eval", payloadSnippet: "eval(\"alert('vulnscan')\")" }
  ]);
  assert.notStrictEqual(finding, null);
  assert.strictEqual(finding?.type, "dom-xss");
  assert.strictEqual(finding?.severity, "HIGH");
  assert.strictEqual(finding?.isVerified, true);
});

test("probeNoSQLiJson detects MongoDB operator execution", async () => {
  const mockAuthedFetch = async (url: string, init?: RequestInit) => {
    const body = JSON.parse(init?.body as string);
    if (body.username && typeof body.username === "object" && "$ne" in body.username) {
      return new Response(JSON.stringify({ status: "success", token: "mock_jwt_token" }), { status: 200 });
    }
    return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 });
  };

  const finding = await probeNoSQLiJson("https://example.com/api/login", ["username", "password"], mockAuthedFetch);
  assert.notStrictEqual(finding, null);
  assert.strictEqual(finding?.type, "nosqli");
  assert.strictEqual(finding?.severity, "CRITICAL");
});
test("extractHtmlLinksAndForms extracts SPA router directives and forms", () => {
  const { extractHtmlLinksAndForms } = require("../scanner/crawler");
  const html = `
    <html>
      <body>
        <a routerlink="/dashboard">Dashboard</a>
        <div to="/profile">Profile</div>
        <form action="/api/login" method="POST">
          <input name="username" type="text" />
          <input name="password" type="password" />
        </form>
      </body>
    </html>
  `;
  const result = extractHtmlLinksAndForms(html, "https://example.com");
  assert.ok(result.links.includes("https://example.com/dashboard"));
  assert.ok(result.links.includes("https://example.com/profile"));
  assert.strictEqual(result.forms.length, 1);
  assert.strictEqual(result.forms[0].actionUrl, "https://example.com/api/login");
  assert.deepStrictEqual(result.forms[0].fields, ["username", "password"]);
});

test("extractHtmlLinksAndForms extracts SPA router paths from inline script blocks", () => {
  const { extractHtmlLinksAndForms } = require("../scanner/crawler");
  const html = `
    <html>
      <body>
        <script>
          const routes = [
            { path: "/users/settings" },
            { path: "/admin/analytics" }
          ];
        </script>
      </body>
    </html>
  `;
  const result = extractHtmlLinksAndForms(html, "https://example.com");
  assert.ok(result.links.includes("https://example.com/users/settings"));
  assert.ok(result.links.includes("https://example.com/admin/analytics"));
});


import test from "node:test";
import assert from "node:assert";
import { buildPayloadTarget } from "../scanner/payloads";
import { isSpaHtmlFallback } from "../scanner/crawler";
import { analyzeDomXssEvents } from "../scanner/probes/xss";
import { probeNoSQLiJson } from "../scanner/probes/api";
import {
  probeGraphQLIntrospection,
  probeGraphQLBatchedQueries,
  probeGraphQLAliasFlooding,
  probeGraphQLDoS,
} from "../scanner/probes/api";
import { probeNegativeQuantity } from "../scanner/probes/misc";
import { probeSSTI, probeRestApiSSTI } from "../scanner/probes/injection";
import { EMPTY_SESSION } from "../scanner/types";

// ── Original tests ────────────────────────────────────────────────────────────

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
    <html><body>
      <a routerlink="/dashboard">Dashboard</a>
      <div to="/profile">Profile</div>
      <form action="/api/login" method="POST">
        <input name="username" type="text" />
        <input name="password" type="password" />
      </form>
    </body></html>
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
    <html><body>
      <script>
        const routes = [{ path: "/users/settings" }, { path: "/admin/analytics" }];
      </script>
    </body></html>
  `;
  const result = extractHtmlLinksAndForms(html, "https://example.com");
  assert.ok(result.links.includes("https://example.com/users/settings"));
  assert.ok(result.links.includes("https://example.com/admin/analytics"));
});

test("analyzeJsAst detects dangerous DOM sinks via AST parsing", () => {
  const { analyzeJsAst } = require("../scanner/js-analyzer");
  const code = `
    // Safe comment: eval('should be ignored')
    const safeStr = "eval('in string should be ignored')";
    function dangerousAction() {
      eval(location.hash);
      document.write("<p>unsafe</p>");
      document.body.innerHTML = window.location.search;
    }
  `;
  const findings = analyzeJsAst(code);
  assert.strictEqual(findings.length, 3);
  assert.strictEqual(findings[0].sinkType, "eval");
  assert.strictEqual(findings[1].sinkType, "document.write");
  assert.strictEqual(findings[2].sinkType, "innerHTML");
});

test("analyzeJsAst ignores comments and string literals (no false positives)", () => {
  const { analyzeJsAst } = require("../scanner/js-analyzer");
  const code = `
    // eval("this is a comment")
    /* document.write("multiline comment") */
    const text = "eval() in a string literal";
  `;
  const findings = analyzeJsAst(code);
  assert.strictEqual(findings.length, 0);
});

test("analyzeJsAst handles invalid JS syntax gracefully", () => {
  const { analyzeJsAst } = require("../scanner/js-analyzer");
  const code = `<div>Invalid JS syntax <<<<</div>`;
  const findings = analyzeJsAst(code);
  assert.deepStrictEqual(findings, []);
});

// ── Business Logic: Negative Quantity Manipulation ────────────────────────────

test("probeNegativeQuantity detects server accepting quantity=-1 (echoed in response)", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (body.quantity === -1) {
      return new Response(JSON.stringify({ id: 42, quantity: -1, total: -100 }),
        { status: 201, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ error: "Bad request" }), { status: 400 });
  };
  const findings = await probeNegativeQuantity("https://example.com", EMPTY_SESSION, mockFetch);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, "business-logic-negative-quantity");
  assert.strictEqual(findings[0].severity, "CRITICAL");
  assert.strictEqual(findings[0].parameter, "quantity");
  assert.strictEqual(findings[0].isVerified, true);
});

test("probeNegativeQuantity detects server accepting qty=-1 (success status + id only)", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (typeof body.qty === "number" && body.qty < 0) {
      return new Response(JSON.stringify({ id: "order-99", status: "success" }),
        { status: 201, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
  };
  const findings = await probeNegativeQuantity("https://example.com", EMPTY_SESSION, mockFetch);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, "business-logic-negative-quantity");
  assert.strictEqual(findings[0].parameter, "qty");
});

test("probeNegativeQuantity does not flag a server that rejects negative quantity", async () => {
  const mockFetch = async (_url: string, _init?: RequestInit): Promise<Response | null> => {
    return new Response(
      JSON.stringify({ status: "error", message: "Quantity must be a positive integer" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  };
  const findings = await probeNegativeQuantity("https://example.com", EMPTY_SESSION, mockFetch);
  assert.strictEqual(findings.length, 0);
});

// ── GraphQL Probes ────────────────────────────────────────────────────────────

test("probeGraphQLIntrospection detects full schema dump", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (body?.query?.includes("__typename") && !body?.query?.includes("__schema")) {
      return new Response(JSON.stringify({ data: { __typename: "Query" } }),
        { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (body?.query?.includes("IntrospectionQuery") || body?.query?.includes("__schema")) {
      return new Response(JSON.stringify({
        data: {
          __schema: {
            queryType: { name: "Query" }, mutationType: { name: "Mutation" },
            subscriptionType: null, directives: [],
            types: [
              { kind: "OBJECT", name: "User",    description: null, fields: [], inputFields: [], enumValues: [] },
              { kind: "OBJECT", name: "Product", description: null, fields: [], inputFields: [], enumValues: [] },
              { kind: "OBJECT", name: "__Schema",description: null, fields: [], inputFields: [], enumValues: [] },
            ],
          },
        },
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ errors: [{ message: "Unknown field" }] }),
      { status: 400, headers: { "Content-Type": "application/json" } });
  };

  const findings = await probeGraphQLIntrospection("https://example.com", EMPTY_SESSION, mockFetch);
  assert.ok(findings.length >= 1, "Expected at least one introspection finding");
  const introspectionFinding = findings.find((f) => f.type === "graphql-introspection");
  if (!introspectionFinding) throw new Error("Expected a graphql-introspection finding");
  assert.strictEqual(introspectionFinding.severity, "MEDIUM");
  assert.strictEqual(introspectionFinding.isVerified, true);
  assert.ok(introspectionFinding.evidence.includes("2 user-defined type(s)"));
});

test("probeGraphQLIntrospection detects field suggestion oracle when full introspection is blocked", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (body?.query?.includes("__schema")) {
      return new Response(JSON.stringify({ errors: [{ message: "GraphQL introspection is not allowed" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (body?.query?.includes("_usrz")) {
      return new Response(JSON.stringify({
        errors: [{ message: "Cannot query field \"_usrz\" on type \"Query\". Did you mean \"user\"?" }],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ data: { __typename: "Query" } }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const findings = await probeGraphQLIntrospection("https://example.com", EMPTY_SESSION, mockFetch);
  const suggestionFinding = findings.find((f) => f.type === "graphql-field-suggestion-leak");
  if (!suggestionFinding) throw new Error("Expected a graphql-field-suggestion-leak finding");
  assert.strictEqual(suggestionFinding.severity, "LOW");
  assert.ok(suggestionFinding.evidence.includes("user"));
});

test("probeGraphQLBatchedQueries detects server accepting batched operation arrays", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (!Array.isArray(body)) {
      return new Response(JSON.stringify({ data: { __typename: "Query" } }),
        { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify(body.map(() => ({ data: { __typename: "Query" } }))),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const finding = await probeGraphQLBatchedQueries("https://example.com", EMPTY_SESSION, mockFetch);
  if (!finding) throw new Error("Expected a batched query finding");
  assert.strictEqual(finding.type, "graphql-batched-queries");
  assert.strictEqual(finding.severity, "HIGH");
  assert.strictEqual(finding.isVerified, true);
  assert.ok(finding.evidence.includes("50 operations"));
});

test("probeGraphQLBatchedQueries does not flag a server that rejects batch arrays", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    if (Array.isArray(body)) {
      return new Response(JSON.stringify({ errors: [{ message: "Batching is not supported" }] }),
        { status: 400, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ data: { __typename: "Query" } }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };
  assert.strictEqual(await probeGraphQLBatchedQueries("https://example.com", EMPTY_SESSION, mockFetch), null);
});

test("probeGraphQLAliasFlooding detects server resolving 100 aliased fields", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    const aliasCount = (body?.query?.match(/a\d+: __typename/g) ?? []).length;
    if (aliasCount >= 100) {
      const data: Record<string, string> = {};
      for (let i = 0; i < aliasCount; i++) data[`a${i}`] = "Query";
      return new Response(JSON.stringify({ data }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ data: { __typename: "Query" } }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const finding = await probeGraphQLAliasFlooding("https://example.com", EMPTY_SESSION, mockFetch);
  if (!finding) throw new Error("Expected an alias flooding finding");
  assert.strictEqual(finding.type, "graphql-dos-alias-flooding");
  assert.strictEqual(finding.severity, "HIGH");
  assert.ok(finding.evidence.includes("100 aliased field"));
});

test("probeGraphQLAliasFlooding does not flag a server that enforces an alias complexity limit", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    const aliasCount = (body?.query?.match(/a\d+: __typename/g) ?? []).length;
    if (aliasCount >= 100) {
      return new Response(
        JSON.stringify({ errors: [{ message: "Alias limit exceeded: too many aliases in a single query" }] }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
    return new Response(JSON.stringify({ data: { __typename: "Query" } }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };
  assert.strictEqual(await probeGraphQLAliasFlooding("https://example.com", EMPTY_SESSION, mockFetch), null);
});

test("probeGraphQLDoS does not flag an endpoint that enforces query depth limits", async () => {
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    const nestingLevel = ((body?.query ?? "").match(/\{/g) ?? []).length;
    if (nestingLevel > 5) {
      return new Response(
        JSON.stringify({ errors: [{ message: "Query depth limit exceeded: max depth is 5" }] }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    return new Response(JSON.stringify({ data: { __typename: "Query" } }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };
  assert.strictEqual(
    await probeGraphQLDoS("https://example.com", EMPTY_SESSION, mockFetch),
    null,
    "A server enforcing depth limits should not be flagged"
  );
});

// ── SSTI Probes ───────────────────────────────────────────────────────────────

test("probeSSTI detects Jinja2/Twig expression execution in URL parameter", async () => {
  // Simulates a server that evaluates {{N*M}} template expressions in query params
  const mockFetch = (url: string): Promise<Response | null> => {
    const u = new URL(url);
    const val = u.searchParams.get("q") ?? "";
    // Evaluate all {{N*M}} patterns, returning the computed product
    const rendered = val.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
    return Promise.resolve(new Response(rendered, { status: 200, headers: { "Content-Type": "text/html" } }));
  };

  const finding = await probeSSTI("https://example.com/search?q=hello", mockFetch as any);
  if (!finding) throw new Error("Expected an SSTI finding");
  assert.strictEqual(finding.type, "ssti-injection");
  assert.strictEqual(finding.severity, "CRITICAL");
  assert.strictEqual(finding.parameter, "q");
  assert.strictEqual(finding.isVerified, true);
  assert.ok(finding.evidence.includes("Jinja2"), "Evidence should name the template engine family");
  assert.ok(finding.evidence.includes("756877"), "Evidence should contain the evaluated marker");
});

test("probeSSTI does not flag a server that reflects {{N*M}} literally (pure reflection, no execution)", async () => {
  // Server echoes the raw payload string — this is NOT SSTI, just reflected input
  const mockFetch = (url: string): Promise<Response | null> => {
    const u = new URL(url);
    const val = u.searchParams.get("q") ?? "";
    return Promise.resolve(new Response(`You searched for: ${val}`, {
      status: 200, headers: { "Content-Type": "text/html" },
    }));
  };
  const finding = await probeSSTI("https://example.com/search?q=hello", mockFetch as any);
  assert.strictEqual(finding, null, "Pure reflection without evaluation must not be flagged");
});

test("probeRestApiSSTI detects SSTI in a JSON body field (name field evaluated by template engine)", async () => {
  // Simulates a REST API that renders the 'name' field through a Jinja2-like template engine
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    const rendered: Record<string, any> = {};
    for (const [k, v] of Object.entries(body)) {
      rendered[k] = typeof v === "string"
        ? v.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_, a, b) => String(Number(a) * Number(b)))
        : v;
    }
    return new Response(JSON.stringify({ message: `Hello ${rendered.name ?? ""}`, ...rendered }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };

  const finding = await probeRestApiSSTI("https://example.com", EMPTY_SESSION, mockFetch);
  if (!finding) throw new Error("Expected an SSTI finding from the REST API probe");
  assert.strictEqual(finding.type, "ssti-injection-rest");
  assert.strictEqual(finding.severity, "CRITICAL");
  assert.strictEqual(finding.isVerified, true);
  assert.ok(finding.evidence.includes("756877"), "Evidence should contain the evaluated marker value");
  assert.ok(finding.evidence.includes("Jinja2"), "Evidence should identify the engine family");
});

test("probeRestApiSSTI does not flag a server that echoes payload verbatim (no template evaluation)", async () => {
  // Server stores and returns the field value unchanged — no template engine involved
  const mockFetch = async (_url: string, init?: RequestInit): Promise<Response | null> => {
    const body = JSON.parse(init?.body as string);
    return new Response(JSON.stringify({ echo: body, message: `Hello ${body.name ?? ""}` }),
      { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const finding = await probeRestApiSSTI("https://example.com", EMPTY_SESSION, mockFetch);
  assert.strictEqual(finding, null, "Verbatim echo without evaluation must not be flagged");
});

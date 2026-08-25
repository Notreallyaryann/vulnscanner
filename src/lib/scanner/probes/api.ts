import SwaggerParser from "@apidevtools/swagger-parser";
import { AuthSession, EMPTY_SESSION, FETCH_HEADERS, PendingFinding } from "../types";
import { authedFetch, safeFetch } from "../session";

export async function checkGraphQLIntrospection(
  baseUrl: string,
  sessionOrFetch?: AuthSession | ((url: string, init?: RequestInit) => Promise<Response | null>),
  authedFetchFn?: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<PendingFinding | null> {
  const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"];
  let fetcher: (url: string, init?: RequestInit) => Promise<Response | null>;
  if (typeof sessionOrFetch === "function") {
    fetcher = sessionOrFetch;
  } else if (authedFetchFn) {
    fetcher = authedFetchFn;
  } else {
    const session = (sessionOrFetch as AuthSession) || EMPTY_SESSION;
    fetcher = (u, init) => authedFetch(u, init, 8000, false, session);
  }
  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();
      const resp = await fetcher(u, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      });
      if (!resp || resp.status !== 200) continue;
      const json = await resp.json().catch(() => null);
      if (json?.data?.__schema) {
        return {
          type: "graphql-introspection",
          severity: "MEDIUM",
          url: u,
          evidence: `GraphQL Introspection is enabled at ${path}. Attackers can extract the complete GraphQL schema and query structure.`,
          cvssScore: 5.3,
          cveId: "CWE-200",
          confidence: 0.99,
          validationSteps: [
            `Sent introspection query to ${u}`,
            `Server returned HTTP 200 with full schema definition`,
          ],
          isVerified: true,
        };
      }
    } catch {}
  }
  return null;
}

/**
 * Probes GraphQL endpoints for injection vulnerabilities (SQLi, NoSQLi, SSTI)
 * injected through GraphQL query variables and inline arguments.
 */
export async function probeGraphQLInjection(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION
): Promise<PendingFinding | null> {
  const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"];
  const SQLI_PATTERNS = [
    /SQL syntax.*MySQL/i, /PostgreSQL.*ERROR/i, /SQLITE_ERROR/i,
    /SequelizeDatabaseError/i, /ORA-\d{4}/i, /You have an error in your SQL syntax/i,
    /near ".*": syntax error/i, /unrecognized token/i,
  ];

  const injections = [
    { value: "' OR 1=1--", type: "SQL Injection", cwe: "CWE-89", cvss: 9.1 },
    { value: '{"$gt":""}', type: "NoSQL Injection", cwe: "CWE-943", cvss: 9.1 },
    { value: "{{7*7}}", type: "SSTI", cwe: "CWE-94", cvss: 8.5 },
  ];

  const buildQueries = (p: string) => [
    { q: `query { search(query: "${p}") { id } }`, field: "query" },
    { q: `mutation { login(email: "${p}", password: "test") { token } }`, field: "email" },
    { q: `query { user(id: "${p}") { id } }`, field: "id" },
  ];

  for (const path of GRAPHQL_PATHS) {
    const u = new URL(path, baseUrl).toString();
    try {
      const probe = await authedFetch(u, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ __typename }" }),
      }, 5000, false, session);
      if (!probe || probe.status === 404 || probe.status >= 502) continue;

      for (const { value, type, cwe, cvss } of injections) {
        for (const { q, field } of buildQueries(value)) {
          try {
            const resp = await authedFetch(u, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ query: q }),
            }, 7000, false, session);
            if (!resp) continue;
            const text = await resp.text();
            const hasDbError = SQLI_PATTERNS.some((p) => p.test(text));
            const hasSSTE = type === "SSTI" && text.includes("49");
            if (hasDbError || hasSSTE) {
              return {
                type: "graphql-injection",
                severity: "CRITICAL",
                url: u,
                parameter: field,
                evidence: `GraphQL ${type} detected at ${u}. Field "${field}" accepted payload "${value}" and triggered a backend error or execution pattern.`,
                cvssScore: cvss,
                cveId: cwe,
                confidence: 0.88,
                validationSteps: [
                  `Injected ${type} payload "${value}" into GraphQL field "${field}"`,
                  `Response contained database error or template execution signal`,
                ],
                isVerified: true,
              };
            }
          } catch { /* next */ }
        }
      }
    } catch { /* endpoint not available */ }
  }
  return null;
}

export async function probeNoSQLiJson(
  targetUrl: string,
  fields: string[],
  sessionOrFetch?: AuthSession | ((url: string, init?: RequestInit) => Promise<Response | null>),
  authedFetchFn?: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<PendingFinding | null> {
  if (fields.length === 0) return null;
  let fetcher: (url: string, init?: RequestInit) => Promise<Response | null>;
  if (typeof sessionOrFetch === "function") {
    fetcher = sessionOrFetch;
  } else if (authedFetchFn) {
    fetcher = authedFetchFn;
  } else {
    const session = (sessionOrFetch as AuthSession) || EMPTY_SESSION;
    fetcher = (u, init) => authedFetch(u, init, 8000, false, session);
  }
  for (const field of fields) {
    try {
      const nosqlBody: Record<string, any> = {};
      for (const f of fields) {
        nosqlBody[f] = f === field ? { "$ne": "invalid_probe_val" } : "test";
      }
      const resp = await fetcher(targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(nosqlBody),
      });
      if (!resp) continue;
      const status = resp.status;
      const text = await resp.text();
      if (status === 200 && (text.includes("token") || text.includes("success") || text.includes("user") || text.includes("id"))) {
        return {
          type: "nosqli",
          severity: "CRITICAL",
          url: targetUrl,
          parameter: field,
          evidence: `NoSQL Injection operator '\$ne' accepted on JSON endpoint parameter '${field}'. Returned HTTP ${status}.`,
          cvssScore: 9.1,
          cveId: "CWE-943",
          confidence: 0.92,
          validationSteps: [
            `Injected NoSQL object operator '{ "${field}": { "\$ne": "invalid_probe_val" } }'`,
            `Received HTTP ${status} success response indicating query operator execution`,
          ],
          isVerified: true,
        };
      }
    } catch {}
  }
  return null;
}

/**
 * Tests if the server honors HTTP method override headers used to bypass method-based ACLs.
 */
export async function probeHTTPMethodOverride(targetUrl: string): Promise<PendingFinding | null> {
  const OVERRIDE_PATHS = ["/api/users", "/api/v1/users", "/api/admin", "/api/accounts", "/api/settings"];
  const OVERRIDE_HEADERS = [
    { header: "X-HTTP-Method-Override", value: "DELETE" },
    { header: "X-HTTP-Method", value: "DELETE" },
    { header: "X-Method-Override", value: "PUT" },
  ];
  for (const path of OVERRIDE_PATHS) {
    try {
      const url = new URL(path, targetUrl).toString();
      const baseline = await safeFetch(url, 5000);
      if (!baseline || baseline.status === 404) continue;
      const baselineStatus = baseline.status;
      for (const { header, value } of OVERRIDE_HEADERS) {
        try {
          const resp = await fetch(url, {
            method: "POST",
            headers: { ...FETCH_HEADERS, [header]: value, "Content-Type": "application/json" },
            body: JSON.stringify({}),
            signal: AbortSignal.timeout(6000),
            next: { revalidate: 0 },
          }).catch(() => null);
          if (!resp) continue;
          if (resp.status === 401 || resp.status === 403 || resp.status === 405 || resp.status === 404) continue;
          if (resp.status !== baselineStatus) {
            return {
              type: "http-method-override",
              severity: "MEDIUM",
              url,
              parameter: header,
              evidence: `HTTP Method Override accepted at ${url}. POST with "${header}: ${value}" returned HTTP ${resp.status} (baseline POST was ${baselineStatus}). This can bypass method-based access controls.`,
              cvssScore: 6.5,
              cveId: "CWE-650",
              confidence: 0.82,
              validationSteps: [
                `Baseline POST ${url} returned HTTP ${baselineStatus}`,
                `POST with header "${header}: ${value}" returned HTTP ${resp.status}`,
              ],
              isVerified: true,
            };
          }
        } catch { /* next override */ }
      }
    } catch { /* skip */ }
  }
  return null;
}

/**
 * Scans discovered API endpoints for sensitive data exposed without authentication.
 * Detects AWS keys, private keys, bcrypt hashes, JWTs in response bodies.
 */
export async function probeApiSensitiveDataExposure(
  targetUrl: string,
  apiEndpoints: string[]
): Promise<PendingFinding | null> {
  const PII_PATTERNS: Array<{ label: string; re: RegExp }> = [
    { label: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
    { label: "Private Key header", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
    { label: "JWT token in body", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
    { label: "bcrypt password hash", re: /\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}/ },
    { label: "Database connection string", re: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s"']{8,}/ },
    { label: "Bulk user email list", re: /("email"\s*:\s*"[^"@]{2,}@[^"]{2,}"\s*,?\s*){3,}/ },
    { label: "Social Security Number", re: /\b\d{3}-\d{2}-\d{4}\b/ },
  ];

  const endpointsToTest = [...new Set([
    "/api/users", "/api/v1/users", "/api/customers", "/api/orders",
    "/api/me", "/api/admin/users", "/api/all-users",
    ...apiEndpoints.filter((e) => /\/api\//i.test(e)),
  ])].slice(0, 15);

  for (const path of endpointsToTest) {
    try {
      const url = path.startsWith("http") ? path : new URL(path, targetUrl).toString();
      const resp = await safeFetch(url, 6000);
      if (!resp || resp.status !== 200) continue;
      const ct = resp.headers.get("content-type") || "";
      if (!ct.includes("json")) continue;
      const body = await resp.text();
      if (body.length < 30) continue;
      for (const { label, re } of PII_PATTERNS) {
        const match = re.exec(body);
        if (match) {
          const masked = match[0].slice(0, 8) + "****";
          return {
            type: "api-sensitive-data-exposure",
            severity: "HIGH",
            url,
            evidence: `API endpoint exposed sensitive data (${label}) without authentication. Pattern "${masked}..." found in unauthenticated response from ${url}.`,
            cvssScore: 8.6,
            cveId: "CWE-200",
            confidence: 0.90,
            validationSteps: [
              `GET ${url} returned HTTP 200 with application/json (no auth)`,
              `Response body matched "${label}" pattern`,
            ],
            isVerified: true,
          };
        }
      }
    } catch { /* skip */ }
  }
  return null;
}

export async function discoverOpenApiEndpoints(
  baseUrl: string,
  log: (m: string) => void
): Promise<{ path: string; fields: string[] }[]> {
  const SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/v1/swagger.json", "/v2/api-docs", "/v3/api-docs",
  ];
  const results: { path: string; fields: string[] }[] = [];

  const parseSpec = async (specUrl: string): Promise<number> => {
    try {
      const api = (await SwaggerParser.parse(specUrl)) as any;
      const paths = api?.paths || {};
      let count = 0;
      for (const [path, pathItem] of Object.entries(paths as Record<string, any>)) {
        const methods = ["get", "post", "put", "patch", "delete"] as const;
        for (const method of methods) {
          const operation = (pathItem as any)?.[method];
          if (!operation) continue;
          const fields = new Set<string>();
          const params: any[] = operation.parameters || (pathItem as any).parameters || [];
          for (const p of params) { if (p?.name) fields.add(p.name); }
          const reqBodySchema = operation?.requestBody?.content?.["application/json"]?.schema;
          if (reqBodySchema?.properties) {
            for (const propName of Object.keys(reqBodySchema.properties)) fields.add(propName);
          }
          if (fields.size > 0) { results.push({ path, fields: [...fields] }); count++; }
        }
      }
      return count;
    } catch { return 0; }
  };

  for (const specPath of SPEC_PATHS) {
    try {
      const specUrl = new URL(specPath, baseUrl).toString();
      const probe = await fetch(specUrl, {
        headers: { ...FETCH_HEADERS, Accept: "application/json, application/yaml, */*" },
        signal: AbortSignal.timeout(5000),
        next: { revalidate: 0 },
      }).catch(() => null);
      if (!probe || probe.status !== 200) continue;
      const ct = (probe.headers.get("content-type") || "").toLowerCase();
      const body = await probe.text();

      if (ct.includes("json") || ct.includes("yaml") || body.trim().startsWith("{")) {
        log(`📖  OpenAPI spec found at ${specPath} — parsing endpoint surface...`);
        const count = await parseSpec(specUrl);
        if (count > 0) { log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) from ${specPath}`); break; }
      }

      if (ct.includes("html") || body.includes("swagger-ui") || body.includes("SwaggerUI")) {
        const urlMatch =
          body.match(/[Uu][Rr][Ll]\s*:\s*["']([^"']+\.(?:json|yaml))["']/) ||
          body.match(/[Uu][Rr][Ll]\s*:\s*["'](\/[^"']{4,80})["']/) ||
          body.match(/spec-url=["']([^"']+)["']/) ||
          body.match(/data-url=["']([^"']+)["']/);
        if (urlMatch) {
          const embeddedSpecUrl = new URL(urlMatch[1], baseUrl).toString();
          log(`📖  Swagger UI at ${specPath} — extracting spec from ${urlMatch[1]}...`);
          const count = await parseSpec(embeddedSpecUrl);
          if (count > 0) { log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) via Swagger UI at ${specPath}`); break; }
        }
        const jsonFallback = specUrl.replace(/\/?$/, ".json").replace(".json.json", ".json");
        if (jsonFallback !== specUrl) {
          const count = await parseSpec(jsonFallback);
          if (count > 0) { log(`🗂️   OpenAPI: discovered ${count} parameterized endpoint(s) from ${jsonFallback}`); break; }
        }
      }
    } catch { /* spec not found */ }
  }
  return results;
}

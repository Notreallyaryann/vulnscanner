import SwaggerParser from "@apidevtools/swagger-parser";
import { AuthSession, CONFIDENCE, EMPTY_SESSION, FETCH_HEADERS, PendingFinding } from "../types";
import { authedFetch, safeFetch } from "../session";

// ─── Shared ──────────────────────────────────────────────────────────────────

const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/playground", "/query"] as const;

type Fetcher = (url: string, init?: RequestInit) => Promise<Response | null>;

/** Resolve a Fetcher from either a raw function or an AuthSession. */
function resolveFetcher(session: AuthSession, fetchFn?: Fetcher): Fetcher {
  return fetchFn ?? ((u, init) => authedFetch(u, init ?? {}, 8000, false, session));
}

/** POST a GraphQL JSON body and return the parsed JSON (or null on failure). */
async function gqlPost(fetcher: Fetcher, url: string, body: object, timeoutMs = 8000): Promise<any | null> {
  try {
    const resp = await fetcher(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp) return null;
    const text = await resp.text().catch(() => "");
    try { return { status: resp.status, json: JSON.parse(text) }; }
    catch { return { status: resp.status, json: null, raw: text }; }
  } catch {
    return null;
  }
}

/** Detect whether a URL is a live (non-404) GraphQL endpoint. */
async function detectGraphQLEndpoint(fetcher: Fetcher, baseUrl: string): Promise<string | null> {
  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();
      // A minimal introspection ping — every spec-compliant server returns data or errors, never 404
      const result = await gqlPost(fetcher, u, { query: "{ __typename }" });
      if (!result) continue;
      if (result.status === 404 || result.status >= 502) continue;
      // Accept 200, 400 (query errors still mean GraphQL is alive), 405
      return u;
    } catch { /* try next */ }
  }
  return null;
}

// ─── 1. Introspection Leak ────────────────────────────────────────────────────

/** Full introspection schema dump + field suggestion harvesting via deliberate typos. */
export async function probeGraphQLIntrospection(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION,
  fetchFn?: Fetcher
): Promise<PendingFinding[]> {
  const findings: PendingFinding[] = [];
  const fetcher = resolveFetcher(session, fetchFn);

  const FULL_INTROSPECTION_QUERY = `
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind name description
          fields(includeDeprecated: true) {
            name description isDeprecated deprecationReason
            args { name description type { kind name ofType { kind name } } }
            type { kind name ofType { kind name } }
          }
          inputFields {
            name description
            type { kind name ofType { kind name } }
          }
          enumValues(includeDeprecated: true) { name description isDeprecated }
        }
        directives {
          name description locations
          args { name description type { kind name ofType { kind name } } }
        }
      }
    }
  `;

  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();

      // Step 1: Full introspection dump
      const result = await gqlPost(fetcher, u, { query: FULL_INTROSPECTION_QUERY });
      if (!result || result.status !== 200) continue;

      const schema = result.json?.data?.__schema;
      if (schema) {
        const typeCount = (schema.types as any[])?.filter(
          (t: any) => !t.name?.startsWith("__")
        ).length ?? 0;
        const mutationTypeName = schema.mutationType?.name ?? "none";

        findings.push({
          type: "graphql-introspection",
          severity: "MEDIUM",
          url: u,
          evidence:
            `GraphQL Introspection fully enabled at ${u}. ` +
            `Complete schema dumped: ${typeCount} user-defined type(s) exposed including mutation root "${mutationTypeName}". ` +
            `Attackers can enumerate every query, mutation, field name, argument, and enum value without authentication.`,
          cvssScore: 5.3,
          cveId: "CWE-200",
          confidence: CONFIDENCE.DETERMINISTIC,
          validationSteps: [
            `POST ${u} — full __schema introspection query returned HTTP 200`,
            `Response contained ${typeCount} non-built-in type definitions`,
          ],
          isVerified: true,
        });

        // Step 2: Field suggestion harvesting — send a deliberate typo and parse "Did you mean...?" hints
        const typoResult = await gqlPost(fetcher, u, { query: "{ _usrz }" });
        if (typoResult?.json?.errors) {
          const suggestions: string[] = [];
          for (const err of typoResult.json.errors) {
            const msg: string = err?.message ?? "";
            const match = msg.match(/Did you mean ["']?([\w, "']+)["']?/i);
            if (match) suggestions.push(match[1]);
          }
          if (suggestions.length > 0) {
            findings.push({
              type: "graphql-field-suggestion-leak",
              severity: "LOW",
              url: u,
              evidence:
                `GraphQL field suggestion oracle active at ${u}. ` +
                `Sending a deliberate typo returned: "Did you mean ${suggestions[0]}?". ` +
                `Attackers can brute-force field names without introspection being explicitly enabled.`,
              cvssScore: 3.7,
              cveId: "CWE-203",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [
                `POST ${u} with intentional typo query "{ _usrz }"`,
                `Error response suggested real field names: ${suggestions.join(", ")}`,
              ],
              isVerified: true,
            });
          }
        }
        break; // No need to probe further paths once confirmed
      }

      // Step 2b: Even if full introspection is blocked, check field suggestions alone
      const typoResult2 = await gqlPost(fetcher, u, { query: "{ _usrz }" });
      if (typoResult2?.json?.errors) {
        for (const err of typoResult2.json.errors) {
          const msg: string = err?.message ?? "";
          const match = msg.match(/Did you mean ["']?([\w, "']+)["']?/i);
          if (match) {
            findings.push({
              type: "graphql-field-suggestion-leak",
              severity: "LOW",
              url: u,
              evidence:
                `GraphQL field suggestion oracle active at ${u} even though full introspection is disabled. ` +
                `Typo query returned: "Did you mean ${match[1]}?". ` +
                `Attackers can enumerate real field names character-by-character.`,
              cvssScore: 3.7,
              cveId: "CWE-203",
              confidence: CONFIDENCE.DUAL_VERIFIED,
              validationSteps: [
                `POST ${u} with intentional typo query "{ _usrz }"`,
                `Error contained field name suggestion: "${match[1]}"`,
              ],
              isVerified: true,
            });
            break;
          }
        }
      }
    } catch { /* next path */ }
  }
  return findings;
}

// ─── 2. Deep Nesting DoS ─────────────────────────────────────────────────────

/**
 * Constructs a deeply nested GraphQL query to test for resource exhaustion.
 * e.g. { a { b { a { b { ... } } } } } at configurable depth.
 * A server with no depth limit will attempt to resolve O(2^depth) graph traversals.
 */
export async function probeGraphQLDoS(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION,
  fetchFn?: Fetcher
): Promise<PendingFinding | null> {
  const fetcher = resolveFetcher(session, fetchFn);
  const NESTING_DEPTH = 12; // enough to trigger exhaustion without being abusive
  const TIMEOUT_MS = 10_000;
  const SLOW_THRESHOLD_MS = 3_000; // response slower than this suggests no depth limit

  /** Build a singly-chained nested query: { field { field { ... } } } */
  function buildNestedQuery(fields: string[], depth: number): string {
    let inner = "id";
    for (let i = 0; i < depth; i++) {
      const field = fields[i % fields.length];
      inner = `${field} { ${inner} }`;
    }
    return `{ ${inner} }`;
  }

  // Common relational field names that parsers recurse on
  const RELATIONAL_FIELDS = ["user", "posts", "comments", "author", "friends", "followers", "orders", "items", "node"];

  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();

      // Liveness check: bail if the endpoint doesn't exist
      const ping = await gqlPost(fetcher, u, { query: "{ __typename }" });
      if (!ping || ping.status === 404 || ping.status >= 502) continue;

      const nestedQuery = buildNestedQuery(RELATIONAL_FIELDS, NESTING_DEPTH);

      const start = Date.now();
      const result = await fetcher(u, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: nestedQuery }),
      });
      const elapsed = Date.now() - start;

      if (!result) continue;
      const text = await result.text().catch(() => "");

      // Signals: slow response (no depth guard) OR server-side DoS protection triggered (429/503)
      const isSlowResponse = elapsed >= SLOW_THRESHOLD_MS;
      const isRateLimited = result.status === 429 || result.status === 503;
      const hasDepthError = /max.*depth|query.*depth|depth.*limit|complexity.*exceeded|too.*deep|query.*too.*complex/i.test(text);

      if (isSlowResponse && !hasDepthError) {
        return {
          type: "graphql-dos-deep-nesting",
          severity: "HIGH",
          url: u,
          evidence:
            `GraphQL Deep Nesting DoS: endpoint ${u} responded in ${elapsed}ms to a ${NESTING_DEPTH}-level nested query with no depth-limit error. ` +
            `Attackers can craft malicious queries that exhaust server CPU/memory and cause denial of service.`,
          cvssScore: 7.5,
          cveId: "CWE-400",
          confidence: CONFIDENCE.TIMING_VERIFIED,
          validationSteps: [
            `Sent ${NESTING_DEPTH}-deep nested GraphQL query to ${u}`,
            `Server responded in ${elapsed}ms with no depth-limit enforcement`,
          ],
          isVerified: true,
        };
      }

      if (isRateLimited && !hasDepthError) {
        return {
          type: "graphql-dos-deep-nesting",
          severity: "MEDIUM",
          url: u,
          evidence:
            `GraphQL Deep Nesting probe returned HTTP ${result.status} at ${u}. ` +
            `No query-depth error was returned; the server relies solely on rate limiting for DoS protection. ` +
            `Depth-level query guards are recommended in addition to rate limiting.`,
          cvssScore: 5.3,
          cveId: "CWE-400",
          confidence: CONFIDENCE.SINGLE_PAYLOAD,
          validationSteps: [
            `Sent ${NESTING_DEPTH}-deep nested GraphQL query to ${u}`,
            `Server returned HTTP ${result.status} — no explicit depth guard message`,
          ],
          isVerified: false,
        };
      }
    } catch { /* next */ }
  }
  return null;
}

// ─── 3. Batched Query Rate-Limit Bypass ──────────────────────────────────────

/**
 * Sends an array of GraphQL operations in a single HTTP request.
 * Many servers share the rate-limit budget per HTTP request, not per operation,
 * allowing attackers to amplify requests by 50–100× at no extra cost.
 */
export async function probeGraphQLBatchedQueries(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION,
  fetchFn?: Fetcher
): Promise<PendingFinding | null> {
  const fetcher = resolveFetcher(session, fetchFn);
  const BATCH_SIZE = 50;

  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();

      // Liveness check
      const ping = await gqlPost(fetcher, u, { query: "{ __typename }" });
      if (!ping || ping.status === 404 || ping.status >= 502) continue;

      // Build a batch: 50 identical lightweight introspection operations
      const batch = Array.from({ length: BATCH_SIZE }, (_, i) => ({
        operationName: `Op${i}`,
        query: `query Op${i} { __typename }`,
        variables: {},
      }));

      const result = await gqlPost(fetcher, u, batch);
      if (!result) continue;

      const { status, json } = result;

      // Success: server returned an array of responses (one per operation)
      const serverAcceptedBatch =
        status === 200 &&
        Array.isArray(json) &&
        json.length > 1;

      // Soft signal: server accepted but collapsed to single response
      const serverAcceptedSingle = status === 200 && !Array.isArray(json);

      if (serverAcceptedBatch) {
        return {
          type: "graphql-batched-queries",
          severity: "HIGH",
          url: u,
          evidence:
            `GraphQL Batched Query Attack confirmed at ${u}. ` +
            `A single HTTP POST containing ${BATCH_SIZE} operations returned an array of ${json.length} responses. ` +
            `Attackers can bypass per-request rate limits and amplify brute-force or enumeration attacks ${BATCH_SIZE}×.`,
          cvssScore: 7.5,
          cveId: "CWE-770",
          confidence: CONFIDENCE.EXEC_VERIFIED,
          validationSteps: [
            `Sent array of ${BATCH_SIZE} operations in one POST to ${u}`,
            `Server returned HTTP 200 with array of ${json.length} result objects`,
          ],
          isVerified: true,
        };
      }

      if (serverAcceptedSingle) {
        return {
          type: "graphql-batched-queries",
          severity: "MEDIUM",
          url: u,
          evidence:
            `GraphQL endpoint at ${u} accepted a batched request array (HTTP 200) but returned a single result. ` +
            `The server may process all operations internally before collapsing the response. Manual verification recommended.`,
          cvssScore: 5.3,
          cveId: "CWE-770",
          confidence: CONFIDENCE.SINGLE_PAYLOAD,
          validationSteps: [
            `Sent array of ${BATCH_SIZE} operations in one POST to ${u}`,
            `Server returned HTTP 200 (non-array) — batch may be silently processed`,
          ],
          isVerified: false,
        };
      }
    } catch { /* next */ }
  }
  return null;
}

// ─── 4. Alias Flooding DoS ───────────────────────────────────────────────────

/**
 * Sends a single operation with many aliased field resolvers.
 * Unlike batching (which needs array support), alias flooding works on any GraphQL server
 * and forces N resolver invocations from one request.
 */
export async function probeGraphQLAliasFlooding(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION,
  fetchFn?: Fetcher
): Promise<PendingFinding | null> {
  const fetcher = resolveFetcher(session, fetchFn);
  const ALIAS_COUNT = 100;
  const SLOW_THRESHOLD_MS = 3_000;

  // Build: { a0: __typename a1: __typename ... a99: __typename }
  function buildAliasBomb(count: number): string {
    const aliases = Array.from({ length: count }, (_, i) => `a${i}: __typename`).join(" ");
    return `{ ${aliases} }`;
  }

  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();

      // Liveness check
      const ping = await gqlPost(fetcher, u, { query: "{ __typename }" });
      if (!ping || ping.status === 404 || ping.status >= 502) continue;

      const aliasQuery = buildAliasBomb(ALIAS_COUNT);

      const start = Date.now();
      const result = await fetcher(u, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: aliasQuery }),
      });
      const elapsed = Date.now() - start;

      if (!result) continue;
      const text = await result.text().catch(() => "");

      const hasComplexityError = /alias.*limit|too many alias|complexity|field.*limit/i.test(text);

      if (result.status === 200 && !hasComplexityError) {
        // Count how many alias keys appear in the response — confirms all were resolved
        let resolvedAliases = 0;
        try {
          const json = JSON.parse(text);
          if (json?.data) resolvedAliases = Object.keys(json.data).length;
        } catch { /* estimate */ }

        const isSlowOrAmplified = elapsed >= SLOW_THRESHOLD_MS || resolvedAliases >= ALIAS_COUNT * 0.8;

        if (isSlowOrAmplified) {
          return {
            type: "graphql-dos-alias-flooding",
            severity: "HIGH",
            url: u,
            evidence:
              `GraphQL Alias Flooding DoS: endpoint ${u} resolved ${resolvedAliases} aliased field calls in one request ` +
              `(elapsed: ${elapsed}ms). No alias-count or complexity limit is enforced. ` +
              `Attackers can trigger N resolver executions with a single HTTP request.`,
            cvssScore: 7.5,
            cveId: "CWE-400",
            confidence: resolvedAliases >= ALIAS_COUNT * 0.8 ? CONFIDENCE.EXEC_VERIFIED : CONFIDENCE.TIMING_VERIFIED,
            validationSteps: [
              `Sent query with ${ALIAS_COUNT} aliased __typename resolvers to ${u}`,
              `Server responded in ${elapsed}ms, resolving ${resolvedAliases} alias(es) — no complexity guard`,
            ],
            isVerified: resolvedAliases >= ALIAS_COUNT * 0.8,
          };
        }
      }
    } catch { /* next */ }
  }
  return null;
}

// ─── Master entry point ───────────────────────────────────────────────────────

/**
 * Master GraphQL probe — runs all four attack classes in parallel and returns
 * every finding. Call this from the engine instead of the individual probes.
 */
export async function probeGraphQL(
  baseUrl: string,
  session: AuthSession = EMPTY_SESSION,
  fetchFn?: Fetcher
): Promise<PendingFinding[]> {
  const [introspectionFindings, dosNesting, batchFinding, aliasFinding] = await Promise.all([
    probeGraphQLIntrospection(baseUrl, session, fetchFn),
    probeGraphQLDoS(baseUrl, session, fetchFn),
    probeGraphQLBatchedQueries(baseUrl, session, fetchFn),
    probeGraphQLAliasFlooding(baseUrl, session, fetchFn),
  ]);

  return [
    ...introspectionFindings,
    ...(dosNesting ? [dosNesting] : []),
    ...(batchFinding ? [batchFinding] : []),
    ...(aliasFinding ? [aliasFinding] : []),
  ];
}

/** @deprecated Use probeGraphQL() instead — kept for backward compatibility. */
export async function checkGraphQLIntrospection(
  baseUrl: string,
  sessionOrFetch?: AuthSession | Fetcher,
  authedFetchFn?: Fetcher
): Promise<PendingFinding | null> {
  const session = typeof sessionOrFetch !== "function" ? (sessionOrFetch ?? EMPTY_SESSION) : EMPTY_SESSION;
  const fetchFn = typeof sessionOrFetch === "function" ? sessionOrFetch : authedFetchFn;
  const findings = await probeGraphQLIntrospection(baseUrl, session, fetchFn);
  return findings.find((f) => f.type === "graphql-introspection") ?? null;
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

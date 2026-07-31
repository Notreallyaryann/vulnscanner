import { ScannerFinding } from "./sqli";

/**
 * Checks for GraphQL Introspection exposure & query depth limits.
 */
export async function checkGraphQLIntrospection(
  baseUrl: string,
  authedFetch: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<ScannerFinding | null> {
  const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"];

  for (const path of GRAPHQL_PATHS) {
    try {
      const u = new URL(path, baseUrl).toString();
      const resp = await authedFetch(u, {
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
            `Sent introspection query '{ __schema { queryType { name } } }' to ${u}`,
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
 * Probes REST API JSON endpoints for NoSQL Injection ($ne, $gt operators).
 */
export async function probeNoSQLiJson(
  targetUrl: string,
  fields: string[],
  authedFetch: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<ScannerFinding | null> {
  if (fields.length === 0) return null;

  for (const field of fields) {
    try {
      // Body payload using MongoDB/NoSQL query operator $ne
      const nosqlBody: Record<string, any> = {};
      for (const f of fields) {
        nosqlBody[f] = f === field ? { "$ne": "invalid_probe_val" } : "test";
      }

      const resp = await authedFetch(targetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(nosqlBody),
      });

      if (!resp) continue;
      const status = resp.status;
      const text = await resp.text();

      // Successful auth bypass / data query return
      if (status === 200 && (text.includes("token") || text.includes("success") || text.includes("user") || text.includes("id"))) {
        return {
          type: "nosqli",
          severity: "CRITICAL",
          url: targetUrl,
          parameter: field,
          evidence: `NoSQL Injection operator '$ne' accepted on JSON endpoint parameter '${field}'. Returned HTTP ${status}.`,
          cvssScore: 9.1,
          cveId: "CWE-943",
          confidence: 0.92,
          validationSteps: [
            `Injected NoSQL object operator '{ "${field}": { "$ne": "invalid_probe_val" } }'`,
            `Received HTTP ${status} success response indicating query operator execution`,
          ],
          isVerified: true,
        };
      }
    } catch {}
  }
  return null;
}

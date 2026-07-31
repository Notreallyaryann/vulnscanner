export type PayloadFormat = "URL_PARAM" | "FORM_DATA" | "JSON_BODY" | "GRAPHQL_VAR";

export interface PayloadTarget {
  url: string;
  method: "GET" | "POST" | "PUT" | "PATCH";
  parameter: string;
  format: PayloadFormat;
  payload: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Builds HTTP request configurations for a probe payload in URL query, Form-data, JSON body, or GraphQL.
 */
export function buildPayloadTarget(
  targetUrl: string,
  method: "GET" | "POST" | "PUT" | "PATCH",
  paramName: string,
  payload: string,
  format: PayloadFormat,
  existingFields: string[] = [paramName]
): { fetchUrl: string; options: RequestInit } {
  const headers: Record<string, string> = {};

  if (format === "URL_PARAM" || method === "GET") {
    const u = new URL(targetUrl);
    u.searchParams.set(paramName, payload);
    return {
      fetchUrl: u.toString(),
      options: { method: "GET", headers },
    };
  }

  if (format === "FORM_DATA") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    const bodyParams = new URLSearchParams();
    for (const f of existingFields) {
      bodyParams.set(f, f === paramName ? payload : "test_value");
    }
    return {
      fetchUrl: targetUrl,
      options: { method, headers, body: bodyParams.toString() },
    };
  }

  if (format === "JSON_BODY") {
    headers["Content-Type"] = "application/json";
    const bodyObj: Record<string, any> = {};
    for (const f of existingFields) {
      bodyObj[f] = f === paramName ? payload : "test_value";
    }
    return {
      fetchUrl: targetUrl,
      options: { method, headers, body: JSON.stringify(bodyObj) },
    };
  }

  if (format === "GRAPHQL_VAR") {
    headers["Content-Type"] = "application/json";
    const graphqlPayload = {
      query: `query ProbeQuery($${paramName}: String) { search(${paramName}: $${paramName}) { id } }`,
      variables: { [paramName]: payload },
    };
    return {
      fetchUrl: targetUrl,
      options: { method: "POST", headers, body: JSON.stringify(graphqlPayload) },
    };
  }

  // Fallback GET
  const u = new URL(targetUrl);
  u.searchParams.set(paramName, payload);
  return { fetchUrl: u.toString(), options: { method: "GET", headers } };
}

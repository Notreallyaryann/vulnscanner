import * as acorn from "acorn";
import { simple as walkSimple } from "acorn-walk";

export interface JsAstSinkFinding {
  sinkType: "eval" | "document.write" | "innerHTML" | "Function";
  label: string;
  line?: number;
  snippet?: string;
}

/**
 * Analyzes JavaScript source code using Acorn AST parsing to detect dangerous
 * client-side DOM sinks (eval, Function, document.write, innerHTML).
 *
 * Automatically falls back to null/empty if the code cannot be parsed as valid JS
 * (e.g. TypeScript, JSX, or partial script snippets).
 */
export function analyzeJsAst(code: string): JsAstSinkFinding[] {
  if (!code || typeof code !== "string") return [];

  let ast: acorn.Node | null = null;

  // Try parsing as Module, then as Script
  try {
    ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
  } catch {
    try {
      ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", locations: true });
    } catch {
      // Unparseable (JSX/TS/SyntaxError) — return empty array to trigger regex fallback
      return [];
    }
  }

  if (!ast) return [];

  const findings: JsAstSinkFinding[] = [];
  const lines = code.split("\n");

  const getSnippet = (node: acorn.Node): { line?: number; snippet?: string } => {
    const loc = (node as any).loc;
    if (!loc) return {};
    const lineNum = loc.start.line;
    const rawLine = lines[lineNum - 1] || "";
    return {
      line: lineNum,
      snippet: rawLine.trim().slice(0, 120),
    };
  };

  try {
    walkSimple(ast, {
      CallExpression(node: any) {
        // Check for eval()
        if (node.callee && node.callee.type === "Identifier" && node.callee.name === "eval") {
          const { line, snippet } = getSnippet(node);
          findings.push({
            sinkType: "eval",
            label: "eval() usage",
            line,
            snippet,
          });
        }
        // Check for document.write() or document.writeln()
        if (
          node.callee &&
          node.callee.type === "MemberExpression" &&
          node.callee.object?.type === "Identifier" &&
          node.callee.object.name === "document" &&
          node.callee.property?.type === "Identifier" &&
          (node.callee.property.name === "write" || node.callee.property.name === "writeln")
        ) {
          const { line, snippet } = getSnippet(node);
          findings.push({
            sinkType: "document.write",
            label: `document.${node.callee.property.name}() usage`,
            line,
            snippet,
          });
        }
      },
      NewExpression(node: any) {
        // Check for new Function(...)
        if (node.callee && node.callee.type === "Identifier" && node.callee.name === "Function") {
          const { line, snippet } = getSnippet(node);
          findings.push({
            sinkType: "Function",
            label: "Function() constructor usage",
            line,
            snippet,
          });
        }
      },
      AssignmentExpression(node: any) {
        // Check for element.innerHTML = ... or element.outerHTML = ...
        if (
          node.left &&
          node.left.type === "MemberExpression" &&
          node.left.property &&
          node.left.property.type === "Identifier" &&
          (node.left.property.name === "innerHTML" || node.left.property.name === "outerHTML")
        ) {
          // Check if assignment right side references URL/location sources
          const rightCode = code.slice(node.right.start, node.right.end);
          if (/location|referrer|searchParams|params|query|hash/i.test(rightCode)) {
            const { line, snippet } = getSnippet(node);
            findings.push({
              sinkType: "innerHTML",
              label: `${node.left.property.name} assignment with location/query data`,
              line,
              snippet,
            });
          }
        }
      },
    });
  } catch {
    // AST walk error safety net
  }

  return findings;
}

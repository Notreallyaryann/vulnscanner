---
name: generating-git-patch-remediations
description: Generate clean, minimal unified diffs (.patch files) and unit test regressions to fix discovered security vulnerabilities.
---

# Generating Git Patch Remediations

## Purpose
Produce verified, syntactically correct Git unified diffs (`.patch`) that fix vulnerabilities (such as SQL injection, unvalidated redirects, or vulnerable dependencies) directly in repository files without introducing functional regressions or changing unrelated code formatting.

## Safe operating rules
- Generate minimal diffs that modify only vulnerable statements.
- Follow the existing project's code formatting and syntax standards.
- Include a companion unit or integration test case verifying the fix and preventing regressions.

## Workflow
1. Locate the exact file and line range of the finding.
2. Formulate the parameterized or hardened replacement code.
3. Validate that imports, type definitions, and variable scopes remain intact.
4. Format output as standard Git unified diff (`diff --git a/... b/...`).

## Remediation Format Standard
```diff
diff --git a/src/services/user.ts b/src/services/user.ts
--- a/src/services/user.ts
+++ b/src/services/user.ts
@@ -15,3 +15,3 @@
-  const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
+  const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

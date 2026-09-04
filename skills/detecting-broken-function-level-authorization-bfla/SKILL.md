---
name: detecting-broken-function-level-authorization-bfla
description: Detect Broken Function Level Authorization (BFLA) and vertical privilege escalation across sensitive API routes and administrative functions.
---

# Detecting Broken Function Level Authorization (BFLA)

## Purpose
Audit API endpoints for Broken Function Level Authorization (OWASP API Security Top 10 - API5:2023). BFLA occurs when applications rely on UI obfuscation or client-side checks rather than enforcing server-side role-based access control (RBAC), allowing standard or unauthenticated users to access administrative, audit, or sensitive operational endpoints.

## Safe operating rules
- Only assess systems you own or have explicit authorization to test.
- Prefer read-only probes (e.g. GET/OPTIONS requests or non-destructive status checks) against administrative endpoints.
- Do not execute destructive administrative actions (e.g. `DELETE /api/users`, user role modification, tenant wiping).
- Test systematically across authenticated contexts: Unauthenticated vs Low-Privilege User vs High-Privilege Admin.
- Record endpoint, HTTP method, response status codes, and leaked object properties for every finding.

## Workflow
1. Identify administrative and privileged API routes from OpenAPI/Swagger schemas, client JS bundles, or route definitions (e.g. `/api/admin/*`, `/api/v1/manage/*`, `/api/v1/audit-logs`).
2. Dispatch test requests under:
   - Unauthenticated context (no tokens)
   - Standard user context (low-privilege JWT or session)
3. Check for successful response codes (200, 201, 204) vs expected access control rejections (401 Unauthorized, 403 Forbidden).
4. Verify response bodies for sensitive administrative data leakage (e.g. system configurations, tenant lists, user management records).
5. Assign CVSS severity (High or Critical) and assign remediation tasks.
6. Provide remediation guidance (enforce centralized middleware authorization guards and deny-by-default RBAC policies).

## Script
The `scripts/audit_bfla.py` script tests sensitive endpoints against unauthenticated and low-privilege tokens to flag improper access allowances.

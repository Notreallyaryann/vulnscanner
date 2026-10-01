---
name: detecting-csrf-vulnerabilities
description: Audit web applications for Cross-Site Request Forgery (CSRF) vulnerabilities, missing anti-CSRF tokens, and SameSite cookie configurations.
---

# Detecting CSRF Vulnerabilities

## Purpose
Identify endpoints and state-changing actions susceptible to Cross-Site Request Forgery due to missing anti-forgery tokens, overly permissive cookie flags, or state-changing operations triggered via HTTP GET.

## Safe operating rules
- Only test systems where you have authorization.
- Active payload testing is permitted: submit state-changing test requests (omitting anti-CSRF tokens or using cross-origin Origin/Referer headers) against authorized target environments to confirm defense enforcement.
- Verify CSRF defenses actively through form/API submission and passively by inspecting session cookie attributes (`SameSite=Strict|Lax`), form hidden inputs (`_csrf`, `csrf_token`), and `Origin` / `Referer` validation middleware.

## Workflow
1. Identify all state-changing endpoints (POST, PUT, DELETE, PATCH, or unsafe GETs) and HTML forms.
2. Check if the session authentication cookie is configured with `SameSite=None` or lacks `SameSite`.
3. Check for Anti-CSRF token verification middleware (e.g. `csurf`, `lusca`, `django.middleware.csrf.CsrfViewMiddleware`).
4. Actively test whether state-altering requests (forms and API endpoints) succeed when:
   - Anti-CSRF tokens (`_csrf`, `csrf_token`, `__VIEWSTATE`) are omitted or set to arbitrary invalid values.
   - Cross-origin headers (`Origin: https://evil-attacker.test`, `Referer`) are supplied.
   - Custom headers (`X-Requested-With`, `X-CSRF-Token`) are omitted on simple content types (`application/x-www-form-urlencoded`).
5. Validate server responses: confirm vulnerability when the server accepts cross-origin state changes with HTTP 200/redirects without rejecting the Origin or requiring anti-forgery tokens.

## Remediation Guidance
- Configure session cookies with `SameSite=Lax` or `SameSite=Strict` and `Secure=true`.
- Use the Double Submit Cookie pattern or synchronized anti-CSRF tokens for all state-altering forms.
- Require custom request headers (e.g., `X-Requested-With` or `Authorization: Bearer <token>`) for single-page applications, which are protected by CORS preflight.

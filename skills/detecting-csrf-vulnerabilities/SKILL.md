---
name: detecting-csrf-vulnerabilities
description: Audit web applications for Cross-Site Request Forgery (CSRF) vulnerabilities, missing anti-CSRF tokens, and SameSite cookie configurations.
---

# Detecting CSRF Vulnerabilities

## Purpose
Identify endpoints and state-changing actions susceptible to Cross-Site Request Forgery due to missing anti-forgery tokens, overly permissive cookie flags, or state-changing operations triggered via HTTP GET.

## Safe operating rules
- Only test systems where you have authorization.
- Do not submit unsolicited state-changing payloads against production environments.
- Verify CSRF defenses passively by inspecting session cookie attributes (`SameSite=Strict|Lax`), form hidden inputs (`_csrf`, `csrf_token`), and `Origin` / `Referer` validation middleware.

## Workflow
1. Identify all state-changing endpoints (POST, PUT, DELETE, PATCH, or unsafe GETs).
2. Check if the session authentication cookie is configured with `SameSite=None` without custom header verification.
3. Check for Anti-CSRF token verification middleware (e.g. `csurf`, `lusca`, `django.middleware.csrf.CsrfViewMiddleware`).
4. Test whether sensitive API requests succeed when custom headers (`X-Requested-With`, `X-CSRF-Token`) and body tokens are omitted.

## Remediation Guidance
- Configure session cookies with `SameSite=Lax` or `SameSite=Strict` and `Secure=true`.
- Use the Double Submit Cookie pattern or synchronized anti-CSRF tokens for all state-altering forms.
- Require custom request headers (e.g., `X-Requested-With` or `Authorization: Bearer <token>`) for single-page applications, which are protected by CORS preflight.

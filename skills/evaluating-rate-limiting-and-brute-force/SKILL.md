---
name: evaluating-rate-limiting-and-brute-force
description: Evaluate sensitive authentication, OTP verification, and password reset endpoints for missing rate limits and brute-force defenses.
---

# Evaluating Rate Limiting and Brute-Force Defenses

## Purpose
Identify critical endpoints (e.g. `/api/auth/login`, `/api/auth/verify-otp`, `/api/auth/forgot-password`, `/api/v1/payment/charge`) that lack sliding-window rate limiting, exponential backoff, or IP/account-based throttling, exposing the application to credential stuffing and brute-force attacks.

## Safe operating rules
- Only test systems with authorization.
- Do not perform high-volume DDoS testing.
- Send a minimal burst (e.g. 5–10 requests) with harmless test credentials to observe response codes (`429 Too Many Requests`) and rate-limit headers (`Retry-After`, `X-RateLimit-Remaining`).

## Workflow
1. Map high-risk endpoints (login, register, forgot-password, OTP, API key generation).
2. Inspect server code for rate-limiting middleware (e.g. `express-rate-limit`, `rate-limiter-flexible`, Redis token bucket).
3. Check dynamic responses for standard rate-limit headers (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `Retry-After`).

## Remediation Guidance
- Implement distributed rate limiting (e.g. Redis sliding window):
  ```typescript
  import rateLimit from "express-rate-limit";

  export const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many login attempts, please try again later." },
  });
  ```
- Implement account lockout / CAPTCHA challenges after consecutive failed login attempts.

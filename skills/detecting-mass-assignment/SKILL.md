---
name: detecting-mass-assignment
description: Detect mass assignment and auto-binding vulnerabilities allowing unintended record modifications and privilege escalation.
---

# Detecting Mass Assignment Vulnerabilities

## Purpose
Identify unsafe object binding patterns where entire HTTP request payloads (`req.body`, `params`) are passed directly into database creation or update methods (e.g. `User.create(req.body)`), enabling attackers to modify sensitive attributes such as `role`, `isAdmin`, `is_verified`, or `account_balance`.

## Safe operating rules
- Only test systems with authorization.
- In static code review, check whether ORM calls use raw request bodies without DTO schema validation or field whitelisting.
- In API testing, use harmless metadata test fields without elevating permissions.

## Workflow
1. Identify all POST, PUT, and PATCH controller endpoints updating database models.
2. Check if ORM update methods accept untyped `req.body` directly.
3. Check for the use of validation schemas (Zod, Joi, class-validator, Marshmallow, Pydantic) that enforce strict property whitelisting.

## Remediation Guidance
- Explicitly pick or destructure only permissible fields:
  ```typescript
  // Insecure:
  await prisma.user.update({ where: { id: userId }, data: req.body });

  // Secure (Explicit Whitelist):
  const { name, bio, avatarUrl } = req.body;
  await prisma.user.update({
    where: { id: userId },
    data: { name, bio, avatarUrl }
  });
  ```
- Use strict schema validation with libraries like Zod: `const safeData = userUpdateSchema.strict().parse(req.body);`

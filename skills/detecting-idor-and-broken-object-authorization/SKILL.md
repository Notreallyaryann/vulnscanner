---
name: detecting-idor-and-broken-object-authorization
description: Identify Insecure Direct Object References (IDOR) and Broken Object-Level Authorization (BOLA) in API routes and database queries.
---

# Detecting IDOR and Broken Object Authorization

## Purpose
Identify broken access control patterns where database records or objects are accessed using user-supplied IDs without verifying that the authenticated user owns or has authorization to access the specific object.

## Safe operating rules
- Only assess systems with explicit authorization and pre-provisioned multi-tenant test accounts.
- Use distinct low-privileged test accounts (User A and User B) to test object isolation safely.
- In static code analysis, flag queries where primary keys are looked up directly from `req.params` or `req.query` without scoping to `req.user.id` or checking tenancy relationships.
- Do not modify, tamper with, or delete data belonging to other accounts.

## Workflow
1. Map API routes accepting identifiers (e.g. `/api/documents/:id`, `/api/orders/:orderId`, `/api/users/:userId/settings`).
2. Examine whether the backend authorization middleware verifies ownership or RBAC permissions prior to fetching.
3. In ORM/Database queries, verify whether queries include a tenancy filter (e.g., `where: { id, userId: currentUser.id }`).
4. Generate remediation recommendations with Row-Level Security (RLS) or ownership enforcement patterns.

## Remediation Guidance
- Scope all object queries to the authenticated session user:
  ```typescript
  // Insecure:
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  
  // Secure:
  const order = await prisma.order.findFirst({
    where: { id: req.params.id, userId: req.user.id }
  });
  if (!order) throw new NotFoundException();
  ```
- Implement centralized Policy Enforcement Points (PEP) or Attribute-Based Access Control (ABAC).

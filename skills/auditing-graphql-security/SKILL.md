---
name: auditing-graphql-security
description: Audit GraphQL endpoints for introspection exposure, query depth and complexity limits, field suggestions, and batching attacks.
---

# Auditing GraphQL Security

## Purpose
Evaluate GraphQL API endpoints for security misconfigurations including public schema introspection in production environments, lack of query depth limiting (DoS via recursive relationships), field-level authorization bypass, and batch request flooding.

## Safe operating rules
- Only assess authorized endpoints.
- Do not send deep recursive queries that cause denial of service.
- Use simple introspection queries (`__schema { types { name } }`) to verify whether introspection is disabled in production.

## Workflow
1. Identify GraphQL endpoints (e.g. `/graphql`, `/api/graphql`, `/v1/graphql`).
2. Send a benign query checking if `__schema` introspection is enabled.
3. Check if query depth limits (e.g. `graphql-depth-limit`) and complexity cost analyzers are configured.
4. Verify if batching / array queries are constrained.

## Remediation Guidance
- Disable introspection in production environments:
  ```typescript
  import { ApolloServer } from "@apollo/server";
  import { ApolloServerPluginLandingPageDisabled } from "@apollo/server/plugin/disabled";

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== "production",
    plugins: process.env.NODE_ENV === "production" ? [ApolloServerPluginLandingPageDisabled()] : [],
  });
  ```
- Implement query depth validation: `validationRules: [depthLimit(5)]`
- Implement query cost analysis and rate-limiting on complex resolver fields.

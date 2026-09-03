---
name: detecting-prototype-pollution
description: Identify prototype pollution vulnerabilities in JavaScript and TypeScript applications resulting from recursive object merges or unvalidated property assignments.
---

# Detecting Prototype Pollution

## Purpose
Identify unsafe property injection patterns in JavaScript/TypeScript where merging, cloning, or setting arbitrary object paths (e.g. `obj[a][b] = value`) modifies `Object.prototype`, affecting all runtime objects and leading to denial of service, authentication bypass, or remote code execution.

## Safe operating rules
- Only test authorized targets.
- In static code review, check merge utilities for lack of key filtering (`__proto__`, `constructor`, `prototype`).
- Do not pollute global prototypes in shared multi-tenant environments.

## Workflow
1. Locate recursive merge, deep clone, or object path setter functions (e.g. `merge(target, source)`, `set(obj, path, val)`).
2. Check if the function explicitly prevents assigning to `__proto__`, `constructor`, and `prototype`.
3. Check for unpatched vulnerable libraries in `package.json` (e.g., outdated `lodash.merge`, `minimist`, `deep-extend`).

## Remediation Guidance
- Filter dangerous prototype keys before assignment:
  ```typescript
  function safeSet(target: any, key: string, value: any) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      return;
    }
    target[key] = value;
  }
  ```
- Use `Object.create(null)` for dictionary lookups to eliminate inheritance from `Object.prototype`.
- Freeze prototypes using `Object.freeze(Object.prototype)` where appropriate.

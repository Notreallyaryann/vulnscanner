---
name: detecting-path-traversal-and-lfi
description: Detect directory traversal and local file inclusion vulnerabilities in file-serving endpoints and filesystem APIs.
---

# Detecting Path Traversal and Local File Inclusion (LFI)

## Purpose
Identify insecure filesystem access patterns where untrusted input containing directory traversal sequences (`../`, `..\`, `%2e%2e%2f`) allows unauthorized reading or writing of arbitrary files on the server.

## Safe operating rules
- Only assess authorized systems.
- Do not attempt to read sensitive operating system files (e.g. `/etc/shadow`, `/etc/passwd`) or private keys.
- In static code review, check if file paths are constructed using string concatenation without path canonicalization (`path.resolve()`, `os.path.abspath()`) or boundary containment checks (`startsWith(baseDir)`).
- Provide safe path normalization and sandboxing recommendations.

## Workflow
1. Identify all file-system read/write sinks (`fs.readFile`, `fs.createReadStream`, `open()`, `send_file`, `include`, `require`).
2. Trace path variables back to user request sources (`req.params`, `req.query`, `req.body.filename`).
3. Verify if safe base directory path validation is enforced using root containment verification.

## Remediation Guidance
- Resolve the target path and assert that it begins strictly with the allowed base directory:
  ```typescript
  import path from "path";

  const safeBaseDir = path.resolve("/app/storage/uploads");
  const resolvedPath = path.resolve(safeBaseDir, req.query.filename);

  if (!resolvedPath.startsWith(safeBaseDir + path.sep)) {
    throw new Error("Access Denied: Path Traversal Detected");
  }
  ```
- Alternatively, store files indexed by UUID and map identifiers in a database rather than exposing raw filesystem paths.

---
name: detecting-command-injection
description: Identify OS command execution flaws and unescaped shell invocations in source code and web endpoints.
---

# Detecting Command Injection

## Purpose
Detect potential OS command injection vulnerabilities in application source code, API parameters, and administrative utilities through static dataflow auditing and non-destructive syntax verification.

## Safe operating rules
- Only assess systems you own or have explicit authorization to test.
- Do not execute destructive commands (e.g. `rm -rf`, disk wipes, reverse shells).
- In source code reviews, trace inputs from HTTP request parameters to shell execution sinks (`exec`, `spawn`, `subprocess.Popen`, `os.system`, `system()`).
- In dynamic testing, use safe, harmless, time-invariant or benign reflection identifiers (e.g. `echo safe_test_token`).
- Document the vulnerable sink, tainted source, affected parameters, and parameterized alternatives.

## Workflow
1. Identify all process-spawning and shell invocation sinks in the codebase.
2. Verify if user-supplied parameters (query strings, headers, body values) flow into the command string without strict whitelisting.
3. Check for the presence of shell interpreter invocations (`shell=True`, `sh -c`, `bash -c`, `cmd.exe /c`).
4. Recommend refactoring shell executions to argument arrays without shell interpolation or using native runtime APIs.

## Remediation Guidance
- Avoid invoking system shell interpreters. Use parameterized process invocation (e.g., `subprocess.run(["ping", "-c", "1", host], shell=False)` in Python, or `execFile("executable", [arg1, arg2])` in Node.js).
- If dynamic arguments must be validated, apply strict allowlists (e.g. alphanumeric regular expressions `^[a-zA-Z0-9_-]+$`).

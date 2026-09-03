---
name: detecting-insecure-file-uploads
description: Audit file upload endpoints and handling logic for missing extension validation, MIME-type spoofing, unconstrained file size, and executable storage paths.
---

# Detecting Insecure File Uploads

## Purpose
Identify insecure file upload handling that could lead to Remote Code Execution (RCE), Cross-Site Scripting (stored HTML/SVG uploads), or server storage exhaustion due to lack of extension whitelisting, MIME validation, or file-type verification.

## Safe operating rules
- Only test systems with authorization.
- Do not upload real web shells or malicious payloads.
- Use safe, inert test files (e.g. text files with harmless metadata) or inspect backend upload logic statically.

## Workflow
1. Identify all multipart form upload endpoints and file handling controllers (`multer`, `formidable`, `busboy`, `django.core.files`).
2. Verify if the file extension is strictly validated against a strict allowlist (not a blocklist).
3. Check if uploaded files are stored inside public web roots where direct script execution is permitted (e.g. `.php`, `.jsp`, `.phtml`, `.cgi`, `.aspx`).
4. Check if file names are regenerated as random UUIDs to avoid path traversal in upload paths.
5. Check if maximum upload size limits (`limits: { fileSize: ... }`) are configured.

## Remediation Guidance
- Never trust the client-provided `Content-Type` header or original filename.
- Validate file magic bytes (signatures) server-side:
  ```typescript
  import fileType from "file-type";
  const type = await fileType.fromBuffer(uploadedBuffer);
  if (!type || !["image/png", "image/jpeg"].includes(type.mime)) {
    throw new Error("Invalid file format");
  }
  ```
- Store uploads outside the web document root or in object storage (AWS S3, GCP Cloud Storage) with private ACLs and serve via signed URLs.
- Regenerate file names as UUIDs (`const safeName = `${crypto.randomUUID()}.${ext}`;`).

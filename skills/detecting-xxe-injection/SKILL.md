---
name: detecting-xxe-injection
description: Detect XML External Entity (XXE) vulnerabilities and unhardened XML parser configurations.
---

# Detecting XML External Entity (XXE) Injection

## Purpose
Identify XML parsers configured without disabling Document Type Definitions (DTD) or external entity resolution (`SYSTEM` entities), which could allow arbitrary file disclosure, SSRF, or denial of service via XML entity expansion.

## Safe operating rules
- Only test authorized targets.
- Do not attempt out-of-band data exfiltration or denial-of-service entity bombs (e.g. Billion Laughs payload).
- Inspect XML parser configurations in source code to verify that DTD processing and external entity resolution are disabled.

## Workflow
1. Identify all XML parsing libraries and endpoints accepting XML/SAML/SOAP payloads.
2. Check parser initialization settings in code (e.g., `libxml2`, `lxml`, `DOMParser`, `XMLReader`, `SAXParser`).
3. Verify if external entity resolution (`resolveEntities`, `external-general-entities`, `external-parameter-entities`, `loadDTD`) is disabled.

## Remediation Guidance
- Explicitly disable external entity resolution and DTD processing:
  - **Node.js (`libxmljs`)**: `libxmljs.parseXml(xml, { noent: false, dtdload: false, dtdvalid: false })`
  - **Python (`defusedxml`)**: Use `defusedxml.ElementTree` instead of `xml.etree.ElementTree`.
  - **Java (`DocumentBuilderFactory`)**:
    ```java
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    ```

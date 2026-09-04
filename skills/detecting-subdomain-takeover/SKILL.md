---
name: detecting-subdomain-takeover
description: Detect dangling DNS CNAME records pointing to decommissioned third-party cloud services and web hosting platforms.
---

# Detecting Subdomain Takeover

## Purpose
Identify dangling DNS CNAME pointers belonging to the organization's domain that resolve to unclaimed or deleted resources on third-party cloud services (e.g. AWS S3, GitHub Pages, Heroku, Azure App Service, Vercel, Shopify). An attacker can claim the abandoned resource name to serve arbitrary content under the organization's trusted domain.

## Safe operating rules
- Only assess domain names owned by or explicitly authorized by your organization.
- Inspect DNS records and perform read-only HTTP GET requests to detect provider error fingerprints (e.g. "There isn't a GitHub Pages site here", "NoSuchBucket").
- Do not attempt to register or claim the abandoned resource on the third-party provider.
- Record domain, CNAME target, fingerprint, severity, and remediation guidance for every finding.

## Workflow
1. Enumerate target subdomains and resolve DNS `CNAME` records.
2. Filter for known cloud and PaaS provider CNAME suffixes (e.g., `s3.amazonaws.com`, `github.io`, `herokuapp.com`, `azurewebsites.net`).
3. Send a non-destructive HTTP request to the unresolved CNAME host.
4. Match response status and body against known provider "unclaimed resource" fingerprints.
5. If fingerprinted, assign High severity finding (subdomain hijacking risk).
6. Provide remediation guidance (delete the dangling DNS record or reclaim the resource name under official accounts).

## Script
The `scripts/check_takeover.py` script queries DNS CNAME records and performs non-destructive fingerprint checks against common cloud provider signatures.

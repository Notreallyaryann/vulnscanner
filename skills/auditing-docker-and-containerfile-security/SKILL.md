---
name: auditing-docker-and-containerfile-security
description: Audit Dockerfiles, container configurations, and docker-compose definitions for root execution, sensitive mounts, unpinned base images, and secret leaks.
---

# Auditing Docker and Container Security

## Purpose
Scan `Dockerfile`, `Containerfile`, and `docker-compose.yml` configurations for container security anti-patterns including running containers as root (`USER root`), mounting sensitive host sockets (`/var/run/docker.sock`), unpinned base images (`node:latest`), and baking build-time secrets into image layers.

## Safe operating rules
- Statically parse container definitions and manifest files.
- Do not deploy or execute untrusted container images.
- Provide production-ready, multi-stage, rootless Dockerfile recommendations.

## Workflow
1. Locate all `Dockerfile`, `Containerfile`, and `docker-compose*.yml` files.
2. Check for explicit `USER` instruction to ensure non-root execution.
3. Check for base image tag pinning (avoiding `:latest`).
4. Check for dangerous volume mounts (e.g. `/var/run/docker.sock`, `/`, `/etc`).
5. Verify multi-stage build patterns to reduce image attack surface and eliminate build toolchains from final artifacts.

## Remediation Guidance
- Always specify a non-root user in the final build stage:
  ```dockerfile
  # Create a dedicated system user
  RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
  USER nextjs
  ```
- Pin base image digests or immutable release tags (`node:20.11-alpine3.19` instead of `node:latest`).
- Never mount the host Docker daemon socket (`/var/run/docker.sock`) into containers.

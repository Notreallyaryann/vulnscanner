# Nuclei Scanning Microservice

A production-ready microservice wrapper around [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner built for `VulnScanner`.

---

## Features

- ⚡ **Fast & Lightweight**: Built on Express.js and Node 20.
- 🎯 **JSON Output**: Executes Nuclei in `-j` JSON-Lines mode and parses security findings into clean JSON arrays.
- ⏰ **Render Anti-Sleep (Keep-Alive)**: Includes an automatic background self-ping loop (running every 10 minutes) that hits the endpoint `/health` to reset Render's 15-minute free tier inactivity timer.
- 🎛️ **Fully Toggleable**: Turn the keep-alive loop ON/OFF via `ENABLE_KEEP_ALIVE=true|false`.
- 📦 **Docker Ready**: Multi-stage Docker build pre-packaged with the official Nuclei binary and initial templates.

---

## API Endpoints

### 1. `GET /health`
Returns microservice health status, installed Nuclei version, system uptime, and keep-alive ping stats.

### 2. `POST /scan`
Triggers a Nuclei scan against a target URL or IP.

**Request Body:**
```json
{
  "targetUrl": "https://example.com",
  "severity": "critical,high,medium",
  "tags": "cve,exposure,misconfig",
  "timeoutMs": 180000
}
```

**Response Body:**
```json
{
  "target": "https://example.com",
  "count": 2,
  "findings": [
    {
      "template-id": "git-config",
      "info": {
        "name": "Git Config Exposure",
        "author": ["geeknik"],
        "tags": ["exposure", "git"],
        "reference": ["https://git-scm.com"],
        "severity": "medium"
      },
      "type": "http",
      "host": "https://example.com",
      "matched-at": "https://example.com/.git/config"
    }
  ]
}
```

### 3. `POST /update-templates`
Triggers `nuclei -update-templates` to pull fresh vulnerability definitions.

---

## Deployment on Render

1. **Create New Web Service**: Choose **Docker** as environment.
2. **Root Directory**: `nuclei-service`
3. **Environment Variables**:
   - `PORT`: `3002` (or default port assigned by Render)
   - `SELF_PING_URL`: `https://<your-nuclei-service-name>.onrender.com` (Optional; if omitted, Render's `RENDER_EXTERNAL_URL` is automatically detected)
   - `ENABLE_KEEP_ALIVE`: `true` (Set to `false` if you want the service to sleep normally)

---

## How Anti-Sleep Keep-Alive Works

Render free tier web services spin down / freeze process execution after **15 minutes** of HTTP inactivity.

1. When deployed, the service reads `RENDER_EXTERNAL_URL` (or `SELF_PING_URL`).
2. Every 10 minutes (600,000 ms), the internal loop makes an HTTP GET request to `https://<your-service>.onrender.com/health`.
3. Because the request passes through Render's external router/proxy, Render treats it as inbound user traffic, **resetting the 15-minute inactivity counter to zero**.

const express = require("express");
const cors = require("cors");
const { spawn, execSync } = require("child_process");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3002;

// ── Keep-Alive / Anti-Sleep Configuration ─────────────────────────────────────
const KEEP_ALIVE_ENABLED = process.env.ENABLE_KEEP_ALIVE !== "false";
const SELF_PING_INTERVAL_MS = parseInt(process.env.SELF_PING_INTERVAL_MS || "600000", 10); // 10 minutes default

const pingStats = {
  enabled: KEEP_ALIVE_ENABLED,
  pingCount: 0,
  lastPingTime: null,
  lastPingStatus: null,
  targetUrl: null,
};

// Start Keep-Alive self-ping background loop if enabled
function startKeepAliveLoop() {
  if (!KEEP_ALIVE_ENABLED) {
    console.log("ℹ️  Keep-Alive self-ping is DISABLED via ENABLE_KEEP_ALIVE=false");
    return;
  }

  // Determine target URL for self-ping:
  // 1. SELF_PING_URL (user defined, e.g. https://nuclei-service.onrender.com)
  // 2. RENDER_EXTERNAL_URL (automatically provided by Render on deployed Web Services)
  // 3. Fallback to localhost
  const targetHost =
    process.env.SELF_PING_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    `http://localhost:${PORT}`;

  const cleanTargetHost = targetHost.replace(/\/$/, "");
  const pingEndpoint = `${cleanTargetHost}/health`;
  pingStats.targetUrl = pingEndpoint;

  console.log(`⏰ Starting Anti-Sleep Keep-Alive loop (pinging ${pingEndpoint} every ${SELF_PING_INTERVAL_MS / 1000}s)`);

  setInterval(async () => {
    try {
      pingStats.lastPingTime = new Date().toISOString();
      const response = await fetch(pingEndpoint, {
        method: "GET",
        headers: { "User-Agent": "Render-KeepAlive-Ping/1.0" },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        pingStats.pingCount++;
        pingStats.lastPingStatus = `OK (${response.status})`;
        console.log(`📡 [Keep-Alive Ping #${pingStats.pingCount}] Successfully pinged ${pingEndpoint} — service state reset`);
      } else {
        pingStats.lastPingStatus = `HTTP Error ${response.status}`;
        console.warn(`⚠️ [Keep-Alive Ping] Ping to ${pingEndpoint} returned status ${response.status}`);
      }
    } catch (err) {
      pingStats.lastPingStatus = `Error: ${err.message}`;
      console.error(`❌ [Keep-Alive Ping] Ping failed:`, err.message);
    }
  }, SELF_PING_INTERVAL_MS);
}

// ── Nuclei CLI Helper ─────────────────────────────────────────────────────────

function getNucleiVersion() {
  try {
    const out = execSync("nuclei -version", { timeout: 5000, encoding: "utf8" });
    return out.trim().split("\n")[0] || "Installed";
  } catch (err) {
    return "Not installed or not in PATH";
  }
}

// ── Endpoints ─────────────────────────────────────────────────────────────────

// Root endpoint for default health check
app.get("/", (req, res) => {
  res.status(200).send("Nuclei Vulnerability Scanning Microservice is online.");
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    service: "nuclei-microservice",
    nucleiVersion: getNucleiVersion(),
    uptimeSeconds: Math.floor(process.uptime()),
    keepAlive: pingStats,
    timestamp: new Date().toISOString(),
  });
});

// Endpoint to trigger Nuclei template updates
app.post("/update-templates", (req, res) => {
  console.log("🔄 Triggering Nuclei template update...");
  try {
    const proc = spawn("nuclei", ["-update-templates"], { timeout: 120_000 });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    proc.stderr.on("data", (chunk) => (stderr += chunk.toString()));

    proc.on("close", (code) => {
      if (code === 0) {
        res.status(200).json({ status: "success", message: stdout || "Templates updated" });
      } else {
        res.status(500).json({ error: `Nuclei exited with code ${code}: ${stderr}` });
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Scan endpoint
app.post("/scan", async (req, res) => {
  const target = req.body.target || req.body.targetUrl || req.body.host;
  const severity = req.body.severity; // e.g. "critical,high,medium"
  const tags = req.body.tags;         // e.g. "cve,exposure"
  const templates = req.body.templates; // specific template path/file
  const customTimeoutMs = req.body.timeoutMs;

  if (!target) {
    return res.status(400).json({ error: "target or targetUrl or host is required in request body" });
  }

  // Basic sanitization
  if (typeof target !== "string" || target.startsWith("-") || /[;&|`$]/g.test(target)) {
    return res.status(400).json({ error: "Invalid target format" });
  }

  console.log(`🎯 Received Nuclei scan request for target: ${target}`);

  const timeoutMs = Math.min(parseInt(customTimeoutMs || "180000", 10), 300_000); // capped at 5 mins

  const args = [
    "-u", target,
    "-j",                       // Output in JSON lines format
    "-silent",                  // Only print findings JSON
    "-no-color",
    "-disable-update-check",
    "-rate-limit", "150",
    "-concurrency", "25",
  ];

  if (severity && typeof severity === "string") {
    // e.g. "critical,high,medium"
    const safeSev = severity.replace(/[^a-zA-Z,]/g, "");
    if (safeSev) args.push("-severity", safeSev);
  }

  if (tags && typeof tags === "string") {
    const safeTags = tags.replace(/[^a-zA-Z0-9,-]/g, "");
    if (safeTags) args.push("-tags", safeTags);
  }

  if (templates && typeof templates === "string") {
    if (!/[;&|`$]/g.test(templates)) {
      args.push("-t", templates);
    }
  }

  let stdout = "";
  let stderr = "";

  try {
    let responded = false;
    const proc = spawn("nuclei", args, { timeout: timeoutMs });

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (responded) return;
      responded = true;

      console.log(`✅ Nuclei process exited with code ${code} for target: ${target}`);

      const findings = [];
      const lines = stdout.split("\n").filter((l) => l.trim().length > 0);

      for (const line of lines) {
        try {
          const item = JSON.parse(line);
          findings.push(item);
        } catch {
          // Ignore non-JSON output lines
        }
      }

      res.status(200).json({
        target,
        count: findings.length,
        findings,
        rawCount: lines.length,
      });
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      if (responded) return;
      responded = true;

      console.error(`❌ Nuclei process error:`, err);
      const isNotFound = err.code === "ENOENT" || err.message.includes("ENOENT");
      res.status(500).json({
        error: isNotFound
          ? "Nuclei binary not found in PATH on host/container. Install nuclei or deploy via Docker."
          : err.message || "Failed to start nuclei scan",
      });
    });

  } catch (error) {
    console.error(`❌ Exception during scan dispatch:`, error);
    res.status(500).json({ error: error.message || "Internal server error during scan" });
  }
});

// Start listening
app.listen(PORT, () => {
  console.log(`🚀 Nuclei microservice listening on port ${PORT}`);
  startKeepAliveLoop();
});

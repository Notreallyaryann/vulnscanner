const express = require("express");
const { spawn } = require("child_process");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;

// Target ports list matching the main scanner
const TARGET_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
  1433, 3306, 3389, 4444, 5432, 5900, 6379,
  8080, 8443, 9200, 11211, 27017,
  2181, 2375, 2376, 4200, 9092,
];

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

function startKeepAliveLoop() {
  if (!KEEP_ALIVE_ENABLED) {
    console.log("ℹ️  Keep-Alive self-ping is DISABLED via ENABLE_KEEP_ALIVE=false");
    return;
  }

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

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    service: "nmap-microservice",
    uptimeSeconds: Math.floor(process.uptime()),
    keepAlive: pingStats,
    timestamp: new Date().toISOString(),
  });
});

// Root path handler to satisfy Render's default health check
app.get("/", (req, res) => {
  res.status(200).send("Nmap Port Scanning Microservice is online.");
});

// Scan endpoint
app.post("/scan", async (req, res) => {
  const { host } = req.body;

  if (!host) {
    return res.status(400).json({ error: "Host is required in request body" });
  }

  // Basic sanitization to prevent passing malicious flags
  if (typeof host !== "string" || host.startsWith("-") || /[;&|`$]/g.test(host)) {
    return res.status(400).json({ error: "Invalid host format" });
  }

  console.log(`🔌 Received scan request for host: ${host}`);

  const timeoutMs = 180_000; // 3 minutes
  const args = [
    "-Pn",                              // Skip host discovery
    "-sV",                              // Service/version detection
    "-T4",                              // Aggressive timing template
    "--open",                           // Only show confirmed open ports
    "-p", TARGET_PORTS.join(","),       // Explicit targeted port list
    "--version-intensity", "5",         // Balance speed vs accuracy
    "--host-timeout", "2m",
    "-oX", "-",                         // XML output to stdout
    host,
  ];

  let stdout = "";
  let stderr = "";

  try {
    const proc = spawn("nmap", args, { timeout: timeoutMs });

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
      console.log(`✅ Nmap process exited with code ${code} for host: ${host}`);
      if (code === 0 || stdout.length > 0) {
        res.status(200).json({ xml: stdout });
      } else {
        res.status(500).json({ error: `Nmap exited with code ${code}: ${stderr.slice(0, 300)}` });
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      console.error(`❌ Nmap process error:`, err);
      res.status(500).json({ error: err.message || "Failed to start nmap scan" });
    });

  } catch (error) {
    console.error(`❌ Exception during scan dispatch:`, error);
    res.status(500).json({ error: error.message || "Internal server error during scan" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Nmap service listening on port ${PORT}`);
  startKeepAliveLoop();
});

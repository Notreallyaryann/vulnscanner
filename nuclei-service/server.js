const express = require("express");
const cors = require("cors");
const { spawn, execSync } = require("child_process");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3002;

// Set this to true while debugging, false (or unset) in production —
// controls whether stderr/args get echoed back in the API response.
const DEBUG_SCAN = process.env.DEBUG_SCAN === "true";

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

// ── Nuclei CLI Helper ─────────────────────────────────────────────────────────

function getNucleiVersion() {
  try {
    const out = execSync("nuclei -version", { timeout: 5000, encoding: "utf8" });
    return out.trim().split("\n")[0] || "Installed";
  } catch (err) {
    return "Not installed or not in PATH";
  }
}

// Resolve the template directory once at startup and log it loudly —
// if this ever logs "NOT FOUND", every scan below is silently running
// with zero templates (or falling back to Nuclei's own default lookup,
// which will fail under -disable-update-check with no network).
function resolveTemplateDir() {
  const homeDir = process.env.HOME || "/root";
  const candidates = ["/root/nuclei-templates", `${homeDir}/nuclei-templates`];

  for (const dir of candidates) {
    if (fs.existsSync(dir)) {
      let count = 0;
      try {
        count = execSync(`find ${dir} -name "*.yaml" | wc -l`, { encoding: "utf8" }).trim();
      } catch {
        count = "unknown";
      }
      console.log(`✅ Template dir resolved: ${dir} (${count} templates)`);
      return dir;
    }
  }

  console.error(`❌ No template dir found. Checked: ${candidates.join(", ")} — scans will run with NO -t flag.`);
  return null;
}

const RESOLVED_TEMPLATE_DIR = resolveTemplateDir();

// ── Endpoints ─────────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.status(200).send("Nuclei Vulnerability Scanning Microservice is online.");
});

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    service: "nuclei-microservice",
    nucleiVersion: getNucleiVersion(),
    templateDir: RESOLVED_TEMPLATE_DIR,
    uptimeSeconds: Math.floor(process.uptime()),
    keepAlive: pingStats,
    timestamp: new Date().toISOString(),
  });
});

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
  let rawTarget = req.body.target || req.body.targetUrl || req.body.host;
  const severity = req.body.severity; // e.g. "critical,high,medium"
  const tags = req.body.tags;         // e.g. "cve,exposure"
  const templates = req.body.templates; // specific template path/file
  const customTimeoutMs = req.body.timeoutMs;

  if (!rawTarget) {
    return res.status(400).json({ error: "target or targetUrl or host is required in request body" });
  }

  if (typeof rawTarget !== "string" || rawTarget.startsWith("-") || /[;&|`$]/g.test(rawTarget)) {
    return res.status(400).json({ error: "Invalid target format" });
  }

  // Strip client-side SPA hash fragments (e.g. /#/)
  const target = rawTarget.split('#')[0] || rawTarget;

  console.log(`🎯 Received Nuclei scan request for target: ${target}`);

  // Bumped default ceiling — a full unscoped template run against one host
  // can genuinely take several minutes. If you need faster turnaround,
  // scope with severity/tags rather than lowering this.
  const timeoutMs = Math.max(
    Math.min(parseInt(customTimeoutMs || "180000", 10), 600_000), // capped at 10 mins
    120_000 // never allow a caller to set less than 2 minutes
  );

  const homeDir = process.env.HOME || "/root";

  const args = [
    "-u", target,
    "-j",                       // JSONL output
    "-silent",                  // only findings on stdout (warnings/errors still go to stderr)
    "-no-color",
    "-disable-update-check",
    "-fr",                       // follow redirects
    "-timeout", "3",             // 3s per-request timeout — keeps scan fast
    "-max-host-error", "5",      // abort scan if host drops 5 requests (prevents 5-min stalls)
    "-rate-limit", "50",         // 50 req/sec — memory safe for 512MB free container
    "-concurrency", "10",        // 10 worker threads — prevents container OOM
    "-bulk-size", "25",
  ];

  if (templates && typeof templates === "string" && !/[;&|`$]/g.test(templates)) {
    args.push("-t", templates);
  } else if (RESOLVED_TEMPLATE_DIR) {
    args.push("-t", RESOLVED_TEMPLATE_DIR);
  }

  if (severity && typeof severity === "string") {
    const safeSev = severity.replace(/[^a-zA-Z,]/g, "");
    if (safeSev) args.push("-severity", safeSev);
  }

  if (tags && typeof tags === "string") {
    const safeTags = tags.replace(/[^a-zA-Z0-9,-]/g, "");
    if (safeTags) args.push("-tags", safeTags);
  }

  console.log(`▶️  nuclei ${args.join(" ")}`);

  let stdout = "";
  let stderr = "";

  // ── Heartbeat Keep-Alive to prevent Cloudflare/Render 100s proxy timeout ───
  // Send HTTP 200 headers immediately and emit whitespace every 10s while nuclei runs
  res.setHeader("Content-Type", "application/json");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.status(200);

  const heartbeatTimer = setInterval(() => {
    try {
      res.write(" ");
    } catch {
      // Socket closed by client
    }
  }, 10_000);

  try {
    let responded = false;
    const procEnv = { ...process.env, HOME: homeDir };
    const proc = spawn("nuclei", args, { timeout: timeoutMs, env: procEnv });

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    const timer = setTimeout(() => {
      console.warn(`⏱️  Scan for ${target} hit ${timeoutMs}ms timeout — killing process`);
      proc.kill("SIGTERM");
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      clearInterval(heartbeatTimer);

      if (responded) return;
      responded = true;

      console.log(`✅ Nuclei process exited with code ${code} for target: ${target}`);
      if (stderr.trim()) {
        console.log(`   stderr: ${stderr.slice(0, 2000)}`);
      }

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

      const responseBody = {
        target,
        count: findings.length,
        findings,
        rawCount: lines.length,
        exitCode: code,
      };

      if (DEBUG_SCAN) {
        responseBody.debug = {
          args,
          templateDir: RESOLVED_TEMPLATE_DIR,
          stderr: stderr.slice(0, 4000),
        };
      }

      res.write(JSON.stringify(responseBody));
      res.end();
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      clearInterval(heartbeatTimer);
      if (responded) return;
      responded = true;

      console.error(`❌ Nuclei process error:`, err);
      const isNotFound = err.code === "ENOENT" || err.message.includes("ENOENT");
      const errPayload = {
        error: isNotFound
          ? "Nuclei binary not found in PATH on host/container. Install nuclei or deploy via Docker."
          : err.message || "Failed to start nuclei scan",
      };
      res.write(JSON.stringify(errPayload));
      res.end();
    });

  } catch (error) {
    clearInterval(heartbeatTimer);
    console.error(`❌ Exception during scan dispatch:`, error);
    if (!res.headersSent) {
      res.status(500).json({ error: error.message || "Internal server error during scan" });
    } else {
      res.write(JSON.stringify({ error: error.message || "Internal server error during scan" }));
      res.end();
    }
  }
});

// Start listening
app.listen(PORT, () => {
  console.log(`🚀 Nuclei microservice listening on port ${PORT}`);
  startKeepAliveLoop();
});

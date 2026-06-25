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

// Simple health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "healthy" });
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
});

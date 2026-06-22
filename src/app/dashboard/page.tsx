"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { 
  Shield, 
  Terminal, 
  Globe, 
  AlertTriangle, 
  CheckCircle, 
  Activity, 
  Search, 
  Cpu, 
  BookOpen, 
  ArrowRight, 
  ChevronRight, 
  RefreshCw, 
  Send,
  Code,
  FileCode,
  AlertCircle,
  Zap,
  Lock,
  Database,
  Eye,
  Server,
  Layers,
  X,
  TrendingUp,
  Download,
  Terminal as TerminalIcon,
  Wifi
} from "lucide-react";
import { 
  createScanAction, 
  getScansAction, 
  getScanDetailsAction, 
  deleteScanAction,
  askRAGAction 
} from "@/lib/actions";

// ─── OWASP Top 10 2021 Mapping ────────────────────────────────────────────────
const OWASP_MAP: Record<string, { code: string; name: string; color: string }> = {
  // A01: Broken Access Control
  "idor-numeric-id":              { code: "A01", name: "Broken Access Control", color: "#ef4444" },
  "unauthenticated-api-access":   { code: "A01", name: "Broken Access Control", color: "#ef4444" },
  "sensitive-endpoint-exposed":   { code: "A01", name: "Broken Access Control", color: "#ef4444" },
  "directory-listing-exposed":    { code: "A01", name: "Broken Access Control", color: "#ef4444" },
  // A02: Cryptographic Failures
  "missing-https-redirect":       { code: "A02", name: "Cryptographic Failures", color: "#f97316" },
  "session-fixation-weak-token":  { code: "A02", name: "Cryptographic Failures", color: "#f97316" },
  "jwt-weakness":                 { code: "A02", name: "Cryptographic Failures", color: "#f97316" },
  "env-variable-leak":            { code: "A02", name: "Cryptographic Failures", color: "#f97316" },
  "js-secret-disclosure":         { code: "A02", name: "Cryptographic Failures", color: "#f97316" },
  // A03: Injection
  "sql-injection-reflected":      { code: "A03", name: "Injection", color: "#dc2626" },
  "sql-injection-form":           { code: "A03", name: "Injection", color: "#dc2626" },
  "sql-injection-blind-timing":   { code: "A03", name: "Injection", color: "#dc2626" },
  "reflected-xss":                { code: "A03", name: "Injection", color: "#dc2626" },
  "reflected-xss-form":           { code: "A03", name: "Injection", color: "#dc2626" },
  "command-injection":            { code: "A03", name: "Injection", color: "#dc2626" },
  "path-traversal-lfi":           { code: "A03", name: "Injection", color: "#dc2626" },
  "ssti-injection":               { code: "A03", name: "Injection", color: "#dc2626" },
  "ssti-injection-form":          { code: "A03", name: "Injection", color: "#dc2626" },
  "xxe-injection":                { code: "A03", name: "Injection", color: "#dc2626" },
  "xxe-endpoint-accepts-xml":     { code: "A03", name: "Injection", color: "#dc2626" },
  "html-injection":               { code: "A03", name: "Injection", color: "#dc2626" },
  "prototype-pollution":          { code: "A03", name: "Injection", color: "#dc2626" },
  // A04: Insecure Design
  "csrf-missing-token":           { code: "A04", name: "Insecure Design", color: "#eab308" },
  "open-redirect":                { code: "A04", name: "Insecure Design", color: "#eab308" },
  "rate-limiting-absent":         { code: "A04", name: "Insecure Design", color: "#eab308" },
  // A05: Security Misconfiguration
  "cors-wildcard":                { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "cors-arbitrary-origin-reflected": { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "cors-arbitrary-origin-with-credentials": { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "graphql-introspection-enabled":{ code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "dangerous-http-methods":       { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "http-trace-method-enabled":    { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "debug-mode-exposed":           { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "missing-csp":                  { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "missing-hsts":                 { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "missing-x-frame-options":      { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "missing-x-content-type":       { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "clickjacking-no-frameancestors":{ code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  "subdomain-takeover-signal":    { code: "A05", name: "Security Misconfiguration", color: "#a855f7" },
  // A06: Vulnerable & Outdated Components
  "technology-fingerprinting":    { code: "A06", name: "Outdated Components", color: "#6366f1" },
  // A07: Identification & Authentication Failures
  "broken-authentication-default-creds": { code: "A07", name: "Auth Failures", color: "#ec4899" },
  "session-cookie-insecure-attributes": { code: "A07", name: "Auth Failures", color: "#ec4899" },
  "cookie-missing-httponly":      { code: "A07", name: "Auth Failures", color: "#ec4899" },
  "cookie-missing-secure":        { code: "A07", name: "Auth Failures", color: "#ec4899" },
  "cookie-missing-samesite":      { code: "A07", name: "Auth Failures", color: "#ec4899" },
  // A08: Software & Data Integrity Failures
  "js-dangerous-sink":            { code: "A08", name: "Data Integrity", color: "#14b8a6" },
  // A09: Logging Failures
  // A10: SSRF
  "ssrf-parameter-detected":      { code: "A10", name: "SSRF", color: "#06b6d4" },
  "host-header-injection":        { code: "A10", name: "SSRF", color: "#06b6d4" },
  "host-header-injection-redirect": { code: "A10", name: "SSRF", color: "#06b6d4" },
};

function getOWASP(findingType: string) {
  // Fuzzy match — check if type contains any key substring
  const direct = OWASP_MAP[findingType];
  if (direct) return direct;
  for (const [key, val] of Object.entries(OWASP_MAP)) {
    if (findingType.includes(key) || key.includes(findingType)) return val;
  }
  return { code: "OWA", name: "Security Issue", color: "#64748b" };
}

function calcRiskScore(findings: any[]): number {
  if (!findings.length) return 0;
  const weights: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 0.5 };
  const total = findings.reduce((s, f) => s + (weights[f.severity] ?? 1), 0);
  const max = findings.length * 10;
  return Math.min(100, Math.round((total / max) * 100));
}

interface ScanSummary {
  id: string;
  targetUrl: string;
  status: "PENDING" | "CRAWLING" | "SCANNING" | "ANALYZING" | "COMPLETED" | "FAILED";
  createdAt: Date;
  completedAt: Date | null;
  _count: {
    findings: number;
  };
}

interface Finding {
  id: string;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter?: string | null;
  evidence?: string | null;
  cvssScore?: number | null;
  cveId?: string | null;
  title?: string | null;
  explanation?: string | null;
  attackSimulation?: string | null; // step-by-step exploit walkthrough
  fixSteps?: any; // parsed JSON
  codeExample?: any; // parsed JSON
  createdAt: Date;
}

interface ChatMessage {
  sender: "user" | "bot";
  text: string;
  sources?: {
    guidelines: boolean;
    pastFindings: Array<{ title: string; severity: string; url: string }>;
  };
}

export default function DashboardPage() {
  // Navigation State
  const [activeTab, setActiveTab] = useState<"dashboard" | "scans" | "rag" | "knowledge">("dashboard");

  // Real-time clock
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Scanner Input States
  const [targetUrl, setTargetUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  // Live scan log terminal
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [showLogs, setShowLogs] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  
  // Scans History State
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScan, setSelectedScan] = useState<any | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // RAG Chat States
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      sender: "bot",
      text: "Hello, Security Officer. I am your AI Remediation Assistant. Ask me security questions about your past scans or general OWASP vulnerability fixes.",
    }
  ]);
  const [isAskingRAG, setIsAskingRAG] = useState(false);
  const [isDeletingScan, setIsDeletingScan] = useState<string | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Load Scans List on Mount + auto-trigger scan if domain param is present
  useEffect(() => {
    loadScans();
    
    // If the landing page passed a domain via ?domain=, auto-start the real scan
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const autoDomain = params.get("domain");
      if (autoDomain) {
        setTargetUrl(autoDomain);
        // Auto-trigger the scan after state is set
        setTimeout(async () => {
          try {
            setIsScanning(true);
            const { createScanAction: csa, getScanDetailsAction: gsda } = await import("@/lib/actions");
            let cleanUrl = autoDomain.trim();
            if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
              cleanUrl = "https://" + cleanUrl;
            }
            const scanId = await csa(cleanUrl);
            setCurrentScanId(scanId);
            const tempScanDetails = await gsda(scanId);
            setSelectedScan(tempScanDetails);
            setSelectedFinding(null);
            loadScans();
            // Clean the URL param to avoid re-triggering on refresh
            window.history.replaceState({}, "", "/dashboard");
          } catch (err: any) {
            console.error("Auto-scan failed:", err);
            setIsScanning(false);
          }
        }, 300);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Scroll to bottom of chat when new message arrives
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, isAskingRAG]);

  // Auto-scroll log terminal
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [scanLogs]);

  // SSE: connect to live log stream for active scan
  useEffect(() => {
    if (!currentScanId) {
      // Close any existing SSE connection when no scan is running
      eventSourceRef.current?.close();
      eventSourceRef.current = null;
      return;
    }

    setScanLogs([]);
    setShowLogs(true);

    const es = new EventSource(`/api/scan-logs/${currentScanId}`);
    eventSourceRef.current = es;

    es.addEventListener("log", (e) => {
      const msg = JSON.parse((e as MessageEvent).data) as string;
      setScanLogs((prev) => [...prev, msg]);
    });

    es.addEventListener("done", () => {
      es.close();
      eventSourceRef.current = null;
    });

    es.onerror = () => {
      es.close();
      eventSourceRef.current = null;
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [currentScanId]);

  // Polling helper for active scans
  useEffect(() => {
    if (!currentScanId) return;

    const interval = setInterval(async () => {
      const details = await getScanDetailsAction(currentScanId);
      if (details) {
        // Update history in background
        loadScans();

        if (details.status === "COMPLETED" || details.status === "FAILED") {
          setIsScanning(false);
          setCurrentScanId(null);
          // Set detail selection to show the newly finished scan
          setSelectedScan(details);
          if (details.findings && details.findings.length > 0) {
            setSelectedFinding(details.findings[0]);
          }
          clearInterval(interval);
        } else {
          // If still running, update the current screen scan state
          setSelectedScan(details);
        }
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [currentScanId]);

  const loadScans = async () => {
    const list = await getScansAction();
    // Safely cast or map timestamps
    const formattedList = (list as any[]).map(s => ({
      ...s,
      createdAt: new Date(s.createdAt),
      completedAt: s.completedAt ? new Date(s.completedAt) : null,
    }));
    setScans(formattedList);
  };

  const handleLaunchScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl) return;

    try {
      setIsScanning(true);
      const scanId = await createScanAction(targetUrl);
      setCurrentScanId(scanId);

      // Instantly load temporary scan stats
      const tempScanDetails = await getScanDetailsAction(scanId);
      setSelectedScan(tempScanDetails);
      setSelectedFinding(null);
      
      setTargetUrl("");
      loadScans();
    } catch (err: any) {
      alert(err.message || "Failed to trigger scan.");
      setIsScanning(false);
      setCurrentScanId(null);
    }
  };

  const handleSelectScan = async (scanId: string) => {
    const details = await getScanDetailsAction(scanId);
    if (details) {
      setSelectedScan(details);
      if (details.findings && details.findings.length > 0) {
        setSelectedFinding(details.findings[0] as Finding);
      } else {
        setSelectedFinding(null);
      }
      setActiveTab("dashboard"); // Switch to dashboard to view finding breakdown
    }
  };

  const handleSendChatMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userText = chatInput.trim();
    setChatMessages(prev => [...prev, { sender: "user", text: userText }]);
    setChatInput("");
    setIsAskingRAG(true);

    try {
      const response = await askRAGAction(userText);
      setChatMessages(prev => [
        ...prev, 
        { 
          sender: "bot", 
          text: response.answer,
          sources: response.sources
        }
      ]);
    } catch (err: any) {
      setChatMessages(prev => [
        ...prev, 
        { 
          sender: "bot", 
          text: `Error processing RAG context: ${err.message || "Something went wrong."}`
        }
      ]);
    } finally {
      setIsAskingRAG(false);
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!confirm("Delete this scan and all its findings permanently?")) return;
    setIsDeletingScan(scanId);
    try {
      await deleteScanAction(scanId);
      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
        setSelectedFinding(null);
      }
      await loadScans();
    } catch (err: any) {
      alert(err.message || "Failed to delete scan.");
    } finally {
      setIsDeletingScan(null);
    }
  };

  const handleExportJSON = useCallback(() => {
    if (!selectedScan) return;
    const report = {
      scanId: selectedScan.id,
      targetUrl: selectedScan.targetUrl,
      status: selectedScan.status,
      scannedAt: selectedScan.createdAt,
      completedAt: selectedScan.completedAt,
      summary: {
        totalFindings: selectedScan.findings?.length ?? 0,
        critical: selectedScan.findings?.filter((f: any) => f.severity === "CRITICAL").length ?? 0,
        high:     selectedScan.findings?.filter((f: any) => f.severity === "HIGH").length ?? 0,
        medium:   selectedScan.findings?.filter((f: any) => f.severity === "MEDIUM").length ?? 0,
        low:      selectedScan.findings?.filter((f: any) => f.severity === "LOW").length ?? 0,
      },
      findings: selectedScan.findings ?? [],
      generatedBy: "VulnScanner v2.0 — AI-Augmented Security Audit",
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `vulnscan-report-${selectedScan.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [selectedScan]);

  const getSafetyVerdict = (scan: any) => {
    if (!scan || scan.status !== "COMPLETED") return null;
    const findings = scan.findings || [];
    const critical = findings.filter((f: any) => f.severity === "CRITICAL").length;
    const high = findings.filter((f: any) => f.severity === "HIGH").length;
    if (findings.length === 0) return { label: "SAFE", color: "emerald" };
    if (critical > 0) return { label: "CRITICAL RISK", color: "red" };
    if (high > 0) return { label: "HIGH RISK", color: "orange" };
    return { label: "VULNERABLE", color: "amber" };
  };

  // Status Badge Formatter
  const getStatusBadge = (status: string) => {
    switch (status) {
      case "PENDING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-stone-100 border border-stone-200 text-stone-600 flex items-center gap-1 w-max"><Activity className="w-3 h-3 animate-pulse" /> Pending</span>;
      case "CRAWLING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-50 border border-[#D4380D]/30 text-[#D4380D] flex items-center gap-1 w-max animate-pulse"><Globe className="w-3 h-3" /> Crawling</span>;
      case "SCANNING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-50 border border-[#D4380D]/30 text-[#D4380D] flex items-center gap-1 w-max"><Cpu className="w-3 h-3 animate-spin" /> Auditing</span>;
      case "ANALYZING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 border border-amber-200 text-amber-700 flex items-center gap-1 w-max"><RefreshCw className="w-3 h-3 animate-spin" /> AI RAG Analysis</span>;
      case "COMPLETED":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 border border-emerald-250 text-emerald-700 flex items-center gap-1 w-max"><CheckCircle className="w-3 h-3" /> Protected</span>;
      case "FAILED":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-50 border border-red-200 text-red-700 flex items-center gap-1 w-max"><AlertTriangle className="w-3 h-3" /> Failed</span>;
      default:
        return null;
    }
  };

  // Severity Tag Formatter
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-red-50 border border-red-200 text-red-750">CRITICAL</span>;
      case "HIGH":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-orange-50 border border-[#D4380D]/30 text-[#D4380D]">HIGH</span>;
      case "MEDIUM":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-amber-50 border border-amber-200 text-amber-700">MEDIUM</span>;
      case "LOW":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-stone-100 border border-stone-200 text-stone-600">LOW</span>;
      default:
        return <span className="px-2 py-1 text-xs font-bold rounded bg-stone-100 border border-stone-200 text-stone-500">INFO</span>;
    }
  };

  return (
    <div className="flex min-h-screen bg-[#FAF8F5] radar-bg">
      {/* 🚀 LEFT SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-stone-200/80 bg-[#FFFEFB] flex flex-col justify-between p-6">
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="p-2 rounded bg-[#D4380D] text-white">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-lg tracking-tight text-stone-900">VulnScanner</h1>
              <span className="text-[10px] font-bold uppercase tracking-wider bg-orange-50 border border-orange-200 text-[#D4380D] px-1.5 py-0.5 rounded">RAG Remediator</span>
            </div>
          </div>

          <nav className="space-y-1.5">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all cursor-pointer ${
                activeTab === "dashboard"
                  ? "bg-stone-100 border-l-4 border-[#D4380D] text-stone-900 font-bold"
                  : "text-stone-600 hover:text-stone-900 hover:bg-stone-50"
              }`}
            >
              <Activity className="w-4 h-4 text-[#D4380D]" />
              Audits Dashboard
            </button>

            <button
              onClick={() => setActiveTab("scans")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all cursor-pointer ${
                activeTab === "scans"
                  ? "bg-stone-100 border-l-4 border-[#D4380D] text-stone-900 font-bold"
                  : "text-stone-600 hover:text-stone-900 hover:bg-stone-50"
              }`}
            >
              <Terminal className="w-4 h-4 text-[#D4380D]" />
              Scanner History
            </button>

            <button
              onClick={() => setActiveTab("rag")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all cursor-pointer ${
                activeTab === "rag"
                  ? "bg-stone-100 border-l-4 border-[#D4380D] text-stone-900 font-bold"
                  : "text-stone-600 hover:text-stone-900 hover:bg-stone-50"
              }`}
            >
              <Cpu className="w-4 h-4 text-[#D4380D]" />
              Remediation RAG Chat
            </button>

            <button
              onClick={() => setActiveTab("knowledge")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all cursor-pointer ${
                activeTab === "knowledge"
                  ? "bg-stone-100 border-l-4 border-[#D4380D] text-stone-900 font-bold"
                  : "text-stone-600 hover:text-stone-900 hover:bg-stone-50"
              }`}
            >
              <BookOpen className="w-4 h-4 text-[#D4380D]" />
              Security Standards KB
            </button>
          </nav>
        </div>

        <div className="border-t border-stone-150 pt-6 text-[11px] text-stone-400 font-mono">
          <p>Protected Environment</p>
        </div>
      </aside>

      {/* 🚀 MAIN CONTENT CONTAINER */}
      <main className="flex-1 flex flex-col min-h-screen max-h-screen overflow-y-auto bg-[#FAF8F5]">
        {/* TOP STATUS BAR */}
        <header className="h-16 border-b border-stone-200/80 bg-[#FFFEFB]/85 backdrop-blur-md px-8 flex items-center justify-between z-10 sticky top-0">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#D4380D] animate-ping" />
            <span className="text-xs font-semibold text-stone-600 uppercase tracking-widest font-mono">Auditor Node Active</span>
          </div>
        </header>

        <div className="flex-1 p-8">
          {/* TAB 1: AUDITS DASHBOARD */}
          {activeTab === "dashboard" && (
            <div className="space-y-6">
              {/* Launcher Form & Stats */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Launch Scan Card */}
                <div className="cyber-card p-6 rounded-xl lg:col-span-2 flex flex-col justify-between">
                  <div>
                    <h2 className="text-lg font-bold text-stone-900 mb-1">Launch Active Security Audit</h2>
                    <p className="text-xs text-stone-600 mb-6">20+ real attack probes — SQLi, XSS, SSTI, XXE, CORS, host header, prototype pollution, blind timing injection — plus AI-powered RAG remediation.</p>
                  </div>

                  <form onSubmit={handleLaunchScan} className="flex gap-3">
                    <div className="relative flex-1">
                      <Globe className="absolute left-3 top-3.5 w-4 h-4 text-stone-400" />
                      <input
                        type="text"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="e.g. example.com or https://yoursite.com"
                        required
                        disabled={isScanning}
                        className="w-full bg-[#FAF8F5] border border-stone-200 hover:border-stone-300 focus:border-[#D4380D] focus:ring-1 focus:ring-[#D4380D] text-stone-900 rounded-lg pl-10 pr-4 py-2.5 text-sm outline-none transition-all placeholder:text-stone-450"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={isScanning}
                      className="px-6 py-2.5 rounded-lg text-sm font-semibold bg-[#D4380D] hover:bg-[#B5300A] text-white transition-all shadow-md flex items-center gap-2 disabled:opacity-50 cursor-pointer"
                    >
                      {isScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin animate-spin-slow" />
                          Auditing...
                        </>
                      ) : (
                        <>
                          Analyze Target
                          <ArrowRight className="w-4 h-4" />
                        </>
                      )}
                    </button>
                  </form>
                </div>

                {/* Scan Status Tracker */}
                <div className="cyber-card p-6 rounded-xl scanner-line">
                  <h3 className="text-sm font-bold text-stone-900 uppercase tracking-widest mb-4">Active Auditor Feed</h3>
                  {selectedScan ? (
                    <div className="space-y-4">
                      <div>
                        <p className="text-xs text-stone-500 font-mono">TARGET</p>
                        <p className="text-sm font-bold text-stone-900 truncate">{selectedScan.targetUrl}</p>
                      </div>
                      <div className="flex justify-between items-center bg-stone-50 p-3 rounded-lg border border-stone-200">
                        <span className="text-xs text-stone-600">Current Status</span>
                        {getStatusBadge(selectedScan.status)}
                      </div>
                      {selectedScan.status === "SCANNING" && (
                        <div className="w-full bg-stone-100 h-1.5 rounded-full overflow-hidden">
                          <div className="h-full bg-[#D4380D] animate-pulse w-3/5" />
                        </div>
                      )}
                      {selectedScan.status === "CRAWLING" && (
                        <div className="w-full bg-stone-100 h-1.5 rounded-full overflow-hidden">
                          <div className="h-full bg-[#D4380D] animate-pulse w-1/3" />
                        </div>
                      )}
                      {selectedScan.status === "ANALYZING" && (
                        <div className="w-full bg-stone-100 h-1.5 rounded-full overflow-hidden">
                          <div className="h-full bg-[#D4380D] animate-pulse w-4/5" />
                        </div>
                      )}
                      {selectedScan.status === "COMPLETED" && (
                        <p className="text-[11px] text-emerald-700 font-semibold flex items-center gap-1.5">
                          <CheckCircle className="w-3.5 h-3.5" /> Scan complete. {selectedScan.findings?.length || 0} alerts.
                        </p>
                      )}

                      {/* Integrated logs on the dashboard directly */}
                      {scanLogs.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-stone-200/80 space-y-1.5 max-h-[220px] overflow-y-auto font-mono text-[11px]">
                          {scanLogs.map((line, i) => {
                            const isError   = line.includes("❌") || line.includes("Failed");
                            const isWarning = line.includes("⚠️") || line.includes("Warning");
                            const isSuccess = line.includes("✅") || line.includes("🎉") || line.includes("complete");
                            const isPhase   = /Phase \d+:/.test(line);
                            return (
                              <div
                                key={i}
                                className={`leading-relaxed pb-0.5 border-b border-stone-50 last:border-0 ${
                                  isError   ? "text-red-650 font-bold" :
                                  isWarning ? "text-amber-600" :
                                  isSuccess ? "text-emerald-700 font-bold" :
                                  isPhase   ? "text-[#D4380D] font-bold" :
                                  "text-stone-600"
                                }`}
                              >
                                {line}
                              </div>
                            );
                          })}
                          <div ref={logEndRef} />
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="h-28 flex flex-col items-center justify-center text-center text-stone-500">
                      <Activity className="w-8 h-8 mb-2 opacity-30 animate-pulse" />
                      <p className="text-xs">No active scan selected.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Live Scan Log Terminal Removed - Now streamed directly in the dashboard feed above */}

              {/* Main Analysis Screen */}
              {selectedScan ? (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
                  {/* Safety Verdict Banner */}
                  {(() => {
                    const verdict = getSafetyVerdict(selectedScan);
                    if (!verdict) return null;
                    const colorMap: Record<string, string> = {
                      emerald: "bg-emerald-50 border-emerald-200 text-emerald-800",
                      red: "bg-red-50 border-red-200 text-red-800",
                      orange: "bg-orange-50 border-orange-200/80 text-orange-900",
                      amber: "bg-amber-50 border-amber-200 text-amber-800",
                    };
                    return (
                      <div className={`xl:col-span-12 flex items-center justify-between p-4 rounded-xl border ${colorMap[verdict.color]}`}>
                        <div className="flex items-center gap-3">
                          <Shield className="w-5 h-5" />
                          <div>
                            <p className="text-sm font-extrabold uppercase tracking-widest">{verdict.label}</p>
                            <p className="text-[11px] opacity-70">{selectedScan.targetUrl} · {selectedScan.findings?.length || 0} issues found</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 print:hidden">
                          <button
                            onClick={handleExportJSON}
                            className="px-4 py-2 rounded-lg text-xs font-bold bg-[#D4380D] border border-[#D4380D]/30 text-white hover:bg-[#B5300A] transition-all flex items-center gap-2 cursor-pointer"
                          >
                            <Download className="w-3.5 h-3.5" /> Export JSON
                          </button>
                        </div>
                      </div>
                    );
                  })()}
                  
                  {/* Left Column: Alerts List */}
                  <div className="xl:col-span-4 space-y-3">
                    <div className="flex justify-between items-center mb-1">
                      <h3 className="text-sm font-bold text-stone-900 uppercase tracking-wider">Alerts & Findings</h3>
                      <span className="px-2 py-0.5 text-xs rounded bg-red-50 border border-red-200 text-red-700 font-mono font-bold">
                        {selectedScan.findings?.length || 0} Issues
                      </span>
                    </div>

                    {/* Severity Stats Bar */}
                    {selectedScan.findings && selectedScan.findings.length > 0 && (() => {
                      const f = selectedScan.findings;
                      const c = f.filter((x: Finding) => x.severity === "CRITICAL").length;
                      const h = f.filter((x: Finding) => x.severity === "HIGH").length;
                      const m = f.filter((x: Finding) => x.severity === "MEDIUM").length;
                      const l = f.filter((x: Finding) => x.severity === "LOW" || x.severity === "INFO").length;
                      const score = calcRiskScore(f);
                      return (
                        <div className="mb-3 p-3 bg-stone-50 rounded-lg border border-stone-200 space-y-2">
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <div className="flex items-center gap-2.5">
                              {c > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500"/><span className="text-red-750 font-bold">{c} CRIT</span></span>}
                              {h > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500"/><span className="text-[#D4380D] font-bold">{h} HIGH</span></span>}
                              {m > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500"/><span className="text-amber-700">{m} MED</span></span>}
                              {l > 0 && <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-stone-400"/><span className="text-stone-500">{l} LOW</span></span>}
                            </div>
                            <div className="text-right">
                              <span className="text-stone-500">Risk: </span>
                              <span className={`font-bold ${score >= 70 ? "text-red-700" : score >= 40 ? "text-[#D4380D]" : "text-emerald-700"}`}>{score}%</span>
                            </div>
                          </div>
                          <div className="h-1.5 rounded-full bg-stone-200 overflow-hidden flex">
                            {c > 0 && <div className="h-full bg-red-500" style={{ width: `${(c/f.length)*100}%` }}/>}
                            {h > 0 && <div className="h-full bg-orange-550" style={{ width: `${(h/f.length)*100}%` }}/>}
                            {m > 0 && <div className="h-full bg-amber-500" style={{ width: `${(m/f.length)*100}%` }}/>}
                            {l > 0 && <div className="h-full bg-stone-400" style={{ width: `${(l/f.length)*100}%` }}/>}
                          </div>
                        </div>
                      );
                    })()}

                    <div className="space-y-2.5 max-h-[540px] overflow-y-auto pr-1">
                      {selectedScan.findings && selectedScan.findings.length > 0 ? (
                        selectedScan.findings.map((f: Finding) => {
                          const owasp = getOWASP(f.type);
                          return (
                          <div
                            key={f.id}
                            onClick={() => setSelectedFinding(f)}
                            className={`p-3.5 rounded-lg border transition-all cursor-pointer ${
                              selectedFinding?.id === f.id
                                ? "bg-orange-50/50 border-[#D4380D]/70"
                                : "bg-[#FFFEFB] border-stone-200/85 hover:border-stone-300"
                            }`}
                          >
                            <div className="flex justify-between items-start gap-2 mb-1.5">
                              <span className="font-bold text-xs text-stone-900 truncate max-w-[150px] leading-snug">
                                {f.title || f.type.replace(/-/g, " ").toUpperCase()}
                              </span>
                              {getSeverityBadge(f.severity)}
                            </div>
                            <div className="flex items-center gap-1.5 mb-1.5">
                              <span
                                className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider"
                                style={{ backgroundColor: owasp.color + "11", color: owasp.color, border: `1px solid ${owasp.color}33` }}
                              >
                                {owasp.code}: {owasp.name}
                              </span>
                              {f.cveId && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-50 border border-red-200 text-red-700 font-mono">
                                  {f.cveId}
                                </span>
                              )}
                            </div>
                            <p className="text-[10px] text-stone-500 font-mono truncate">{f.url}</p>
                            <div className="flex items-center justify-between mt-1.5 text-[10px] text-stone-500 font-mono">
                              <span>CVSS <span className="text-stone-900 font-bold">{f.cvssScore || "N/A"}</span></span>
                              {f.parameter && <span>Param: <code className="bg-stone-100 border border-stone-200 px-1 rounded text-stone-800">{f.parameter.slice(0, 20)}</code></span>}
                            </div>
                          </div>
                          );
                        })
                      ) : (
                        <div className="p-6 text-center text-stone-500 bg-[#FFFEFB] border border-stone-200 rounded-lg">
                          No vulnerabilities identified in this audit.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Column: Remediation Details & RAG Code comparisons */}
                  <div className="xl:col-span-8">
                    {selectedFinding ? (
                      <div className="cyber-card p-6 rounded-xl space-y-6">
                        
                        {/* Header Details */}
                        <div className="border-b border-stone-200 pb-4">
                          <div className="flex justify-between items-start gap-4 mb-3">
                            <div className="flex-1">
                              <div className="flex items-center flex-wrap gap-2 mb-2">
                                {(() => {
                                  const owasp = getOWASP(selectedFinding.type);
                                  return (
                                    <span
                                      className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                                      style={{ backgroundColor: owasp.color + "11", color: owasp.color, border: `1px solid ${owasp.color}33` }}
                                    >
                                      OWASP {owasp.code} · {owasp.name}
                                    </span>
                                  );
                                })()}
                                {selectedFinding.cveId && (
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-50 border border-red-200 text-red-700 font-mono font-semibold">{selectedFinding.cveId}</span>
                                )}
                                {getSeverityBadge(selectedFinding.severity)}
                              </div>
                              <h2 className="text-lg font-bold text-stone-900 leading-tight mb-1">{selectedFinding.title || selectedFinding.type.replace(/-/g," ").toUpperCase()}</h2>
                              <p className="text-xs text-[#D4380D] font-mono truncate">{selectedFinding.url}</p>
                            </div>
                            <div className="text-right shrink-0">
                              <span className="block text-[10px] text-stone-500 font-mono uppercase">CVSSv3</span>
                              <span className={`text-3xl font-black ${
                                (selectedFinding.cvssScore ?? 0) >= 9 ? "text-red-750" :
                                (selectedFinding.cvssScore ?? 0) >= 7 ? "text-[#D4380D]" :
                                (selectedFinding.cvssScore ?? 0) >= 4 ? "text-amber-700" : "text-emerald-700"
                              }`}>{selectedFinding.cvssScore ?? "N/A"}</span>
                              <span className="block text-[10px] text-stone-500 font-mono">/ 10.0</span>
                            </div>
                          </div>
                          {selectedFinding.parameter && (
                            <div className="text-[10px] font-mono text-stone-500 flex items-center gap-2">
                              <span>Affected Parameter:</span>
                              <code className="bg-stone-100 border border-stone-200 px-2 py-0.5 rounded text-stone-900">{selectedFinding.parameter}</code>
                            </div>
                          )}
                        </div>

                        {/* Evidence / RAG Explanation */}
                        <div>
                          <h4 className="text-xs font-bold text-stone-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                            <Cpu className="w-3.5 h-3.5 text-[#D4380D]" /> Executive Analysis
                          </h4>
                          <p className="text-sm text-stone-800 leading-relaxed bg-stone-50 p-4 rounded-lg border border-stone-200">
                            {selectedFinding.explanation || selectedFinding.evidence || "Retrieving security summary..."}
                          </p>
                        </div>

                        {/* Attack Simulation */}
                        {selectedFinding.attackSimulation && (
                          <div>
                            <h4 className="text-xs font-bold text-stone-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                              <Zap className="w-3.5 h-3.5 text-red-700" /> Attack Simulation
                            </h4>
                            <div className="bg-red-50/50 border border-red-200 rounded-lg p-4">
                              <pre className="text-xs text-red-800 font-mono whitespace-pre-wrap leading-relaxed">{selectedFinding.attackSimulation}</pre>
                            </div>
                          </div>
                        )}

                        {/* Fix Steps */}
                        {selectedFinding.fixSteps && selectedFinding.fixSteps.length > 0 && (
                          <div>
                            <h4 className="text-xs font-bold text-stone-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                              <CheckCircle className="w-3.5 h-3.5 text-emerald-700" /> Remediation Steps
                            </h4>
                            <ol className="space-y-2">
                              {selectedFinding.fixSteps.map((step: string, i: number) => (
                                <li key={i} className="flex items-start gap-2.5 text-sm text-stone-800">
                                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 text-[10px] font-bold flex items-center justify-center mt-0.5">{i+1}</span>
                                  {step}
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}
                        {/* Vulnerable vs Fixed Code Split Screen */}
                        {selectedFinding.codeExample && (
                          <div>
                            <h4 className="text-xs font-bold text-stone-600 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                              <Code className="w-3.5 h-3.5 text-emerald-700" /> Remediation Code Comparison
                            </h4>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              {/* Vulnerable Snippet */}
                              <div className="rounded-lg border border-red-200 bg-red-50/30 overflow-hidden">
                                <div className="px-4 py-2 border-b border-red-200 bg-red-100/50 flex items-center justify-between text-xs text-red-750 font-semibold">
                                  <span className="flex items-center gap-1.5"><AlertCircle className="w-3.5 h-3.5" /> Vulnerable Code</span>
                                  <span className="font-mono opacity-60">.{selectedFinding.codeExample.language || "js"}</span>
                                </div>
                                <pre className="p-4 overflow-x-auto text-[11px] font-mono text-stone-900 max-h-48">
                                  <code>{selectedFinding.codeExample.vulnerable}</code>
                                </pre>
                              </div>

                              {/* Fixed Snippet */}
                              <div className="rounded-lg border border-emerald-200 bg-emerald-50/30 overflow-hidden">
                                <div className="px-4 py-2 border-b border-emerald-200 bg-emerald-100/50 flex items-center justify-between text-xs text-emerald-800 font-semibold">
                                  <span className="flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5" /> Remediated Code</span>
                                  <span className="font-mono opacity-60">.{selectedFinding.codeExample.language || "js"}</span>
                                </div>
                                <pre className="p-4 overflow-x-auto text-[11px] font-mono text-stone-900 max-h-48">
                                  <code>{selectedFinding.codeExample.fixed}</code>
                                </pre>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Remediative Action Checklist */}
                        {selectedFinding.fixSteps && Array.isArray(selectedFinding.fixSteps) && (
                          <div>
                            <h4 className="text-xs font-bold text-stone-600 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                              <FileCode className="w-3.5 h-3.5 text-stone-750" /> Recommended Fix Actions
                            </h4>
                            <ul className="space-y-2.5">
                              {selectedFinding.fixSteps.map((step: string, idx: number) => (
                                <li key={idx} className="flex gap-3 text-sm text-stone-800 items-start">
                                  <span className="w-5 h-5 rounded-full bg-orange-50 border border-orange-200 text-[10px] font-mono text-[#D4380D] flex items-center justify-center shrink-0 mt-0.5">{idx + 1}</span>
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                      </div>
                    ) : (
                      <div className="cyber-card p-12 text-center text-stone-500 rounded-xl flex flex-col items-center justify-center bg-white border border-stone-200">
                        <Shield className="w-12 h-12 mb-3 text-[#D4380D] opacity-20" />
                        <p className="text-sm">Select an alert from the checklist to explore AI fixes and code adjustments.</p>
                      </div>
                    )}
                  </div>

                </div>
              ) : (
                <div className="cyber-card p-12 rounded-xl text-center max-w-2xl mx-auto mt-8 bg-white border border-stone-200">
                  <Shield className="w-16 h-16 text-[#D4380D]/20 mx-auto mb-4" />
                  <h3 className="text-lg font-bold text-stone-900 mb-2">No Target Audited</h3>
                  <p className="text-xs text-stone-600 mb-6">Enter any public URL above to run a real passive security audit — checks HTTP headers, cookies, CORS policy, robots.txt exposure and more.</p>
                  <div className="flex gap-4 justify-center flex-wrap">
                    <button 
                      onClick={() => setTargetUrl("http://testphp.vulnweb.com")} 
                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-stone-100 border border-stone-250 text-stone-800 hover:bg-stone-200 transition-all cursor-pointer"
                    >
                      Try: testphp.vulnweb.com (intentionally vulnerable)
                    </button>
                    <button 
                      onClick={() => setTargetUrl("https://example.com")} 
                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-stone-100 border border-stone-250 text-stone-800 hover:bg-stone-200 transition-all cursor-pointer"
                    >
                      Try: example.com
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SCANNER HISTORY */}
          {activeTab === "scans" && (
            <div className="space-y-6 max-w-4xl mx-auto">
              <div className="flex justify-between items-center">
                <div>
                  <h2 className="text-xl font-extrabold text-stone-900">Vulnerability Scans History</h2>
                  <p className="text-xs text-stone-600">Review all previously run audits, target endpoints, scan dates, and detected alert frequencies.</p>
                </div>
                <button
                  onClick={loadScans}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white border border-stone-250 text-[#D4380D] hover:bg-stone-50 flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" /> Refresh List
                </button>
              </div>

              <div className="cyber-card rounded-xl overflow-hidden bg-white border border-stone-200/80">
                <table className="w-full text-left text-sm border-collapse">
                  <thead>
                    <tr className="bg-stone-50 border-b border-stone-200 text-[11px] text-stone-500 uppercase tracking-widest font-mono">
                      <th className="p-4">Target Website</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Date Started</th>
                      <th className="p-4 text-center">Alerts</th>
                      <th className="p-4"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-200 bg-white">
                    {scans.length > 0 ? (
                      scans.map((s) => (
                        <tr key={s.id} className="hover:bg-stone-50/50 transition-all">
                          <td className="p-4 font-bold text-stone-900 truncate max-w-xs">{s.targetUrl}</td>
                          <td className="p-4">{getStatusBadge(s.status)}</td>
                          <td className="p-4 text-xs text-stone-600 font-mono">
                            {s.createdAt.toLocaleString()}
                          </td>
                          <td className="p-4 text-center">
                            <span className="px-2 py-0.5 text-xs font-bold font-mono rounded bg-red-50 border border-red-200 text-red-700">
                              {s._count.findings}
                            </span>
                          </td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => handleSelectScan(s.id)}
                                className="px-3 py-1 rounded text-xs font-semibold bg-orange-50 border border-orange-200 text-[#D4380D] hover:bg-[#D4380D] hover:text-white transition-all flex items-center gap-1.5 cursor-pointer"
                              >
                                Details <ChevronRight className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDeleteScan(s.id)}
                                disabled={isDeletingScan === s.id}
                                className="px-3 py-1 rounded text-xs font-semibold bg-red-50 border border-red-200 text-red-700 hover:bg-red-600 hover:text-white transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40"
                              >
                                {isDeletingScan === s.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <AlertTriangle className="w-3 h-3" />}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="p-12 text-center text-stone-500">
                          <Shield className="w-12 h-12 opacity-20 mx-auto mb-3" />
                          No history logged. Deploy an analysis from the main dashboard.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: REMEDIATION RAG CHAT */}
          {activeTab === "rag" && (
            <div className="max-w-4xl mx-auto h-[calc(100vh-12rem)] flex flex-col justify-between">
              <div>
                <h2 className="text-xl font-extrabold text-stone-900 mb-1">Remediation RAG Chat</h2>
                <p className="text-xs text-stone-600">Ask questions using your scanner's past historical results coupled with global OWASP standards.</p>
              </div>

              {/* Chat Viewport */}
              <div className="flex-1 bg-stone-50 border border-stone-200 rounded-xl my-4 p-6 overflow-y-auto space-y-4 max-h-[500px]">
                {chatMessages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex ${
                      msg.sender === "user" ? "justify-end" : "justify-start"
                    }`}
                  >
                    <div
                      className={`max-w-[80%] rounded-xl p-4 text-sm leading-relaxed border ${
                        msg.sender === "user"
                          ? "bg-orange-50/70 border-orange-200/80 text-stone-900"
                          : "bg-white border-stone-200 text-stone-900"
                      }`}
                    >
                      {/* Message Text */}
                      <p className="whitespace-pre-wrap">{msg.text}</p>

                      {/* Source attribution rendering */}
                      {msg.sources && (
                        <div className="mt-3.5 pt-2 border-t border-stone-200 text-[10px] text-stone-500 font-mono">
                          <p className="font-bold text-stone-500 uppercase tracking-wider mb-1">RAG Context Checked:</p>
                          <ul className="space-y-1">
                            {msg.sources.guidelines && (
                              <li className="flex items-center gap-1.5 text-emerald-700">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                Reference guidelines (OWASP, CWE, NVD)
                              </li>
                            )}
                            {msg.sources.pastFindings.length > 0 ? (
                              msg.sources.pastFindings.map((f, fIdx) => (
                                <li key={fIdx} className="flex items-center gap-1.5 text-stone-700">
                                  <span className="w-1.5 h-1.5 rounded-full bg-stone-400" />
                                  Past Finding: {f.title} ({f.severity}) on {f.url.substring(0, 30)}...
                                </li>
                              ))
                            ) : (
                              <li className="flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-stone-400" />
                                No matching anomalies in past audits.
                              </li>
                            )}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {isAskingRAG && (
                  <div className="flex justify-start">
                    <div className="max-w-[80%] rounded-xl p-4 bg-white border border-stone-200 text-stone-500 flex items-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#D4380D]" />
                      <span>Vectorizing inquiry and fetching database nodes...</span>
                    </div>
                  </div>
                )}
                <div ref={chatBottomRef} />
              </div>

              {/* Chat Form */}
              <form onSubmit={handleSendChatMessage} className="flex gap-3 bg-white p-2 rounded-xl border border-stone-200 hover:border-stone-300 transition-all">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="e.g. 'How do I resolve SQL injection?' or 'Have we detected XSS in past scans?'"
                  disabled={isAskingRAG}
                  className="flex-1 bg-transparent text-sm text-stone-900 px-3 outline-none py-2"
                />
                <button
                  type="submit"
                  disabled={isAskingRAG || !chatInput.trim()}
                  className="p-2.5 rounded-lg bg-[#D4380D] hover:bg-[#B5300A] text-white font-semibold transition-all disabled:opacity-40 cursor-pointer"
                >
                  <Send className="w-4.5 h-4.5" />
                </button>
              </form>
            </div>
          )}

          {/* TAB 4: SECURITY STANDARDS KB */}
          {activeTab === "knowledge" && (
            <div className="max-w-4xl mx-auto space-y-6">
              <div>
                <h2 className="text-xl font-extrabold text-stone-900">Vulnerability Reference Base</h2>
                <p className="text-xs text-stone-600">Review reference criteria loaded in the local vector DB to provide context for AI recommendations.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="cyber-card p-5 rounded-lg bg-white border border-stone-200/80">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-orange-50 border border-orange-200 text-[#D4380D] uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-stone-900 text-sm">SQL Injection (SQLi)</h3>
                  </div>
                  <p className="text-xs text-stone-600 leading-relaxed">Direct string concatenations into SQL formats. Remediate with parameterized queries and prepared interfaces.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg bg-white border border-stone-200/80">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-orange-50 border border-orange-200 text-[#D4380D] uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-stone-900 text-sm">Cross-Site Scripting (XSS)</h3>
                  </div>
                  <p className="text-xs text-stone-600 leading-relaxed">Reflecting query arguments or saving them to DOM locations without HTML escaping. Remediate by context escaping inputs.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg bg-white border border-stone-200/80">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-orange-50 border border-orange-200 text-[#D4380D] uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-stone-900 text-sm">Missing Security Headers</h3>
                  </div>
                  <p className="text-xs text-stone-600 leading-relaxed">Servers lacking HSTS, CSP, X-Frame-Options, or mime sniffing controls. Remediate by configuring proxy headers.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg bg-white border border-stone-200/80">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 uppercase tracking-widest font-mono">NVD CVE</span>
                    <h3 className="font-bold text-stone-900 text-sm">CVE-2024-34351 SSRF</h3>
                  </div>
                  <p className="text-xs text-stone-600 leading-relaxed">Server action redirect inputs resulting in server side request forgery inside Next.js. Remediate by limiting redirect destinations.</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

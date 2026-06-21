"use client";

import React, { useState, useEffect, useRef } from "react";
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
  AlertCircle
} from "lucide-react";
import { 
  createScanAction, 
  getScansAction, 
  getScanDetailsAction, 
  deleteScanAction,
  askRAGAction 
} from "@/lib/actions";

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

  const handleExportPDF = () => {
    if (!selectedScan) return;
    window.print();
  };

  const getSafetyVerdict = (scan: any) => {
    if (!scan || scan.status !== "COMPLETED") return null;
    const findings = scan.findings || [];
    const critical = findings.filter((f: any) => f.severity === "CRITICAL").length;
    const high = findings.filter((f: any) => f.severity === "HIGH").length;
    if (findings.length === 0) return { label: "SAFE", color: "emerald" };
    if (critical > 0) return { label: "CRITICAL RISK", color: "red" };
    if (high > 0) return { label: "HIGH RISK", color: "orange" };
    return { label: "MODERATE RISK", color: "amber" };
  };

  // Status Badge Formatter
  const getStatusBadge = (status: string) => {
    switch (status) {
      case "PENDING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-900 border border-gray-800 text-gray-400 flex items-center gap-1 w-max"><Activity className="w-3 h-3 animate-pulse" /> Pending</span>;
      case "CRAWLING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950/50 border border-cyan-800/50 text-cyan-400 flex items-center gap-1 w-max animate-pulse"><Globe className="w-3 h-3" /> Crawling</span>;
      case "SCANNING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-950/50 border border-blue-800/50 text-blue-400 flex items-center gap-1 w-max"><Cpu className="w-3 h-3 animate-spin" /> Auditing</span>;
      case "ANALYZING":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/50 border border-amber-800/50 text-amber-400 flex items-center gap-1 w-max"><RefreshCw className="w-3 h-3 animate-spin" /> AI RAG Analysis</span>;
      case "COMPLETED":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/50 border border-emerald-800/50 text-emerald-400 flex items-center gap-1 w-max"><CheckCircle className="w-3 h-3" /> Protected</span>;
      case "FAILED":
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-950/50 border border-red-800/50 text-red-400 flex items-center gap-1 w-max"><AlertTriangle className="w-3 h-3" /> Failed</span>;
      default:
        return null;
    }
  };

  // Severity Tag Formatter
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-red-950 border border-red-800 text-red-400">CRITICAL</span>;
      case "HIGH":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-orange-950 border border-orange-850 text-orange-400">HIGH</span>;
      case "MEDIUM":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-amber-950 border border-amber-800 text-amber-400">MEDIUM</span>;
      case "LOW":
        return <span className="px-2 py-1 text-xs font-bold rounded bg-blue-950 border border-blue-800 text-blue-400">LOW</span>;
      default:
        return <span className="px-2 py-1 text-xs font-bold rounded bg-gray-900 border border-gray-800 text-gray-400">INFO</span>;
    }
  };

  return (
    <div className="flex min-h-screen bg-[#07090e] radar-bg">
      {/* 🚀 LEFT SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-[#1e2638] bg-[#0b0e17] flex flex-col justify-between p-6">
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="p-2 rounded bg-gradient-to-tr from-cyan-600 to-emerald-600 text-white">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-lg tracking-tight text-white glow-teal">VulnScanner</h1>
              <span className="text-[10px] uppercase font-semibold text-cyan-400 tracking-widest bg-cyan-950/40 px-1.5 py-0.5 rounded">RAG remediator</span>
            </div>
          </div>

          <nav className="space-y-1.5">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all ${
                activeTab === "dashboard"
                  ? "bg-gradient-to-r from-cyan-950/50 to-emerald-950/20 border-l-4 border-cyan-500 text-white font-bold"
                  : "text-gray-400 hover:text-white hover:bg-gray-900/50"
              }`}
            >
              <Activity className="w-4 h-4" />
              Audits Dashboard
            </button>

            <button
              onClick={() => setActiveTab("scans")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all ${
                activeTab === "scans"
                  ? "bg-gradient-to-r from-cyan-950/50 to-emerald-950/20 border-l-4 border-cyan-500 text-white font-bold"
                  : "text-gray-400 hover:text-white hover:bg-gray-900/50"
              }`}
            >
              <Terminal className="w-4 h-4" />
              Scanner History
            </button>

            <button
              onClick={() => setActiveTab("rag")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all ${
                activeTab === "rag"
                  ? "bg-gradient-to-r from-cyan-950/50 to-emerald-950/20 border-l-4 border-cyan-500 text-white font-bold"
                  : "text-gray-400 hover:text-white hover:bg-gray-900/50"
              }`}
            >
              <Cpu className="w-4 h-4" />
              Remediation RAG Chat
            </button>

            <button
              onClick={() => setActiveTab("knowledge")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all ${
                activeTab === "knowledge"
                  ? "bg-gradient-to-r from-cyan-950/50 to-emerald-950/20 border-l-4 border-cyan-500 text-white font-bold"
                  : "text-gray-400 hover:text-white hover:bg-gray-900/50"
              }`}
            >
              <BookOpen className="w-4 h-4" />
              Security Standards KB
            </button>
          </nav>
        </div>

        <div className="border-t border-[#1e2638] pt-6 text-[11px] text-gray-500 font-mono">
          <p>Local time: {now.toLocaleTimeString()}</p>
          <p>{now.toLocaleDateString()}</p>
          <p>Scanner Host: localhost</p>
        </div>
      </aside>

      {/* 🚀 MAIN CONTENT CONTAINER */}
      <main className="flex-1 flex flex-col min-h-screen max-h-screen overflow-y-auto">
        {/* TOP STATUS BAR */}
        <header className="h-16 border-b border-[#1e2638] bg-[#090d16]/80 backdrop-blur-md px-8 flex items-center justify-between z-10 sticky top-0">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-widest font-mono">SecOps Node Online</span>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-xs font-semibold text-white">Security Admin</p>
              <p className="text-[10px] text-cyan-400 font-mono">admin@vulnscanner.io</p>
            </div>
            <div className="w-9 h-9 rounded-full bg-[#1e2638] border border-cyan-500/30 flex items-center justify-center font-bold text-cyan-400">
              SA
            </div>
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
                    <h2 className="text-lg font-bold text-white mb-1">Launch Passive Security Audit</h2>
                    <p className="text-xs text-gray-400 mb-6">Real HTTP header inspection, cookie security checks, CORS analysis, and AI-powered RAG remediation — all non-destructive passive checks.</p>
                  </div>

                  <form onSubmit={handleLaunchScan} className="flex gap-3">
                    <div className="relative flex-1">
                      <Globe className="absolute left-3 top-3 w-4 h-4 text-gray-500" />
                      <input
                        type="text"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="e.g. example.com or https://yoursite.com"
                        required
                        disabled={isScanning}
                        className="w-full bg-[#0a0d15] border border-[#1e2638] hover:border-cyan-500/40 focus:border-cyan-500 text-white rounded-lg pl-10 pr-4 py-2.5 text-sm outline-none transition-all placeholder:text-gray-600"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={isScanning}
                      className="px-6 py-2.5 rounded-lg text-sm font-semibold bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white transition-all shadow-md shadow-cyan-950/40 flex items-center gap-2 disabled:opacity-50 cursor-pointer"
                    >
                      {isScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
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
                  <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-4">Active Auditor Feed</h3>
                  {selectedScan ? (
                    <div className="space-y-4">
                      <div>
                        <p className="text-xs text-gray-500 font-mono">TARGET TARGET</p>
                        <p className="text-sm font-bold text-white truncate">{selectedScan.targetUrl}</p>
                      </div>
                      <div className="flex justify-between items-center bg-[#07090e] p-3 rounded-lg border border-[#1e2638]">
                        <span className="text-xs text-gray-400">Current Phase</span>
                        {getStatusBadge(selectedScan.status)}
                      </div>
                      {selectedScan.status === "SCANNING" && (
                        <div className="w-full bg-gray-950 h-1 rounded-full overflow-hidden">
                          <div className="h-full bg-blue-500 animate-pulse w-3/5" />
                        </div>
                      )}
                      {selectedScan.status === "CRAWLING" && (
                        <div className="w-full bg-gray-950 h-1 rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-500 animate-pulse w-1/3" />
                        </div>
                      )}
                      {selectedScan.status === "ANALYZING" && (
                        <div className="w-full bg-gray-950 h-1 rounded-full overflow-hidden">
                          <div className="h-full bg-amber-500 animate-pulse w-4/5" />
                        </div>
                      )}
                      {selectedScan.status === "COMPLETED" && (
                        <p className="text-[11px] text-emerald-400 font-mono flex items-center gap-1.5">
                          <CheckCircle className="w-3.5 h-3.5" /> Scan complete. {selectedScan.findings?.length || 0} alerts.
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="h-28 flex flex-col items-center justify-center text-center text-gray-600">
                      <Activity className="w-8 h-8 mb-2 opacity-30 animate-pulse" />
                      <p className="text-xs">No active scan selected.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Main Analysis Screen */}
              {selectedScan ? (
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
                  {/* Safety Verdict Banner */}
                  {(() => {
                    const verdict = getSafetyVerdict(selectedScan);
                    if (!verdict) return null;
                    const colorMap: Record<string, string> = {
                      emerald: "bg-emerald-950/30 border-emerald-700/50 text-emerald-400",
                      red: "bg-red-950/30 border-red-700/50 text-red-400",
                      orange: "bg-orange-950/30 border-orange-700/50 text-orange-400",
                      amber: "bg-amber-950/30 border-amber-700/50 text-amber-400",
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
                        <button
                          onClick={handleExportPDF}
                          className="px-4 py-2 rounded-lg text-xs font-bold bg-[#0e121a] border border-[#1e2638] text-gray-300 hover:text-white hover:border-gray-600 transition-all flex items-center gap-2 cursor-pointer print:hidden"
                        >
                          <FileCode className="w-3.5 h-3.5" /> Export PDF Report
                        </button>
                      </div>
                    );
                  })()}
                  
                  {/* Left Column: Alerts List */}
                  <div className="xl:col-span-4 space-y-3">
                    <div className="flex justify-between items-center mb-1">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider">Alerts & Findings</h3>
                      <span className="px-2 py-0.5 text-xs rounded bg-red-950 border border-red-800 text-red-400 font-mono font-bold">
                        {selectedScan.findings?.length || 0} Issues
                      </span>
                    </div>

                    <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
                      {selectedScan.findings && selectedScan.findings.length > 0 ? (
                        selectedScan.findings.map((f: Finding) => (
                          <div
                            key={f.id}
                            onClick={() => setSelectedFinding(f)}
                            className={`p-4 rounded-lg border transition-all cursor-pointer ${
                              selectedFinding?.id === f.id
                                ? "bg-cyan-950/20 border-cyan-500/70"
                                : "bg-[#0c0f18] border-[#1e2638] hover:border-gray-750"
                            }`}
                          >
                            <div className="flex justify-between items-start gap-3 mb-2">
                              <span className="font-bold text-sm text-white truncate max-w-[170px]">
                                {f.title || f.type.toUpperCase()}
                              </span>
                              {getSeverityBadge(f.severity)}
                            </div>
                            <p className="text-xs text-gray-400 font-mono truncate mb-2">{f.url}</p>
                            <div className="flex items-center justify-between text-[10px] text-gray-500 font-mono">
                              <span>CVSS: {f.cvssScore || "N/A"}</span>
                              {f.parameter && <span>Param: <code className="bg-[#1e2638] px-1 rounded text-cyan-400">{f.parameter}</code></span>}
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="p-6 text-center text-gray-500 bg-[#0c0f18] border border-[#1e2638] rounded-lg">
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
                        <div className="border-b border-[#1e2638] pb-4 flex justify-between items-start gap-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1.5">
                              <h2 className="text-xl font-bold text-white leading-tight">{selectedFinding.title || selectedFinding.type.toUpperCase()}</h2>
                              {selectedFinding.cveId && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/40 border border-red-800/40 text-red-400 font-mono font-semibold">{selectedFinding.cveId}</span>
                              )}
                            </div>
                            <p className="text-xs text-cyan-400 font-mono truncate">{selectedFinding.url}</p>
                          </div>
                          <div className="text-right">
                            <span className="block text-[10px] text-gray-500 font-mono uppercase">CVSS Score</span>
                            <span className="text-2xl font-black text-white glow-teal">{selectedFinding.cvssScore || "N/A"}</span>
                          </div>
                        </div>

                        {/* RAG Explanation */}
                        <div>
                          <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                            <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Executive Analysis
                          </h4>
                          <p className="text-sm text-gray-300 leading-relaxed bg-[#07090e] p-4 rounded-lg border border-[#1e2638]">
                            {selectedFinding.explanation || "Retrieving security summary..."}
                          </p>
                        </div>

                        {/* Vulnerable vs Fixed Code Split Screen */}
                        {selectedFinding.codeExample && (
                          <div>
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                              <Code className="w-3.5 h-3.5 text-emerald-400" /> Remediation Code Comparison
                            </h4>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                              {/* Vulnerable Snippet */}
                              <div className="rounded-lg border border-red-800/50 bg-[#0d0a0b] overflow-hidden">
                                <div className="px-4 py-2 border-b border-red-800/40 bg-red-950/20 flex items-center justify-between text-xs text-red-400 font-semibold">
                                  <span className="flex items-center gap-1.5"><AlertCircle className="w-3.5 h-3.5" /> Vulnerable Code</span>
                                  <span className="font-mono opacity-60">.{selectedFinding.codeExample.language || "js"}</span>
                                </div>
                                <pre className="p-4 overflow-x-auto text-[11px] font-mono text-gray-300 max-h-48">
                                  <code>{selectedFinding.codeExample.vulnerable}</code>
                                </pre>
                              </div>

                              {/* Fixed Snippet */}
                              <div className="rounded-lg border border-emerald-800/50 bg-[#0a0d0b] overflow-hidden">
                                <div className="px-4 py-2 border-b border-emerald-800/40 bg-emerald-950/20 flex items-center justify-between text-xs text-emerald-400 font-semibold">
                                  <span className="flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5" /> Remediated Code</span>
                                  <span className="font-mono opacity-60">.{selectedFinding.codeExample.language || "js"}</span>
                                </div>
                                <pre className="p-4 overflow-x-auto text-[11px] font-mono text-gray-300 max-h-48">
                                  <code>{selectedFinding.codeExample.fixed}</code>
                                </pre>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Remediative Action Checklist */}
                        {selectedFinding.fixSteps && Array.isArray(selectedFinding.fixSteps) && (
                          <div>
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                              <FileCode className="w-3.5 h-3.5 text-cyan-400" /> Recommended Fix Actions
                            </h4>
                            <ul className="space-y-2.5">
                              {selectedFinding.fixSteps.map((step: string, idx: number) => (
                                <li key={idx} className="flex gap-3 text-sm text-gray-300 items-start">
                                  <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-[10px] font-mono text-cyan-400 flex items-center justify-center shrink-0 mt-0.5">{idx + 1}</span>
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                      </div>
                    ) : (
                      <div className="cyber-card p-12 text-center text-gray-500 rounded-xl flex flex-col items-center justify-center">
                        <Shield className="w-12 h-12 mb-3 text-cyan-500 opacity-20" />
                        <p className="text-sm">Select an alert from the checklist to explore AI fixes and code adjustments.</p>
                      </div>
                    )}
                  </div>

                </div>
              ) : (
                <div className="cyber-card p-12 rounded-xl text-center max-w-2xl mx-auto mt-8">
                  <Shield className="w-16 h-16 text-cyan-500/20 mx-auto mb-4" />
                  <h3 className="text-lg font-bold text-white mb-2">No Target Audited</h3>
                  <p className="text-xs text-gray-400 mb-6">Enter any public URL above to run a real passive security audit — checks HTTP headers, cookies, CORS policy, robots.txt exposure and more.</p>
                  <div className="flex gap-4 justify-center flex-wrap">
                    <button 
                      onClick={() => setTargetUrl("http://testphp.vulnweb.com")} 
                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#111624] border border-[#1e2638] text-gray-300 hover:text-white hover:border-gray-700 transition-all cursor-pointer"
                    >
                      Try: testphp.vulnweb.com (intentionally vulnerable)
                    </button>
                    <button 
                      onClick={() => setTargetUrl("https://example.com")} 
                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#111624] border border-[#1e2638] text-gray-300 hover:text-white hover:border-gray-700 transition-all cursor-pointer"
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
                  <h2 className="text-xl font-extrabold text-white">Vulnerability Scans History</h2>
                  <p className="text-xs text-gray-400">Review all previously run audits, target endpoints, scan dates, and detected alert frequencies.</p>
                </div>
                <button
                  onClick={loadScans}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#0e121a] border border-[#1e2638] text-cyan-400 hover:text-white hover:border-cyan-500/30 flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" /> Refresh List
                </button>
              </div>

              <div className="cyber-card rounded-xl overflow-hidden">
                <table className="w-full text-left text-sm border-collapse">
                  <thead>
                    <tr className="bg-[#0e121a] border-b border-[#1e2638] text-[11px] text-gray-500 uppercase tracking-widest font-mono">
                      <th className="p-4">Target Website</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Date Started</th>
                      <th className="p-4 text-center">Alerts</th>
                      <th className="p-4"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2638] bg-[#0c0f18]/40">
                    {scans.length > 0 ? (
                      scans.map((s) => (
                        <tr key={s.id} className="hover:bg-gray-950/30 transition-all">
                          <td className="p-4 font-bold text-white truncate max-w-xs">{s.targetUrl}</td>
                          <td className="p-4">{getStatusBadge(s.status)}</td>
                          <td className="p-4 text-xs text-gray-400 font-mono">
                            {s.createdAt.toLocaleString()}
                          </td>
                          <td className="p-4 text-center">
                            <span className="px-2 py-0.5 text-xs font-bold font-mono rounded bg-red-950/40 border border-red-800/40 text-red-400">
                              {s._count.findings}
                            </span>
                          </td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => handleSelectScan(s.id)}
                                className="px-3 py-1 rounded text-xs font-semibold bg-cyan-950/50 border border-cyan-800 text-cyan-400 hover:bg-cyan-500 hover:text-black transition-all flex items-center gap-1.5 cursor-pointer"
                              >
                                Details <ChevronRight className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDeleteScan(s.id)}
                                disabled={isDeletingScan === s.id}
                                className="px-3 py-1 rounded text-xs font-semibold bg-red-950/30 border border-red-900/50 text-red-400 hover:bg-red-500 hover:text-white transition-all flex items-center gap-1 cursor-pointer disabled:opacity-40"
                              >
                                {isDeletingScan === s.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <AlertTriangle className="w-3 h-3" />}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="p-12 text-center text-gray-500">
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
                <h2 className="text-xl font-extrabold text-white mb-1">Remediation RAG Chat</h2>
                <p className="text-xs text-gray-400">Ask questions using your scanner's past historical results coupled with global OWASP standards.</p>
              </div>

              {/* Chat Viewport */}
              <div className="flex-1 bg-[#090d16]/40 border border-[#1e2638] rounded-xl my-4 p-6 overflow-y-auto space-y-4 max-h-[500px]">
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
                          ? "bg-gradient-to-tr from-cyan-600/20 to-emerald-600/10 border-cyan-500/50 text-white"
                          : "bg-[#0f131f]/90 border-[#1e2638] text-gray-200"
                      }`}
                    >
                      {/* Message Text (Markdown Render Support Mock) */}
                      <p className="whitespace-pre-wrap">{msg.text}</p>

                      {/* Source attribution rendering */}
                      {msg.sources && (
                        <div className="mt-3.5 pt-2 border-t border-[#1e2638] text-[10px] text-gray-500 font-mono">
                          <p className="font-bold text-gray-400 uppercase tracking-wider mb-1">RAG Context Checked:</p>
                          <ul className="space-y-1">
                            {msg.sources.guidelines && (
                              <li className="flex items-center gap-1.5 text-emerald-400">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                Reference guidelines (OWASP, CWE, NVD)
                              </li>
                            )}
                            {msg.sources.pastFindings.length > 0 ? (
                              msg.sources.pastFindings.map((f, fIdx) => (
                                <li key={fIdx} className="flex items-center gap-1.5 text-cyan-400">
                                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
                                  Past Finding: {f.title} ({f.severity}) on {f.url.substring(0, 30)}...
                                </li>
                              ))
                            ) : (
                              <li className="flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-gray-600" />
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
                    <div className="max-w-[80%] rounded-xl p-4 bg-[#0f131f]/90 border border-[#1e2638] text-gray-400 flex items-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                      <span>Vectorizing inquiry and fetching database nodes...</span>
                    </div>
                  </div>
                )}
                <div ref={chatBottomRef} />
              </div>

              {/* Chat Form */}
              <form onSubmit={handleSendChatMessage} className="flex gap-3 bg-[#0a0d15] p-2 rounded-xl border border-[#1e2638] hover:border-cyan-500/30 transition-all">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="e.g. 'How do I resolve SQL injection?' or 'Have we detected XSS in past scans?'"
                  disabled={isAskingRAG}
                  className="flex-1 bg-transparent text-sm text-white px-3 outline-none py-2"
                />
                <button
                  type="submit"
                  disabled={isAskingRAG || !chatInput.trim()}
                  className="p-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-black font-semibold transition-all disabled:opacity-40 cursor-pointer"
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
                <h2 className="text-xl font-extrabold text-white">Vulnerability Reference Base</h2>
                <p className="text-xs text-gray-400">Review reference criteria loaded in the local vector DB to provide context for AI recommendations.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="cyber-card p-5 rounded-lg">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-white text-sm">SQL Injection (SQLi)</h3>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">Direct string concatenations into SQL formats. Remediate with parameterized queries and prepared interfaces.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-white text-sm">Cross-Site Scripting (XSS)</h3>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">Reflecting query arguments or saving them to DOM locations without HTML escaping. Remediate by context escaping inputs.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 uppercase tracking-widest font-mono">OWASP</span>
                    <h3 className="font-bold text-white text-sm">Missing Security Headers</h3>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">Servers lacking HSTS, CSP, X-Frame-Options, or mime sniffing controls. Remediate by configuring proxy headers.</p>
                </div>

                <div className="cyber-card p-5 rounded-lg">
                  <div className="flex items-center gap-2.5 mb-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-400 uppercase tracking-widest font-mono">NVD CVE</span>
                    <h3 className="font-bold text-white text-sm">CVE-2024-34351 SSRF</h3>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">Server action redirect inputs resulting in server side request forgery inside Next.js. Remediate by limiting redirect destinations.</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo, Suspense } from "react";
import {
  Shield,
  Lock,
  Search,
  GitBranch,
  Star,
  Clock,
  ChevronDown,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  LogOut,
  Sparkles,
  ExternalLink,
  Code,
  Package,
  Key,
  Brain,
  AlertCircle,
  X,
  ArrowRight,
  Layers,
  List,
  Tag,
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  getGitHubSessionAction,
  getGitHubReposAction,
  getRepoBranchesAction,
  createGitHubScanAction,
  getGitHubScanDetailsAction,
} from "@/lib/actions";

// GitHub icon SVG (lucide-react v1.18+ dropped it)
const Github = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
  </svg>
);

// ── Types ──────────────────────────────────────────────────────────────────────
interface GitHubUser {
  login: string;
  avatarUrl: string;
  name: string | null;
}

interface Repo {
  id: number;
  fullName: string;
  name: string;
  private: boolean;
  language: string | null;
  description: string | null;
  stargazersCount: number;
  pushedAt: string | null;
  defaultBranch: string;
}

interface Finding {
  id: string;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  url: string;
  parameter: string | null;
  evidence: string | null;
  cvssScore: number | null;
  cveId: string | null;
  title: string | null;
  explanation: string | null;
  fixSteps: string[] | null;
  codeExample: { vulnerable: string; fixed: string; language: string } | null;
}

// ── Constants ──────────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff3b30", bg: "#fff0ee", label: "Critical", rank: 4 },
  HIGH: { color: "#ff9500", bg: "#fff8ee", label: "High", rank: 3 },
  MEDIUM: { color: "#ffcc00", bg: "#fffbee", label: "Medium", rank: 2 },
  LOW: { color: "#34c759", bg: "#f0fff4", label: "Low", rank: 1 },
  INFO: { color: "#007aff", bg: "#eef4ff", label: "Info", rank: 0 },
};

const ENGINE_CONFIG = [
  { key: "secrets", label: "Secrets Scanner", icon: Key, color: "#ff3b30", desc: "Regex detection of API keys, tokens & passwords" },
  { key: "sast", label: "SAST Analysis", icon: Code, color: "#ff9500", desc: "Static analysis for dangerous code patterns" },
  { key: "sca", label: "SCA — Dependency CVEs", icon: Package, color: "#007aff", desc: "OSV.dev CVE lookup for all npm packages" },
  { key: "llm", label: "LLM Deep Review", icon: Brain, color: "#af52de", desc: "Llama 3.3 70B AI security code review" },
];

const LANG_COLORS: Record<string, string> = {
  TypeScript: "#3178c6", JavaScript: "#f0db4f", Python: "#3572a5",
  Go: "#00add8", Rust: "#ce422b", Java: "#b07219", Ruby: "#701516",
  PHP: "#4f5d95",
};

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}

function getEngineFromEvidence(evidence: string | null, type: string): string {
  if (!evidence) return "sast";
  if (evidence.startsWith("[LLM Review]")) return "llm";
  if (type === "sca-cve") return "sca";
  if (type === "secrets") return "secrets";
  return "sast";
}

// ── Components ─────────────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.INFO;
  const engine = getEngineFromEvidence(finding.evidence, finding.type);
  const eng = ENGINE_CONFIG.find((e) => e.key === engine) ?? ENGINE_CONFIG[1];
  const EngIcon = eng.icon;

  const advisoryUrl = finding.cveId?.startsWith("GHSA-")
    ? `https://github.com/advisories/${finding.cveId}`
    : finding.cveId?.startsWith("CVE-")
    ? `https://nvd.nist.gov/vuln/detail/${finding.cveId}`
    : null;

  return (
    <div
      style={{ borderLeft: `3px solid ${sev.color}` }}
      className="bg-white rounded-xl border border-[#E5E5EA] overflow-hidden transition-all shadow-sm"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-start gap-3 hover:bg-[#FBFBFC] transition-colors"
      >
        <span
          style={{ background: sev.bg, color: sev.color }}
          className="text-[10px] font-bold px-2 py-1 rounded-full shrink-0 mt-0.5"
        >
          {sev.label}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="font-bold text-sm text-[#1D1D1F] leading-snug">
              {finding.title ?? finding.type}
            </span>
            <span
              style={{ background: eng.color + "18", color: eng.color }}
              className="text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1 shrink-0"
            >
              <EngIcon className="w-2.5 h-2.5" />
              {eng.label}
            </span>
            {finding.cveId && (
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#1D1D1F]/5 text-[#1D1D1F] border border-[#1D1D1F]/10">
                {finding.cveId}
              </span>
            )}
          </div>
          {finding.parameter && (
            <p className="text-[11px] text-[#007aff] font-mono font-semibold truncate">{finding.parameter}</p>
          )}
          {finding.evidence && (
            <p className="text-[11px] text-[#86868B] mt-1 line-clamp-2">{finding.evidence}</p>
          )}
        </div>
        {finding.cvssScore != null && (
          <span
            style={{ color: sev.color }}
            className="text-xs font-bold shrink-0 ml-auto bg-[#FBFBFC] px-2 py-1 rounded-md border border-[#E5E5EA]"
          >
            CVSS {finding.cvssScore.toFixed(1)}
          </span>
        )}
        <ChevronDown
          className={`w-4 h-4 text-[#86868B] shrink-0 transition-transform mt-1 ${expanded ? "rotate-180" : ""}`}
        />
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-[#F2F2F7] pt-3 space-y-3">
          {finding.explanation && (
            <p className="text-sm text-[#3A3A3C] leading-relaxed">{finding.explanation}</p>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            {finding.url && (
              <a
                href={finding.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-[#007aff] hover:underline font-mono"
              >
                <ExternalLink className="w-3 h-3 shrink-0" />
                Source File
              </a>
            )}

            {advisoryUrl && (
              <a
                href={advisoryUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-[#D4380D] hover:underline font-mono font-semibold"
              >
                <ExternalLink className="w-3 h-3 shrink-0" />
                Official Advisory ({finding.cveId})
              </a>
            )}
          </div>

          {Array.isArray(finding.fixSteps) && finding.fixSteps.length > 0 && (
            <div className="bg-[#FAF8F5] p-3 rounded-xl border border-stone-200/80">
              <p className="text-xs font-bold text-[#1D1D1F] mb-2 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-[#D4380D]" />
                Remediation Steps
              </p>
              <ol className="space-y-1">
                {(finding.fixSteps as string[]).map((step, i) => (
                  <li key={i} className="text-xs text-[#3A3A3C] flex gap-2">
                    <span className="text-[#D4380D] font-bold shrink-0">{i + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {finding.codeExample && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <div>
                <p className="text-[10px] font-bold text-[#ff3b30] mb-1 uppercase tracking-wide">Vulnerable</p>
                <pre className="bg-[#1D1D1F] text-[#ff453a] rounded-lg p-3 text-[10px] overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">
                  {finding.codeExample.vulnerable}
                </pre>
              </div>
              <div>
                <p className="text-[10px] font-bold text-[#34c759] mb-1 uppercase tracking-wide">Fixed</p>
                <pre className="bg-[#1D1D1F] text-[#30d158] rounded-lg p-3 text-[10px] overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap">
                  {finding.codeExample.fixed}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PackageGroupCard({
  packageName,
  findings,
}: {
  packageName: string;
  findings: Finding[];
}) {
  const [expanded, setExpanded] = useState(false);

  // Highest severity
  const highestSev = useMemo(() => {
    let top = "LOW";
    let maxRank = 0;
    for (const f of findings) {
      const r = SEVERITY_CONFIG[f.severity]?.rank ?? 0;
      if (r > maxRank) {
        maxRank = r;
        top = f.severity;
      }
    }
    return top as keyof typeof SEVERITY_CONFIG;
  }, [findings]);

  const topConfig = SEVERITY_CONFIG[highestSev] ?? SEVERITY_CONFIG.MEDIUM;

  return (
    <div className="bg-white rounded-2xl border border-[#E5E5EA] overflow-hidden shadow-sm transition-all">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-center justify-between gap-4 hover:bg-[#FBFBFC] transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-[#007aff]/10 flex items-center justify-center shrink-0 text-[#007aff]">
            <Package className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-extrabold text-base text-[#1D1D1F] font-mono truncate">
                {packageName}
              </span>
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-[#1D1D1F]/5 text-[#1D1D1F] border border-[#1D1D1F]/10">
                {findings.length} {findings.length === 1 ? "Advisory" : "Advisories"}
              </span>
            </div>
            <p className="text-xs text-[#86868B] mt-0.5">
              Software Composition Analysis (SCA) Dependency CVEs
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="text-right">
            <span
              style={{ background: topConfig.bg, color: topConfig.color }}
              className="text-[10px] font-bold px-2.5 py-1 rounded-full inline-block"
            >
              Max: {topConfig.label}
            </span>
          </div>
          <ChevronDown
            className={`w-5 h-5 text-[#86868B] transition-transform ${expanded ? "rotate-180" : ""}`}
          />
        </div>
      </button>

      {expanded && (
        <div className="p-4 bg-[#FAF8F5] border-t border-[#E5E5EA] space-y-3">
          <p className="text-xs font-bold text-[#86868B] uppercase tracking-wider">
            All Advisories for {packageName} ({findings.length})
          </p>
          <div className="space-y-2">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

function GitHubPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Auth state
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [loadingUser, setLoadingUser] = useState(true);

  // Repo selection
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [repoSearch, setRepoSearch] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<Repo | null>(null);
  const [repoDropdownOpen, setRepoDropdownOpen] = useState(false);

  // Branch selection
  const [branches, setBranches] = useState<string[]>([]);
  const [selectedBranch, setSelectedBranch] = useState("main");
  const [loadingBranches, setLoadingBranches] = useState(false);
  const [branchDropdownOpen, setBranchDropdownOpen] = useState(false);

  // Scan settings
  const [enableLLM, setEnableLLM] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  // Scan results
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [engineProgress, setEngineProgress] = useState<Record<string, "pending" | "running" | "done">>({
    secrets: "pending", sast: "pending", sca: "pending", llm: "pending",
  });
  const [filterEngine, setFilterEngine] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [viewMode, setViewMode] = useState<"grouped" | "flat">("grouped");

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Load session on mount ────────────────────────────────────────────────────
  useEffect(() => {
    getGitHubSessionAction()
      .then((s) => {
        setUser(s);
        if (s) loadRepos();
      })
      .finally(() => setLoadingUser(false));
  }, []);

  // ── Check OAuth error ────────────────────────────────────────────────────────
  const oauthError = searchParams.get("error");

  // ── Load repos ───────────────────────────────────────────────────────────────
  const loadRepos = async () => {
    setLoadingRepos(true);
    try {
      const data = await getGitHubReposAction();
      setRepos(data);
    } catch {
      /* ignore */
    } finally {
      setLoadingRepos(false);
    }
  };

  // ── Repo selection ───────────────────────────────────────────────────────────
  const handleSelectRepo = async (repo: Repo) => {
    setSelectedRepo(repo);
    setRepoDropdownOpen(false);
    setSelectedBranch(repo.defaultBranch);
    setBranches([]);
    setLoadingBranches(true);
    try {
      const b = await getRepoBranchesAction(repo.fullName);
      setBranches(b);
    } catch {
      setBranches([repo.defaultBranch]);
    } finally {
      setLoadingBranches(false);
    }
  };

  // ── Start scan ───────────────────────────────────────────────────────────────
  const handleStartScan = async () => {
    if (!selectedRepo) return;
    setIsScanning(true);
    setFindings([]);
    setScanStatus("PENDING");
    setEngineProgress({ secrets: "pending", sast: "pending", sca: "pending", llm: "pending" });

    try {
      const scanId = await createGitHubScanAction(selectedRepo.fullName, selectedBranch, enableLLM);
      setCurrentScanId(scanId);
      startPolling(scanId);
    } catch (err: any) {
      setIsScanning(false);
      alert(`Failed to start scan: ${err.message}`);
    }
  };

  // ── Polling ──────────────────────────────────────────────────────────────────
  const updateEngineProgress = useCallback((status: string, findingsArr: Finding[]) => {
    const hasSecrets = findingsArr.some((f) => f.type === "secrets");
    const hasSAST = findingsArr.some((f) => !["secrets", "sca-cve"].includes(f.type) && !f.evidence?.startsWith("[LLM Review]"));
    const hasSCA = findingsArr.some((f) => f.type === "sca-cve");
    const hasLLM = findingsArr.some((f) => f.evidence?.startsWith("[LLM Review]"));

    setEngineProgress({
      secrets: status === "PENDING" ? "pending" : hasSecrets || ["SCANNING", "ANALYZING", "COMPLETED"].includes(status) ? "done" : "running",
      sast: ["PENDING", "CRAWLING"].includes(status) ? "pending" : hasSAST || ["ANALYZING", "COMPLETED"].includes(status) ? "done" : "running",
      sca: ["PENDING", "CRAWLING", "SCANNING"].includes(status) ? "pending" : hasSCA || status === "COMPLETED" ? "done" : "running",
      llm: status !== "ANALYZING" && status !== "COMPLETED" ? "pending" : hasLLM || status === "COMPLETED" ? "done" : "running",
    });
  }, []);

  const startPolling = (scanId: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const data = await getGitHubScanDetailsAction(scanId);
        if (!data) return;
        setScanStatus(data.status);
        setFindings(data.findings as Finding[]);
        updateEngineProgress(data.status, data.findings as Finding[]);

        if (data.status === "COMPLETED" || data.status === "FAILED") {
          clearInterval(pollRef.current!);
          pollRef.current = null;
          setIsScanning(false);
        }
      } catch {
        /* keep polling */
      }
    }, 3000);
  };

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  // ── Filtered findings ────────────────────────────────────────────────────────
  const filteredFindings = findings.filter((f) => {
    const engineMatch =
      filterEngine === "all" ||
      (filterEngine === "llm" && f.evidence?.startsWith("[LLM Review]")) ||
      (filterEngine === "sca" && f.type === "sca-cve") ||
      (filterEngine === "secrets" && f.type === "secrets") ||
      (filterEngine === "sast" && !["secrets", "sca-cve"].includes(f.type) && !f.evidence?.startsWith("[LLM Review]"));
    const sevMatch = filterSeverity === "all" || f.severity === filterSeverity;
    return engineMatch && sevMatch;
  });

  // Grouped findings by package for SCA
  const { scaGroups, nonScaFindings } = useMemo(() => {
    const sca: Record<string, Finding[]> = {};
    const nonSca: Finding[] = [];

    for (const f of filteredFindings) {
      if (f.type === "sca-cve" && f.parameter) {
        if (!sca[f.parameter]) sca[f.parameter] = [];
        sca[f.parameter].push(f);
      } else {
        nonSca.push(f);
      }
    }

    return { scaGroups: sca, nonScaFindings: nonSca };
  }, [filteredFindings]);

  const filteredRepos = repos.filter((r) =>
    r.fullName.toLowerCase().includes(repoSearch.toLowerCase())
  );

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#FBFBFC] text-[#1D1D1F] font-sans antialiased">

      {/* Nav */}
      <header className="fixed top-6 left-1/2 -translate-x-1/2 w-[90%] max-w-4xl h-14 bg-white/85 backdrop-blur-md border border-[#E5E5EA] rounded-full shadow-sm flex items-center justify-between px-6 z-50">
        <button onClick={() => router.push("/")} className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-[#D4380D] flex items-center justify-center text-white">
            <Shield className="w-4.5 h-4.5" />
          </div>
          <span className="font-extrabold text-base tracking-tight">VulnScanner</span>
        </button>

        <div className="flex items-center gap-3">
          {user ? (
            <>
              <img src={user.avatarUrl} alt={user.login} className="w-7 h-7 rounded-full border-2 border-[#E5E5EA]" />
              <span className="text-sm font-semibold text-[#1D1D1F] hidden sm:block">@{user.login}</span>
              <a
                href="/api/auth/github/logout"
                className="flex items-center gap-1 px-3 py-1.5 rounded-full border border-[#E5E5EA] text-xs font-semibold text-[#86868B] hover:text-[#D4380D] hover:border-[#D4380D] transition-colors"
              >
                <LogOut className="w-3 h-3" /> Disconnect
              </a>
            </>
          ) : (
            <a
              href="/api/auth/github"
              className="flex items-center gap-1.5 px-4 h-9 rounded-full bg-[#1D1D1F] hover:bg-[#D4380D] text-white text-xs font-bold transition-all"
            >
              <Github className="w-3.5 h-3.5" /> Connect GitHub
            </a>
          )}
        </div>
      </header>

      <main className="pt-28 pb-20 px-4 max-w-5xl mx-auto">

        {/* Page Header */}
        <div className="mb-8 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#1D1D1F]/5 border border-[#1D1D1F]/10 text-[#1D1D1F] text-xs font-semibold uppercase tracking-wider mb-4">
            <Github className="w-3.5 h-3.5" />
            GitHub Source Code Scanner
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[#1D1D1F] mb-3">
            Scan your repository for <span className="text-[#D4380D]">vulnerabilities</span>
          </h1>
          <p className="text-[#86868B] max-w-xl mx-auto">
            4-engine analysis: Secrets detection, SAST, Dependency CVEs (SCA), and LLM deep code review powered by Llama&nbsp;3.3&nbsp;70B.
          </p>
        </div>

        {/* OAuth Error */}
        {oauthError && (
          <div className="mb-6 flex items-center gap-3 p-4 bg-[#fff0ee] border border-[#ff3b30]/20 rounded-xl text-[#D4380D] text-sm font-semibold">
            <AlertCircle className="w-4 h-4 shrink-0" />
            GitHub authentication failed ({oauthError}). Please try again.
          </div>
        )}

        {/* Not connected CTA */}
        {!loadingUser && !user && (
          <div className="flex flex-col items-center justify-center py-20 gap-6">
            <div className="w-20 h-20 rounded-3xl bg-[#1D1D1F] flex items-center justify-center">
              <Github className="w-10 h-10 text-white" />
            </div>
            <div className="text-center">
              <h2 className="text-xl font-bold text-[#1D1D1F] mb-2">Connect your GitHub account</h2>
              <p className="text-[#86868B] text-sm max-w-sm">
                Authorize VulnScanner to read your repositories. We only request read-only access and never store your code.
              </p>
            </div>
            <a
              href="/api/auth/github"
              className="flex items-center gap-2 px-6 py-3 rounded-full bg-[#1D1D1F] hover:bg-[#D4380D] text-white font-bold transition-all shadow-lg"
            >
              <Github className="w-4 h-4" />
              Connect GitHub
              <ArrowRight className="w-4 h-4" />
            </a>
            <p className="text-xs text-[#C5C5C7]">
              Scopes requested: <code>read:user</code> · <code>repo</code> (for private repos)
            </p>
          </div>
        )}

        {/* Connected — Scan Configuration */}
        {user && !isScanning && scanStatus !== "COMPLETED" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Left — Repo & Branch selection */}
            <div className="lg:col-span-2 space-y-4">

              {/* Engine badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {ENGINE_CONFIG.map((eng) => {
                  const EIcon = eng.icon;
                  return (
                    <div key={eng.key} className="bg-white border border-[#E5E5EA] rounded-xl p-3 text-center">
                      <div className="w-8 h-8 rounded-lg mx-auto mb-2 flex items-center justify-center" style={{ background: eng.color + "18" }}>
                        <EIcon className="w-4 h-4" style={{ color: eng.color }} />
                      </div>
                      <p className="text-[10px] font-bold text-[#1D1D1F] leading-tight">{eng.label}</p>
                    </div>
                  );
                })}
              </div>

              {/* Repo selector */}
              <div className="bg-white border border-[#E5E5EA] rounded-2xl p-4">
                <label className="text-xs font-bold text-[#86868B] uppercase tracking-wide mb-2 block">
                  Select Repository
                </label>
                <div className="relative">
                  <button
                    onClick={() => setRepoDropdownOpen(!repoDropdownOpen)}
                    className="w-full flex items-center justify-between px-4 py-3 bg-[#FBFBFC] border border-[#E5E5EA] rounded-xl text-sm hover:border-[#D4380D] transition-colors"
                  >
                    {selectedRepo ? (
                      <span className="flex items-center gap-2 font-semibold">
                        {selectedRepo.private ? <Lock className="w-3.5 h-3.5 text-[#86868B]" /> : <Github className="w-3.5 h-3.5 text-[#86868B]" />}
                        {selectedRepo.fullName}
                      </span>
                    ) : (
                      <span className="text-[#C5C5C7]">Choose a repository...</span>
                    )}
                    <ChevronDown className={`w-4 h-4 text-[#86868B] transition-transform ${repoDropdownOpen ? "rotate-180" : ""}`} />
                  </button>

                  {repoDropdownOpen && (
                    <div className="absolute z-30 mt-1 w-full bg-white border border-[#E5E5EA] rounded-xl shadow-xl overflow-hidden">
                      <div className="p-2 border-b border-[#F2F2F7]">
                        <div className="flex items-center gap-2 px-3 py-2 bg-[#FBFBFC] rounded-lg">
                          <Search className="w-3.5 h-3.5 text-[#86868B]" />
                          <input
                            autoFocus
                            value={repoSearch}
                            onChange={(e) => setRepoSearch(e.target.value)}
                            placeholder="Search repositories..."
                            className="flex-1 bg-transparent text-sm outline-none"
                          />
                        </div>
                      </div>
                      <div className="max-h-56 overflow-y-auto">
                        {loadingRepos ? (
                          <div className="p-4 text-center text-sm text-[#86868B]">
                            <Loader2 className="w-4 h-4 animate-spin mx-auto" />
                          </div>
                        ) : filteredRepos.length === 0 ? (
                          <p className="p-4 text-center text-sm text-[#86868B]">No repositories found</p>
                        ) : (
                          filteredRepos.map((repo) => (
                            <button
                              key={repo.id}
                              onClick={() => handleSelectRepo(repo)}
                              className="w-full text-left px-4 py-3 hover:bg-[#FBFBFC] transition-colors border-b border-[#F2F2F7] last:border-0"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2 min-w-0">
                                  {repo.private ? <Lock className="w-3 h-3 text-[#86868B] shrink-0" /> : <Github className="w-3 h-3 text-[#86868B] shrink-0" />}
                                  <span className="text-sm font-semibold truncate">{repo.fullName}</span>
                                </div>
                                <div className="flex items-center gap-2 shrink-0 text-[#86868B]">
                                  {repo.language && (
                                    <span className="text-[10px] font-semibold" style={{ color: LANG_COLORS[repo.language] ?? "#86868B" }}>
                                      {repo.language}
                                    </span>
                                  )}
                                  {repo.stargazersCount > 0 && (
                                    <span className="flex items-center gap-0.5 text-[10px]">
                                      <Star className="w-2.5 h-2.5" /> {repo.stargazersCount}
                                    </span>
                                  )}
                                  <span className="text-[10px]">{timeAgo(repo.pushedAt)}</span>
                                </div>
                              </div>
                              {repo.description && (
                                <p className="text-[11px] text-[#86868B] mt-0.5 truncate pl-5">{repo.description}</p>
                              )}
                            </button>
                          ))
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Branch selector */}
              {selectedRepo && (
                <div className="bg-white border border-[#E5E5EA] rounded-2xl p-4">
                  <label className="text-xs font-bold text-[#86868B] uppercase tracking-wide mb-2 block">
                    Select Branch
                  </label>
                  <div className="relative">
                    <button
                      onClick={() => setBranchDropdownOpen(!branchDropdownOpen)}
                      className="w-full flex items-center justify-between px-4 py-3 bg-[#FBFBFC] border border-[#E5E5EA] rounded-xl text-sm hover:border-[#D4380D] transition-colors"
                    >
                      <span className="flex items-center gap-2 font-semibold">
                        <GitBranch className="w-3.5 h-3.5 text-[#86868B]" />
                        {selectedBranch}
                      </span>
                      {loadingBranches ? <Loader2 className="w-4 h-4 animate-spin text-[#86868B]" /> : <ChevronDown className={`w-4 h-4 text-[#86868B] transition-transform ${branchDropdownOpen ? "rotate-180" : ""}`} />}
                    </button>

                    {branchDropdownOpen && branches.length > 0 && (
                      <div className="absolute z-20 mt-1 w-full bg-white border border-[#E5E5EA] rounded-xl shadow-xl overflow-hidden max-h-48 overflow-y-auto">
                        {branches.map((b) => (
                          <button
                            key={b}
                            onClick={() => { setSelectedBranch(b); setBranchDropdownOpen(false); }}
                            className="w-full text-left px-4 py-2.5 text-sm hover:bg-[#FBFBFC] transition-colors flex items-center gap-2 border-b border-[#F2F2F7] last:border-0"
                          >
                            <GitBranch className="w-3 h-3 text-[#86868B]" />
                            {b}
                            {b === selectedRepo.defaultBranch && (
                              <span className="text-[10px] text-[#86868B] font-semibold">default</span>
                            )}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Right — Scan Settings & Start */}
            <div className="space-y-4">
              <div className="bg-white border border-[#E5E5EA] rounded-2xl p-4">
                <p className="text-xs font-bold text-[#86868B] uppercase tracking-wide mb-3">Scan Settings</p>

                {/* LLM Toggle */}
                <div className="flex items-center justify-between p-3 bg-[#FBFBFC] rounded-xl border border-[#E5E5EA] mb-3">
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-[#af52de]" />
                    <div>
                      <p className="text-xs font-bold text-[#1D1D1F]">LLM Deep Review</p>
                      <p className="text-[10px] text-[#86868B]">Llama 3.3 70B AI review</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setEnableLLM(!enableLLM)}
                    className={`w-10 h-6 rounded-full transition-colors flex items-center ${enableLLM ? "bg-[#af52de]" : "bg-[#E5E5EA]"}`}
                  >
                    <div className={`w-4 h-4 bg-white rounded-full shadow transition-transform mx-1 ${enableLLM ? "translate-x-4" : "translate-x-0"}`} />
                  </button>
                </div>

                {/* Static engines always on */}
                {[
                  { icon: Key, label: "Secrets Scanner", color: "#ff3b30" },
                  { icon: Code, label: "SAST Analysis", color: "#ff9500" },
                  { icon: Package, label: "SCA — CVE Scan", color: "#007aff" },
                ].map(({ icon: Icon, label, color }) => (
                  <div key={label} className="flex items-center justify-between p-2.5 mb-2 bg-[#FBFBFC] rounded-lg border border-[#E5E5EA]">
                    <div className="flex items-center gap-2">
                      <Icon className="w-3.5 h-3.5" style={{ color }} />
                      <p className="text-xs font-semibold text-[#1D1D1F]">{label}</p>
                    </div>
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#34c759]" />
                  </div>
                ))}
              </div>

              <button
                onClick={handleStartScan}
                disabled={!selectedRepo || isScanning}
                className="w-full py-4 rounded-2xl bg-[#D4380D] hover:bg-[#b02f0a] disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold text-sm flex items-center justify-center gap-2 shadow-lg shadow-[#D4380D]/20 transition-all"
              >
                {isScanning ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
                ) : (
                  <><Sparkles className="w-4 h-4" /> Start Security Scan</>
                )}
              </button>

              {!selectedRepo && (
                <p className="text-center text-xs text-[#C5C5C7]">Select a repository to begin</p>
              )}
            </div>
          </div>
        )}

        {/* Scanning in progress */}
        {isScanning && currentScanId && (
          <div className="mt-8 bg-white border border-[#E5E5EA] rounded-2xl p-6">
            <div className="flex items-center gap-3 mb-6">
              <Loader2 className="w-5 h-5 text-[#D4380D] animate-spin" />
              <div>
                <p className="font-bold text-[#1D1D1F]">Scanning {selectedRepo?.fullName}</p>
                <p className="text-xs text-[#86868B]">Status: {scanStatus ?? "PENDING"}</p>
              </div>
            </div>

            <div className="space-y-3">
              {ENGINE_CONFIG.map((eng) => {
                if (!enableLLM && eng.key === "llm") return null;
                const EIcon = eng.icon;
                const status = engineProgress[eng.key];
                return (
                  <div key={eng.key} className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ background: eng.color + "18" }}>
                      {status === "running" ? (
                        <Loader2 className="w-4 h-4 animate-spin" style={{ color: eng.color }} />
                      ) : status === "done" ? (
                        <CheckCircle2 className="w-4 h-4 text-[#34c759]" />
                      ) : (
                        <EIcon className="w-4 h-4 text-[#C5C5C7]" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-sm font-semibold text-[#1D1D1F]">{eng.label}</p>
                        <span className="text-xs text-[#86868B]">
                          {status === "done" ? "Complete" : status === "running" ? "Running..." : "Queued"}
                        </span>
                      </div>
                      <div className="h-1.5 bg-[#F2F2F7] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-1000"
                          style={{
                            background: eng.color,
                            width: status === "done" ? "100%" : status === "running" ? "60%" : "0%",
                          }}
                        />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {findings.length > 0 && (
              <p className="mt-4 text-xs text-[#86868B] text-center">
                {findings.length} finding(s) discovered so far...
              </p>
            )}
          </div>
        )}

        {/* Results */}
        {(scanStatus === "COMPLETED" || scanStatus === "FAILED") && (
          <div className="mt-8 space-y-6">

            {/* Summary bar */}
            <div className="bg-white border border-[#E5E5EA] rounded-2xl p-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    {scanStatus === "COMPLETED" ? (
                      <CheckCircle2 className="w-5 h-5 text-[#34c759]" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-[#ff3b30]" />
                    )}
                    <h2 className="font-extrabold text-lg text-[#1D1D1F]">
                      {scanStatus === "COMPLETED" ? "Scan Complete" : "Scan Failed"}
                    </h2>
                  </div>
                  <p className="text-sm text-[#86868B]">
                    {selectedRepo?.fullName} · {selectedBranch} · {findings.length} finding(s)
                  </p>
                </div>

                <div className="flex items-center gap-3">
                  {criticalCount > 0 && (
                    <div className="text-center px-3 py-2 bg-[#fff0ee] rounded-xl">
                      <p className="text-xs font-bold text-[#ff3b30]">CRITICAL</p>
                      <p className="text-xl font-black text-[#ff3b30]">{criticalCount}</p>
                    </div>
                  )}
                  {highCount > 0 && (
                    <div className="text-center px-3 py-2 bg-[#fff8ee] rounded-xl">
                      <p className="text-xs font-bold text-[#ff9500]">HIGH</p>
                      <p className="text-xl font-black text-[#ff9500]">{highCount}</p>
                    </div>
                  )}
                  <button
                    onClick={() => {
                      setScanStatus(null);
                      setIsScanning(false);
                      setCurrentScanId(null);
                      setFindings([]);
                    }}
                    className="px-4 py-2 rounded-full border border-[#E5E5EA] text-sm font-semibold hover:border-[#D4380D] hover:text-[#D4380D] transition-colors"
                  >
                    New Scan
                  </button>
                </div>
              </div>

              {/* Engine summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4 pt-4 border-t border-[#F2F2F7]">
                {ENGINE_CONFIG.map((eng) => {
                  const count = findings.filter((f) => {
                    if (eng.key === "llm") return f.evidence?.startsWith("[LLM Review]");
                    if (eng.key === "sca") return f.type === "sca-cve";
                    if (eng.key === "secrets") return f.type === "secrets";
                    return !["secrets", "sca-cve"].includes(f.type) && !f.evidence?.startsWith("[LLM Review]");
                  }).length;
                  const EIcon = eng.icon;
                  return (
                    <div key={eng.key} className="text-center p-3 bg-[#FBFBFC] rounded-xl border border-[#E5E5EA]">
                      <EIcon className="w-4 h-4 mx-auto mb-1" style={{ color: eng.color }} />
                      <p className="text-lg font-black text-[#1D1D1F]">{count}</p>
                      <p className="text-[10px] font-semibold text-[#86868B]">{eng.label}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Filters */}
            {findings.length > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="flex items-center gap-1 bg-white border border-[#E5E5EA] rounded-full px-2 py-1">
                    <span className="text-[10px] font-bold text-[#86868B] uppercase mr-1">Engine</span>
                    {["all", ...ENGINE_CONFIG.map((e) => e.key)].map((k) => (
                      <button
                        key={k}
                        onClick={() => setFilterEngine(k)}
                        className={`px-2.5 py-1 rounded-full text-xs font-semibold transition-colors ${filterEngine === k ? "bg-[#1D1D1F] text-white" : "text-[#86868B] hover:text-[#1D1D1F]"}`}
                      >
                        {k === "all" ? "All" : ENGINE_CONFIG.find((e) => e.key === k)?.label.split(" ")[0] ?? k}
                      </button>
                    ))}
                  </div>
                  <div className="flex items-center gap-1 bg-white border border-[#E5E5EA] rounded-full px-2 py-1">
                    <span className="text-[10px] font-bold text-[#86868B] uppercase mr-1">Severity</span>
                    {["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                      <button
                        key={s}
                        onClick={() => setFilterSeverity(s)}
                        style={filterSeverity === s && s !== "all" ? { background: SEVERITY_CONFIG[s as keyof typeof SEVERITY_CONFIG]?.color, color: "white" } : {}}
                        className={`px-2.5 py-1 rounded-full text-xs font-semibold transition-colors ${filterSeverity === s ? s === "all" ? "bg-[#1D1D1F] text-white" : "" : "text-[#86868B] hover:text-[#1D1D1F]"}`}
                      >
                        {s === "all" ? "All" : s}
                      </button>
                    ))}
                  </div>
                </div>

                {/* View Mode Toggle */}
                <div className="flex items-center gap-1 bg-white border border-[#E5E5EA] rounded-full px-2 py-1">
                  <span className="text-[10px] font-bold text-[#86868B] uppercase mr-1">View</span>
                  <button
                    onClick={() => setViewMode("grouped")}
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold flex items-center gap-1 transition-colors ${
                      viewMode === "grouped" ? "bg-[#1D1D1F] text-white" : "text-[#86868B] hover:text-[#1D1D1F]"
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    Grouped
                  </button>
                  <button
                    onClick={() => setViewMode("flat")}
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold flex items-center gap-1 transition-colors ${
                      viewMode === "flat" ? "bg-[#1D1D1F] text-white" : "text-[#86868B] hover:text-[#1D1D1F]"
                    }`}
                  >
                    <List className="w-3.5 h-3.5" />
                    Flat List
                  </button>
                </div>
              </div>
            )}

            {/* Findings list */}
            {findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <CheckCircle2 className="w-12 h-12 text-[#34c759] mb-3" />
                <h3 className="text-lg font-bold text-[#1D1D1F]">No vulnerabilities found!</h3>
                <p className="text-sm text-[#86868B] mt-1">This repository looks clean across all 4 scan engines.</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between text-xs text-[#86868B] font-semibold px-1">
                  <span>
                    Showing {filteredFindings.length} of {findings.length} finding(s)
                  </span>
                  {viewMode === "grouped" && Object.keys(scaGroups).length > 0 && (
                    <span>
                      {Object.keys(scaGroups).length} vulnerable package(s)
                    </span>
                  )}
                </div>

                {viewMode === "grouped" ? (
                  <div className="space-y-4">
                    {/* Render Non-SCA findings first (Secrets, SAST, LLM) */}
                    {nonScaFindings.length > 0 && (
                      <div className="space-y-3">
                        {nonScaFindings.map((f) => (
                          <FindingCard key={f.id} finding={f} />
                        ))}
                      </div>
                    )}

                    {/* Render Grouped SCA Packages */}
                    {Object.entries(scaGroups).map(([pkg, pkgFindings]) => (
                      <PackageGroupCard
                        key={pkg}
                        packageName={pkg}
                        findings={pkgFindings}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="space-y-3">
                    {filteredFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default function GitHubPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#FBFBFC] flex items-center justify-center">
        <div className="flex items-center gap-2 text-[#86868B]">
          <div className="w-5 h-5 border-2 border-[#D4380D] border-t-transparent rounded-full animate-spin" />
          Loading...
        </div>
      </div>
    }>
      <GitHubPageInner />
    </Suspense>
  );
}

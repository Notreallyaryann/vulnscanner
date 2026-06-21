"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Terminal, 
  Globe, 
  CheckCircle2, 
  AlertTriangle, 
  ArrowRight, 
  ChevronDown, 
  Activity, 
  Cpu, 
  Lock, 
  FileText, 
  Sparkles, 
  Check, 
  X,
  Code
} from "lucide-react";
import { useRouter } from "next/navigation";

// FAQ Accordion Interface
interface FaqItem {
  question: string;
  answer: string;
}

// Defined outside component to avoid recreating on every render
const SIMULATION_STEPS = [
  { log: "🔍 Resolving DNS, TLS/SSL certificate chain and security protocols...", progress: 10 },
  { log: "🌐 Crawling same-origin links, sitemaps and API endpoints...", progress: 20 },
  { log: "🛡️ Auditing security headers: CSP, HSTS, X-Frame-Options, CORS...", progress: 32 },
  { log: "🍪 Analyzing session cookies: HttpOnly, Secure, SameSite flags...", progress: 44 },
  { log: "⚡ Probing parameterized URLs for SQL Injection and XSS payloads...", progress: 55 },
  { log: "⚠️  CSRF token check: scanning POST forms for anti-forgery tokens...", progress: 63 },
  { log: "🔑 Testing login forms against default credential sets...", progress: 71 },
  { log: "📁 Scanning JS files for hardcoded API keys and env variable leaks...", progress: 78 },
  { log: "⚡ Probing parameters for command injection and path traversal (LFI)...", progress: 84 },
  { log: "🌩️  Checking for DoS/rate-limit protection and SSRF vectors...", progress: 90 },
  { log: "🔎 Inspecting sensitive endpoints: .env, .git, phpMyAdmin, backups...", progress: 95 },
  { log: "🧠 Vectorizing findings and running RAG remediation analysis...", progress: 98 },
  { log: "🤖 AI report complete. Launching results dashboard...", progress: 100 },
];

const FAQ_ITEMS: FaqItem[] = [
  {
    question: "Do I need a security degree to use VulnScanner?",
    answer: "Absolutely not. We designed VulnScanner specifically for developers, startup founders, and agile teams. Every alert is explained in plain English, paired with step-by-step fix guides and copy-paste ready code examples.",
  },
  {
    question: "How does the AI RAG remediation work?",
    answer: "When a vulnerability is identified, VulnScanner pulls reference guidelines from its local OWASP, CWE, and NVD vector knowledge base, combines it with the scan findings, and uses Cerebras Llama 3.1 to generate exact, contextual code fixes.",
  },
  {
    question: "Will the security audit impact my server's performance?",
    answer: "No. Our scanner operates via passive inspections and lightweight simulated queries. We mimic realistic browser actions without running brute-force attacks, ensuring zero downtime for your active users.",
  },
  {
    question: "Can I use this for Next.js, Lovable, or Cursor apps?",
    answer: "Yes. It is optimized for modern web frameworks and AI builders. We detect common routing errors, missing security headers, CSRF misconfigurations, and standard CVE vulnerabilities typical in modern full-stack codebases.",
  },
];

export default function LandingPage() {
  const router = useRouter();
  
  // State variables
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [currentProgress, setCurrentProgress] = useState(0);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  // Vulnerable vs Fixed Code snippet toggle
  const [selectedLanguage, setSelectedLanguage] = useState<"js" | "python">("js");

  // Use a ref for the interval step counter to avoid stale closure
  const stepRef = useRef(0);

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setIsScanning(true);
    setLogs([]);
    setCurrentProgress(0);
    stepRef.current = 0;

    const interval = setInterval(() => {
      const step = stepRef.current;
      if (step < SIMULATION_STEPS.length) {
        setLogs(prev => [...prev, SIMULATION_STEPS[step].log]);
        setCurrentProgress(SIMULATION_STEPS[step].progress);
        stepRef.current = step + 1;
      } else {
        clearInterval(interval);
        // Redirect to dashboard with the scanned domain
        setTimeout(() => {
          router.push(`/dashboard?domain=${encodeURIComponent(domain)}`);
        }, 800);
      }
    }, 380);
  };

  const toggleFaq = (index: number) => {
    setOpenFaq(prev => (prev === index ? null : index));
  };

  return (
    <div className="min-h-screen bg-[#FBFBFC] text-[#1D1D1F] selection:bg-[#D4380D] selection:text-white font-sans antialiased">
      
      {/* 🚀 1. FLOATING NAVIGATION BAR */}
      <header className="fixed top-6 left-1/2 -translate-x-1/2 w-[90%] max-w-4xl h-14 bg-[#FFFFFF]/85 backdrop-blur-md border border-[#E5E5EA] rounded-full shadow-sm flex items-center justify-between px-6 z-50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-[#D4380D] flex items-center justify-center text-white">
            <Shield className="w-4.5 h-4.5" />
          </div>
          <span className="font-extrabold text-base tracking-tight text-[#1D1D1F]">VulnScanner</span>
        </div>
        
        <nav className="hidden md:flex items-center gap-8 text-sm font-semibold text-[#86868B]">
          <a href="#features" className="hover:text-[#D4380D] transition-colors">Product</a>
          <a href="#code" className="hover:text-[#D4380D] transition-colors">Remediation</a>
          <a href="#pricing" className="hover:text-[#D4380D] transition-colors">Pricing</a>
          <a href="#faq" className="hover:text-[#D4380D] transition-colors">FAQ</a>
        </nav>

        <button 
          onClick={() => router.push("/dashboard")}
          className="px-5 h-9 rounded-full bg-[#1D1D1F] hover:bg-[#D4380D] text-white text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer"
        >
          Launch App
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </header>

      {/* 🚀 2. HERO SECTION */}
      <section className="pt-32 pb-20 px-6 max-w-6xl mx-auto flex flex-col items-center text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#D4380D]/5 border border-[#D4380D]/20 text-[#D4380D] text-xs font-semibold uppercase tracking-wider mb-6">
          <Sparkles className="w-3.5 h-3.5" />
          AI-Powered Security Auditing
        </div>
        
        <h1 className="text-4xl sm:text-6xl font-extrabold text-[#1D1D1F] tracking-tight leading-[1.1] max-w-4xl mb-6">
          Find vulnerabilities before <span className="text-[#D4380D] underline decoration-wavy decoration-[#D4380D]/30 underline-offset-8">hackers do</span>.
        </h1>
        
        <p className="text-lg text-[#86868B] max-w-2xl mb-10 leading-relaxed">
          The automated security testing platform built for fast-moving startups and developers. Test headers, scan endpoints, and receive instant copy-paste RAG fix recommendations.
        </p>

        {/* Domain Input Form */}
        {!isScanning ? (
          <form onSubmit={handleStartScan} className="w-full max-w-lg flex flex-col sm:flex-row gap-3 bg-[#FFFFFF] p-2 rounded-2xl border border-[#E5E5EA] shadow-md mb-8">
            <div className="flex-1 flex items-center px-3 gap-2">
              <Globe className="w-4.5 h-4.5 text-[#86868B]" />
              <input
                type="text"
                placeholder="yourdomain.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
                className="w-full bg-transparent text-sm py-2.5 outline-none font-medium placeholder:text-[#C5C5C7]"
              />
            </div>
            <button
              type="submit"
              className="px-6 py-3 rounded-xl bg-[#D4380D] hover:bg-[#b02f0a] text-white text-sm font-bold shadow-md shadow-[#D4380D]/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              Scan Domain
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        ) : (
          /* Live Scanner Terminal Simulation */
          <div className="w-full max-w-2xl bg-[#0F0F13] text-[#F5F5F7] rounded-2xl border border-[#2D2D34] shadow-2xl p-6 mb-8 text-left font-mono text-xs overflow-hidden relative">
            <div className="flex items-center justify-between border-b border-[#2D2D34] pb-3 mb-4">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-[#FF5F56]" />
                <span className="w-3 h-3 rounded-full bg-[#FFBD2E]" />
                <span className="w-3 h-3 rounded-full bg-[#27C93F]" />
              </div>
              <span className="text-[10px] text-[#86868B] uppercase tracking-wider font-bold">VulnScanner Sim v1.2</span>
            </div>

            <div className="space-y-2 h-44 overflow-y-auto mb-4">
              {logs.map((log, idx) => (
                <div key={idx} className={`leading-relaxed ${
                  log.includes("🚨") ? "text-[#FF5F56] font-bold" : log.includes("⚠️") ? "text-[#FFBD2E]" : "text-[#A1A1A6]"
                }`}>
                  {log}
                </div>
              ))}
            </div>

            {/* Progress bar */}
            <div>
              <div className="flex justify-between items-center text-[10px] text-[#86868B] mb-1.5 font-bold uppercase">
                <span>Auditing: {domain}</span>
                <span>{currentProgress}%</span>
              </div>
              <div className="w-full bg-[#2D2D34] h-1.5 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-[#D4380D] to-[#FF5F56] transition-all duration-300"
                  style={{ width: `${currentProgress}%` }}
                />
              </div>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-center gap-8 text-[#86868B] text-xs font-semibold uppercase tracking-widest mt-4">
          <span className="flex items-center gap-1.5"><Lock className="w-4 h-4 text-[#D4380D]" /> OWASP Compliance</span>
          <span className="flex items-center gap-1.5"><Activity className="w-4 h-4 text-[#D4380D]" /> Real-time Audits</span>
          <span className="flex items-center gap-1.5"><Cpu className="w-4 h-4 text-[#D4380D]" /> AI Remediation</span>
        </div>
      </section>

      {/* 🚀 3. CORE BENEFITS SECTION */}
      <section id="features" className="py-20 bg-[#FFFFFF] border-y border-[#E5E5EA] px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-[#1D1D1F] tracking-tight mb-4">
              Designed to make app security accessible.
            </h2>
            <p className="text-sm text-[#86868B] leading-relaxed">
              Skip complex, manual PDF penetration testing logs. VulnScanner actively alerts you and formats exact code remedies within seconds.
            </p>
          </div>

          {/* Vulnerability coverage tags */}
          <div className="flex flex-wrap justify-center gap-2 mb-14">
            {["SQL Injection","XSS","CSRF","Session Hijacking","DoS / Rate Limiting","CORS Misconfiguration","Clickjacking","Broken Auth","Command Injection","Path Traversal (LFI)","SSRF","Env Variable Leaks","JWT Weakness","Open Redirect","GraphQL Introspection","Subdomain Takeover","Sensitive Endpoints (.env, .git)","Security Headers"].map(tag => (
              <span key={tag} className="px-2.5 py-1 rounded-full border border-[#D4380D]/20 bg-[#D4380D]/5 text-[#D4380D] text-[11px] font-semibold">
                {tag}
              </span>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="p-6 rounded-2xl bg-[#FBFBFC] border border-[#E5E5EA] flex flex-col justify-between">
              <div>
                <div className="w-10 h-10 rounded-xl bg-[#D4380D]/5 border border-[#D4380D]/15 flex items-center justify-center text-[#D4380D] mb-5">
                  <Terminal className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-lg text-[#1D1D1F] mb-2">18+ Automated Checks</h3>
                <p className="text-xs text-[#86868B] leading-relaxed">
                  Active payload probing (SQLi, XSS, LFI, command injection) combined with passive header, cookie, CORS, JWT, and secrets audits — all non-destructive.
                </p>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-[#FBFBFC] border border-[#E5E5EA] flex flex-col justify-between">
              <div>
                <div className="w-10 h-10 rounded-xl bg-[#D4380D]/5 border border-[#D4380D]/15 flex items-center justify-center text-[#D4380D] mb-5">
                  <Cpu className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-lg text-[#1D1D1F] mb-2">Vectorized RAG System</h3>
                <p className="text-xs text-[#86868B] leading-relaxed">
                  Searches local OWASP, CWE and NVD reference vector datasets and matches them to your exact findings for copy-paste AI code fixes.
                </p>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-[#FBFBFC] border border-[#E5E5EA] flex flex-col justify-between">
              <div>
                <div className="w-10 h-10 rounded-xl bg-[#D4380D]/5 border border-[#D4380D]/15 flex items-center justify-center text-[#D4380D] mb-5">
                  <FileText className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-lg text-[#1D1D1F] mb-2">Exportable Reports</h3>
                <p className="text-xs text-[#86868B] leading-relaxed">
                  Compile comprehensive technical advisories into downloadable, developer-friendly formats within one click.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 🚀 4. REMEDIATION CODE PREVIEW */}
      <section id="code" className="py-20 px-6 max-w-5xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#D4380D]/5 border border-[#D4380D]/15 text-[#D4380D] text-[10px] font-bold uppercase tracking-wider mb-4">
              <Code className="w-3.5 h-3.5" /> Code Comparison
            </div>
            <h2 className="text-3xl font-extrabold text-[#1D1D1F] tracking-tight mb-4">
              Copy-paste ready remediation code.
            </h2>
            <p className="text-sm text-[#86868B] leading-relaxed mb-6">
              When an issue is flagged, we don't just tell you it is broken—we provide the direct diff of code showing what needs to be changed. Simply select your environment and apply the patch.
            </p>

            <div className="flex gap-2">
              <button 
                onClick={() => setSelectedLanguage("js")}
                className={`px-4 py-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                  selectedLanguage === "js" 
                    ? "bg-[#1D1D1F] text-white border-[#1D1D1F]" 
                    : "bg-white text-[#86868B] border-[#E5E5EA] hover:border-gray-400"
                }`}
              >
                JavaScript / Next.js
              </button>
              <button 
                onClick={() => setSelectedLanguage("python")}
                className={`px-4 py-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                  selectedLanguage === "python" 
                    ? "bg-[#1D1D1F] text-white border-[#1D1D1F]" 
                    : "bg-white text-[#86868B] border-[#E5E5EA] hover:border-gray-400"
                }`}
              >
                Python / Flask
              </button>
            </div>
          </div>

          <div className="space-y-4">
            {selectedLanguage === "js" ? (
              <>
                {/* Vulnerable JavaScript */}
                <div className="rounded-2xl border border-red-200 bg-[#FFF5F5] overflow-hidden">
                  <div className="px-4 py-2 bg-red-100/40 border-b border-red-200/50 flex items-center justify-between text-xs text-red-700 font-bold">
                    <span>Vulnerable Concatenation</span>
                    <span className="font-mono text-[10px] opacity-60">db.js</span>
                  </div>
                  <pre className="p-4 text-[11px] font-mono text-[#D4380D] overflow-x-auto leading-relaxed">
                    <code>
{`// Interpolating input strings directly into raw SQL
const id = req.query.id;
const query = \`SELECT * FROM users WHERE id = '\${id}'\`;
const user = await db.query(query);`}
                    </code>
                  </pre>
                </div>

                {/* Fixed JavaScript */}
                <div className="rounded-2xl border border-emerald-200 bg-[#F5FFF7] overflow-hidden">
                  <div className="px-4 py-2 bg-emerald-100/40 border-b border-emerald-200/50 flex items-center justify-between text-xs text-emerald-800 font-bold">
                    <span>Remediated Parameterized Call</span>
                    <span className="font-mono text-[10px] opacity-60">db.js</span>
                  </div>
                  <pre className="p-4 text-[11px] font-mono text-emerald-700 overflow-x-auto leading-relaxed">
                    <code>
{`// Secure parameter binding using ORM schema
const id = req.query.id;
const user = await prisma.user.findUnique({
  where: { id: String(id) }
});`}
                    </code>
                  </pre>
                </div>
              </>
            ) : (
              <>
                {/* Vulnerable Python */}
                <div className="rounded-2xl border border-red-200 bg-[#FFF5F5] overflow-hidden">
                  <div className="px-4 py-2 bg-red-100/40 border-b border-red-200/50 flex items-center justify-between text-xs text-red-700 font-bold">
                    <span>Vulnerable Concatenation</span>
                    <span className="font-mono text-[10px] opacity-60">app.py</span>
                  </div>
                  <pre className="p-4 text-[11px] font-mono text-[#D4380D] overflow-x-auto leading-relaxed">
                    <code>
{`# Vulnerable to query string injection
user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")`}
                    </code>
                  </pre>
                </div>

                {/* Fixed Python */}
                <div className="rounded-2xl border border-emerald-200 bg-[#F5FFF7] overflow-hidden">
                  <div className="px-4 py-2 bg-emerald-100/40 border-b border-emerald-200/50 flex items-center justify-between text-xs text-emerald-800 font-bold">
                    <span>Remediated Safe Bind</span>
                    <span className="font-mono text-[10px] opacity-60">app.py</span>
                  </div>
                  <pre className="p-4 text-[11px] font-mono text-emerald-700 overflow-x-auto leading-relaxed">
                    <code>
{`# Secure parameterized tuple queries
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`}
                    </code>
                  </pre>
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      {/* 🚀 5. TRANSPARENT PRICING GRID */}
      <section id="pricing" className="py-20 bg-[#F2F2F7]/50 border-t border-[#E5E5EA] px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center max-w-xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-[#1D1D1F] tracking-tight mb-4">
              Transparent, scale-ready pricing.
            </h2>
            <p className="text-sm text-[#86868B]">
              Choose the tier that matches your development speed. Upgrade or downgrade at any time.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
            
            {/* TIER 1: FREE */}
            <div className="p-5 rounded-2xl bg-white border border-[#E5E5EA] shadow-sm flex flex-col justify-between">
              <div>
                <h3 className="font-bold text-sm text-[#86868B] uppercase tracking-wider mb-2">Free</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className="text-3xl font-black text-[#1D1D1F]">$0</span>
                  <span className="text-xs text-[#86868B] font-medium">/mo</span>
                </div>
                <p className="text-[11px] text-[#86868B] leading-relaxed mb-6">For individual devs testing hobby projects.</p>
                <ul className="space-y-3 border-t border-[#E5E5EA] pt-4 text-xs font-semibold text-[#86868B]">
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> 1 domain</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Monthly scans</li>
                  <li className="flex items-center gap-2"><X className="w-4 h-4 text-[#86868B]/30 shrink-0" /> Slack alerts</li>
                  <li className="flex items-center gap-2"><X className="w-4 h-4 text-[#86868B]/30 shrink-0" /> PDF reports</li>
                </ul>
              </div>
            </div>

            {/* TIER 2: STARTER */}
            <div className="p-5 rounded-2xl bg-white border border-[#E5E5EA] shadow-sm flex flex-col justify-between">
              <div>
                <h3 className="font-bold text-sm text-[#86868B] uppercase tracking-wider mb-2">Starter</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className="text-3xl font-black text-[#1D1D1F]">$16</span>
                  <span className="text-xs text-[#86868B] font-medium">/mo</span>
                </div>
                <p className="text-[11px] text-[#86868B] leading-relaxed mb-6">For single active apps or simple landing pages.</p>
                <ul className="space-y-3 border-t border-[#E5E5EA] pt-4 text-xs font-semibold text-[#86868B]">
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> 3 domains</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Weekly scans</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Email alerts</li>
                  <li className="flex items-center gap-2"><X className="w-4 h-4 text-[#86868B]/30 shrink-0" /> Slack alerts</li>
                </ul>
              </div>
            </div>

            {/* TIER 3: PROTECTOR */}
            <div className="p-5 rounded-2xl bg-white border border-[#D4380D]/40 border-2 shadow-md flex flex-col justify-between relative">
              <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-[#D4380D] text-white text-[9px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-full shadow-sm">Popular</span>
              <div>
                <h3 className="font-bold text-sm text-[#D4380D] uppercase tracking-wider mb-2">Protector</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className="text-3xl font-black text-[#1D1D1F]">$49</span>
                  <span className="text-xs text-[#86868B] font-medium">/mo</span>
                </div>
                <p className="text-[11px] text-[#86868B] leading-relaxed mb-6">For small startups keeping apps continuously safe.</p>
                <ul className="space-y-3 border-t border-[#E5E5EA] pt-4 text-xs font-semibold text-[#86868B]">
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> 10 domains</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Daily scans</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Slack & Email</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> PDF exports</li>
                </ul>
              </div>
            </div>

            {/* TIER 4: PRO */}
            <div className="p-5 rounded-2xl bg-white border border-[#E5E5EA] shadow-sm flex flex-col justify-between">
              <div>
                <h3 className="font-bold text-sm text-[#86868B] uppercase tracking-wider mb-2">Pro</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className="text-3xl font-black text-[#1D1D1F]">$129</span>
                  <span className="text-xs text-[#86868B] font-medium">/mo</span>
                </div>
                <p className="text-[11px] text-[#86868B] leading-relaxed mb-6">For growing teams and multi-app SaaS networks.</p>
                <ul className="space-y-3 border-t border-[#E5E5EA] pt-4 text-xs font-semibold text-[#86868B]">
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> 25 domains</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> AI RAG remediate</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Slack / Webhooks</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> API Access</li>
                </ul>
              </div>
            </div>

            {/* TIER 5: MAX */}
            <div className="p-5 rounded-2xl bg-white border border-[#E5E5EA] shadow-sm flex flex-col justify-between">
              <div>
                <h3 className="font-bold text-sm text-[#86868B] uppercase tracking-wider mb-2">Max</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className="text-3xl font-black text-[#1D1D1F]">$299</span>
                  <span className="text-xs text-[#86868B] font-medium">/mo</span>
                </div>
                <p className="text-[11px] text-[#86868B] leading-relaxed mb-6">For agencies managing dozens of client portals.</p>
                <ul className="space-y-3 border-t border-[#E5E5EA] pt-4 text-xs font-semibold text-[#86868B]">
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Unlimited domains</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Continuous auditing</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Full webhook logs</li>
                  <li className="flex items-center gap-2 text-[#1D1D1F]"><Check className="w-4 h-4 text-[#D4380D] shrink-0" /> Dedicated support</li>
                </ul>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* 🚀 6. FAQ ACCORDION SECTION */}
      <section id="faq" className="py-20 px-6 max-w-4xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-extrabold text-[#1D1D1F] tracking-tight mb-4">
            Frequently Asked Questions
          </h2>
          <p className="text-sm text-[#86868B]">
            Everything you need to know about setting up scans and getting fixes.
          </p>
        </div>

        <div className="space-y-4">
          {FAQ_ITEMS.map((item, idx) => (
            <div 
              key={idx} 
              className="bg-white border border-[#E5E5EA] rounded-2xl overflow-hidden transition-all duration-300"
            >
              <button
                onClick={() => toggleFaq(idx)}
                className="w-full flex justify-between items-center px-6 py-5 text-left font-bold text-sm text-[#1D1D1F] hover:bg-[#F2F2F7]/30 transition-all cursor-pointer"
              >
                <span>{item.question}</span>
                <ChevronDown className={`w-4 h-4 text-[#86868B] transition-transform duration-300 ${
                  openFaq === idx ? "rotate-180 text-[#D4380D]" : ""
                }`} />
              </button>
              
              {openFaq === idx && (
                <div className="px-6 pb-6 text-xs text-[#86868B] leading-relaxed border-t border-[#F2F2F7] pt-4">
                  {item.answer}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* 🚀 7. SLEEK DARK FOOTER */}
      <footer className="bg-[#1D1D1F] text-[#86868B] py-12 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-6 border-b border-[#2D2D34] pb-8 mb-8">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-[#D4380D] flex items-center justify-center text-white">
              <Shield className="w-4.5 h-4.5" />
            </div>
            <span className="font-extrabold text-base tracking-tight text-white">VulnScanner</span>
          </div>

          <div className="flex gap-8 text-xs font-semibold">
            <a href="#features" className="hover:text-white transition-colors">Product</a>
            <a href="#code" className="hover:text-white transition-colors">Remediation</a>
            <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
            <a href="#faq" className="hover:text-white transition-colors">FAQ</a>
          </div>
        </div>

        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row justify-between text-[11px] font-mono leading-relaxed">
          <p>© 2026 VulnScanner Node. All rights reserved.</p>
          <p className="flex gap-4">
            <span>Support: support@vulnscanner.io</span>
            <span>Host: Local Node</span>
          </p>
        </div>
      </footer>

    </div>
  );
}

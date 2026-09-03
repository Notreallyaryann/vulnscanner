/**
 * github-scanner/index.ts
 * 4-engine GitHub repository security scan orchestrator.
 *
 * Engines:
 *  1. Secrets  — regex patterns for hardcoded credentials
 *  2. SAST     — static analysis for dangerous code patterns
 *  3. SCA      — dependency CVE lookup via OSV.dev
 *  4. LLM      — deep AI code review via OpenRouter/Llama 3.3 70B
 */

import pLimit from "p-limit";
import { prisma } from "../prisma";
import { generateFixReport, getMockFixReport } from "../openrouter";
import { retrieveContext } from "../rag";
import { scanFileForSecrets } from "./secrets";
import { scanFileForSAST } from "./sast";
import { extractPackages, scanDependenciesForCVEs } from "./sca";
import { runLLMCodeReview, type FileContent } from "./llm-review";
import { loadSecuritySkills, getRelevantSkillContext } from "./skills-loader";
import { PendingFinding } from "../scanner/types";

// ── GitHub API helpers ─────────────────────────────────────────────────────────

interface GHTreeItem {
  path: string;
  type: "blob" | "tree";
  sha: string;
  size?: number;
}

interface GHTreeResponse {
  sha: string;
  tree: GHTreeItem[];
  truncated: boolean;
}

async function githubFetch(url: string, token: string) {
  return fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
}

async function getRepoTree(owner: string, repo: string, branch: string, token: string): Promise<GHTreeItem[]> {
  // First resolve the branch to a commit SHA
  const branchRes = await githubFetch(
    `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`,
    token
  );
  if (!branchRes.ok) throw new Error(`Failed to fetch branch: ${branchRes.status}`);
  const branchData = await branchRes.json();
  const treeSha: string = branchData.commit.commit.tree.sha;

  // Fetch recursive tree
  const treeRes = await githubFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`,
    token
  );
  if (!treeRes.ok) throw new Error(`Failed to fetch tree: ${treeRes.status}`);
  const treeData = (await treeRes.json()) as GHTreeResponse;
  return treeData.tree;
}

const RELEVANT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rb", ".php",
  ".json", ".lock", ".yaml", ".yml", ".env",
]);

const SKIP_PATHS = [
  /node_modules\//,
  /\.next\//,
  /dist\//,
  /build\//,
  /\.git\//,
  /coverage\//,
  /\.cache\//,
];

const MAX_FILE_SIZE = 300_000; // 300 KB — skip very large generated files

function isRelevantFile(item: GHTreeItem): boolean {
  if (item.type !== "blob") return false;
  if (SKIP_PATHS.some((p) => p.test(item.path))) return false;
  if (item.size && item.size > MAX_FILE_SIZE) return false;
  const ext = item.path.slice(item.path.lastIndexOf("."));
  // Always include files like .env, package.json, Pipfile
  if ([".env", ".envlocal", ".envproduction"].includes(item.path.split("/").pop() ?? "")) return true;
  if (item.path.endsWith("package.json") || item.path.endsWith("package-lock.json")) return true;
  return RELEVANT_EXTENSIONS.has(ext);
}

async function fetchFileContent(
  owner: string,
  repo: string,
  filePath: string,
  token: string
): Promise<string | null> {
  try {
    const res = await githubFetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}`,
      token
    );
    if (!res.ok) return null;
    const data = await res.json();
    if (data.encoding === "base64" && data.content) {
      return Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf8");
    }
    return null;
  } catch {
    return null;
  }
}

// ── Scan logger helper ─────────────────────────────────────────────────────────

async function updateStatus(scanId: string, status: string) {
  await prisma.gitHubScan.update({
    where: { id: scanId },
    data: { status: status as any },
  }).catch(() => {});
}

// ── AI fix generation ──────────────────────────────────────────────────────────

async function generateFixes(
  findings: PendingFinding[],
  scanId: string,
  isGitHub = true
): Promise<void> {
  const fixLimit = pLimit(2);

  await Promise.all(
    findings.map((f) =>
      fixLimit(async () => {
        try {
          const ragContext = await retrieveContext(`${f.type} vulnerability ${f.evidence ?? ""}`, 2);
          const skillContext = getRelevantSkillContext(f.type);
          const enrichedContext = skillContext ? `${ragContext}\n\n--- SECURITY SKILL GUIDELINE ---\n${skillContext}` : ragContext;

          let report;
          try {
            report = await generateFixReport({
              findingType: f.type,
              url: f.url,
              parameter: f.parameter,
              evidence: f.evidence,
              cveId: f.cveId,
              ragContext: enrichedContext,
            });
          } catch {
            report = getMockFixReport({
              findingType: f.type,
              url: f.url,
              parameter: f.parameter,
              evidence: f.evidence,
              cveId: f.cveId,
            });
          }

          await prisma.finding.create({
            data: {
              gitHubScanId: scanId,
              type: f.type,
              severity: f.severity,
              url: f.url,
              parameter: f.parameter ?? null,
              evidence: f.evidence ?? null,
              cvssScore: f.cvssScore,
              cveId: f.cveId ?? null,
              confidence: f.confidence ?? 0.85,
              isVerified: f.isVerified ?? false,
              validationSteps: f.validationSteps ?? [],
              title: report.title,
              explanation: report.explanation,
              fixSteps: report.fixSteps,
              codeExample: JSON.stringify(report.codeExample),
              embedding: [],
            },
          });
        } catch (err) {
          console.error("Fix generation error for GitHub finding:", err);
          // Save finding without fix to avoid losing it
          await prisma.finding.create({
            data: {
              gitHubScanId: scanId,
              type: f.type,
              severity: f.severity,
              url: f.url,
              parameter: f.parameter ?? null,
              evidence: f.evidence ?? null,
              cvssScore: f.cvssScore,
              cveId: f.cveId ?? null,
              confidence: f.confidence ?? 0.5,
              isVerified: f.isVerified ?? false,
              validationSteps: f.validationSteps ?? [],
              embedding: [],
            },
          }).catch(() => {});
        }
      })
    )
  );
}

// ── Main orchestrator ──────────────────────────────────────────────────────────

export async function runGitHubScan(
  scanId: string,
  repoFullName: string,
  branch: string,
  accessToken: string,
  enableLLM: boolean
): Promise<void> {
  const [owner, repo] = repoFullName.split("/");
  const repoUrl = `https://github.com/${repoFullName}`;

  console.log(`🐙 Starting GitHub scan [${scanId}] for ${repoFullName}@${branch}`);
  const availableSkills = loadSecuritySkills();
  console.log(`  🛡️ Loaded ${availableSkills.length} modular defensive security skill(s) for code review & remediation`);

  try {
    await updateStatus(scanId, "CRAWLING");

    // ── Step 1: Fetch repo file tree ─────────────────────────────────────────
    const tree = await getRepoTree(owner, repo, branch, accessToken);
    const relevantItems = tree.filter(isRelevantFile);
    console.log(`  📂 ${relevantItems.length} relevant files found in ${repoFullName}`);

    // ── Step 2: Fetch file contents in parallel ────────────────────────────
    await updateStatus(scanId, "SCANNING");
    const fetchLimit = pLimit(5);

    const fileContents: FileContent[] = (
      await Promise.all(
        relevantItems.map((item) =>
          fetchLimit(async () => {
            const content = await fetchFileContent(owner, repo, item.path, accessToken);
            if (!content) return null;
            return { path: item.path, content } satisfies FileContent;
          })
        )
      )
    ).filter((f): f is FileContent => f !== null);

    console.log(`  📄 Fetched ${fileContents.length} file contents`);

    // ── Step 3: Run Engine 1 — Secrets ────────────────────────────────────
    console.log("  🔐 Engine 1/4: Secrets Scanner...");
    const secretFindings: PendingFinding[] = [];
    for (const file of fileContents) {
      const results = scanFileForSecrets(file.path, file.content, repoUrl);
      secretFindings.push(...results.map((r) => r.finding));
    }
    console.log(`    └─ ${secretFindings.length} secret(s) found`);

    // ── Step 4: Run Engine 2 — SAST ───────────────────────────────────────
    console.log("  🔬 Engine 2/4: SAST Scanner...");
    const sastFindings: PendingFinding[] = [];
    for (const file of fileContents) {
      const results = scanFileForSAST(file.path, file.content, repoUrl);
      sastFindings.push(...results.map((r) => r.finding));
    }
    console.log(`    └─ ${sastFindings.length} SAST issue(s) found`);

    // ── Step 5: Run Engine 3 — SCA ────────────────────────────────────────
    console.log("  📦 Engine 3/4: SCA (Dependency CVE) Scanner...");
    const allPackages = fileContents.flatMap((f) => extractPackages(f.path, f.content));
    const scaFindings = await scanDependenciesForCVEs(allPackages, repoUrl);
    console.log(`    └─ ${scaFindings.length} CVE(s) found in ${allPackages.length} package(s)`);

    // ── Step 6: Run Engine 4 — LLM Deep Review (optional) ────────────────
    let llmFindings: PendingFinding[] = [];
    if (enableLLM) {
      console.log("  🤖 Engine 4/4: LLM Deep Code Review...");
      await updateStatus(scanId, "ANALYZING");
      llmFindings = await runLLMCodeReview(fileContents, repoUrl, 30);
      console.log(`    └─ ${llmFindings.length} issue(s) found by LLM review`);
    }

    // ── Step 7: Combine all findings ──────────────────────────────────────
    const allFindings = [
      ...secretFindings,
      ...sastFindings,
      ...scaFindings,
      ...llmFindings,
    ];

    // Deduplicate by url + type + evidence
    const deduped = allFindings.filter(
      (f, i, arr) =>
        arr.findIndex(
          (g) => g.type === f.type && g.url === f.url && g.evidence === f.evidence
        ) === i
    );

    console.log(`  ✅ Total findings: ${deduped.length} (after dedup)`);

    // ── Step 8: Generate AI fixes and persist ─────────────────────────────
    await generateFixes(deduped, scanId);

    await prisma.gitHubScan.update({
      where: { id: scanId },
      data: { status: "COMPLETED", completedAt: new Date() },
    });

    console.log(`🎉 GitHub scan [${scanId}] completed.`);
  } catch (err: any) {
    console.error(`💥 GitHub scan [${scanId}] failed:`, err);
    await prisma.gitHubScan.update({
      where: { id: scanId },
      data: { status: "FAILED" },
    }).catch(() => {});
  }
}

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  const scans = await prisma.scan.findMany({
    orderBy: { createdAt: "desc" },
    take: 5,
    include: {
      findings: true
    }
  });

  for (const s of scans) {
    console.log(`Scan ID: ${s.id}`);
    console.log(`Target: ${s.targetUrl}`);
    console.log(`Status: ${s.status}`);
    console.log(`Findings (${s.findings.length}):`);
    for (const f of s.findings) {
      console.log(`  - [${f.severity}] Type: ${f.type}`);
      console.log(`    URL: ${f.url}`);
      console.log(`    Evidence: ${f.evidence}`);
      console.log(`    Title: ${f.title}`);
    }
    console.log("-----------------------------------------");
  }
}

main().finally(() => prisma.$disconnect());

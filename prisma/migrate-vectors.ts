import { prisma } from "../src/lib/prisma";

async function main() {
  console.log("⚡ Altering database tables to use native pgvector 'vector(384)' types...");
  try {
    await prisma.$executeRawUnsafe('ALTER TABLE "KnowledgeChunk" ALTER COLUMN embedding TYPE vector(384) USING embedding::vector;');
    console.log("✅ Converted KnowledgeChunk.embedding to vector(384).");
  } catch (error) {
    console.error("❌ Failed to alter KnowledgeChunk table:", error);
  }

  try {
    await prisma.$executeRawUnsafe('ALTER TABLE "Finding" ALTER COLUMN embedding TYPE vector(384) USING embedding::vector;');
    console.log("✅ Converted Finding.embedding to vector(384).");
  } catch (error) {
    console.error("❌ Failed to alter Finding table:", error);
  }
}

main()
  .catch(console.error)
  .finally(async () => {
    await prisma.$disconnect();
  });

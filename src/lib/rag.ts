import { prisma } from "./prisma";
import { generateEmbedding } from "./embeddings";

interface KnowledgeChunkResult {
  title: string;
  content: string;
  source: string;
}

interface PastFindingResult {
  id: string;
  type: string;
  severity: string;
  url: string;
  title: string;
  scan_id: string;
  created_at: Date;
}


export async function retrieveContext(
  queryText: string,
  topK: number = 5
): Promise<string> {
  const embedding = await generateEmbedding(queryText);

  // pgvector cosine similarity query via Prisma raw SQL
  // The <=> operator = cosine distance (lower = more similar)
  const chunks = await prisma.$queryRaw<KnowledgeChunkResult[]>`
    SELECT title, content, source
    FROM "KnowledgeChunk"
    ORDER BY embedding <=> ${embedding}::vector
    LIMIT ${topK}
  `;

  if (chunks.length === 0) {
    return "No relevant context found in knowledge base.";
  }

  // Format chunks into a single context string for the LLM prompt
  return chunks
    .map((c) => `[${c.source.toUpperCase()}] ${c.title}\n${c.content}`)
    .join("\n\n---\n\n");
}

/**
 * Semantic search across past findings.
 * Lets users ask: "have we seen XSS in our login flow before?"
 */
export async function searchPastFindings(
  queryText: string,
  userId: string,
  topK: number = 10
) {
  const embedding = await generateEmbedding(queryText);

  const findings = await prisma.$queryRaw<PastFindingResult[]>`
    SELECT 
      f.id,
      f.type,
      f.severity,
      f.url,
      f.title,
      f."scanId" as scan_id,
      f."createdAt" as created_at,
      f.embedding <=> ${embedding}::vector as distance
    FROM "Finding" f
    JOIN "Scan" s ON s.id = f."scanId"
    WHERE s."userId" = ${userId}
    ORDER BY distance ASC
    LIMIT ${topK}
  `;

  return findings;
}

/**
 * Store a new knowledge chunk with its embedding.
 * Called during the knowledge base ingestion script.
 */
export async function storeKnowledgeChunk(params: {
  source: "owasp" | "nvd" | "cwe";
  title: string;
  content: string;
}) {
  const embedding = await generateEmbedding(
    `${params.title} ${params.content}`
  );

  await prisma.$executeRaw`
    INSERT INTO "KnowledgeChunk" (id, source, title, content, embedding, "createdAt")
    VALUES (
      gen_random_uuid()::text,
      ${params.source},
      ${params.title},
      ${params.content},
      ${embedding}::vector,
      NOW()
    )
  `;
}
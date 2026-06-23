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
  const vectorString = `[${embedding.join(",")}]`;

  // pgvector cosine similarity query via Prisma raw SQL
  // The <=> operator = cosine distance (lower = more similar)
  const chunks = await prisma.$queryRawUnsafe<KnowledgeChunkResult[]>(`
    SELECT title, content, source
    FROM "KnowledgeChunk"
    ORDER BY embedding::text::vector <=> '[${embedding.join(",")}]'::vector
    LIMIT ${topK}
  `);

  if (chunks.length === 0) {
    return "No relevant context found in knowledge base.";
  }

  // Format chunks into a single context string for the LLM prompt.
  // Each chunk content is capped at 400 chars; total context capped at 1500 chars
  // to prevent the downstream Cerebras prompt from exceeding the token limit.
  const MAX_CHUNK_CHARS = 400;
  const MAX_TOTAL_CHARS = 1500;

  const combined = chunks
    .map((c) => {
      const truncated =
        c.content.length > MAX_CHUNK_CHARS
          ? c.content.slice(0, MAX_CHUNK_CHARS) + "…"
          : c.content;
      return `[${c.source.toUpperCase()}] ${c.title}\n${truncated}`;
    })
    .join("\n\n---\n\n");

  return combined.length > MAX_TOTAL_CHARS
    ? combined.slice(0, MAX_TOTAL_CHARS) + "…"
    : combined;
}

/**
 * Semantic search across past findings.
 * Lets users ask: "have we seen XSS in our login flow before?"
 */
export async function searchPastFindings(
  queryText: string,
  topK: number = 10
) {
  const embedding = await generateEmbedding(queryText);
  const vectorString = `[${embedding.join(",")}]`;

  const findings = await prisma.$queryRawUnsafe<PastFindingResult[]>(`
    SELECT 
      f.id,
      f.type,
      f.severity,
      f.url,
      f.title,
      f."scanId" as scan_id,
      f."createdAt" as created_at,
      f.embedding::text::vector <=> '[${embedding.join(",")}]'::vector as distance
    FROM "Finding" f
    JOIN "Scan" s ON s.id = f."scanId"
    ORDER BY distance ASC
    LIMIT ${topK}
  `);

  return findings;
}


export async function storeKnowledgeChunk(params: {
  source: "owasp" | "nvd" | "cwe";
  title: string;
  content: string;
}) {
  const embedding = await generateEmbedding(
    `${params.title} ${params.content}`
  );
  const vectorString = `[${embedding.join(",")}]`;

  await prisma.$executeRawUnsafe(`
    INSERT INTO "KnowledgeChunk" (id, source, title, content, embedding, "createdAt")
    VALUES (
      gen_random_uuid()::text,
      '${params.source}',
      '${params.title.replace(/'/g, "''")}',
      '${params.content.replace(/'/g, "''")}',
      '[${embedding.join(",")}]'::vector,
      NOW()
    )
  `);
}
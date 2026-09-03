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
  try {
    const embedding = await generateEmbedding(queryText);
    // Build vector string from floats — safe to interpolate (all values are numbers,
    // not user-supplied strings), but we still use the tagged-template form for
    // the text parameters to be consistent and future-proof.
    const vectorStr = `[${embedding.join(",")}]`;

    // pgvector cosine similarity via Prisma tagged-template raw SQL.
    // $queryRaw safely parameterises ${vectorStr} as a $1 placeholder.
    const chunks = await prisma.$queryRaw<KnowledgeChunkResult[]>`
      SELECT title, content, source
      FROM "KnowledgeChunk"
      ORDER BY embedding::vector <=> ${vectorStr}::vector
      LIMIT ${topK}
    `;

    if (chunks.length === 0) {
      return "No relevant context found in knowledge base.";
    }

    // Format chunks into a single context string for the LLM prompt.
    // Each chunk content is capped at 400 chars; total context capped at 1500 chars
    // to prevent the downstream OpenRouter prompt from exceeding the token limit.
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
  } catch (error: any) {
    // Handle pgvector not installed or other database errors
    if (error.code === '42704' || error.message?.includes('type "vector" does not exist')) {
      console.warn('⚠️  pgvector extension not installed. RAG context retrieval disabled.');
      return "pgvector extension not available. Using general OWASP guidelines instead.";
    }
    const errMsg = error?.message || error?.code || (error?.name ? `${error.name}: ${error.message ?? ''}` : 'Database connection error');
    console.warn('⚠️  Could not retrieve RAG context from database (falling back to OWASP guidelines):', errMsg);
    return "Error retrieving context from knowledge base. Using general guidelines instead.";
  }
}

/**
 * Semantic search across past findings.
 * Lets users ask: "have we seen XSS in our login flow before?"
 */
export async function searchPastFindings(
  queryText: string,
  topK: number = 10
) {
  try {
    const embedding = await generateEmbedding(queryText);
    const vectorStr = `[${embedding.join(",")}]`;

    const findings = await prisma.$queryRaw<PastFindingResult[]>`
      SELECT
        f.id,
        f.type,
        f.severity,
        f.url,
        f.title,
        f."scanId" as scan_id,
        f."createdAt" as created_at,
        f.embedding::vector <=> ${vectorStr}::vector as distance
      FROM "Finding" f
      JOIN "Scan" s ON s.id = f."scanId"
      ORDER BY distance ASC
      LIMIT ${topK}
    `;

    return findings;
  } catch (error: any) {
    // Handle pgvector not installed or other database errors
    if (error.code === '42704' || error.message?.includes('type "vector" does not exist')) {
      console.warn('⚠️  pgvector extension not installed. Semantic search disabled.');
      return [];
    }
    console.error('Error in searchPastFindings:', error);
    return [];
  }
}


export async function storeKnowledgeChunk(params: {
  source: "owasp" | "nvd" | "cwe";
  title: string;
  content: string;
}) {
  try {
    const embedding = await generateEmbedding(
      `${params.title} ${params.content}`
    );
    const vectorStr = `[${embedding.join(",")}]`;

    // Use Prisma's tagged-template $executeRaw so that source, title, and content
    // are sent as safe $N parameterised values — never interpolated into SQL.
    // This eliminates the SQL injection vulnerability that the manual quote-escape
    // approach had (e.g., Unicode quote variants, multi-byte encoding bypasses).
    await prisma.$executeRaw`
      INSERT INTO "KnowledgeChunk" (id, source, title, content, embedding, "createdAt")
      VALUES (
        gen_random_uuid()::text,
        ${params.source},
        ${params.title},
        ${params.content},
        ${vectorStr}::vector,
        NOW()
      )
    `;
  } catch (error: any) {
    // Handle pgvector not installed or other database errors
    if (error.code === '42704' || error.message?.includes('type "vector" does not exist')) {
      console.warn('⚠️  pgvector extension not installed. Knowledge chunk storage disabled.');
      return;
    }
    console.error('Error in storeKnowledgeChunk:', error);
  }
}
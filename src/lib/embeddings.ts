import { pipeline, env } from "@xenova/transformers";

env.allowLocalModels = false;
env.useBrowserCache = false;

type EmbeddingPipeline = Awaited<ReturnType<typeof pipeline>>;

const globalForEmbedder = globalThis as unknown as {
    embedder: EmbeddingPipeline | undefined;
};

async function getEmbedder(): Promise<EmbeddingPipeline> {
    if (globalForEmbedder.embedder) return globalForEmbedder.embedder;

    const model = await pipeline(
        "feature-extraction",
        "Xenova/all-MiniLM-L6-v2"
    );

    if (process.env.NODE_ENV !== "production") {
        globalForEmbedder.embedder = model;
    }

    return model;
}


export async function generateEmbedding(text: string): Promise<number[]> {
    const embedder = await getEmbedder();

    // Use any casting to bypass strict type checks for specific pipeline options/outputs
    const output = await (embedder as any)(text, {
        pooling: "mean",
        normalize: true,
    });

    return Array.from(output.data as Float32Array);
}


export function cosineSimilarity(a: number[], b: number[]): number {
    const dot = a.reduce((sum, val, i) => sum + val * b[i], 0);
    const magA = Math.sqrt(a.reduce((sum, val) => sum + val * val, 0));
    const magB = Math.sqrt(b.reduce((sum, val) => sum + val * val, 0));
    return dot / (magA * magB);
}
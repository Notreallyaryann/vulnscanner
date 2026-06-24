import { pipeline, env } from '@xenova/transformers';

// Configure cache directory
if (process.env.VERCEL) {
    env.cacheDir = '/tmp/model_cache';
    env.localModelPath = '/tmp/model_cache';
    console.log('📁 Using Vercel /tmp cache');
} else {
    env.cacheDir = './.model_cache';
    env.localModelPath = './.model_cache';
    console.log('📁 Using local .model_cache');
}

env.allowRemoteModels = true;
env.useFSCache = true;

// Limit execution threads to 1 for serverless compatibility
const onnx = (env.backends as any)?.onnx;
if (onnx?.wasm) {
    onnx.wasm.numThreads = 1;
}

type EmbeddingPipeline = Awaited<ReturnType<typeof pipeline>>;

const globalForEmbedder = globalThis as unknown as {
    embedder: EmbeddingPipeline | undefined;
    modelPromise: Promise<EmbeddingPipeline> | undefined;
};

async function getEmbedder(): Promise<EmbeddingPipeline> {
    if (globalForEmbedder.embedder) return globalForEmbedder.embedder;
    if (globalForEmbedder.modelPromise) return globalForEmbedder.modelPromise;

    globalForEmbedder.modelPromise = (async () => {
        try {
            console.log('⏳ Loading model with @xenova/transformers...');
            const start = Date.now();

            const extractor = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2', {
                quantized: true,
                progress_callback: (progress: any) => {
                    if (progress.status === 'download') {
                        const percent = Math.round(progress.progress * 100);
                        console.log(`📥 Downloading model: ${percent}%`);
                    }
                }
            });

            console.log(`✅ Model loaded in ${((Date.now() - start) / 1000).toFixed(2)}s`);
            globalForEmbedder.embedder = extractor;
            return extractor;
        } catch (error) {
            console.error('❌ Failed to load model:', error);
            globalForEmbedder.modelPromise = undefined;
            throw error;
        }
    })();

    return globalForEmbedder.modelPromise;
}

export async function generateEmbedding(text: string): Promise<number[]> {
    try {
        const extractor = await getEmbedder();

        const output = await (extractor as any)([text], {
            pooling: 'mean',
            normalize: true
        });

        // Convert to array
        return Array.from(output.data as Float32Array);
    } catch (error: any) {
        console.error('Embedding error:', error);
        throw new Error(`Embedding failed: ${error.message}`);
    }
}

export function cosineSimilarity(a: number[], b: number[]): number {
    const dot = a.reduce((sum, val, i) => sum + val * b[i], 0);
    const magA = Math.sqrt(a.reduce((sum, val) => sum + val * val, 0));
    const magB = Math.sqrt(b.reduce((sum, val) => sum + val * val, 0));
    return dot / (magA * magB);
}
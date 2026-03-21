/**
 * WebGPU Embedding Pipeline using Transformers.js
 *
 * Runs local embeddings on the user's device.
 * Uses Xenova/all-MiniLM-L12-v2 (mean pooled token embeddings),
 * with WebGPU preferred and WASM fallback.
 *
 * Performance optimizations:
 * - INT8 quantization on WASM (~2-4x faster, ~95% quality)
 * - Adaptive batch size based on device (WebGPU: 8-16, WASM: 2-8)
 * - Parallel workers on WASM + multi-core devices (2x throughput)
 *
 * Core model functions live in embedder-core.ts so that embed-worker.ts
 * can import them without creating a circular dependency with this file.
 */

import type { CodeChunk } from "./chunker";
import { recordEmbedding } from "./metrics";
import { initEmbedder, embedTexts } from "./embedder-core";

// Re-export all core symbols so existing imports from "./embedder" are unaffected.
export {
	EMBEDDING_MODEL_ID,
	getEmbedderDevice,
	getDetectedWebGPUAvailability,
	initEmbedder,
	embedTexts,
	embedText,
	isEmbedderReady,
} from "./embedder-core";

export interface EmbeddedChunk extends CodeChunk {
	embedding: number[];
}

/**
 * Compute adaptive embedding config based on the active device and CPU count.
 *
 * Scales with device capability while staying conservative on weaker machines.
 * - WebGPU: moderate batches keep laptops responsive with the lighter L6 model
 * - WASM: scale batches with CPU/RAM, parallel workers only on beefy desktops
 */
export function resolveEmbedConfig(device: "webgpu" | "wasm"): {
	batchSize: number;
	workerCount: number;
} {
	const cores =
		typeof navigator !== "undefined" && Number.isFinite(navigator.hardwareConcurrency)
			? navigator.hardwareConcurrency
			: 4;

	const memoryGB =
		typeof navigator !== "undefined"
			? (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? 0
			: 0;

	if (device === "webgpu") {
		if (cores >= 16 || memoryGB >= 16) return { batchSize: 16, workerCount: 1 };
		if (cores >= 8 || memoryGB >= 8) return { batchSize: 12, workerCount: 1 };
		return { batchSize: 8, workerCount: 1 };
	}

	// WASM runs on CPU — scale up, but keep weaker devices responsive.
	const useParallel = cores >= 12 && memoryGB >= 8;

	if (useParallel) return { batchSize: 8, workerCount: 2 };
	if (cores >= 8 || memoryGB >= 8) return { batchSize: 6, workerCount: 1 };
	if (cores >= 4 || memoryGB >= 4) return { batchSize: 4, workerCount: 1 };
	return { batchSize: 2, workerCount: 1 };
}

type EmbedWorkerOutput =
	| { type: "batch_result"; requestId: number; batchEmbeddings: number[][]; done: number; total: number }
	| { type: "result"; requestId: number; embeddings: number[][]; error?: string };

/**
 * Embed chunks in parallel across N Web Workers (WASM only).
 * Each worker loads its own INT8 model instance.
 *
 * Note: onBatchComplete is not called incrementally during parallel processing
 * (workers process non-overlapping partitions, so there's no safe sequential prefix
 * until the final merge). A single onBatchComplete call fires at the end.
 */
async function embedChunksParallel(
	chunks: CodeChunk[],
	onProgress: ((done: number, total: number) => void) | undefined,
	batchSize: number,
	signal: AbortSignal | undefined,
	onBatchComplete: ((embeddedSoFar: EmbeddedChunk[]) => void) | undefined,
	workerCount: number,
): Promise<EmbeddedChunk[]> {
	const partitionSize = Math.ceil(chunks.length / workerCount);
	const partitions: CodeChunk[][] = [];
	for (let i = 0; i < workerCount; i++) {
		partitions.push(chunks.slice(i * partitionSize, (i + 1) * partitionSize));
	}

	const partitionDone = new Array(workerCount).fill(0);
	const partitionResults: EmbeddedChunk[][] = partitions.map(() => []);

	await Promise.all(
		partitions.map(
			(partition, workerIdx) =>
				new Promise<void>((resolve, reject) => {
					if (partition.length === 0) {
						resolve();
						return;
					}

					const worker = new Worker(new URL("../workers/embed-worker.ts", import.meta.url), {
						type: "module",
					});

					worker.onmessage = (e: MessageEvent<EmbedWorkerOutput>) => {
						const msg = e.data;

						if (msg.type === "batch_result") {
							const { batchEmbeddings, done } = msg;
							const batchStart = done - batchEmbeddings.length;
							for (let j = 0; j < batchEmbeddings.length; j++) {
								const chunk = partition[batchStart + j];
								if (chunk) {
									partitionResults[workerIdx].push({ ...chunk, embedding: batchEmbeddings[j] });
								}
							}
							partitionDone[workerIdx] = done;

							const totalDone = partitionDone.reduce((a, b) => a + b, 0);
							onProgress?.(totalDone, chunks.length);

							if (signal?.aborted) {
								worker.terminate();
								reject(new DOMException("Aborted", "AbortError"));
							}
						} else if (msg.type === "result") {
							worker.terminate();
							if (msg.error) {
								reject(new Error(msg.error));
							} else {
								resolve();
							}
						}
					};

					worker.onerror = (e) => {
						worker.terminate();
						reject(new Error(e.message ?? "Embed worker error"));
					};

					worker.postMessage({
						type: "embed",
						requestId: workerIdx,
						texts: partition.map((c) => c.code),
						batchSize,
					});
				}),
		),
	);

	const allEmbedded = partitionResults.flat();
	onBatchComplete?.(allEmbedded);
	return allEmbedded;
}

/**
 * Embed an array of code chunks in batches.
 * Supports cancellation via optional AbortSignal (checked between batches).
 * Optional onBatchComplete called after each batch for incremental persistence.
 *
 * When workerCount > 1 (WASM + multi-core), delegates to parallel workers for ~2x throughput.
 * In parallel mode, onBatchComplete fires once at the end rather than incrementally.
 */
export async function embedChunks(
	chunks: CodeChunk[],
	onProgress?: (done: number, total: number) => void,
	batchSize: number = 8,
	signal?: AbortSignal,
	onBatchComplete?: (embeddedSoFar: EmbeddedChunk[]) => void,
	workerCount: number = 1,
): Promise<EmbeddedChunk[]> {
	if (workerCount > 1 && chunks.length > workerCount && typeof Worker !== "undefined") {
		const startTime = performance.now();
		const result = await embedChunksParallel(
			chunks,
			onProgress,
			batchSize,
			signal,
			onBatchComplete,
			workerCount,
		);
		recordEmbedding(chunks.length, performance.now() - startTime);
		return result;
	}

	// Single-thread path
	await initEmbedder();

	const results: EmbeddedChunk[] = [];
	const startTime = performance.now();

	for (let i = 0; i < chunks.length; i += batchSize) {
		if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

		const batch = chunks.slice(i, i + batchSize);
		const embeddings = await embedTexts(batch.map((chunk) => chunk.code));
		if (embeddings.length !== batch.length) {
			throw new Error(
				`Embedding batch size mismatch: expected ${batch.length}, got ${embeddings.length}.`,
			);
		}
		for (let j = 0; j < batch.length; j++) {
			results.push({ ...batch[j], embedding: embeddings[j] });
		}

		const done = Math.min(i + batchSize, chunks.length);
		onProgress?.(done, chunks.length);
		onBatchComplete?.(results);
	}

	recordEmbedding(chunks.length, performance.now() - startTime);

	return results;
}

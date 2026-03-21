/**
 * embedder-core — pure model init and inference functions.
 *
 * Extracted from embedder.ts so that embed-worker.ts can import these without
 * creating a circular dependency:
 *
 *   BEFORE (circular):
 *     embedder.ts → new URL(embed-worker.ts)  ← webpack dep
 *     embed-worker.ts → import(embedder.ts)    ← import dep
 *
 *   AFTER (no cycle):
 *     embedder.ts → new URL(embed-worker.ts) + import(embedder-core.ts)
 *     embed-worker.ts → import(embedder-core.ts)
 *
 * All symbols are re-exported from embedder.ts so existing imports are unaffected.
 */

import { detectWebGPUAvailability, type WebGPUAvailability } from "./webgpu";

export const EMBEDDING_MODEL_ID = "Xenova/all-MiniLM-L12-v2";

type EmbeddingRuntime = {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	tokenizer: any;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	model: any;
};

// Module-level singletons — each JS context (main thread / worker) gets its own.
let embedRuntime: EmbeddingRuntime | null = null;
let pipelinePromise: Promise<void> | null = null;
let activeDevice: "webgpu" | "wasm" | null = null;
let detectedWebGPUAvailability: WebGPUAvailability | null = null;

const EMBEDDER_INIT_TIMEOUT_MS = 90_000;
const EMBEDDER_WARMUP_TEXT = "warmup";

/** Returns the device the embedder is actually running on, or null if not yet initialized. */
export function getEmbedderDevice(): "webgpu" | "wasm" | null {
	return activeDevice;
}

export function getDetectedWebGPUAvailability(): WebGPUAvailability | null {
	return detectedWebGPUAvailability;
}

/**
 * Initialize the embedding model.
 * Call once; subsequent calls are no-ops.
 * Rejects if the model takes longer than 90 s to load.
 *
 * @param deviceOverride - Force a specific device (embed workers must pass "wasm")
 */
export async function initEmbedder(
	onProgress?: (msg: string) => void,
	deviceOverride?: "webgpu" | "wasm",
): Promise<void> {
	if (embedRuntime) return;
	if (pipelinePromise) return pipelinePromise;

	pipelinePromise = new Promise<void>((resolve, reject) => {
		const timeoutId = setTimeout(() => {
			pipelinePromise = null;
			embedRuntime = null;
			reject(
				new Error(
					"Embedding model failed to load within 90 s. Check your network connection and reload the page.",
				),
			);
		}, EMBEDDER_INIT_TIMEOUT_MS);

		(async () => {
			try {
				onProgress?.("Loading embedding model...");

				// Dynamic import so this does not break SSR
				const { AutoTokenizer, AutoModel, env } = await import("@huggingface/transformers");

				env.allowLocalModels = false;

				// Suppress ONNX Runtime warnings about execution provider node assignments.
				// logSeverityLevel: 0=verbose, 1=info, 2=warning, 3=error, 4=fatal
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const onnxEnv = (env as any).backends?.onnx;
				if (onnxEnv) {
					onnxEnv.logSeverityLevel = 3;
					onnxEnv.logLevel = "error";
				}

				// ONNX Runtime WASM bypasses its own log level and writes
				// VerifyEachNodeIsAssignedToAnEp warnings directly to console.error/warn.
				// Patch console to drop them so they don't trigger the dev overlay.
				const ONNX_WARN_RE = /\[W:onnxruntime:/;
				const _origError = console.error.bind(console);
				const _origWarn = console.warn.bind(console);
				console.error = (...args: unknown[]) => {
					if (args.length > 0 && typeof args[0] === "string" && ONNX_WARN_RE.test(args[0])) return;
					_origError(...args);
				};
				console.warn = (...args: unknown[]) => {
					if (args.length > 0 && typeof args[0] === "string" && ONNX_WARN_RE.test(args[0])) return;
					_origWarn(...args);
				};

				// Resolve device: use override (e.g. from embed worker) or auto-detect
				let device: "webgpu" | "wasm";
				if (deviceOverride) {
					device = deviceOverride;
					detectedWebGPUAvailability = {
						supported: deviceOverride === "webgpu",
						reason: deviceOverride === "webgpu" ? "ok" : "missing-api",
					};
				} else {
					const availability = await detectWebGPUAvailability();
					detectedWebGPUAvailability = availability;
					device = availability.supported ? "webgpu" : "wasm";
					if (!availability.supported) {
						console.info(`WebGPU fallback reason: ${availability.reason}`);
					}
				}
				activeDevice = device;
				console.info(`Embedder using device: ${device.toUpperCase()}`);
				onProgress?.(`Using device: ${device}`);

				const tokenizer = await AutoTokenizer.from_pretrained(EMBEDDING_MODEL_ID);

				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const modelOptions: Record<string, any> = {
					device,
					session_options: { log_severity_level: 3 },
				};

				let model;
				if (device === "webgpu") {
					modelOptions.dtype = "fp16";
					try {
						model = await AutoModel.from_pretrained(EMBEDDING_MODEL_ID, modelOptions);
						console.info("Embedder loaded WebGPU fp16 model");
						onProgress?.("Loaded WebGPU fp16 model");
					} catch (fp16Error) {
						console.warn("WebGPU fp16 unavailable, falling back to fp32", fp16Error);
						delete modelOptions.dtype;
						model = await AutoModel.from_pretrained(EMBEDDING_MODEL_ID, modelOptions);
						onProgress?.("Loaded WebGPU fp32 fallback");
					}
				} else {
					modelOptions.dtype = "q8";
					try {
						model = await AutoModel.from_pretrained(EMBEDDING_MODEL_ID, modelOptions);
						console.info("Embedder loaded INT8 quantized model (q8)");
						onProgress?.("Loaded INT8 model (faster)");
					} catch {
						console.warn("INT8 model unavailable, falling back to fp32");
						delete modelOptions.dtype;
						model = await AutoModel.from_pretrained(EMBEDDING_MODEL_ID, modelOptions);
					}
				}

				embedRuntime = { tokenizer, model };
				if (device === "webgpu") {
					onProgress?.("Warming up WebGPU shaders...");
					const warmupInputs = tokenizer([EMBEDDER_WARMUP_TEXT], {
						truncation: true,
						padding: true,
					});
					await model(warmupInputs);
				}

				clearTimeout(timeoutId);
				onProgress?.(`Embedding model ready (${EMBEDDING_MODEL_ID})`);
				resolve();
			} catch (err) {
				clearTimeout(timeoutId);
				pipelinePromise = null;
				embedRuntime = null;
				reject(err);
			}
		})();
	});

	return pipelinePromise;
}

function l2Normalize(values: Float32Array): number[] {
	let norm = 0;
	for (let i = 0; i < values.length; i++) {
		norm += values[i] * values[i];
	}
	norm = Math.sqrt(norm);
	if (norm > 0) {
		for (let i = 0; i < values.length; i++) {
			values[i] /= norm;
		}
	}
	return Array.from(values);
}

function meanPoolAndNormalizeBatch(
	features: ArrayLike<number>,
	dims: number[],
	attentionMaskData?: ArrayLike<number>,
	attentionMaskDims?: number[],
): number[][] {
	let batch = 0;
	let seq = 0;
	let width = 0;
	let isAlreadyPooledBatch = false;

	if (dims.length === 3) {
		batch = dims[0] ?? 0;
		seq = dims[1] ?? 0;
		width = dims[2] ?? 0;
	} else if (dims.length === 2) {
		const maybeBatch = dims[0] ?? 0;
		const maybeWidth = dims[1] ?? 0;
		if (
			attentionMaskDims &&
			attentionMaskDims.length === 2 &&
			(attentionMaskDims[0] ?? 0) === maybeBatch
		) {
			batch = maybeBatch;
			width = maybeWidth;
			seq = 1;
			isAlreadyPooledBatch = true;
		} else {
			batch = 1;
			seq = maybeBatch;
			width = maybeWidth;
		}
	} else {
		throw new Error(`Unsupported embedding tensor dims: [${dims.join(", ")}]`);
	}

	if (batch <= 0 || seq <= 0 || width <= 0) {
		throw new Error(`Invalid embedding tensor dims: [${dims.join(", ")}]`);
	}

	const hasMask =
		!isAlreadyPooledBatch &&
		!!attentionMaskData &&
		!!attentionMaskDims &&
		attentionMaskDims.length === 2 &&
		(attentionMaskDims[0] ?? 0) === batch &&
		(attentionMaskDims[1] ?? 0) === seq;

	const output: number[][] = [];
	for (let b = 0; b < batch; b++) {
		const pooled = new Float32Array(width);

		if (isAlreadyPooledBatch) {
			const rowBase = b * width;
			for (let j = 0; j < width; j++) {
				pooled[j] = (features[rowBase + j] ?? 0) as number;
			}
			output.push(l2Normalize(pooled));
			continue;
		}

		let tokenCount = 0;
		for (let t = 0; t < seq; t++) {
			const tokenActive = hasMask
				? (attentionMaskData![b * (attentionMaskDims![1] ?? 0) + t] ?? 0) > 0
				: true;
			if (!tokenActive) continue;
			const tokenBase = b * seq * width + t * width;
			for (let j = 0; j < width; j++) {
				pooled[j] += (features[tokenBase + j] ?? 0) as number;
			}
			tokenCount += 1;
		}

		const divisor = tokenCount > 0 ? tokenCount : seq;
		for (let j = 0; j < width; j++) {
			pooled[j] /= divisor;
		}
		output.push(l2Normalize(pooled));
	}

	return output;
}

/**
 * Embed a batch of text strings.
 * Returns mean-pooled, L2-normalized vectors.
 */
export async function embedTexts(texts: string[]): Promise<number[][]> {
	if (!embedRuntime) {
		await initEmbedder();
	}
	if (!embedRuntime) {
		throw new Error("Embedding runtime failed to initialize.");
	}
	if (texts.length === 0) return [];

	const inputs = embedRuntime.tokenizer(texts, {
		truncation: true,
		padding: true,
	});
	const output = await embedRuntime.model(inputs);
	const hidden = output?.last_hidden_state ?? output?.output;
	if (!hidden?.data || !Array.isArray(hidden?.dims)) {
		throw new Error(
			`Embedding model "${EMBEDDING_MODEL_ID}" returned an unexpected output shape.`,
		);
	}

	return meanPoolAndNormalizeBatch(
		hidden.data as ArrayLike<number>,
		hidden.dims as number[],
		inputs?.attention_mask?.data as ArrayLike<number> | undefined,
		inputs?.attention_mask?.dims as number[] | undefined,
	);
}

/** Embed a single text string. Returns the mean-pooled, normalized vector. */
export async function embedText(text: string): Promise<number[]> {
	const vectors = await embedTexts([text]);
	if (vectors.length !== 1) {
		throw new Error(
			`Embedding model "${EMBEDDING_MODEL_ID}" returned ${vectors.length} vectors for a single input.`,
		);
	}
	return vectors[0];
}

/** Check if the embedder is ready. */
export function isEmbedderReady(): boolean {
	return embedRuntime != null;
}

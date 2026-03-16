/**
 * Custom Upload Connector
 *
 * Accepts File[] from the browser file picker, extracts text content
 * (TXT/MD natively, JSON/YAML as formatted text, PDF via pdfjs-dist),
 * splits into overlapping chunks, embeds, and stores in the VectorStore.
 *
 * Cache key: "secask" / "custom" / content-fingerprint
 * FilePath convention: custom://{filename}::chunk_{n}
 */

import type { CodeChunk } from "@/lib/chunker";
import { embedChunks, initEmbedder, getEmbedderDevice, resolveEmbedConfig } from "@/lib/embedder";
import { VectorStore } from "@/lib/vectorStore";
import type { ConnectorProgress, ConnectorResult } from "./attack";

// ─── Text splitter ────────────────────────────────────────────────────────────

const CHUNK_SIZE_CHARS = 1500;   // ~375 tokens @ 4 chars/token
const CHUNK_OVERLAP_CHARS = 200; // overlap to preserve context across chunks

/**
 * Split text into overlapping chunks of roughly CHUNK_SIZE_CHARS characters.
 * Tries to split on paragraph or sentence boundaries.
 */
function splitText(text: string): string[] {
	const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
	if (normalized.length <= CHUNK_SIZE_CHARS) return [normalized];

	const chunks: string[] = [];
	let start = 0;

	while (start < normalized.length) {
		let end = start + CHUNK_SIZE_CHARS;
		if (end >= normalized.length) {
			chunks.push(normalized.slice(start).trim());
			break;
		}

		// Try to break on double newline (paragraph)
		let breakAt = normalized.lastIndexOf("\n\n", end);
		if (breakAt <= start + CHUNK_SIZE_CHARS / 2) {
			// Paragraph boundary too far back — try single newline
			breakAt = normalized.lastIndexOf("\n", end);
		}
		if (breakAt <= start + CHUNK_SIZE_CHARS / 2) {
			// No good newline — try space
			breakAt = normalized.lastIndexOf(" ", end);
		}
		if (breakAt <= start + CHUNK_SIZE_CHARS / 2) {
			// Hard cut
			breakAt = end;
		}

		const chunk = normalized.slice(start, breakAt).trim();
		if (chunk.length > 0) chunks.push(chunk);

		// Move forward with overlap
		start = Math.max(start + 1, breakAt - CHUNK_OVERLAP_CHARS);
	}

	return chunks.filter((c) => c.length > 0);
}

// ─── Text extractors ──────────────────────────────────────────────────────────

async function readTextFile(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(reader.result as string);
		reader.onerror = () => reject(new Error(`FileReader error: ${reader.error?.message}`));
		reader.readAsText(file, "utf-8");
	});
}

function formatJson(text: string): string {
	try {
		const parsed = JSON.parse(text);
		// If it's an array, join items as formatted strings
		if (Array.isArray(parsed)) {
			return parsed
				.map((item: unknown) =>
					typeof item === "object" && item !== null
						? JSON.stringify(item, null, 2)
						: String(item)
				)
				.join("\n\n");
		}
		return JSON.stringify(parsed, null, 2);
	} catch {
		return text; // Not valid JSON — treat as raw text
	}
}

async function extractPDF(file: File): Promise<string> {
	// Dynamically import pdfjs-dist (optional dependency)
	// Falls back gracefully if not installed
	try {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pdfjsLib = await import("pdfjs-dist" as any).catch(() => null);
		if (!pdfjsLib) {
			throw new Error(
				"pdfjs-dist is not installed. Run: npm install pdfjs-dist\n" +
				"Or upload the document as a .txt or .md file instead."
			);
		}

		// Set worker path
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(pdfjsLib as any).GlobalWorkerOptions.workerSrc =
			`https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${(pdfjsLib as any).version}/pdf.worker.min.js`;

		const arrayBuffer = await file.arrayBuffer();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pdf = await (pdfjsLib as any).getDocument({ data: arrayBuffer }).promise;
		const pages: string[] = [];

		for (let i = 1; i <= pdf.numPages; i++) {
			const page = await pdf.getPage(i);
			const content = await page.getTextContent();
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const pageText = content.items.map((item: any) => item.str).join(" ");
			if (pageText.trim()) pages.push(`[Page ${i}]\n${pageText.trim()}`);
		}

		return pages.join("\n\n");
	} catch (err) {
		if (err instanceof Error && err.message.includes("pdfjs-dist")) throw err;
		throw new Error(`Failed to extract PDF text: ${err instanceof Error ? err.message : String(err)}`);
	}
}

async function extractFileText(file: File): Promise<string> {
	const ext = file.name.split(".").pop()?.toLowerCase() ?? "";

	switch (ext) {
		case "txt":
		case "md":
		case "markdown":
		case "rst":
			return readTextFile(file);

		case "json":
			return formatJson(await readTextFile(file));

		case "yaml":
		case "yml":
			// Return raw YAML as-is (it's human-readable)
			return readTextFile(file);

		case "pdf":
			return extractPDF(file);

		case "csv":
			// First 100 lines of CSV
			return (await readTextFile(file)).split("\n").slice(0, 100).join("\n");

		default:
			// Try to read as text, fall back to error
			try {
				return readTextFile(file);
			} catch {
				throw new Error(`Unsupported file type: .${ext}`);
			}
	}
}

// ─── Fingerprint for cache key ────────────────────────────────────────────────

async function fingerprintFiles(files: File[]): Promise<string> {
	const parts = files.map((f) => `${f.name}:${f.size}:${f.lastModified}`).join("|");
	// Use a simple hash-like string (no crypto needed)
	let hash = 0;
	for (let i = 0; i < parts.length; i++) {
		hash = ((hash << 5) - hash + parts.charCodeAt(i)) | 0;
	}
	return `upload-${Math.abs(hash).toString(36)}`;
}

// ─── Main indexer ─────────────────────────────────────────────────────────────

export async function indexUpload(
	files: File[],
	store: VectorStore,
	onProgress?: (p: ConnectorProgress) => void,
	signal?: AbortSignal
): Promise<ConnectorResult> {
	if (files.length === 0) throw new Error("No files provided");

	const cacheKey = await fingerprintFiles(files);

	// 1. Check cache
	const cached = await store.loadFromCache("secask", "custom", cacheKey);
	if (cached) {
		onProgress?.({
			phase: "cached",
			message: `Loaded ${store.size} chunks from cache`,
			current: store.size,
			total: store.size,
		});
		return { chunkCount: store.size, fromCache: true };
	}

	store.clear();

	// 2. Extract text from each file
	const chunks: CodeChunk[] = [];

	for (let fi = 0; fi < files.length; fi++) {
		if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
		const file = files[fi];

		onProgress?.({
			phase: "fetching",
			message: `Reading ${file.name} (${Math.round(file.size / 1024)} KB)…`,
			current: fi,
			total: files.length,
		});

		let text: string;
		try {
			text = await extractFileText(file);
		} catch (err) {
			throw new Error(`Failed to read ${file.name}: ${err instanceof Error ? err.message : String(err)}`);
		}

		if (!text.trim()) continue;

		// 3. Split into chunks
		const segments = splitText(text);
		for (let ci = 0; ci < segments.length; ci++) {
			const segment = segments[ci];
			chunks.push({
				id: `custom::${file.name}::${ci}`,
				filePath: `custom://${file.name}`,
				language: "custom",
				nodeType: "text_chunk",
				name: segments.length > 1 ? `${file.name} (chunk ${ci + 1}/${segments.length})` : file.name,
				code: segment,
				startLine: ci,
				endLine: ci,
			});
		}
	}

	if (chunks.length === 0) throw new Error("No text content found in uploaded files");
	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 4. Embed
	onProgress?.({
		phase: "embedding",
		message: `Embedding ${chunks.length} chunks from ${files.length} file(s)…`,
		current: 0,
		total: chunks.length,
	});

	await initEmbedder((msg) =>
		onProgress?.({ phase: "embedding", message: msg, current: 0, total: chunks.length })
	);
	const embedConfig = resolveEmbedConfig(getEmbedderDevice() ?? "wasm");

	const embedded = await embedChunks(
		chunks,
		(done, total) =>
			onProgress?.({
				phase: "embedding",
				message: `Embedded ${done}/${total} chunks`,
				current: done,
				total,
			}),
		embedConfig.batchSize,
		signal,
		undefined,
		embedConfig.workerCount
	);

	// 5. Store & persist
	store.insert(embedded);

	onProgress?.({ phase: "persisting", message: "Saving upload index…", current: 0, total: 1 });
	await store.persist("secask", "custom", cacheKey);

	onProgress?.({
		phase: "done",
		message: `Indexed ${embedded.length} chunks from ${files.length} file(s)`,
		current: embedded.length,
		total: embedded.length,
	});

	return { chunkCount: embedded.length, fromCache: false };
}

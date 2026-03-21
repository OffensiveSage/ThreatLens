/**
 * nistControlEnrichment — reads NIST 800-53 control text from the IndexedDB
 * cache (if NIST has been indexed in ThreatLens) and returns a map of
 * controlId → description text that can be shown alongside findings.
 *
 * Strategy:
 *   1. Open gitask-cache IndexedDB
 *   2. Load the threatlens/nist blob (same key pattern as nvd)
 *   3. For each chunk, scan its `code` text for control ID patterns
 *   4. Return a Record<controlId, excerpt> map
 */

export type NistControlDescriptions = Record<string, string>;

type ChunkItem = { code?: string; filePath?: string; text?: string; content?: string };

interface CachedBlob {
	chunks?: ChunkItem[];
}

function extractTextFromChunk(chunk: ChunkItem): string {
	return chunk.code ?? chunk.text ?? chunk.content ?? "";
}

/** Opens IndexedDB and fetches the threatlens/nist cache blob. Returns null if not indexed. */
async function loadNistBlob(): Promise<CachedBlob | null> {
	return new Promise((resolve) => {
		try {
			const req = indexedDB.open("gitask-cache", 1);
			req.onerror = () => resolve(null);
			req.onsuccess = () => {
				const db = req.result;
				if (!db.objectStoreNames.contains("repos")) {
					resolve(null);
					return;
				}
				const tx = db.transaction("repos", "readonly");
				const store = tx.objectStore("repos");
				const getReq = store.get("threatlens/nist");
				getReq.onsuccess = () => {
					resolve(getReq.result ?? null);
				};
				getReq.onerror = () => resolve(null);
			};
		} catch {
			resolve(null);
		}
	});
}

/**
 * Check if NIST 800-53 is indexed.
 * Returns true if the threatlens/nist key exists in IndexedDB.
 */
export async function isNistIndexed(): Promise<boolean> {
	const blob = await loadNistBlob();
	return blob !== null && Array.isArray((blob as CachedBlob).chunks) && (blob as CachedBlob).chunks!.length > 0;
}

/**
 * Load NIST control descriptions from the indexed data.
 * Returns a map of controlId → best excerpt text.
 * E.g. { "SI-10": "SI-10 Information Input Validation: The organization..." }
 */
export async function loadNistControlDescriptions(
	controlIds: string[]
): Promise<NistControlDescriptions> {
	const result: NistControlDescriptions = {};
	if (controlIds.length === 0) return result;

	const blob = await loadNistBlob();
	if (!blob) return result;

	const chunks = (blob as CachedBlob).chunks ?? [];
	if (chunks.length === 0) return result;

	// For each requested control, find the best matching chunk
	for (const controlId of controlIds) {
		// Build regex: match "SI-10" or "SI-10 " at word boundary (case-insensitive)
		const escaped = controlId.replace("-", "\\-");
		const re = new RegExp(`\\b${escaped}\\b`, "i");

		let bestExcerpt = "";
		let bestLen = 0;

		for (const chunk of chunks) {
			const text = extractTextFromChunk(chunk);
			if (!re.test(text)) continue;

			// Find the match position and extract a window around it
			const match = re.exec(text);
			if (!match) continue;

			const start = Math.max(0, match.index - 20);
			const end = Math.min(text.length, match.index + 400);
			const excerpt = text.slice(start, end).trim().replace(/\s+/g, " ");

			// Prefer longer excerpts that start near the control ID
			if (excerpt.length > bestLen) {
				bestLen = excerpt.length;
				bestExcerpt = excerpt;
			}
		}

		if (bestExcerpt) {
			// Clean up: truncate to ~300 chars and add ellipsis if needed
			result[controlId] = bestExcerpt.length > 300
				? bestExcerpt.slice(0, 300) + "…"
				: bestExcerpt;
		}
	}

	return result;
}

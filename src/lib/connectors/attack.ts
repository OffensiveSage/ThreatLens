/**
 * MITRE ATT&CK Connector
 *
 * Fetches the Enterprise ATT&CK STIX 2.1 bundle, parses techniques,
 * groups, software, mitigations, and data sources into CodeChunks,
 * then embeds and stores them in the VectorStore.
 *
 * Cache key: "secask" / "attack" / ATTACK_CACHE_KEY
 * FilePath convention: attack://technique/T1059.001, attack://group/G0016, etc.
 */

import type { CodeChunk } from "@/lib/chunker";
import { embedChunks, initEmbedder, getEmbedderDevice, resolveEmbedConfig } from "@/lib/embedder";
import { VectorStore } from "@/lib/vectorStore";

export interface ConnectorProgress {
	phase: "fetching" | "parsing" | "embedding" | "persisting" | "done" | "cached" | "error";
	message: string;
	current: number;
	total: number;
}

export interface ConnectorResult {
	chunkCount: number;
	fromCache: boolean;
}

/** Increment this when ATT&CK releases a new version to invalidate caches. */
const ATTACK_CACHE_KEY = "enterprise-v16.1";

const ATTACK_STIX_URL =
	"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

const RELEVANT_STIX_TYPES = new Set([
	"attack-pattern",       // techniques
	"intrusion-set",        // threat groups
	"tool",                 // software (tool)
	"malware",              // software (malware)
	"course-of-action",     // mitigations
	"x-mitre-data-source",  // data sources
]);

// ─── STIX helpers ────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type StixObject = Record<string, any>;

function getMitreId(obj: StixObject): string {
	const refs = obj.external_references as Array<Record<string, string>> | undefined;
	return refs?.find((r) => r.source_name === "mitre-attack")?.external_id ?? "";
}

function getTactics(obj: StixObject): string[] {
	const phases = obj.kill_chain_phases as Array<{ phase_name: string }> | undefined;
	return phases?.map((p) => p.phase_name) ?? [];
}

function truncate(text: string, maxChars = 3000): string {
	if (!text || text.length <= maxChars) return text ?? "";
	return text.slice(0, maxChars) + "…";
}

// ─── Per-type parsers ────────────────────────────────────────────────────────

function parseTechnique(obj: StixObject): CodeChunk | null {
	if (obj.x_mitre_deprecated || obj.revoked) return null;
	const id = getMitreId(obj);
	if (!id) return null;

	const tactics = getTactics(obj);
	const platforms: string[] = obj.x_mitre_platforms ?? [];
	const dataSources: string[] = obj.x_mitre_data_sources ?? [];
	const detection = truncate(obj.x_mitre_detection ?? "", 1500);
	const description = truncate(obj.description ?? "", 2000);
	const isSubtechnique: boolean = obj.x_mitre_is_subtechnique ?? false;

	const parts = [
		`ATT&CK ${isSubtechnique ? "Sub-Technique" : "Technique"}: ${id} - ${obj.name as string}`,
		tactics.length ? `Tactics: ${tactics.join(", ")}` : "",
		platforms.length ? `Platforms: ${platforms.join(", ")}` : "",
		description ? `Description: ${description}` : "",
		dataSources.length ? `Data Sources: ${dataSources.join(", ")}` : "",
		detection ? `Detection: ${detection}` : "",
	].filter(Boolean);

	return {
		id: `attack::${id}`,
		filePath: `attack://technique/${id}`,
		language: "attack",
		nodeType: isSubtechnique ? "sub-technique" : "technique",
		name: `${id}: ${obj.name as string}`,
		code: parts.join("\n\n"),
		startLine: 0,
		endLine: 0,
	};
}

function parseGroup(obj: StixObject): CodeChunk | null {
	if (obj.x_mitre_deprecated || obj.revoked) return null;
	const id = getMitreId(obj);
	if (!id) return null;

	const aliases: string[] = obj.aliases ?? [];
	const description = truncate(obj.description ?? "", 2500);

	const parts = [
		`ATT&CK Threat Group: ${id} - ${obj.name as string}`,
		aliases.length > 1 ? `Also known as: ${aliases.filter((a) => a !== obj.name).join(", ")}` : "",
		description ? `Description: ${description}` : "",
	].filter(Boolean);

	return {
		id: `attack::${id}`,
		filePath: `attack://group/${id}`,
		language: "attack",
		nodeType: "group",
		name: `${id}: ${obj.name as string}`,
		code: parts.join("\n\n"),
		startLine: 0,
		endLine: 0,
	};
}

function parseSoftware(obj: StixObject): CodeChunk | null {
	if (obj.x_mitre_deprecated || obj.revoked) return null;
	const id = getMitreId(obj);
	if (!id) return null;

	const aliases: string[] = obj.x_mitre_aliases ?? [];
	const platforms: string[] = obj.x_mitre_platforms ?? [];
	const description = truncate(obj.description ?? "", 2500);
	const softwareType = obj.type === "tool" ? "Tool" : "Malware";

	const parts = [
		`ATT&CK Software (${softwareType}): ${id} - ${obj.name as string}`,
		aliases.length ? `Aliases: ${aliases.join(", ")}` : "",
		platforms.length ? `Platforms: ${platforms.join(", ")}` : "",
		description ? `Description: ${description}` : "",
	].filter(Boolean);

	return {
		id: `attack::${id}`,
		filePath: `attack://software/${id}`,
		language: "attack",
		nodeType: softwareType.toLowerCase(),
		name: `${id}: ${obj.name as string}`,
		code: parts.join("\n\n"),
		startLine: 0,
		endLine: 0,
	};
}

function parseMitigation(obj: StixObject): CodeChunk | null {
	if (obj.x_mitre_deprecated || obj.revoked) return null;
	const id = getMitreId(obj);
	if (!id) return null;

	const description = truncate(obj.description ?? "", 2500);

	const parts = [
		`ATT&CK Mitigation: ${id} - ${obj.name as string}`,
		description ? `Description: ${description}` : "",
	].filter(Boolean);

	return {
		id: `attack::${id}`,
		filePath: `attack://mitigation/${id}`,
		language: "attack",
		nodeType: "mitigation",
		name: `${id}: ${obj.name as string}`,
		code: parts.join("\n\n"),
		startLine: 0,
		endLine: 0,
	};
}

function parseDataSource(obj: StixObject): CodeChunk | null {
	if (obj.x_mitre_deprecated || obj.revoked) return null;
	const id = getMitreId(obj);
	if (!id) return null;

	const description = truncate(obj.description ?? "", 2000);
	const platforms: string[] = obj.x_mitre_platforms ?? [];

	const parts = [
		`ATT&CK Data Source: ${id} - ${obj.name as string}`,
		platforms.length ? `Platforms: ${platforms.join(", ")}` : "",
		description ? `Description: ${description}` : "",
	].filter(Boolean);

	return {
		id: `attack::${id}`,
		filePath: `attack://data-source/${id}`,
		language: "attack",
		nodeType: "data-source",
		name: `${id}: ${obj.name as string}`,
		code: parts.join("\n\n"),
		startLine: 0,
		endLine: 0,
	};
}

function stixObjectToChunk(obj: StixObject): CodeChunk | null {
	switch (obj.type) {
		case "attack-pattern":       return parseTechnique(obj);
		case "intrusion-set":        return parseGroup(obj);
		case "tool":
		case "malware":              return parseSoftware(obj);
		case "course-of-action":     return parseMitigation(obj);
		case "x-mitre-data-source":  return parseDataSource(obj);
		default:                     return null;
	}
}

// ─── Main indexer ─────────────────────────────────────────────────────────────

export async function indexAttack(
	store: VectorStore,
	onProgress?: (p: ConnectorProgress) => void,
	signal?: AbortSignal
): Promise<ConnectorResult> {
	// 1. Check cache
	const cached = await store.loadFromCache("secask", "attack", ATTACK_CACHE_KEY);
	if (cached) {
		onProgress?.({
			phase: "cached",
			message: `Loaded ${store.size} ATT&CK objects from cache`,
			current: store.size,
			total: store.size,
		});
		return { chunkCount: store.size, fromCache: true };
	}

	store.clear();

	// 2. Fetch STIX bundle
	onProgress?.({
		phase: "fetching",
		message: "Fetching MITRE ATT&CK Enterprise STIX data (~50 MB)…",
		current: 0,
		total: 1,
	});

	const resp = await fetch(ATTACK_STIX_URL, { signal });
	if (!resp.ok) throw new Error(`ATT&CK fetch failed: ${resp.status} ${resp.statusText}`);
	const bundle = (await resp.json()) as { objects: StixObject[] };

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 3. Parse objects → CodeChunks
	onProgress?.({
		phase: "parsing",
		message: "Parsing ATT&CK objects…",
		current: 0,
		total: bundle.objects.length,
	});

	const chunks: CodeChunk[] = [];
	for (const obj of bundle.objects) {
		if (!RELEVANT_STIX_TYPES.has(obj.type)) continue;
		const chunk = stixObjectToChunk(obj);
		if (chunk) chunks.push(chunk);
	}

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 4. Embed
	onProgress?.({
		phase: "embedding",
		message: `Embedding ${chunks.length} ATT&CK objects…`,
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
				message: `Embedded ${done}/${total} ATT&CK objects`,
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

	onProgress?.({ phase: "persisting", message: "Saving ATT&CK index…", current: 0, total: 1 });
	await store.persist("secask", "attack", ATTACK_CACHE_KEY);

	onProgress?.({
		phase: "done",
		message: `Indexed ${embedded.length} ATT&CK objects`,
		current: embedded.length,
		total: embedded.length,
	});

	return { chunkCount: embedded.length, fromCache: false };
}

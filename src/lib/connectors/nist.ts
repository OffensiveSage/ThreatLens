/**
 * NIST SP 800-53 Rev 5 Connector
 *
 * Fetches the NIST 800-53 Rev 5 OSCAL catalog JSON, parses each control
 * and enhancement into CodeChunks, embeds, and stores in the VectorStore.
 *
 * Cache key: "secask" / "nist" / NIST_CACHE_KEY
 * FilePath convention: nist://control/AC-2, nist://control/AC-2(1)
 */

import type { CodeChunk } from "@/lib/chunker";
import { embedChunks, initEmbedder, getEmbedderDevice, resolveEmbedConfig } from "@/lib/embedder";
import { VectorStore } from "@/lib/vectorStore";
import type { ConnectorProgress, ConnectorResult } from "./attack";

/** Update when NIST releases a new revision to invalidate caches. */
const NIST_CACHE_KEY = "nist-800-53-rev5-v1";

const OSCAL_CATALOG_URL =
	"https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json";

// ─── OSCAL types (minimal) ────────────────────────────────────────────────────

interface OscalPart {
	id?: string;
	name: string;
	prose?: string;
	parts?: OscalPart[];
}

interface OscalLink {
	href: string;
	rel?: string;
}

interface OscalProp {
	name: string;
	value: string;
	ns?: string;
}

interface OscalControl {
	id: string;
	class?: string;
	title: string;
	props?: OscalProp[];
	links?: OscalLink[];
	parts?: OscalPart[];
	controls?: OscalControl[]; // control enhancements (sub-controls)
}

interface OscalGroup {
	id: string;
	class?: string;
	title: string;
	props?: OscalProp[];
	parts?: OscalPart[];
	controls?: OscalControl[];
	groups?: OscalGroup[];
}

interface OscalCatalog {
	catalog: {
		uuid: string;
		metadata: { title: string; version: string };
		groups: OscalGroup[];
	};
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getControlId(control: OscalControl): string {
	// OSCAL IDs are like "ac-2" → normalize to "AC-2"
	// Enhancements are like "ac-2.1" → "AC-2(1)"
	const raw = control.id.toUpperCase();
	const dotMatch = raw.match(/^([A-Z]+-\d+)\.(\d+)$/);
	if (dotMatch) return `${dotMatch[1]}(${dotMatch[2]})`;
	return raw;
}

function getPropValue(props: OscalProp[] | undefined, name: string): string {
	return props?.find((p) => p.name === name)?.value ?? "";
}

function extractProse(parts: OscalPart[] | undefined, name?: string): string {
	if (!parts) return "";
	const lines: string[] = [];
	for (const part of parts) {
		if (name && part.name !== name) continue;
		if (part.prose) lines.push(part.prose.trim());
		if (part.parts) lines.push(extractProse(part.parts));
	}
	return lines.filter(Boolean).join("\n");
}

function getRelatedControls(links: OscalLink[] | undefined): string[] {
	if (!links) return [];
	return links
		.filter((l) => l.rel === "related")
		.map((l) => l.href.replace(/^#/, "").toUpperCase())
		.filter(Boolean);
}

function getBaselines(props: OscalProp[] | undefined): string[] {
	const baselines: string[] = [];
	for (const p of props ?? []) {
		if (p.name === "impact") {
			if (p.value === "LOW") baselines.push("LOW");
			else if (p.value === "MODERATE") baselines.push("MODERATE");
			else if (p.value === "HIGH") baselines.push("HIGH");
		}
	}
	return baselines;
}

function controlToChunk(
	control: OscalControl,
	familyTitle: string,
	familyId: string
): CodeChunk {
	const controlId = getControlId(control);
	const priority = getPropValue(control.props, "priority");
	const related = getRelatedControls(control.links);
	const baselines = getBaselines(control.props);

	// Statement prose (the actual control requirement)
	const statement = extractProse(control.parts, "statement");
	// Guidance prose (supplemental guidance)
	const guidance = extractProse(control.parts, "guidance");
	// Objective prose
	const objective = extractProse(control.parts, "objective");

	const parts = [
		`NIST SP 800-53 Rev 5 Control: ${controlId} - ${control.title}`,
		`Control Family: ${familyId} - ${familyTitle}`,
		priority ? `Priority: ${priority}` : "",
		baselines.length ? `Applicable Baselines: ${baselines.join(", ")}` : "",
		statement ? `Control Statement:\n${statement}` : "",
		objective ? `Control Objective:\n${objective}` : "",
		guidance ? `Supplemental Guidance:\n${guidance.slice(0, 2000)}` : "",
		related.length ? `Related Controls: ${related.join(", ")}` : "",
	].filter(Boolean);

	return {
		id: `nist::${controlId}`,
		filePath: `nist://control/${controlId}`,
		language: "nist",
		nodeType: controlId.includes("(") ? "enhancement" : "control",
		name: `${controlId}: ${control.title}`,
		code: parts.join("\n\n").slice(0, 8000),
		startLine: 0,
		endLine: 0,
	};
}

function flattenControls(
	controls: OscalControl[] | undefined,
	familyTitle: string,
	familyId: string,
	output: CodeChunk[]
): void {
	if (!controls) return;
	for (const control of controls) {
		output.push(controlToChunk(control, familyTitle, familyId));
		// Recurse into enhancements
		flattenControls(control.controls, familyTitle, familyId, output);
	}
}

function flattenGroups(groups: OscalGroup[] | undefined, output: CodeChunk[]): void {
	if (!groups) return;
	for (const group of groups) {
		const familyId = group.id.toUpperCase();
		const familyTitle = group.title;
		flattenControls(group.controls, familyTitle, familyId, output);
		flattenGroups(group.groups, output);
	}
}

// ─── Main indexer ─────────────────────────────────────────────────────────────

export async function indexNIST(
	store: VectorStore,
	onProgress?: (p: ConnectorProgress) => void,
	signal?: AbortSignal
): Promise<ConnectorResult> {
	// 1. Check cache
	const cached = await store.loadFromCache("secask", "nist", NIST_CACHE_KEY);
	if (cached) {
		onProgress?.({
			phase: "cached",
			message: `Loaded ${store.size} NIST controls from cache`,
			current: store.size,
			total: store.size,
		});
		return { chunkCount: store.size, fromCache: true };
	}

	store.clear();

	// 2. Fetch OSCAL catalog
	onProgress?.({
		phase: "fetching",
		message: "Fetching NIST SP 800-53 Rev 5 OSCAL catalog…",
		current: 0,
		total: 1,
	});

	const resp = await fetch(OSCAL_CATALOG_URL, { signal });
	if (!resp.ok) throw new Error(`NIST catalog fetch failed: ${resp.status} ${resp.statusText}`);
	const catalog = (await resp.json()) as OscalCatalog;

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 3. Parse controls → CodeChunks
	onProgress?.({
		phase: "parsing",
		message: "Parsing NIST controls…",
		current: 0,
		total: 1,
	});

	const chunks: CodeChunk[] = [];
	flattenGroups(catalog.catalog.groups, chunks);

	onProgress?.({
		phase: "parsing",
		message: `Parsed ${chunks.length} controls and enhancements`,
		current: chunks.length,
		total: chunks.length,
	});

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 4. Embed
	onProgress?.({
		phase: "embedding",
		message: `Embedding ${chunks.length} NIST controls…`,
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
				message: `Embedded ${done}/${total} NIST controls`,
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

	onProgress?.({ phase: "persisting", message: "Saving NIST index…", current: 0, total: 1 });
	await store.persist("secask", "nist", NIST_CACHE_KEY);

	onProgress?.({
		phase: "done",
		message: `Indexed ${embedded.length} NIST SP 800-53 controls`,
		current: embedded.length,
		total: embedded.length,
	});

	return { chunkCount: embedded.length, fromCache: false };
}

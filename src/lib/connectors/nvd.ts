/**
 * NVD / CVE Connector
 *
 * Fetches CVE records from the NVD REST API v2.0, parses CVSS scores,
 * affected products, and descriptions into CodeChunks, then embeds
 * and stores in the VectorStore.
 *
 * Cache key: "secask" / "nvd" / options-fingerprint
 * FilePath convention: nvd://cve/CVE-2024-XXXXX
 *
 * Rate limits:
 *   - Without API key: 5 requests / 30 seconds
 *   - With API key:    50 requests / 30 seconds
 */

import type { CodeChunk } from "@/lib/chunker";
import { embedChunks, initEmbedder, getEmbedderDevice, resolveEmbedConfig } from "@/lib/embedder";
import { VectorStore } from "@/lib/vectorStore";
import type { ConnectorProgress, ConnectorResult } from "./attack";

export interface NVDOptions {
	/** ISO 8601 start date, e.g. "2024-01-01T00:00:00.000". Defaults to 90 days ago. */
	pubStartDate?: string;
	/** ISO 8601 end date. Defaults to now. */
	pubEndDate?: string;
	/** Keyword to filter CVEs. */
	keyword?: string;
	/** CVSS v3 severity filter. Defaults to ["CRITICAL", "HIGH"]. */
	severity?: ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW")[];
	/** Maximum CVEs to index. Defaults to 2000. */
	maxCVEs?: number;
	/** NVD API key (increases rate limit 10×). */
	apiKey?: string;
}

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_PAGE_SIZE = 2000; // max results per request

// ─── NVD API types ────────────────────────────────────────────────────────────

interface NVDResponse {
	totalResults: number;
	resultsPerPage: number;
	startIndex: number;
	vulnerabilities: Array<{ cve: NVDCveItem }>;
}

interface NVDCveItem {
	id: string;
	published: string;
	lastModified: string;
	vulnStatus: string;
	descriptions: Array<{ lang: string; value: string }>;
	metrics?: {
		cvssMetricV31?: Array<{
			cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
			exploitabilityScore?: number;
			impactScore?: number;
		}>;
		cvssMetricV30?: Array<{
			cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
		}>;
		cvssMetricV2?: Array<{
			cvssData: { baseScore: number; vectorString: string };
			baseSeverity?: string;
		}>;
	};
	weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
	configurations?: Array<{
		nodes: Array<{
			cpeMatch: Array<{ criteria: string; vulnerable: boolean }>;
		}>;
	}>;
	references?: Array<{ url: string; source: string; tags?: string[] }>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getEnglishDesc(cve: NVDCveItem): string {
	return cve.descriptions.find((d) => d.lang === "en")?.value ?? "";
}

function getCvss(cve: NVDCveItem): {
	score: number | null;
	severity: string;
	vector: string;
	version: string;
} {
	const v31 = cve.metrics?.cvssMetricV31?.[0];
	if (v31) {
		return {
			score: v31.cvssData.baseScore,
			severity: v31.cvssData.baseSeverity,
			vector: v31.cvssData.vectorString,
			version: "3.1",
		};
	}
	const v30 = cve.metrics?.cvssMetricV30?.[0];
	if (v30) {
		return {
			score: v30.cvssData.baseScore,
			severity: v30.cvssData.baseSeverity,
			vector: v30.cvssData.vectorString,
			version: "3.0",
		};
	}
	const v2 = cve.metrics?.cvssMetricV2?.[0];
	if (v2) {
		return {
			score: v2.cvssData.baseScore,
			severity: v2.baseSeverity ?? "UNKNOWN",
			vector: v2.cvssData.vectorString,
			version: "2.0",
		};
	}
	return { score: null, severity: "UNKNOWN", vector: "", version: "" };
}

function extractCPEs(cve: NVDCveItem): string[] {
	const cpes: string[] = [];
	for (const config of cve.configurations ?? []) {
		for (const node of config.nodes) {
			for (const match of node.cpeMatch) {
				if (match.vulnerable) {
					// Extract product name from CPE: cpe:2.3:a:vendor:product:...
					const parts = match.criteria.split(":");
					if (parts.length >= 5) {
						cpes.push(`${parts[3]}:${parts[4]}`);
					}
				}
			}
		}
	}
	// Deduplicate
	return [...new Set(cpes)].slice(0, 10);
}

function extractCWEs(cve: NVDCveItem): string[] {
	const cwes: string[] = [];
	for (const weakness of cve.weaknesses ?? []) {
		for (const desc of weakness.description) {
			if (desc.lang === "en" && desc.value.startsWith("CWE-")) {
				cwes.push(desc.value);
			}
		}
	}
	return [...new Set(cwes)];
}

function cveToChunk(cve: NVDCveItem): CodeChunk {
	const desc = getEnglishDesc(cve);
	const cvss = getCvss(cve);
	const cpes = extractCPEs(cve);
	const cwes = extractCWEs(cve);
	const pubDate = cve.published.split("T")[0];

	const parts = [
		`CVE: ${cve.id}`,
		cvss.score !== null
			? `CVSS ${cvss.version}: ${cvss.score} (${cvss.severity})`
			: "CVSS: Not Available",
		cvss.vector ? `CVSS Vector: ${cvss.vector}` : "",
		`Published: ${pubDate}`,
		`Status: ${cve.vulnStatus}`,
		cwes.length ? `Weaknesses: ${cwes.join(", ")}` : "",
		cpes.length ? `Affected Products: ${cpes.join(", ")}` : "",
		desc ? `Description: ${desc}` : "",
	].filter(Boolean);

	return {
		id: `nvd::${cve.id}`,
		filePath: `nvd://cve/${cve.id}`,
		language: "nvd",
		nodeType: "cve",
		name: cve.id,
		code: parts.join("\n\n").slice(0, 6000),
		startLine: 0,
		endLine: 0,
	};
}

// ─── Rate-limited fetch ───────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchNVDPage(
	params: URLSearchParams,
	apiKey: string | undefined,
	signal?: AbortSignal
): Promise<NVDResponse> {
	const url = `${NVD_API_BASE}?${params.toString()}`;
	const headers: Record<string, string> = {};
	if (apiKey) headers["apiKey"] = apiKey;

	const resp = await fetch(url, { headers, signal });
	if (resp.status === 429) {
		// Rate limited — wait 35 seconds then retry once
		await sleep(35_000);
		const retry = await fetch(url, { headers, signal });
		if (!retry.ok) throw new Error(`NVD API rate limit error: ${retry.status}`);
		return retry.json() as Promise<NVDResponse>;
	}
	if (!resp.ok) throw new Error(`NVD API error: ${resp.status} ${resp.statusText}`);
	return resp.json() as Promise<NVDResponse>;
}

// ─── Cache key fingerprint ────────────────────────────────────────────────────

function makeNVDCacheKey(options: NVDOptions): string {
	const parts = [
		options.pubStartDate?.slice(0, 10) ?? "",
		options.pubEndDate?.slice(0, 10) ?? "",
		options.keyword ?? "",
		(options.severity ?? []).sort().join(","),
		String(options.maxCVEs ?? 2000),
	];
	return `nvd-${parts.join("|").replace(/[^a-zA-Z0-9|-]/g, "")}`;
}

function defaultStartDate(): string {
	const d = new Date();
	d.setDate(d.getDate() - 90);
	return d.toISOString().slice(0, 19) + ".000";
}

// ─── Main indexer ─────────────────────────────────────────────────────────────

export async function indexNVD(
	store: VectorStore,
	options: NVDOptions = {},
	onProgress?: (p: ConnectorProgress) => void,
	signal?: AbortSignal
): Promise<ConnectorResult> {
	const maxCVEs = options.maxCVEs ?? 2000;
	const severities = options.severity ?? ["CRITICAL", "HIGH"];
	const pubStartDate = options.pubStartDate ?? defaultStartDate();
	const pubEndDate = options.pubEndDate ?? new Date().toISOString().slice(0, 19) + ".000";
	const cacheKey = makeNVDCacheKey({ ...options, pubStartDate, pubEndDate });

	// 1. Check cache
	const cached = await store.loadFromCache("secask", "nvd", cacheKey);
	if (cached) {
		onProgress?.({
			phase: "cached",
			message: `Loaded ${store.size} CVEs from cache`,
			current: store.size,
			total: store.size,
		});
		return { chunkCount: store.size, fromCache: true };
	}

	store.clear();

	// 2. Build base query params
	const baseParams: Record<string, string> = {
		pubStartDate,
		pubEndDate,
		resultsPerPage: String(Math.min(NVD_PAGE_SIZE, maxCVEs)),
	};
	if (options.keyword) baseParams.keywordSearch = options.keyword;

	// 3. Fetch pages (one per severity unless filtering by all)
	const allChunks: CodeChunk[] = [];
	const rateLimitDelay = options.apiKey ? 1000 : 6500; // ms between requests

	for (const severity of severities) {
		if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
		if (allChunks.length >= maxCVEs) break;

		const params = new URLSearchParams({ ...baseParams, cvssV3Severity: severity });
		let startIndex = 0;
		let totalForSeverity = 0;

		do {
			if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

			params.set("startIndex", String(startIndex));
			onProgress?.({
				phase: "fetching",
				message: `Fetching ${severity} CVEs (${allChunks.length} so far)…`,
				current: allChunks.length,
				total: maxCVEs,
			});

			const page = await fetchNVDPage(params, options.apiKey, signal);
			totalForSeverity = page.totalResults;

			for (const { cve } of page.vulnerabilities) {
				if (allChunks.length >= maxCVEs) break;
				allChunks.push(cveToChunk(cve));
			}

			startIndex += page.resultsPerPage;

			// Rate limit delay between pages
			if (startIndex < totalForSeverity && allChunks.length < maxCVEs) {
				await sleep(rateLimitDelay);
			}
		} while (startIndex < totalForSeverity && allChunks.length < maxCVEs);
	}

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 4. Embed
	onProgress?.({
		phase: "embedding",
		message: `Embedding ${allChunks.length} CVEs…`,
		current: 0,
		total: allChunks.length,
	});

	await initEmbedder((msg) =>
		onProgress?.({ phase: "embedding", message: msg, current: 0, total: allChunks.length })
	);
	const embedConfig = resolveEmbedConfig(getEmbedderDevice() ?? "wasm");

	const embedded = await embedChunks(
		allChunks,
		(done, total) =>
			onProgress?.({
				phase: "embedding",
				message: `Embedded ${done}/${total} CVEs`,
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

	onProgress?.({ phase: "persisting", message: "Saving NVD index…", current: 0, total: 1 });
	await store.persist("secask", "nvd", cacheKey);

	onProgress?.({
		phase: "done",
		message: `Indexed ${embedded.length} CVEs`,
		current: embedded.length,
		total: embedded.length,
	});

	return { chunkCount: embedded.length, fromCache: false };
}

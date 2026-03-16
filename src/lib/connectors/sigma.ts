/**
 * Sigma Rules Connector
 *
 * Fetches the SigmaHQ rule repository via GitHub API (tree + raw content),
 * parses each YAML rule file with a lightweight extractor, creates CodeChunks,
 * embeds, and stores in the VectorStore.
 *
 * Cache key: "secask" / "sigma" / latest commit SHA
 * FilePath convention: sigma://rule/{rule-id}
 */

import type { CodeChunk } from "@/lib/chunker";
import { embedChunks, initEmbedder, getEmbedderDevice, resolveEmbedConfig } from "@/lib/embedder";
import { VectorStore } from "@/lib/vectorStore";
import type { ConnectorProgress, ConnectorResult } from "./attack";

export interface SigmaOptions {
	/** Max number of rules to index. Defaults to 2000. */
	maxRules?: number;
	/** Only index rules with these status values. Defaults to ["stable", "test"]. */
	statusFilter?: ("stable" | "test" | "experimental")[];
	/** GitHub personal access token (optional, increases rate limit). */
	githubToken?: string;
}

const SIGMAHQ_OWNER = "SigmaHQ";
const SIGMAHQ_REPO = "sigma";
const SIGMA_CACHE_PREFIX = "sigma-";

// ─── Lightweight YAML field extractor ─────────────────────────────────────────

/**
 * Extract a single scalar value from a YAML file.
 * Handles: `key: value` and `key: |` (block scalar prefix only).
 */
function yamlScalar(content: string, key: string): string {
	const re = new RegExp(`^${key}:\\s*(.+)$`, "m");
	const m = content.match(re);
	if (!m) return "";
	const val = m[1].trim();
	// Remove surrounding quotes
	if ((val.startsWith('"') && val.endsWith('"')) ||
		(val.startsWith("'") && val.endsWith("'"))) {
		return val.slice(1, -1);
	}
	return val;
}

/**
 * Extract an array value from a YAML file.
 * Handles sequences like:
 *   key:
 *     - item1
 *     - item2
 */
function yamlArray(content: string, key: string): string[] {
	const keyRe = new RegExp(`^(${key}):[ \\t]*$`, "m");
	const m = content.match(keyRe);
	if (!m || m.index === undefined) return [];

	const after = content.slice(m.index + m[0].length);
	const lines = after.split("\n");
	const items: string[] = [];

	for (const line of lines) {
		const itemMatch = line.match(/^[ \t]+-[ \t]+(.+)$/);
		if (itemMatch) {
			items.push(itemMatch[1].trim().replace(/^['"]|['"]$/g, ""));
		} else if (line.match(/^\S/) && !line.match(/^[ \t]/)) {
			// Back at root indent → stop
			break;
		} else if (line.trim() !== "" && !line.match(/^[ \t]+-/)) {
			// Non-list line at indent → stop
			break;
		}
	}
	return items;
}

/**
 * Extract a block scalar value (key: | or key: >).
 */
function yamlBlockScalar(content: string, key: string): string {
	const re = new RegExp(`^${key}:\\s*[|>]\\s*$`, "m");
	const m = content.match(re);
	if (!m || m.index === undefined) return "";

	const after = content.slice(m.index + m[0].length + 1);
	const lines = after.split("\n");
	const blockLines: string[] = [];

	for (const line of lines) {
		if (line === "" || line.match(/^[ \t]/)) {
			blockLines.push(line.replace(/^  /, "").replace(/^    /, ""));
		} else {
			break;
		}
	}
	return blockLines.join("\n").trim();
}

/** Extract ATT&CK technique IDs from Sigma tags (e.g. attack.t1059.001 → T1059.001) */
function extractAttackTags(tags: string[]): string[] {
	return tags
		.filter((t) => t.toLowerCase().startsWith("attack.t"))
		.map((t) => {
			const parts = t.replace(/^attack\./, "").toUpperCase().split(".");
			// T1059 or T1059.001
			if (parts.length === 1) return parts[0];
			return `${parts[0]}.${parts[1]}`;
		})
		.filter(Boolean);
}

interface SigmaRule {
	id: string;
	title: string;
	status: string;
	description: string;
	author: string;
	date: string;
	level: string;
	product: string;
	service: string;
	attackTags: string[];
	tactics: string[];
	rawDetection: string;
	references: string[];
	falsepositives: string[];
}

function parseSigmaYaml(content: string): SigmaRule {
	const title = yamlScalar(content, "title");
	const id = yamlScalar(content, "id");
	const status = yamlScalar(content, "status");
	const author = yamlScalar(content, "author");
	const date = yamlScalar(content, "date");
	const level = yamlScalar(content, "level");
	const tags = yamlArray(content, "tags");
	const references = yamlArray(content, "references");
	const falsepositives = yamlArray(content, "falsepositives");

	// Description: may be scalar or block scalar
	const description = yamlBlockScalar(content, "description") || yamlScalar(content, "description");

	// logsource.product / .service (nested)
	const logsourceMatch = content.match(/^logsource:[ \t]*$([\s\S]*?)^(?=\S)/m);
	let product = "";
	let service = "";
	if (logsourceMatch) {
		const ls = logsourceMatch[1];
		product = ls.match(/product:\s*(.+)/)?.[1]?.trim() ?? "";
		service = ls.match(/service:\s*(.+)/)?.[1]?.trim() ?? "";
	}

	// Extract raw detection block
	const detectionMatch = content.match(/^detection:[ \t]*$([\s\S]*?)^(?=\S)/m);
	const rawDetection = detectionMatch ? detectionMatch[1].trimEnd() : "";

	const attackTags = extractAttackTags(tags);
	const tactics = tags
		.filter((t) => t.toLowerCase().startsWith("attack.") && !t.toLowerCase().startsWith("attack.t"))
		.map((t) => t.replace(/^attack\./, "").replace(/_/g, " "));

	return {
		id: id || `unknown-${Math.random().toString(36).slice(2)}`,
		title: title || "Unknown Rule",
		status: status || "unknown",
		description,
		author,
		date,
		level: level || "medium",
		product,
		service,
		attackTags,
		tactics,
		rawDetection,
		references,
		falsepositives,
	};
}

function sigmaRuleToChunk(rule: SigmaRule, filePath: string): CodeChunk {
	const parts = [
		`Sigma Detection Rule: ${rule.title}`,
		`Rule ID: ${rule.id}`,
		`Severity: ${rule.level}`,
		`Status: ${rule.status}`,
		rule.product ? `Log Source Product: ${rule.product}` : "",
		rule.service ? `Log Source Service: ${rule.service}` : "",
		rule.attackTags.length ? `ATT&CK Techniques: ${rule.attackTags.join(", ")}` : "",
		rule.tactics.length ? `ATT&CK Tactics: ${rule.tactics.join(", ")}` : "",
		rule.description ? `Description: ${rule.description}` : "",
		rule.rawDetection ? `Detection Logic:\n${rule.rawDetection}` : "",
		rule.falsepositives.length ? `False Positives: ${rule.falsepositives.join(", ")}` : "",
		rule.author ? `Author: ${rule.author}` : "",
	].filter(Boolean);

	return {
		id: `sigma::${rule.id}`,
		filePath: `sigma://rule/${rule.id}`,
		language: "sigma",
		nodeType: "rule",
		name: rule.title,
		code: parts.join("\n\n").slice(0, 8000), // cap at 8KB
		startLine: 0,
		endLine: 0,
	};
}

// ─── GitHub API helpers ───────────────────────────────────────────────────────

async function fetchGitHubTree(
	owner: string,
	repo: string,
	token?: string
): Promise<{ sha: string; tree: Array<{ path: string; type: string }> }> {
	// First get the default branch HEAD commit SHA
	const branchUrl = `https://api.github.com/repos/${owner}/${repo}/branches/main`;
	const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
	if (token) headers["Authorization"] = `token ${token}`;

	const branchResp = await fetch(branchUrl, { headers });
	if (!branchResp.ok) throw new Error(`GitHub API error: ${branchResp.status}`);
	const branchData = await branchResp.json() as { commit: { sha: string } };
	const sha = branchData.commit.sha;

	// Fetch recursive tree
	const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${sha}?recursive=1`;
	const treeResp = await fetch(treeUrl, { headers });
	if (!treeResp.ok) throw new Error(`GitHub tree API error: ${treeResp.status}`);
	const treeData = await treeResp.json() as { tree: Array<{ path: string; type: string }> };

	return { sha, tree: treeData.tree };
}

async function fetchRawContent(
	owner: string,
	repo: string,
	path: string,
	sha: string
): Promise<string> {
	const url = `https://raw.githubusercontent.com/${owner}/${repo}/${sha}/${path}`;
	const resp = await fetch(url);
	if (!resp.ok) throw new Error(`Failed to fetch ${path}: ${resp.status}`);
	return resp.text();
}

// ─── Main indexer ─────────────────────────────────────────────────────────────

export async function indexSigma(
	store: VectorStore,
	options: SigmaOptions = {},
	onProgress?: (p: ConnectorProgress) => void,
	signal?: AbortSignal
): Promise<ConnectorResult> {
	const maxRules = options.maxRules ?? 2000;
	const statusFilter = new Set(options.statusFilter ?? ["stable", "test"]);
	const token = options.githubToken;

	// 1. Fetch GitHub tree to get current SHA
	onProgress?.({
		phase: "fetching",
		message: "Fetching SigmaHQ repository tree…",
		current: 0,
		total: 1,
	});

	const { sha, tree } = await fetchGitHubTree(SIGMAHQ_OWNER, SIGMAHQ_REPO, token);
	const cacheKey = SIGMA_CACHE_PREFIX + sha.slice(0, 12);

	// 2. Check cache
	const cached = await store.loadFromCache("secask", "sigma", cacheKey);
	if (cached) {
		onProgress?.({
			phase: "cached",
			message: `Loaded ${store.size} Sigma rules from cache`,
			current: store.size,
			total: store.size,
		});
		return { chunkCount: store.size, fromCache: true };
	}

	store.clear();

	// 3. Filter rule files from tree
	const ruleFiles = tree
		.filter(
			(item) =>
				item.type === "blob" &&
				item.path.startsWith("rules/") &&
				item.path.endsWith(".yml") &&
				// Skip deprecated/ and sigma_detection_templates/
				!item.path.includes("/deprecated/") &&
				!item.path.includes("sigma_detection_templates")
		)
		.slice(0, maxRules * 2); // over-fetch since some will be filtered by status

	onProgress?.({
		phase: "fetching",
		message: `Found ${ruleFiles.length} Sigma rule files. Fetching content…`,
		current: 0,
		total: ruleFiles.length,
	});

	// 4. Batch-fetch rule content in parallel batches of 20
	const BATCH_SIZE = 20;
	const chunks: CodeChunk[] = [];
	let fetched = 0;

	for (let i = 0; i < ruleFiles.length && chunks.length < maxRules; i += BATCH_SIZE) {
		if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

		const batch = ruleFiles.slice(i, i + BATCH_SIZE);
		const results = await Promise.allSettled(
			batch.map((f) => fetchRawContent(SIGMAHQ_OWNER, SIGMAHQ_REPO, f.path, sha))
		);

		for (let j = 0; j < results.length; j++) {
			const r = results[j];
			if (r.status === "rejected") continue;

			const content = r.value;
			const rule = parseSigmaYaml(content);

			// Apply status filter
			if (!statusFilter.has(rule.status as "stable" | "test" | "experimental")) continue;

			const filePath = ruleFiles[i + j]?.path ?? "";
			chunks.push(sigmaRuleToChunk(rule, filePath));

			if (chunks.length >= maxRules) break;
		}

		fetched = Math.min(i + BATCH_SIZE, ruleFiles.length);
		onProgress?.({
			phase: "fetching",
			message: `Fetched ${fetched}/${ruleFiles.length} files, parsed ${chunks.length} rules…`,
			current: fetched,
			total: ruleFiles.length,
		});
	}

	if (signal?.aborted) throw new DOMException("Aborted", "AbortError");

	// 5. Embed
	onProgress?.({
		phase: "embedding",
		message: `Embedding ${chunks.length} Sigma rules…`,
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
				message: `Embedded ${done}/${total} Sigma rules`,
				current: done,
				total,
			}),
		embedConfig.batchSize,
		signal,
		undefined,
		embedConfig.workerCount
	);

	// 6. Store & persist
	store.insert(embedded);

	onProgress?.({ phase: "persisting", message: "Saving Sigma index…", current: 0, total: 1 });
	await store.persist("secask", "sigma", cacheKey);

	onProgress?.({
		phase: "done",
		message: `Indexed ${embedded.length} Sigma detection rules`,
		current: embedded.length,
		total: embedded.length,
	});

	return { chunkCount: embedded.length, fromCache: false };
}

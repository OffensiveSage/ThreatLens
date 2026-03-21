import {
	buildInventory,
	type AgenticFinding,
	type FileEntry,
	type InventorySummary,
} from "./agenticScan";
import type { EmbeddedChunk } from "./embedder";
import type { SearchResult, VectorStore } from "./vectorStore";

type InventoryBucket =
	| "authFiles"
	| "apiFiles"
	| "configFiles"
	| "packageFiles"
	| "entryPoints";

type SecurityTopic =
	| "auth"
	| "injection"
	| "secrets"
	| "dependencies"
	| "attack-surface"
	| "general";

export interface SecurityChatIntent {
	topics: SecurityTopic[];
	inventoryBuckets: InventoryBucket[];
	filenameTerms: string[];
	contentTerms: string[];
	findingTerms: string[];
	topChunkLimit: number;
	topFiles: number;
}

export interface RankedSecurityFile {
	filePath: string;
	score: number;
	reasons: string[];
}

const SECURITY_QUERY_PATTERN =
	/\b(auth|authentication|authorization|login|signin|session|token|jwt|oauth|password|credential|permission|secret|api key|private key|hardcoded|injection|sqli|sql injection|xss|csrf|idor|rce|deserializ|ssrf|security|vulnerab|exploit|attack surface|dependency|dependencies|package audit|supply chain)\b/i;

const TOP_K_SECURITY_CHUNKS = 20;
const TOP_SECURITY_FILES = 5;

const TOPIC_DEFINITIONS: Array<{
	topic: SecurityTopic;
	pattern: RegExp;
	inventoryBuckets: InventoryBucket[];
	filenameTerms: string[];
	contentTerms: string[];
	findingTerms: string[];
}> = [
	{
		topic: "auth",
		pattern: /\b(auth|authentication|authorization|login|signin|session|token|jwt|oauth|password|credential|permission|rbac|mfa)\b/i,
		inventoryBuckets: ["authFiles", "apiFiles"],
		filenameTerms: ["auth", "login", "session", "token", "oauth", "jwt", "password", "credential", "permission"],
		contentTerms: ["authenticate", "authorization", "login", "session", "token", "jwt", "oauth", "password", "permission"],
		findingTerms: ["auth", "authentication", "authorization", "access control", "credential"],
	},
	{
		topic: "injection",
		pattern: /\b(injection|sqli|sql injection|nosql|xss|command injection|template injection|ldap injection|deserializ|ssrf|rce)\b/i,
		inventoryBuckets: ["apiFiles", "entryPoints"],
		filenameTerms: ["db", "database", "query", "sql", "repo", "repository", "dao", "model", "api", "route"],
		contentTerms: ["select ", "insert ", "update ", "delete ", "query", "execute", "cursor", "rawsql", "statement", "find(", "where("],
		findingTerms: ["injection", "sql", "xss", "command", "deserial", "ssrf", "rce"],
	},
	{
		topic: "secrets",
		pattern: /\b(secret|api key|apikey|private key|hardcoded|credential|password|dotenv|env file|token leak|secrets?)\b/i,
		inventoryBuckets: ["configFiles", "authFiles"],
		filenameTerms: [".env", "config", "secret", "credential", "token", "key", "settings"],
		contentTerms: ["api_key", "apikey", "secret", "private_key", "access_key", "token", "password", "credential"],
		findingTerms: ["secret", "credential", "password", "token", "key"],
	},
	{
		topic: "dependencies",
		pattern: /\b(dependenc|package|library|module|supply chain|npm|pip|cargo|gem|composer)\b/i,
		inventoryBuckets: ["packageFiles"],
		filenameTerms: ["package.json", "requirements.txt", "go.mod", "cargo.toml", "gemfile", "pom.xml", "build.gradle", "composer.json"],
		contentTerms: ["dependencies", "devdependencies", "require", "version", "package"],
		findingTerms: ["dependency", "package", "library", "supply chain"],
	},
	{
		topic: "attack-surface",
		pattern: /\b(attack surface|entry point|route|endpoint|controller|handler|api|exposed|public)\b/i,
		inventoryBuckets: ["apiFiles", "entryPoints"],
		filenameTerms: ["route", "api", "endpoint", "controller", "handler", "view", "main", "server", "app"],
		contentTerms: ["router", "app.", "listen(", "@app.", "@router.", "http", "endpoint", "handler"],
		findingTerms: ["attack surface", "entry point", "endpoint", "api"],
	},
];

function pushUnique(target: string[], values: string[]): void {
	for (const value of values) {
		if (!target.includes(value)) target.push(value);
	}
}

function uniqueBuckets(values: InventoryBucket[]): InventoryBucket[] {
	return [...new Set(values)];
}

function normalizeText(text: string): string {
	return text.toLowerCase();
}

function countIncludes(text: string, terms: string[], maxMatches: number): number {
	let matches = 0;
	for (const term of terms) {
		if (text.includes(term.toLowerCase())) matches++;
		if (matches >= maxMatches) break;
	}
	return matches;
}

function findingMatchesIntent(finding: AgenticFinding, intent: SecurityChatIntent, query: string): boolean {
	const haystack = normalizeText(
		[
			finding.name,
			finding.category,
			finding.cwe,
			finding.explanation,
			finding.context,
			finding.remediation,
		]
			.filter(Boolean)
			.join(" ")
	);
	const queryLower = normalizeText(query);
	if (intent.findingTerms.some((term) => haystack.includes(term))) return true;
	return haystack.includes(queryLower);
}

export function isCodeSecurityChatQuery(query: string): boolean {
	return SECURITY_QUERY_PATTERN.test(query);
}

export function buildSecurityChatIntent(query: string): SecurityChatIntent {
	const inventoryBuckets: InventoryBucket[] = [];
	const filenameTerms: string[] = [];
	const contentTerms: string[] = [];
	const findingTerms: string[] = [];
	const topics: SecurityTopic[] = [];

	for (const definition of TOPIC_DEFINITIONS) {
		if (!definition.pattern.test(query)) continue;
		topics.push(definition.topic);
		inventoryBuckets.push(...definition.inventoryBuckets);
		pushUnique(filenameTerms, definition.filenameTerms);
		pushUnique(contentTerms, definition.contentTerms);
		pushUnique(findingTerms, definition.findingTerms);
	}

	if (topics.length === 0) {
		topics.push("general");
		inventoryBuckets.push("authFiles", "apiFiles", "configFiles", "packageFiles", "entryPoints");
		pushUnique(filenameTerms, ["auth", "api", "config", "secret", "db", "query", "token"]);
		pushUnique(contentTerms, ["auth", "token", "query", "secret", "password", "route", "execute"]);
		pushUnique(findingTerms, ["security", "vulnerability", "auth", "injection", "secret", "dependency"]);
	}

	return {
		topics,
		inventoryBuckets: uniqueBuckets(inventoryBuckets),
		filenameTerms,
		contentTerms,
		findingTerms,
		topChunkLimit: TOP_K_SECURITY_CHUNKS,
		topFiles: TOP_SECURITY_FILES,
	};
}

export function rankFilesForSecurityChat(args: {
	query: string;
	inventory: InventorySummary;
	fileMap: Map<string, FileEntry>;
	seedResults: SearchResult[];
	intent?: SecurityChatIntent;
	scanFindings?: AgenticFinding[];
}): RankedSecurityFile[] {
	const {
		query,
		inventory,
		fileMap,
		seedResults,
		intent = buildSecurityChatIntent(query),
		scanFindings = [],
	} = args;
	const queryLower = normalizeText(query);
	const bucketSets = new Map<InventoryBucket, Set<string>>([
		["authFiles", new Set(inventory.authFiles)],
		["apiFiles", new Set(inventory.apiFiles)],
		["configFiles", new Set(inventory.configFiles)],
		["packageFiles", new Set(inventory.packageFiles)],
		["entryPoints", new Set(inventory.entryPoints)],
	]);

	const seedByFile = new Map<string, { max: number; sum: number; count: number }>();
	for (const result of seedResults) {
		const current = seedByFile.get(result.chunk.filePath) ?? { max: 0, sum: 0, count: 0 };
		current.max = Math.max(current.max, result.score);
		current.sum += result.score;
		current.count += 1;
		seedByFile.set(result.chunk.filePath, current);
	}

	const findingsByFile = new Map<string, AgenticFinding[]>();
	for (const finding of scanFindings) {
		const list = findingsByFile.get(finding.file) ?? [];
		list.push(finding);
		findingsByFile.set(finding.file, list);
	}

	const ranked: RankedSecurityFile[] = [];

	for (const [filePath, file] of fileMap.entries()) {
		let score = 0;
		const reasons: string[] = [];
		const filePathLower = normalizeText(filePath);
		const fileContentLower = normalizeText(file.content);

		const basename = filePathLower.split("/").pop() ?? filePathLower;
		if (queryLower.includes(filePathLower) || queryLower.includes(basename)) {
			score += 8;
			reasons.push("query-path-match");
		}

		for (const bucket of intent.inventoryBuckets) {
			if (bucketSets.get(bucket)?.has(filePath)) {
				score += 3;
				reasons.push(`inventory:${bucket}`);
			}
		}

		const filenameMatches = countIncludes(filePathLower, intent.filenameTerms, 3);
		if (filenameMatches > 0) {
			score += filenameMatches * 2.25;
			reasons.push("filename-signal");
		}

		const contentMatches = countIncludes(fileContentLower, intent.contentTerms, 5);
		if (contentMatches > 0) {
			score += Math.min(2.5, contentMatches * 0.45);
			reasons.push("content-signal");
		}

		const seed = seedByFile.get(filePath);
		if (seed) {
			score += seed.max * 8 + Math.min(2, seed.sum);
			reasons.push("retrieval-signal");
		}

		const fileFindings = findingsByFile.get(filePath) ?? [];
		const relevantFindings = fileFindings.filter((finding) =>
			findingMatchesIntent(finding, intent, query)
		);
		if (relevantFindings.length > 0) {
			score += Math.min(6, relevantFindings.length * 2.5);
			reasons.push("agentic-finding");
		}

		if (score > 0) {
			ranked.push({
				filePath,
				score: Number(score.toFixed(4)),
				reasons,
			});
		}
	}

	ranked.sort((a, b) => {
		if (b.score !== a.score) return b.score - a.score;
		return a.filePath.localeCompare(b.filePath);
	});

	if (ranked.length > 0) return ranked;

	const fallbackFiles = [...new Set(seedResults.map((result) => result.chunk.filePath))];
	return fallbackFiles.map((filePath, index) => ({
		filePath,
		score: fallbackFiles.length - index,
		reasons: ["seed-fallback"],
	}));
}

export function buildFileGroupedSecurityResults(
	store: VectorStore,
	rankedFiles: RankedSecurityFile[],
	seedResults: SearchResult[],
	topFiles: number
): SearchResult[] {
	const selectedFiles = rankedFiles.slice(0, topFiles);
	const seedChunkScores = new Map(seedResults.map((result) => [result.chunk.id, result.score]));
	const expanded: SearchResult[] = [];

	for (const rankedFile of selectedFiles) {
		const fileChunks = [...store.getChunksByFile(rankedFile.filePath)].sort((a, b) => {
			if (a.startLine !== b.startLine) return a.startLine - b.startLine;
			if (a.endLine !== b.endLine) return a.endLine - b.endLine;
			return a.id.localeCompare(b.id);
		});
		for (const chunk of fileChunks) {
			expanded.push({
				chunk,
				score: rankedFile.score + (seedChunkScores.get(chunk.id) ?? 0),
				embedding: chunk.embedding,
			});
		}
	}

	return expanded;
}

export function selectRelevantScanFindings(args: {
	query: string;
	findings: AgenticFinding[];
	intent?: SecurityChatIntent;
	preferredFiles?: string[];
	limit?: number;
}): AgenticFinding[] {
	const {
		query,
		findings,
		intent = buildSecurityChatIntent(query),
		preferredFiles = [],
		limit = 8,
	} = args;
	const preferredFileSet = new Set(preferredFiles);
	const scored = findings
		.map((finding) => {
			let score = 0;
			if (preferredFileSet.has(finding.file)) score += 6;
			if (findingMatchesIntent(finding, intent, query)) score += 4;
			const findingName = normalizeText(finding.name);
			const queryLower = normalizeText(query);
			if (findingName.includes(queryLower) || queryLower.includes(findingName)) score += 3;
			return { finding, score };
		})
		.filter((entry) => entry.score > 0);

	scored.sort((a, b) => {
		if (b.score !== a.score) return b.score - a.score;
		if (a.finding.file !== b.finding.file) return a.finding.file.localeCompare(b.finding.file);
		return (a.finding.line ?? 0) - (b.finding.line ?? 0);
	});

	return scored.slice(0, limit).map((entry) => entry.finding);
}

function compactText(value: string | undefined, maxLength: number): string {
	if (!value) return "";
	if (value.length <= maxLength) return value;
	return `${value.slice(0, maxLength - 3)}...`;
}

export function formatScanFindingsForPrompt(findings: AgenticFinding[]): string {
	if (findings.length === 0) return "";

	return [
		"Existing agentic scan findings for this repo:",
		...findings.map((finding) => [
			`- ${finding.severity} | ${finding.name} | file: ${finding.file}${finding.line ? `:${finding.line}` : ""}`,
			finding.category ? `category: ${finding.category}` : "",
			finding.cwe ? `cwe: ${finding.cwe}` : "",
			finding.explanation ? `explanation: ${compactText(finding.explanation, 220)}` : "",
		].filter(Boolean).join(" | ")),
	].join("\n");
}

export function buildSecurityChatContextPlan(args: {
	store: VectorStore;
	query: string;
	seedResults: SearchResult[];
	scanFindings?: AgenticFinding[];
}): {
	intent: SecurityChatIntent;
	rankedFiles: RankedSecurityFile[];
	fileGroupedResults: SearchResult[];
	relevantScanFindings: AgenticFinding[];
	scanFindingsContext: string;
} {
	const intent = buildSecurityChatIntent(args.query);
	const { inventory, fileMap } = buildInventory(args.store.getAll() as EmbeddedChunk[]);
	const rankedFiles = rankFilesForSecurityChat({
		query: args.query,
		inventory,
		fileMap,
		seedResults: args.seedResults,
		intent,
		scanFindings: args.scanFindings,
	});
	const fileGroupedResults = buildFileGroupedSecurityResults(
		args.store,
		rankedFiles,
		args.seedResults,
		intent.topFiles
	);
	const preferredFiles = rankedFiles.slice(0, intent.topFiles).map((entry) => entry.filePath);
	const relevantScanFindings = selectRelevantScanFindings({
		query: args.query,
		findings: args.scanFindings ?? [],
		intent,
		preferredFiles,
	});

	return {
		intent,
		rankedFiles,
		fileGroupedResults,
		relevantScanFindings,
		scanFindingsContext: formatScanFindingsForPrompt(relevantScanFindings),
	};
}

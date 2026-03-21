/**
 * agenticScan — 6-step agentic security analysis pipeline.
 *
 * Replaces pure RAG for code security scans:
 *   Step 1: INVENTORY       — deterministic, no LLM
 *   Step 2: DEPENDENCY AUDIT — deterministic + optional NVD
 *   Step 3: PATTERN SCAN    — deterministic regex
 *   Step 4: LLM DEEP ANALYSIS — Groq/Gemini via BYOK
 *   Step 5: CROSS-REFERENCE — RAG on knowledge bases
 *   Step 6: REPORT COMPILE  — deterministic template
 *
 * RAG pipeline for knowledge bases (ATT&CK, Sigma, NVD, NIST) is untouched.
 */

import type { EmbeddedChunk } from "./embedder";

// ─── Scan Modes ───────────────────────────────────────────────────────────────

export type ScanMode = "full" | "deps" | "secrets" | "attack-surface" | "improvements";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface InventorySummary {
	totalFiles: number;
	languages: Record<string, number>;
	entryPoints: string[];
	packageFiles: string[];
	configFiles: string[];
	authFiles: string[];
	apiFiles: string[];
	allFiles: Array<{ filename: string; language: string; size: number }>;
}

export interface FileEntry {
	filename: string;
	content: string;
	language: string;
}

export interface DependencyFinding {
	type: "dependency";
	package: string;
	version: string;
	file: string;
	ecosystem: string;
	vulnerable?: boolean;
	cves?: Array<{
		id: string;
		severity: string;
		score: number;
		description: string;
	}>;
}

export interface LLMAnalysis {
	verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNANALYZED";
	confidence: "HIGH" | "MEDIUM" | "LOW";
	exploitability: string;
	actual_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
	cwe_id: string;
	remediation: string;
	explanation: string;
}

export interface PatternFinding {
	type: "pattern" | "logic";
	id: string;
	name: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
	category: string;
	file: string;
	line: number;
	match?: string;
	context: string;
	analysis?: LLMAnalysis;
}

export interface AgenticFinding {
	name: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
	category: string;
	file: string;
	line?: number;
	verdict?: string;
	confidence?: string;
	confidenceScore?: number;
	cwe?: string;
	explanation?: string;
	exploitability?: string;
	remediation?: string;
	context?: string;
	attack_techniques: Array<{ technique_id: string; name: string; tactics: string[] }>;
	sigma_rules: Array<{ title: string; level: string; rule_id: string }>;
	compliance_controls: Array<{ control_id: string; title: string; family: string }>;
}

export interface AgenticReport {
	summary: {
		totalFindings: number;
		counts: Record<string, number>;
		vulnerableDependencies: number;
		filesScanned: number;
		languages: string[];
		score: number;
		grade: "A" | "B" | "C" | "D" | "F";
	};
	findings: AgenticFinding[];
	dependencies: DependencyFinding[];
	inventory: InventorySummary;
	scannedAt: Date;
	mode: ScanMode;
	llmUsed: boolean;
}

export interface ScanStepProgress {
	step: number;
	label: string;
	status: "pending" | "running" | "done" | "error";
	detail?: string;
}

/** Injected by the caller (SecurityScanModal) — uses existing generate() infra */
export type LLMCallFn = (systemPrompt: string, userPrompt: string) => Promise<string>;

export type ProgressCallback = (progress: ScanStepProgress) => void;

// ─── Step 1: INVENTORY ────────────────────────────────────────────────────────

export function buildInventory(chunks: EmbeddedChunk[]): {
	inventory: InventorySummary;
	fileMap: Map<string, FileEntry>;
} {
	const fileMap = new Map<string, FileEntry>();

	// Combine all chunks from the same file
	for (const chunk of chunks) {
		const filename = chunk.filePath || "";
		if (!filename) continue;

		if (!fileMap.has(filename)) {
			fileMap.set(filename, { filename, content: "", language: chunk.language || "unknown" });
		}
		fileMap.get(filename)!.content += "\n" + (chunk.code || "");
	}

	const inventory: InventorySummary = {
		totalFiles: 0,
		languages: {},
		entryPoints: [],
		packageFiles: [],
		configFiles: [],
		authFiles: [],
		apiFiles: [],
		allFiles: [],
	};

	for (const [, file] of fileMap) {
		const { filename } = file;
		inventory.totalFiles++;
		inventory.allFiles.push({ filename, language: file.language, size: file.content.length });

		const lang = file.language;
		inventory.languages[lang] = (inventory.languages[lang] || 0) + 1;

		const lower = filename.toLowerCase();

		if (
			[
				"package.json", "requirements.txt", "go.mod", "cargo.toml", "gemfile",
				"podfile", "build.gradle", "pom.xml", "composer.json", "pubspec.yaml", "mix.exs",
			].some((pkg) => lower.endsWith(pkg))
		) {
			inventory.packageFiles.push(filename);
		}

		if (
			lower.includes("config") || lower.includes(".env") || lower.includes("settings") ||
			lower.includes("docker") || lower.includes(".yml") || lower.includes(".yaml") ||
			lower.includes(".toml") || lower.includes(".ini")
		) {
			inventory.configFiles.push(filename);
		}

		if (
			lower.includes("auth") || lower.includes("login") || lower.includes("session") ||
			lower.includes("token") || lower.includes("oauth") || lower.includes("jwt") ||
			lower.includes("password") || lower.includes("credential") || lower.includes("permission")
		) {
			inventory.authFiles.push(filename);
		}

		if (
			lower.includes("route") || lower.includes("api") || lower.includes("endpoint") ||
			lower.includes("controller") || lower.includes("handler") || lower.includes("view") ||
			lower.includes("servlet") || lower.includes("resolver")
		) {
			inventory.apiFiles.push(filename);
		}

		if (
			lower.includes("main") || lower.includes("index") || lower.includes("app") ||
			lower.includes("server") || lower.includes("startup") || lower === "manage.py"
		) {
			inventory.entryPoints.push(filename);
		}
	}

	return { inventory, fileMap };
}

// ─── Step 2: DEPENDENCY AUDIT ─────────────────────────────────────────────────

export function auditDependencies(fileMap: Map<string, FileEntry>): DependencyFinding[] {
	const findings: DependencyFinding[] = [];

	for (const [, file] of fileMap) {
		const lower = file.filename.toLowerCase();

		// package.json (JavaScript/TypeScript)
		if (lower.endsWith("package.json")) {
			try {
				const jsonStart = file.content.indexOf("{");
				if (jsonStart === -1) continue;
				const pkg = JSON.parse(file.content.substring(jsonStart)) as {
					dependencies?: Record<string, string>;
					devDependencies?: Record<string, string>;
				};
				const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
				for (const [name, version] of Object.entries(allDeps)) {
					findings.push({ type: "dependency", package: name, version: String(version), file: file.filename, ecosystem: "npm" });
				}
			} catch {
				// Malformed JSON — skip
			}
		}

		// requirements.txt (Python)
		if (lower.endsWith("requirements.txt")) {
			for (const line of file.content.split("\n")) {
				const trimmed = line.trim();
				if (!trimmed || trimmed.startsWith("#")) continue;
				const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*([=<>!~]+.+)?/);
				if (match) {
					findings.push({ type: "dependency", package: match[1], version: match[2]?.trim() || "unspecified", file: file.filename, ecosystem: "pip" });
				}
			}
		}

		// go.mod (Go)
		if (lower.endsWith("go.mod")) {
			const requireRegex = /require\s+\(\s*([\s\S]*?)\)/g;
			let match: RegExpExecArray | null;
			while ((match = requireRegex.exec(file.content)) !== null) {
				for (const line of match[1].split("\n")) {
					const parts = line.trim().split(/\s+/);
					if (parts.length >= 2 && parts[0] && !parts[0].startsWith("//")) {
						findings.push({ type: "dependency", package: parts[0], version: parts[1], file: file.filename, ecosystem: "go" });
					}
				}
			}
		}

		// Cargo.toml (Rust)
		if (lower.endsWith("cargo.toml")) {
			const depSection = /\[dependencies\]([\s\S]*?)(?=\[|$)/i.exec(file.content);
			if (depSection) {
				for (const line of depSection[1].split("\n")) {
					const m = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
					if (m) {
						findings.push({ type: "dependency", package: m[1], version: m[2], file: file.filename, ecosystem: "cargo" });
					}
				}
			}
		}
	}

	return findings;
}

// ─── Step 3: PATTERN SCAN ─────────────────────────────────────────────────────

interface ScanPattern {
	name: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
	category: string;
	regex: RegExp;
}

const SCAN_PATTERNS: ScanPattern[] = [
	// Hardcoded Secrets
	{ name: "Hardcoded API Key", severity: "CRITICAL", category: "secrets",
		regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,})['"`]/gi },
	{ name: "Hardcoded Password", severity: "CRITICAL", category: "secrets",
		regex: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]/gi },
	{ name: "Hardcoded Token/Secret", severity: "CRITICAL", category: "secrets",
		regex: /(?:secret|token|private[_-]?key|access[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-\/.+]{16,})['"`]/gi },
	{ name: "AWS Access Key", severity: "CRITICAL", category: "secrets",
		regex: /AKIA[0-9A-Z]{16}/g },
	{ name: "Private Key File", severity: "CRITICAL", category: "secrets",
		regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g },

	// Injection
	{ name: "Potential SQL Injection", severity: "HIGH", category: "injection",
		regex: /(?:execute|query|raw|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[\s\S]*?\$\{/gi },
	{ name: "SQL String Concatenation", severity: "HIGH", category: "injection",
		regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:req\.|request\.|params\.|body\.|query\.)/gi },
	{ name: "Command Injection Risk", severity: "HIGH", category: "injection",
		regex: /(?:\bexec|\bspawn|\bsystem|popen|subprocess\.call|subprocess\.run|os\.system|child_process)\s*\(/gi },
	{ name: "eval() Usage", severity: "HIGH", category: "injection",
		// Negative lookbehind prevents matching identifiers like evalRepoEmbeddings or myEval
		regex: /(?<![a-zA-Z0-9_])eval\s*\(/g },

	// Authentication
	{ name: "Default Credentials", severity: "HIGH", category: "auth",
		regex: /(?:admin[/:]\s*admin|root[/:]\s*root|test[/:]\s*test|user[/:]\s*(?:pass|password))/gi },
	{ name: "Weak Hash Algorithm", severity: "MEDIUM", category: "crypto",
		regex: /(?:md5|sha1)\s*\(|(?:hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"])/gi },
	{ name: "JWT Without Verification", severity: "HIGH", category: "auth",
		regex: /jwt\.decode\s*\([^)]*verify\s*[:=]\s*(?:false|False)|algorithms\s*[:=]\s*\[?\s*['"]none['"]/gi },

	// Network/Transport
	{ name: "Insecure HTTP URL", severity: "MEDIUM", category: "transport",
		regex: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"`\s]+['"`]/gi },
	{ name: "SSL Verification Disabled", severity: "HIGH", category: "transport",
		regex: /verify\s*[:=]\s*(?:false|False)|CERT_NONE|InsecureRequestWarning|rejectUnauthorized\s*[:=]\s*false/gi },
	{ name: "CORS Wildcard", severity: "MEDIUM", category: "transport",
		regex: /(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*['"`]\*['"`]|origin\s*:\s*true/gi },

	// Data Handling
	{ name: "Insecure Deserialization", severity: "HIGH", category: "data",
		regex: /(?:pickle\.loads|yaml\.load\s*\([^)]*\)|unserialize|ObjectInputStream|JSON\.parse\s*\(\s*(?:req\.|request\.))/gi },
	{ name: "Path Traversal Risk", severity: "HIGH", category: "data",
		regex: /(?:readFile|readFileSync|open|fopen)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi },
	{ name: "Sensitive Data in Logs", severity: "MEDIUM", category: "data",
		// Only match when a sensitive VARIABLE (not a plain string literal) is being passed to the log call.
		// Strategy: look for the sensitive word followed by a non-quote char (variable reference),
		// OR directly preceded by a comma/open-paren (direct variable argument like console.log(apiKey)).
		// Excludes: "API_KEY testing...", "hasStoredKey:", method calls like vault.hasKey().
		regex: /(?:console\.log|logger?\.\w+|print\b|println\b)\s*\([^)]*?(?:(?<![a-zA-Z0-9_'"`])(?:password|passwd|secret|token|apiKey|api_key|credential|auth_?key|access_?key|private_?key)\s*[,)=+]|(?:password|passwd|secret|token|apiKey|api_key|credential|auth_?key|access_?key|private_?key)\s*\))/gi },

	// Configuration
	{ name: "Debug Mode Enabled", severity: "MEDIUM", category: "config",
		regex: /(?:DEBUG\s*[:=]\s*(?:true|True|1|['"]true['"])|debug\s*[:=]\s*true|app\.debug\s*=\s*True)/gi },
	{ name: "CSRF Protection Disabled", severity: "HIGH", category: "config",
		regex: /(?:csrf\s*[:=]\s*false|disable.*csrf|@csrf_exempt|CSRFProtect.*disable)/gi },
];

/** Path segments / suffixes that should never be pattern-scanned. */
const SKIP_PATH_SEGMENTS = [
	"node_modules/", "node_modules\\",
	"dist/", "dist\\",
	"build/", "build\\",
	".next/", ".next\\",
	".git/",
	"vendor/",
	".min.js", ".min.css",
];

/** Filename-level patterns for test / utility files that should be excluded. */
const SKIP_FILE_PATTERNS = [
	/\.(test|spec)\.[jt]sx?$/i,        // *.test.ts, *.spec.js, etc.
	/^test-/i,                          // test-something.ts
	/^verify-/i,                        // verify-something.ts
	/^package-lock\.json$/i,            // npm lock file
	/^yarn\.lock$/i,                    // yarn lock file
	/^pnpm-lock\.yaml$/i,               // pnpm lock file
];

/** Directory segments that identify test / utility directories. */
const SKIP_DIR_SEGMENTS = [
	"/test/", "\\test\\",
	"/tests/", "\\tests\\",
	"/__tests__/", "\\__tests__\\",
	"/spec/", "\\spec\\",
	"/scripts/", "\\scripts\\",
];

function shouldSkipFile(filename: string): boolean {
	const lower = filename.toLowerCase();

	// Skip known build/vendor/lock directories
	if (SKIP_PATH_SEGMENTS.some((seg) => lower.includes(seg) || lower.endsWith(seg))) return true;

	// Skip markdown / plain text
	if (lower.endsWith(".md") || lower.endsWith(".txt")) return true;

	// Skip non-config JSON files
	if (lower.endsWith(".json") && !lower.includes("config")) return true;

	// Skip test/spec/script directories
	const normalized = filename.replace(/\\/g, "/");
	if (SKIP_DIR_SEGMENTS.some((seg) => normalized.includes(seg.replace(/\\/g, "/")))) return true;

	// Skip test/verify files by filename pattern
	const basename = normalized.split("/").pop() ?? "";
	if (SKIP_FILE_PATTERNS.some((re) => re.test(basename))) return true;

	return false;
}

export function patternScan(
	fileMap: Map<string, FileEntry>,
	categoryFilter?: string,
): PatternFinding[] {
	const seenLineIds = new Set<string>();

	// Key: "patternName:filename" → accumulated finding for deduplication (Fix 3)
	const groupedFindings = new Map<string, PatternFinding>();

	for (const [, file] of fileMap) {
		if (shouldSkipFile(file.filename)) continue;

		const lines = file.content.split("\n");

		for (const pattern of SCAN_PATTERNS) {
			if (categoryFilter && pattern.category !== categoryFilter) continue;

			pattern.regex.lastIndex = 0;
			let match: RegExpExecArray | null;

			while ((match = pattern.regex.exec(file.content)) !== null) {
				const lineNumber = file.content.substring(0, match.index).split("\n").length;
				const lineId = `${pattern.name}:${file.filename}:${lineNumber}`;
				if (seenLineIds.has(lineId)) continue;
				seenLineIds.add(lineId);

				const startLine = Math.max(0, lineNumber - 4);
				const endLine = Math.min(lines.length, lineNumber + 3);
				const context = lines.slice(startLine, endLine).join("\n");
				const matchText = match[0].substring(0, 120);

				// Deduplication key: same pattern name + same file → merge into one finding
				const groupKey = `${pattern.name}:${file.filename}`;
				const existing = groupedFindings.get(groupKey);

				if (existing) {
					// Append additional location to context; keep the first line number
					existing.context = `${existing.context}\n\n[line ${lineNumber}]:\n${context}`;
					existing.match = `${existing.match} | [line ${lineNumber}]: ${matchText}`.substring(0, 300);
				} else {
					groupedFindings.set(groupKey, {
						type: "pattern",
						id: `${pattern.name}:${file.filename}:${lineNumber}`,
						name: pattern.name,
						severity: pattern.severity,
						category: pattern.category,
						file: file.filename,
						line: lineNumber,
						match: matchText,
						context,
					});
				}
			}
		}
	}

	return Array.from(groupedFindings.values());
}

// ─── Step 4: LLM DEEP ANALYSIS ────────────────────────────────────────────────

/**
 * Robustly extract parseable JSON from an LLM response.
 * Handles: markdown fences, leading/trailing prose, extra whitespace.
 */
function extractJson(response: string): string {
	let text = response.trim();

	// 1. Strip markdown code fences (``` or ```json, with or without trailing newline)
	text = text.replace(/^```(?:json)?\s*/im, "").replace(/\n?```\s*$/im, "").trim();

	// 2. If there's still text before the JSON, find the first { or [
	const objIdx = text.indexOf("{");
	const arrIdx = text.indexOf("[");

	if (objIdx === -1 && arrIdx === -1) return text; // nothing to extract

	// Pick whichever comes first
	const startIdx =
		objIdx === -1 ? arrIdx :
		arrIdx === -1 ? objIdx :
		Math.min(objIdx, arrIdx);

	const openChar = text[startIdx];
	const closeChar = openChar === "{" ? "}" : "]";

	// Walk forward matching braces to find the end of the JSON value
	let depth = 0;
	let inString = false;
	let escaped = false;
	let endIdx = -1;

	for (let i = startIdx; i < text.length; i++) {
		const ch = text[i];
		if (escaped) { escaped = false; continue; }
		if (ch === "\\" && inString) { escaped = true; continue; }
		if (ch === '"') { inString = !inString; continue; }
		if (inString) continue;
		if (ch === openChar) depth++;
		else if (ch === closeChar) {
			depth--;
			if (depth === 0) { endIdx = i; break; }
		}
	}

	if (endIdx !== -1) return text.slice(startIdx, endIdx + 1);

	// Fallback: return from first bracket to end (better than nothing)
	return text.slice(startIdx);
}

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// ─── Guardrail helpers ────────────────────────────────────────────────────────

/** djb2 hash — fast, deterministic, no async required */
function simpleHash(str: string): string {
	let h = 5381;
	for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
	return (h >>> 0).toString(16);
}

/** Default CWE IDs by finding category (Guardrail 2) */
const CWE_DEFAULTS: Record<string, string> = {
	secrets:   "CWE-798",  // Use of Hard-coded Credentials
	injection: "CWE-89",   // SQL Injection
	auth:      "CWE-287",  // Improper Authentication
	crypto:    "CWE-327",  // Use of Broken Cryptographic Algorithm
	transport: "CWE-319",  // Cleartext Transmission of Sensitive Information
	data:      "CWE-532",  // Insertion of Sensitive Information into Log File
	config:    "CWE-16",   // Configuration
	logic:     "CWE-840",  // Business Logic Errors
};

/**
 * Findings that MUST stay TRUE_POSITIVE at full severity.
 * LLM cannot override these to FALSE_POSITIVE. (Guardrail 3)
 */
const MANDATORY_FINDINGS = new Set([
	"AWS Access Key",
	"Private Key File",
	"Default Credentials",
	"eval() Usage",
	"Hardcoded Password",
	"Hardcoded Token/Secret",
	"Hardcoded API Key",
]);

function isMandatory(findingName: string): boolean {
	return MANDATORY_FINDINGS.has(findingName);
}

/**
 * Apply finding validation guardrails (Guardrail 2 + Guardrail 3).
 * - Fills in default CWE if missing
 * - Severity can only escalate, never downgrade
 * - Mandatory findings cannot be FALSE_POSITIVE
 * - FALSE_POSITIVE without a meaningful explanation → reverted to TRUE_POSITIVE
 */
function applyGuardrails(finding: PatternFinding, analysis: LLMAnalysis): LLMAnalysis {
	const result = { ...analysis };

	// G2: CWE default if missing or placeholder
	if (!result.cwe_id || result.cwe_id.trim() === "" || /^CWE-0$/.test(result.cwe_id.trim())) {
		result.cwe_id = CWE_DEFAULTS[finding.category] ?? "CWE-693";
		console.log(`[guardrail] Applied CWE default ${result.cwe_id} for category "${finding.category}"`);
	}

	// G2: Severity may only escalate, never downgrade
	const patternRank = SEVERITY_ORDER[finding.severity] ?? 4;
	const llmRank     = SEVERITY_ORDER[result.actual_severity] ?? 4;
	if (llmRank > patternRank) {
		console.log(`[guardrail] Severity escalation enforced for "${finding.name}": ${result.actual_severity} → ${finding.severity}`);
		result.actual_severity = finding.severity;
	}

	// G3: Mandatory findings — only allow FALSE_POSITIVE when the LLM explains that
	// the pattern matched a variable name, comment, or non-dangerous identifier.
	// This prevents silent filtering while still respecting correct LLM analysis.
	if (isMandatory(finding.name) && result.verdict === "FALSE_POSITIVE") {
		const expl = result.explanation?.toLowerCase() ?? "";
		const hasVariableRationale =
			expl.length >= 30 &&
			(expl.includes("variable name") ||
				expl.includes("identifier") ||
				expl.includes("comment") ||
				expl.includes("not actual") ||
				expl.includes("not a real") ||
				expl.includes("not an actual") ||
				expl.includes("not dangerous") ||
				expl.includes("not executable") ||
				expl.includes("naming convention") ||
				expl.includes("string literal that is not"));
		if (hasVariableRationale) {
			console.log(`[guardrail] Mandatory finding "${finding.name}" — FALSE_POSITIVE allowed (LLM provided variable/comment rationale)`);
		} else {
			console.warn(`[guardrail] Mandatory finding "${finding.name}" — FALSE_POSITIVE blocked (no specific variable/comment rationale)`);
			result.verdict = "TRUE_POSITIVE";
			result.explanation = `[Guardrail: mandatory finding, no dismissal rationale] ${result.explanation}`;
		}
	}

	// G2: FALSE_POSITIVE without a real explanation → treat as unverified / TRUE_POSITIVE
	if (result.verdict === "FALSE_POSITIVE" && (!result.explanation || result.explanation.trim().length < 15)) {
		console.warn(`[guardrail] FALSE_POSITIVE for "${finding.name}" lacked explanation — reverted to TRUE_POSITIVE`);
		result.verdict = "TRUE_POSITIVE";
		result.explanation = "[Guardrail] Reverted: insufficient explanation for FALSE_POSITIVE verdict.";
	}

	return result;
}

/** Assign a numeric confidence score 0–100 to a pattern finding (Guardrail 5) */
function assignConfidenceScore(f: PatternFinding): number {
	if (isMandatory(f.name))                           return 99; // mandatory — always flag
	if (f.type === "logic" && f.analysis?.verdict === "TRUE_POSITIVE") return 70; // LLM logic analysis
	if (f.analysis?.verdict === "TRUE_POSITIVE")       return 90; // LLM-confirmed pattern
	if (f.analysis?.verdict === "UNANALYZED")          return 50; // beyond analysis limit
	return 60;                                                      // pattern-only / parse failure
}

/** Validate required fields and deduplicate findings (Guardrail 6) */
function validateAndDedup(findings: AgenticFinding[]): AgenticFinding[] {
	const seen = new Set<string>();
	const validated: AgenticFinding[] = [];

	for (const f of findings) {
		// Dedup by name + file + line
		const key = `${f.name}::${f.file}::${f.line ?? 0}`;
		if (seen.has(key)) {
			console.warn(`[guardrail] Deduplicated finding: ${key}`);
			continue;
		}
		seen.add(key);

		// Validate + auto-fix required fields
		const fixed = { ...f };
		if (!["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(fixed.severity)) {
			console.warn(`[guardrail] Invalid severity "${fixed.severity}" on "${fixed.name}" — defaulting to MEDIUM`);
			fixed.severity = "MEDIUM";
		}
		if (!fixed.file) {
			console.warn(`[guardrail] Missing file on "${fixed.name}" — marking as unknown`);
			fixed.file = "unknown";
		}
		if (fixed.line === undefined) fixed.line = 0;

		validated.push(fixed);
	}

	// Sort: severity ASC (CRITICAL first), then confidence DESC
	return validated.sort((a, b) => {
		const sevDiff =
			(SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
		if (sevDiff !== 0) return sevDiff;
		return (b.confidenceScore ?? 0) - (a.confidenceScore ?? 0);
	});
}

// ─── Diff-aware scan cache (Guardrail 1 + 4) ─────────────────────────────────

const DIFF_CACHE_KEY = "threatlens-diff-cache";

interface DiffCache {
	fileHashes: Record<string, string>;
	findingsByFile: Record<string, PatternFinding[]>;
	patternFingerprint: string;
	savedAt: number;
}

function loadDiffCache(): DiffCache | null {
	try {
		const raw = localStorage.getItem(DIFF_CACHE_KEY);
		return raw ? (JSON.parse(raw) as DiffCache) : null;
	} catch {
		return null;
	}
}

function saveDiffCache(cache: DiffCache): void {
	try {
		localStorage.setItem(DIFF_CACHE_KEY, JSON.stringify(cache));
	} catch {
		// Quota exceeded — ignore
	}
}

function computeFileHashes(fileMap: Map<string, FileEntry>): Record<string, string> {
	const hashes: Record<string, string> = {};
	for (const [filename, file] of fileMap) {
		hashes[filename] = simpleHash(file.content);
	}
	return hashes;
}

/** Async sleep helper for rate limiting and retry delays */
function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Read LLM provider + key info from localStorage for diagnostic logging.
 * Reads the same storage keys as llm.ts without importing the full module.
 */
function getLLMProviderDiag(): { provider: string; apiKeyPreview: string; endpoint: string } {
	try {
		if (typeof localStorage === "undefined") return { provider: "unknown", apiKeyPreview: "(none)", endpoint: "(none)" };
		const raw = localStorage.getItem("gitask_llm_config");
		const config = raw ? (JSON.parse(raw) as { provider?: string }) : {};
		const provider = config.provider || "unknown";
		const keyStorage: Record<string, string> = {
			groq: "gitask_groq_api_key_local",
			gemini: "gitask_gemini_api_key_local",
		};
		const storageKey = keyStorage[provider];
		const rawKey = storageKey ? (localStorage.getItem(storageKey) ?? "") : "";
		const apiKeyPreview = rawKey ? rawKey.slice(0, 4) + "***" : "(none — check vault or key input)";
		const endpoints: Record<string, string> = {
			groq: "https://api.groq.com/openai/v1/chat/completions",
			gemini: "https://generativelanguage.googleapis.com/v1beta/models/",
		};
		return { provider, apiKeyPreview, endpoint: endpoints[provider] ?? "(none)" };
	} catch {
		return { provider: "unknown", apiKeyPreview: "(none)", endpoint: "(none)" };
	}
}

/** ms delay to insert between LLM calls per provider to avoid rate-limit 429s */
const PROVIDER_RATE_DELAY_MS: Record<string, number> = {
	groq:   1000,
	gemini: 500,
};

export async function deepAnalysis(
	inventory: InventorySummary,
	patternFindings: PatternFinding[],
	fileMap: Map<string, FileEntry>,
	callLLM: LLMCallFn,
	onSubProgress?: (detail: string) => void,
	abortSignal?: { aborted: boolean },
): Promise<PatternFinding[]> {
	const results: PatternFinding[] = [];

	// ── Provider diagnostics ─────────────────────────────────────────────────
	const provDiag = getLLMProviderDiag();
	console.log(
		`[deepAnalysis] Provider: ${provDiag.provider} | Key: ${provDiag.apiKeyPreview} | Endpoint: ${provDiag.endpoint}`,
	);
	const rateDelayMs = PROVIDER_RATE_DELAY_MS[provDiag.provider] ?? 0;
	if (rateDelayMs > 0) {
		console.log(`[deepAnalysis] Rate limiting: ${rateDelayMs}ms between calls for ${provDiag.provider}`);
	}

	// Sort by severity, analyze top 12 findings
	const sorted = [...patternFindings].sort(
		(a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4),
	);
	const toAnalyze = sorted.slice(0, 12);

	console.log(`[deepAnalysis] Starting LLM deep analysis on ${toAnalyze.length} findings (${sorted.length} total)`);

	// 4a: Analyze each pattern finding with code context
	for (let i = 0; i < toAnalyze.length; i++) {
		if (abortSignal?.aborted) break;
		const finding = toAnalyze[i];
		onSubProgress?.(`Analyzing finding ${i + 1}/${toAnalyze.length}: ${finding.name}`);

		const file = fileMap.get(finding.file);
		let codeContext = finding.context;
		if (file) {
			const fileLines = file.content.split("\n");
			const start = Math.max(0, finding.line - 31);
			const end = Math.min(fileLines.length, finding.line + 30);
			codeContext = fileLines
				.slice(start, end)
				.map((line, idx) => `${start + idx + 1}: ${line}`)
				.join("\n");
		}

		const systemPrompt =
			"You are a security code reviewer. Analyze the specific finding and respond ONLY with a single JSON object — no preamble, no explanation, no markdown fences. Just the raw JSON object.";
		const userPrompt = `Analyze this security finding and respond with ONLY the JSON object below (no other text):

FINDING: ${finding.name}
SEVERITY: ${finding.severity}
FILE: ${finding.file}
LINE: ${finding.line}
MATCHED PATTERN: ${finding.match || ""}

CODE CONTEXT:
\`\`\`
${codeContext}
\`\`\`

Respond with exactly this JSON structure:
{"verdict":"TRUE_POSITIVE","confidence":"HIGH","exploitability":"how this could be exploited","actual_severity":"${finding.severity}","cwe_id":"CWE-XXX","remediation":"specific fix","explanation":"what the issue is and why it matters"}

verdict must be TRUE_POSITIVE or FALSE_POSITIVE. confidence must be HIGH, MEDIUM, or LOW. actual_severity must be CRITICAL, HIGH, MEDIUM, or LOW.`;

		// ── Rate-limit delay ────────────────────────────────────────────────
		if (i > 0 && rateDelayMs > 0) {
			console.log(`[deepAnalysis] Rate delay ${rateDelayMs}ms before call ${i + 1} (${provDiag.provider})`);
			await sleep(rateDelayMs);
		}

		// ── Call LLM with one retry on failure ──────────────────────────────
		let rawResponse: string | null = null;
		let lastCallErr: unknown = null;

		for (let attempt = 1; attempt <= 2; attempt++) {
			try {
				if (attempt === 2) {
					console.log(`[deepAnalysis] Finding ${i + 1}: retrying in 2s…`);
					await sleep(2000);
				}
				console.log(`[deepAnalysis] LLM call ${i + 1}/${toAnalyze.length} start (attempt ${attempt}): "${finding.name}"`);
				rawResponse = await callLLM(systemPrompt, userPrompt);
				console.log(`[deepAnalysis] LLM call ${i + 1} done (attempt ${attempt}): ${rawResponse.length} chars`);
				lastCallErr = null;
				break;
			} catch (err) {
				lastCallErr = err;
				const errMsg = err instanceof Error ? err.message : String(err);
				console.error(`[deepAnalysis] Finding ${i + 1} call attempt ${attempt} FAILED:`, err);
				onSubProgress?.(
					`⚠ Step 4: Finding ${i + 1}/${toAnalyze.length} failed — API error: ${errMsg}${attempt < 2 ? " (retrying in 2s…)" : ""}`,
				);
			}
		}

		// Both attempts failed → mark as UNANALYZED and continue
		if (lastCallErr !== null || rawResponse === null) {
			const errMsg = lastCallErr instanceof Error ? lastCallErr.message : String(lastCallErr);
			console.error(`[deepAnalysis] Finding ${i + 1} FAILED after retry — marking UNANALYZED:`, errMsg);
			onSubProgress?.(`⚠ Step 4: Finding ${i + 1}/${toAnalyze.length} permanently failed — ${errMsg}`);
			results.push({
				...finding,
				analysis: {
					verdict: "UNANALYZED",
					confidence: "LOW",
					exploitability: "",
					actual_severity: finding.severity,
					cwe_id: CWE_DEFAULTS[finding.category] ?? "CWE-693",
					remediation: "",
					explanation: `[LLM API Error after retry] ${errMsg}`,
				},
			});
			continue;
		}

		// ── Parse and validate the response ────────────────────────────────
		if (!rawResponse || rawResponse.trim() === "") {
			console.warn(`[deepAnalysis] Finding ${i + 1}: empty response — keeping as pattern match`);
			results.push({ ...finding });
			continue;
		}

		const extracted = extractJson(rawResponse);

		let analysis: LLMAnalysis;
		try {
			analysis = JSON.parse(extracted) as LLMAnalysis;
		} catch (parseErr) {
			// Log the full raw response so we can diagnose LLM formatting issues
			console.error(`[deepAnalysis] Finding ${i + 1} JSON parse FAILED:`, parseErr);
			console.error(`[deepAnalysis] Finding ${i + 1} extracted text was:`, extracted);
			console.error(`[deepAnalysis] Finding ${i + 1} full raw response was:`, rawResponse);
			onSubProgress?.(`⚠ Step 4: Finding ${i + 1}/${toAnalyze.length} parse error — LLM returned invalid JSON (see console)`);
			results.push({ ...finding }); // keep as plain pattern match
			continue;
		}

		// Validate verdict
		if (!["TRUE_POSITIVE", "FALSE_POSITIVE"].includes(analysis.verdict)) {
			console.warn(`[deepAnalysis] Finding ${i + 1}: unexpected verdict "${analysis.verdict}" — treating as TRUE_POSITIVE`);
			analysis.verdict = "TRUE_POSITIVE";
		}

		// Validate actual_severity
		if (!["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(analysis.actual_severity)) {
			analysis.actual_severity = finding.severity;
		}

		// Apply guardrails 2 + 3 (CWE default, severity escalation, mandatory protection)
		const guardedAnalysis = applyGuardrails(finding, analysis);
		results.push({ ...finding, analysis: guardedAnalysis });
		console.log(
			`[deepAnalysis] Finding ${i + 1}: verdict=${guardedAnalysis.verdict} severity=${guardedAnalysis.actual_severity} cwe=${guardedAnalysis.cwe_id}`,
		);
	}

	// Add remaining findings (beyond top 12) without LLM analysis
	for (const f of sorted.slice(12)) {
		results.push({
			...f,
			analysis: {
				verdict: "UNANALYZED",
				confidence: "LOW",
				exploitability: "",
				actual_severity: f.severity,
				cwe_id: CWE_DEFAULTS[f.category] ?? "",
				remediation: "",
				explanation: "",
			},
		});
	}

	// 4b: Check auth + API files for logic flaws (top 5 files)
	const criticalFiles = [...new Set([...inventory.authFiles, ...inventory.apiFiles])].slice(0, 5);
	console.log(`[deepAnalysis] Checking ${criticalFiles.length} auth/API files for logic flaws`);

	for (let i = 0; i < criticalFiles.length; i++) {
		if (abortSignal?.aborted) break;
		const filename = criticalFiles[i];
		const file = fileMap.get(filename);
		if (!file || file.content.length < 50) continue;

		onSubProgress?.(`Checking logic flaws: ${filename.split("/").pop()}`);

		// Rate-limit delay applies to logic scan calls too
		if (rateDelayMs > 0) {
			console.log(`[deepAnalysis] Rate delay ${rateDelayMs}ms before logic scan call (${provDiag.provider})`);
			await sleep(rateDelayMs);
		}

		const systemPrompt =
			"You are a security code reviewer. Find security vulnerabilities that regex cannot catch — logic flaws, broken access control, insecure design patterns. Respond ONLY with a JSON array — no preamble, no markdown fences.";
		const userPrompt = `Analyze for logic flaws and access control issues:

FILE: ${filename}
\`\`\`
${file.content.substring(0, 3000)}
\`\`\`

Respond with ONLY a JSON array (use [] if no issues found):
[{"name":"vuln name","severity":"CRITICAL|HIGH|MEDIUM|LOW","line":0,"cwe_id":"CWE-XXX","explanation":"what it is","exploitability":"how to exploit","remediation":"how to fix"}]`;

		// Retry logic for logic scan calls
		let logicRaw: string | null = null;
		let logicCallErr: unknown = null;

		for (let attempt = 1; attempt <= 2; attempt++) {
			try {
				if (attempt === 2) {
					console.log(`[deepAnalysis] Logic scan ${filename}: retrying in 2s…`);
					await sleep(2000);
				}
				console.log(`[deepAnalysis] Logic scan ${filename} start (attempt ${attempt})`);
				logicRaw = await callLLM(systemPrompt, userPrompt);
				console.log(`[deepAnalysis] Logic scan ${filename} done (attempt ${attempt}): ${logicRaw.length} chars`);
				logicCallErr = null;
				break;
			} catch (err) {
				logicCallErr = err;
				const errMsg = err instanceof Error ? err.message : String(err);
				console.error(`[deepAnalysis] Logic scan ${filename} attempt ${attempt} FAILED:`, err);
				onSubProgress?.(
					`⚠ Step 4: Logic scan ${filename.split("/").pop()} failed — ${errMsg}${attempt < 2 ? " (retrying…)" : ""}`,
				);
			}
		}

		if (logicCallErr !== null || logicRaw === null) {
			console.error(`[deepAnalysis] Logic scan ${filename} FAILED after retry — skipping`);
			continue;
		}

		let logicFindings: Array<{
			name: string;
			severity: string;
			line: number;
			cwe_id: string;
			explanation: string;
			exploitability: string;
			remediation: string;
		}>;

		try {
			const extracted = extractJson(logicRaw);
			logicFindings = JSON.parse(extracted);
		} catch (parseErr) {
			console.error(`[deepAnalysis] Logic scan ${filename} JSON parse FAILED:`, parseErr);
			console.error(`[deepAnalysis] Logic scan ${filename} raw response:`, logicRaw);
			onSubProgress?.(`⚠ Step 4: Logic scan ${filename.split("/").pop()} parse error — invalid JSON (see console)`);
			continue;
		}

		if (!Array.isArray(logicFindings)) {
			console.warn(`[deepAnalysis] Logic scan ${filename}: expected array, got`, typeof logicFindings);
			continue;
		}

		for (const lf of logicFindings) {
			const sev = (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(lf.severity?.toUpperCase?.())
				? lf.severity.toUpperCase()
				: "MEDIUM") as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
			results.push({
				type: "logic",
				id: `logic:${filename}:${lf.name}`,
				name: lf.name,
				severity: sev,
				category: "logic",
				file: filename,
				line: lf.line || 0,
				context: "",
				analysis: {
					verdict: "TRUE_POSITIVE",
					confidence: "MEDIUM",
					cwe_id: lf.cwe_id || "CWE-840",
					exploitability: lf.exploitability || "",
					actual_severity: sev,
					remediation: lf.remediation || "",
					explanation: lf.explanation || "",
				},
			});
		}
		console.log(`[deepAnalysis] Logic scan ${filename}: ${logicFindings.length} findings`);
	}

	return results;
}

// ─── Step 5: CROSS-REFERENCE ─────────────────────────────────────────────────
//
// NOTE: ATT&CK, Sigma, and NIST knowledge bases are indexed in separate
// VectorStore namespaces (threatlens/attack, threatlens/sigma, threatlens/nist)
// that are not loaded in the repo scan context. Cross-reference enrichment
// will be added in a future enhancement when multi-store loading is available.

export function crossReference(findings: PatternFinding[]): PatternFinding[] {
	return findings;
}

// ─── Step 6: COMPILE REPORT ───────────────────────────────────────────────────

function calcRiskScore(counts: Record<string, number>): number {
	const penalty =
		(counts.CRITICAL || 0) * 30 +
		(counts.HIGH || 0) * 12 +
		(counts.MEDIUM || 0) * 4 +
		(counts.LOW || 0) * 1;
	return Math.max(0, Math.min(100, 100 - penalty));
}

function riskGrade(score: number): "A" | "B" | "C" | "D" | "F" {
	if (score >= 90) return "A";
	if (score >= 75) return "B";
	if (score >= 55) return "C";
	if (score >= 35) return "D";
	return "F";
}

export function compileReport(
	inventory: InventorySummary,
	depFindings: DependencyFinding[],
	analysisResults: PatternFinding[],
	scannedAt: Date,
	mode: ScanMode,
	llmUsed: boolean,
): AgenticReport {
	// Filter false positives only. Findings with no analysis (parse failures)
	// and UNANALYZED findings are kept — they're real pattern matches.
	const confirmed = analysisResults
		.filter((f) => f.analysis?.verdict !== "FALSE_POSITIVE")
		.sort(
			(a, b) =>
				(SEVERITY_ORDER[a.analysis?.actual_severity || a.severity] ?? 4) -
				(SEVERITY_ORDER[b.analysis?.actual_severity || b.severity] ?? 4),
		);

	const vulnDeps = depFindings.filter((d) => d.vulnerable);

	const rawFindings: AgenticFinding[] = confirmed.map((f) => {
		const score = assignConfidenceScore(f);
		// G2: apply CWE default for pattern-only findings (no LLM analysis)
		const cwe = f.analysis?.cwe_id || CWE_DEFAULTS[f.category] || undefined;
		return {
			name: f.name,
			severity: (f.analysis?.actual_severity || f.severity) as AgenticFinding["severity"],
			category: f.category,
			file: f.file,
			line: f.line || undefined,
			verdict: f.analysis?.verdict,
			confidence: f.analysis?.confidence,
			confidenceScore: score,
			cwe,
			explanation: f.analysis?.explanation || undefined,
			exploitability: f.analysis?.exploitability || undefined,
			remediation: f.analysis?.remediation || undefined,
			context: f.context || undefined,
			attack_techniques: [],
			sigma_rules: [],
			compliance_controls: [],
		};
	});

	// G6: validate required fields, dedup, sort by severity + confidence
	const findings = validateAndDedup(rawFindings);

	// Risk score is calculated from the FINAL deduplicated findings only.
	// FALSE_POSITIVE findings are already excluded by the `confirmed` filter above;
	// deduplication ensures duplicates don't double-penalize the score.
	const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
	for (const f of findings) {
		counts[f.severity] = (counts[f.severity] || 0) + 1;
	}
	const score = calcRiskScore(counts);
	const grade = riskGrade(score);

	return {
		summary: {
			totalFindings: findings.length,
			counts,
			vulnerableDependencies: vulnDeps.length,
			filesScanned: inventory.totalFiles,
			languages: Object.keys(inventory.languages),
			score,
			grade,
		},
		findings,
		dependencies: depFindings,
		inventory,
		scannedAt,
		mode,
		llmUsed,
	};
}

// ─── Main Orchestrator ────────────────────────────────────────────────────────

export const STEP_LABELS: Record<number, string> = {
	1: "Inventory",
	2: "Dependencies",
	3: "Pattern Scan",
	4: "Deep Analysis",
	5: "Cross-Reference",
	6: "Report",
};

export async function runSecurityScan(
	chunks: EmbeddedChunk[],
	callLLM: LLMCallFn | null,
	onProgress: ProgressCallback,
	mode: ScanMode = "full",
	abortSignal?: { aborted: boolean },
): Promise<AgenticReport> {
	const scannedAt = new Date();
	const llmAvailable = callLLM !== null && (mode !== "secrets" && mode !== "deps");

	// ── Step 1: Inventory ──────────────────────────────────────────────────
	onProgress({ step: 1, label: STEP_LABELS[1], status: "running" });
	const { inventory, fileMap } = buildInventory(chunks);
	onProgress({
		step: 1,
		label: STEP_LABELS[1],
		status: "done",
		detail: `${inventory.totalFiles} files · ${Object.keys(inventory.languages).slice(0, 4).join(", ")}`,
	});

	// ── Step 2: Dependency Audit ───────────────────────────────────────────
	onProgress({ step: 2, label: STEP_LABELS[2], status: "running" });
	const depFindings = auditDependencies(fileMap);
	onProgress({
		step: 2,
		label: STEP_LABELS[2],
		status: "done",
		detail: `${depFindings.length} packages found`,
	});

	// Deps-only mode: compile and return after Step 2
	if (mode === "deps") {
		onProgress({ step: 3, label: STEP_LABELS[3], status: "done", detail: "Skipped" });
		onProgress({ step: 4, label: STEP_LABELS[4], status: "done", detail: "Skipped" });
		onProgress({ step: 5, label: STEP_LABELS[5], status: "done", detail: "Skipped" });
		onProgress({ step: 6, label: STEP_LABELS[6], status: "running" });
		const report = compileReport(inventory, depFindings, [], scannedAt, mode, false);
		onProgress({ step: 6, label: STEP_LABELS[6], status: "done", detail: `${depFindings.length} packages audited` });
		return report;
	}

	// ── Step 3: Pattern Scan ───────────────────────────────────────────────
	onProgress({ step: 3, label: STEP_LABELS[3], status: "running" });
	const categoryFilter = mode === "secrets" ? "secrets" : undefined;
	const patternFindings = patternScan(fileMap, categoryFilter);
	onProgress({
		step: 3,
		label: STEP_LABELS[3],
		status: "done",
		detail: `${patternFindings.length} suspicious patterns found`,
	});

	if (abortSignal?.aborted) {
		return compileReport(inventory, depFindings, patternFindings, scannedAt, mode, false);
	}

	// ── Guardrails 1 + 4: Diff-aware scan + fingerprinting ────────────────
	const currentFileHashes = computeFileHashes(fileMap);
	const patternFingerprint = simpleHash(
		[...patternFindings]
			.sort((a, b) => a.id.localeCompare(b.id))
			.map((f) => `${f.id}:${f.severity}`)
			.join("|"),
	);

	const diffCache = loadDiffCache();
	let cachedAnalysisForUnchanged: PatternFinding[] = [];
	let changedFileCount = fileMap.size; // default: all files are "changed" on first scan

	// G1: Check if pattern results are identical (fingerprint match → full cache hit)
	if (diffCache && diffCache.patternFingerprint === patternFingerprint) {
		console.log("[guardrail] Pattern fingerprint match — reusing all cached deep analysis results");
		const allCached = Object.values(diffCache.findingsByFile).flat();
		onProgress({
			step: 4,
			label: STEP_LABELS[4],
			status: "done",
			detail: `Fingerprint match — ${allCached.length} cached findings (no changes detected)`,
		});
		// Skip Steps 4+ and go straight to compile with cached results
		const enrichedCached = crossReference(allCached);
		onProgress({ step: 5, label: STEP_LABELS[5], status: "done", detail: "ATT&CK · Sigma · NIST mapping (coming soon)" });
		onProgress({ step: 6, label: STEP_LABELS[6], status: "running" });
		const cachedReport = compileReport(inventory, depFindings, enrichedCached, scannedAt, mode, llmAvailable);
		onProgress({ step: 6, label: STEP_LABELS[6], status: "done", detail: `${cachedReport.summary.totalFindings} findings (cached)` });
		return cachedReport;
	}

	// G4: Diff-aware — identify changed files
	const changedFiles = new Set<string>();
	if (diffCache) {
		for (const filename of fileMap.keys()) {
			if (diffCache.fileHashes[filename] !== currentFileHashes[filename]) {
				changedFiles.add(filename);
			}
		}
		// Gather cached analysis for UNCHANGED files
		for (const [filename, findings] of Object.entries(diffCache.findingsByFile)) {
			if (!changedFiles.has(filename)) {
				cachedAnalysisForUnchanged.push(...findings);
			}
		}
		changedFileCount = changedFiles.size;
		const unchanged = fileMap.size - changedFiles.size;
		console.log(`[guardrail] Diff-aware: ${changedFileCount} changed, ${unchanged} unchanged (${cachedAnalysisForUnchanged.length} cached findings)`);
	}

	// Filter pattern findings to changed files only (for LLM) — pattern scan already ran on all
	const changedPatternFindings = diffCache
		? patternFindings.filter((f) => changedFiles.has(f.file))
		: patternFindings;

	// ── Step 4: LLM Deep Analysis ──────────────────────────────────────────
	let freshAnalysisResults: PatternFinding[] = changedPatternFindings;

	if (llmAvailable && callLLM) {
		onProgress({ step: 4, label: STEP_LABELS[4], status: "running" });
		try {
			freshAnalysisResults = await deepAnalysis(
				inventory,
				changedPatternFindings,
				fileMap,
				callLLM,
				(detail) => onProgress({ step: 4, label: STEP_LABELS[4], status: "running", detail }),
				abortSignal,
			);
			const truePositives = freshAnalysisResults.filter((r) => r.analysis?.verdict === "TRUE_POSITIVE").length;
			const falsePositives = freshAnalysisResults.filter((r) => r.analysis?.verdict === "FALSE_POSITIVE").length;
			const unanalyzed = freshAnalysisResults.filter((r) => r.analysis?.verdict === "UNANALYZED").length;
			const patternOnly = freshAnalysisResults.filter((r) => !r.analysis).length;
			const diffNote = diffCache ? ` · ${changedFileCount} files rescanned` : "";
			console.log(`[deepAnalysis] Results: ${truePositives} confirmed, ${falsePositives} false positive, ${unanalyzed} unanalyzed (>12), ${patternOnly} pattern-only (parse error)`);
			onProgress({
				step: 4,
				label: STEP_LABELS[4],
				status: "done",
				detail: `${truePositives} LLM-confirmed · ${falsePositives} false positive · ${patternOnly + unanalyzed} pattern-only${diffNote}`,
			});
		} catch (err) {
			onProgress({
				step: 4,
				label: STEP_LABELS[4],
				status: "error",
				detail: err instanceof Error ? err.message : "LLM analysis failed",
			});
		}
	} else {
		const skipDetail =
			mode === "secrets"
				? "Skipped (secrets-only mode)"
				: "No Groq/Gemini key — pattern scan results only";
		onProgress({ step: 4, label: STEP_LABELS[4], status: "done", detail: skipDetail });
	}

	// Merge fresh analysis with cached results for unchanged files
	const analysisResults: PatternFinding[] = [...freshAnalysisResults, ...cachedAnalysisForUnchanged];

	// Save updated diff cache (per-file analysis for future diff-aware runs)
	const newFindingsByFile: Record<string, PatternFinding[]> = {};
	for (const f of analysisResults) {
		if (!newFindingsByFile[f.file]) newFindingsByFile[f.file] = [];
		newFindingsByFile[f.file].push(f);
	}
	saveDiffCache({ fileHashes: currentFileHashes, findingsByFile: newFindingsByFile, patternFingerprint, savedAt: Date.now() });

	if (abortSignal?.aborted) {
		return compileReport(inventory, depFindings, analysisResults, scannedAt, mode, llmAvailable);
	}

	// ── Step 5: Cross-Reference ────────────────────────────────────────────
	onProgress({ step: 5, label: STEP_LABELS[5], status: "running" });
	const enrichedResults = crossReference(analysisResults);
	onProgress({
		step: 5,
		label: STEP_LABELS[5],
		status: "done",
		detail: "ATT&CK · Sigma · NIST mapping (coming soon)",
	});

	// ── Step 6: Compile Report ─────────────────────────────────────────────
	onProgress({ step: 6, label: STEP_LABELS[6], status: "running" });
	const report = compileReport(inventory, depFindings, enrichedResults, scannedAt, mode, llmAvailable);
	onProgress({
		step: 6,
		label: STEP_LABELS[6],
		status: "done",
		detail: `${report.summary.totalFindings} findings`,
	});

	return report;
}

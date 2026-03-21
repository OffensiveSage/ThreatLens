import { describe, expect, it } from "vitest";
import type { AgenticFinding } from "./agenticScan";
import { buildInventory } from "./agenticScan";
import type { EmbeddedChunk } from "./embedder";
import {
	buildFileGroupedSecurityResults,
	buildSecurityChatContextPlan,
	buildSecurityChatIntent,
	isCodeSecurityChatQuery,
	rankFilesForSecurityChat,
} from "./securityChat";
import { VectorStore, type SearchResult } from "./vectorStore";

function makeChunk(
	id: string,
	filePath: string,
	code: string,
	startLine: number,
	endLine: number
): EmbeddedChunk {
	return {
		id,
		filePath,
		language: "typescript",
		nodeType: "chunk",
		name: id,
		code,
		startLine,
		endLine,
		embedding: [0.1, 0.2, 0.3],
	};
}

describe("securityChat", () => {
	it("detects code security chat queries", () => {
		expect(isCodeSecurityChatQuery("find authentication vulnerabilities")).toBe(true);
		expect(isCodeSecurityChatQuery("where is the request handler defined")).toBe(false);
	});

	it("builds auth-focused retrieval intent with larger top-k", () => {
		const intent = buildSecurityChatIntent("find authentication vulnerabilities");
		expect(intent.topChunkLimit).toBe(20);
		expect(intent.topFiles).toBe(5);
		expect(intent.inventoryBuckets).toContain("authFiles");
		expect(intent.filenameTerms).toContain("auth");
	});

	it("ranks auth files above unrelated seed hits", () => {
		const chunks = [
			makeChunk("auth-1", "src/auth.ts", "function authenticate(token) { return verifyJwt(token); }", 1, 20),
			makeChunk("auth-2", "src/auth.ts", "export function login(password) { return password.length > 0; }", 21, 40),
			makeChunk("util-1", "src/utils.ts", "export function formatDate(input) { return input; }", 1, 20),
		];
		const { inventory, fileMap } = buildInventory(chunks);
		const seedResults: SearchResult[] = [
			{ chunk: chunks[2], score: 0.9, embedding: chunks[2].embedding },
			{ chunk: chunks[0], score: 0.45, embedding: chunks[0].embedding },
		];

		const ranked = rankFilesForSecurityChat({
			query: "find authentication vulnerabilities",
			inventory,
			fileMap,
			seedResults,
		});

		expect(ranked[0]?.filePath).toBe("src/auth.ts");
		expect(ranked[0]?.score).toBeGreaterThan(ranked[1]?.score ?? 0);
	});

	it("uses agentic findings to boost the right file for injection questions", () => {
		const chunks = [
			makeChunk("db-1", "src/db/query.ts", "db.query(`SELECT * FROM users WHERE id = ${id}`)", 1, 20),
			makeChunk("route-1", "src/routes/users.ts", "router.get('/users/:id', loadUser)", 1, 20),
			makeChunk("misc-1", "src/utils.ts", "export const noop = () => null;", 1, 20),
		];
		const { inventory, fileMap } = buildInventory(chunks);
		const findings: AgenticFinding[] = [
			{
				name: "SQL Injection",
				severity: "HIGH",
				category: "injection",
				file: "src/db/query.ts",
				line: 1,
				cwe: "CWE-89",
				explanation: "String interpolation reaches a SQL query sink.",
				attack_techniques: [],
				sigma_rules: [],
				compliance_controls: [],
			},
		];

		const ranked = rankFilesForSecurityChat({
			query: "tell me about the SQL injection",
			inventory,
			fileMap,
			seedResults: [{ chunk: chunks[2], score: 0.85, embedding: chunks[2].embedding }],
			scanFindings: findings,
		});

		expect(ranked[0]?.filePath).toBe("src/db/query.ts");
	});

	it("expands to full-file results in file and line order", () => {
		const store = new VectorStore();
		const chunks = [
			makeChunk("auth-2", "src/auth.ts", "line 20", 20, 25),
			makeChunk("auth-1", "src/auth.ts", "line 1", 1, 10),
			makeChunk("cfg-1", "config/app.env", "SECRET=abc", 1, 1),
		];
		store.insert(chunks);

		const expanded = buildFileGroupedSecurityResults(
			store,
			[
				{ filePath: "src/auth.ts", score: 10, reasons: ["inventory:authFiles"] },
				{ filePath: "config/app.env", score: 8, reasons: ["inventory:configFiles"] },
			],
			[{ chunk: chunks[2], score: 0.5, embedding: chunks[2].embedding }],
			2
		);

		expect(expanded.map((entry) => entry.chunk.id)).toEqual(["auth-1", "auth-2", "cfg-1"]);
	});

	it("builds a file-grouped context plan with relevant scan findings", () => {
		const store = new VectorStore();
		const chunks = [
			makeChunk("auth-1", "src/auth.ts", "function authenticate(token) { return verifyJwt(token); }", 1, 20),
			makeChunk("auth-2", "src/auth.ts", "export function login(password) { return password.length > 0; }", 21, 40),
			makeChunk("cfg-1", "config/app.env", "JWT_SECRET=dev-secret", 1, 1),
		];
		store.insert(chunks);

		const plan = buildSecurityChatContextPlan({
			store,
			query: "find authentication vulnerabilities",
			seedResults: [{ chunk: chunks[0], score: 0.6, embedding: chunks[0].embedding }],
			scanFindings: [
				{
					name: "Weak JWT Validation",
					severity: "HIGH",
					category: "auth",
					file: "src/auth.ts",
					line: 4,
					explanation: "JWT validation skips audience verification.",
					attack_techniques: [],
					sigma_rules: [],
					compliance_controls: [],
				},
			],
		});

		expect(plan.rankedFiles[0]?.filePath).toBe("src/auth.ts");
		expect(plan.fileGroupedResults.length).toBeGreaterThanOrEqual(2);
		expect(plan.relevantScanFindings[0]?.file).toBe("src/auth.ts");
		expect(plan.scanFindingsContext).toContain("Weak JWT Validation");
	});
});

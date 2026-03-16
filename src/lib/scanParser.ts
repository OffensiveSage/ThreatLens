/**
 * scanParser — parses structured LLM scan output into typed findings.
 *
 * Expected LLM output format per finding block:
 *   FINDING: <short title>
 *   SEVERITY: CRITICAL|HIGH|MEDIUM|LOW|INFO
 *   STATUS: CONFIRMED|INFERRED|POTENTIAL
 *   FILE: <path or "—">
 *   DETAIL: <description>
 *   ---
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "CONFIRMED" | "INFERRED" | "POTENTIAL";

export interface ScanFinding {
	section: string;
	severity: Severity;
	status: FindingStatus;
	file?: string;
	detail: string;
	title: string;
}

export interface SeverityCounts {
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

export interface ScanSection {
	id: string;
	label: string;
	queries: string[];
}

export const SCAN_SECTIONS: ScanSection[] = [
	{
		id: "injection",
		label: "Injection & Auth Flaws",
		queries: [
			"sql injection authentication login password session token",
			"command injection eval exec subprocess shell",
			"auth bypass insecure authentication authorization",
		],
	},
	{
		id: "secrets",
		label: "Secrets & Data Exposure",
		queries: [
			"api key secret password token credential hardcoded",
			"sensitive data exposure plaintext private key",
			"environment variable config secret leak",
		],
	},
	{
		id: "attack-surface",
		label: "Attack Surface",
		queries: [
			"route endpoint handler http request response input",
			"file upload user input untrusted data validation",
			"external api network call external service",
		],
	},
	{
		id: "config",
		label: "Config & Hardening",
		queries: [
			"cors header ssl tls certificate configuration insecure",
			"dependency package outdated version vulnerability",
			"logging error handling debug production security",
		],
	},
];

// ─── Parser ────────────────────────────────────────────────────────────────

function normalizeSeverity(raw: string): Severity {
	const s = raw.trim().toLowerCase();
	if (s === "critical") return "critical";
	if (s === "high") return "high";
	if (s === "medium" || s === "med") return "medium";
	if (s === "low") return "low";
	return "info";
}

function normalizeStatus(raw: string): FindingStatus {
	const s = raw.trim().toUpperCase();
	if (s === "CONFIRMED") return "CONFIRMED";
	if (s === "INFERRED") return "INFERRED";
	return "POTENTIAL";
}

/**
 * Parse raw LLM output for a scan section into structured findings.
 * Tolerates minor deviations — treats any paragraph with SEVERITY: as a finding.
 */
export function parseFindings(raw: string, section: string): ScanFinding[] {
	if (!raw?.trim()) return [];

	const findings: ScanFinding[] = [];
	// Split on separator lines or double-newlines before a FINDING: marker
	const blocks = raw.split(/\n---+\n|\n(?=FINDING:)/g);

	for (const block of blocks) {
		const lines = block.split("\n").map((l) => l.trim());

		const titleLine = lines.find((l) => l.startsWith("FINDING:"));
		const severityLine = lines.find((l) => l.startsWith("SEVERITY:"));
		const statusLine = lines.find((l) => l.startsWith("STATUS:"));
		const fileLine = lines.find((l) => l.startsWith("FILE:"));
		const detailLine = lines.find((l) => l.startsWith("DETAIL:"));

		// Must at minimum have a severity to be a real finding
		if (!severityLine) continue;

		const title = titleLine ? titleLine.replace(/^FINDING:\s*/i, "").trim() : "Unnamed Finding";
		const severity = normalizeSeverity(severityLine.replace(/^SEVERITY:\s*/i, ""));
		const status = statusLine ? normalizeStatus(statusLine.replace(/^STATUS:\s*/i, "")) : "POTENTIAL";
		const file = fileLine
			? fileLine.replace(/^FILE:\s*/i, "").trim().replace(/^—$/, "")
			: undefined;
		const detail = detailLine
			? detailLine.replace(/^DETAIL:\s*/i, "").trim()
			: lines.filter((l) => !l.match(/^(FINDING|SEVERITY|STATUS|FILE|DETAIL):/i) && l.length > 0).join(" ").trim();

		if (!detail && !title) continue;

		findings.push({ section, severity, status, file: file || undefined, detail: detail || title, title });
	}

	return findings;
}

// ─── Risk scoring ──────────────────────────────────────────────────────────

export function countSeverities(findings: ScanFinding[]): SeverityCounts {
	const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of findings) counts[f.severity]++;
	return counts;
}

/**
 * Score 0–100. Higher = safer.
 * Critical findings carry the most weight.
 */
export function calcRiskScore(counts: SeverityCounts): number {
	const penalty =
		counts.critical * 30 +
		counts.high * 12 +
		counts.medium * 4 +
		counts.low * 1;
	return Math.max(0, Math.min(100, 100 - penalty));
}

export type RiskGrade = "A" | "B" | "C" | "D" | "F";

export function riskGrade(score: number): RiskGrade {
	if (score >= 90) return "A";
	if (score >= 75) return "B";
	if (score >= 55) return "C";
	if (score >= 35) return "D";
	return "F";
}

export function gradeColor(grade: RiskGrade): string {
	switch (grade) {
		case "A": return "#2E7D32";  // dark green
		case "B": return "#558B2F";  // sage
		case "C": return "#F57F17";  // amber
		case "D": return "#E65100";  // deep orange
		case "F": return "#B71C1C";  // critical red
	}
}

export function severityColor(severity: Severity): string {
	switch (severity) {
		case "critical": return "#B71C1C";
		case "high":     return "#E65100";
		case "medium":   return "#F57F17";
		case "low":      return "#2E7D32";
		case "info":     return "#5B7FA5";
	}
}

export function severityBg(severity: Severity): string {
	switch (severity) {
		case "critical": return "rgba(183,28,28,0.1)";
		case "high":     return "rgba(230,81,0,0.1)";
		case "medium":   return "rgba(245,127,23,0.1)";
		case "low":      return "rgba(46,125,50,0.1)";
		case "info":     return "rgba(91,127,165,0.1)";
	}
}

/**
 * complianceMapper.ts
 *
 * Maps AgenticFinding[] → ComplianceResult by bridging:
 *   Code Finding → CWE ID → NIST 800-53 Controls → NIST CSF Functions → NIS2 Articles
 */

import type { AgenticFinding } from "./agenticScan";
import cweMap from "../data/cweComplianceMap.json";
import nis2Articles from "../data/nis2Articles.json";

// ─── Types ────────────────────────────────────────────────────────────────────

type CWEEntry = {
	name: string;
	nist_800_53: string[];
	nist_csf: { function: string; category: string; subcategory: string } | null;
	nis2_articles: string[];
};

const cweMapTyped = cweMap as Record<string, CWEEntry>;

export interface MappedFinding extends AgenticFinding {
	compliance: {
		nist_800_53: string[];
		nis2_articles: string[];
	};
}

export interface NIS2ArticleStatus {
	id: string;
	article: string;
	title: string;
	description: string;
	status: string;
	assessable_from_code: boolean;
	findings: Array<{ name: string; severity: string; cwe: string; file: string }>;
	finding_count: number;
	statusNote?: string;
}

export interface ComplianceResult {
	riskScore: number;
	mappedFindings: MappedFinding[];
	recommendations: Array<{
		priority: number;
		category: string;
		action: string;
		affectedControls: string[];
		findingCount: number;
		impact: string;
	}>;
	nist80053: {
		totalViolatedControls: number;
		violatedControls: Record<
			string,
			Array<{ finding: string; severity: string; file: string; line?: number; cwe: string }>
		>;
		families: Record<
			string,
			{
				total_violated: number;
				controls: Array<{
					controlId: string;
					findings: Array<{ finding: string; severity: string; file: string; line?: number; cwe: string }>;
				}>;
				max_severity: string;
			}
		>;
	};
	nistCSF: {
		scores: Record<string, number | "N/A">;
		assessableFromCode: Record<string, boolean>;
		functionFindings: Record<string, MappedFinding[]>;
		categoryFindings: Record<string, MappedFinding[]>;
	};
	nis2: {
		articles: Record<string, NIS2ArticleStatus>;
		readinessPercent: number;
		totalArticles: number;
		assessedFromCode: number;
		notAssessed: number;
	};
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function maxSeverity(a: string, b: string): string {
	return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

// ─── NIST 800-53 ──────────────────────────────────────────────────────────────

function calculateNIST80053(mapped: MappedFinding[]): ComplianceResult["nist80053"] {
	const violatedControls: Record<
		string,
		Array<{ finding: string; severity: string; file: string; line?: number; cwe: string }>
	> = {};

	for (const f of mapped) {
		for (const controlId of f.compliance.nist_800_53) {
			if (!violatedControls[controlId]) violatedControls[controlId] = [];
			violatedControls[controlId].push({
				finding: f.name,
				severity: f.severity,
				file: f.file,
				line: f.line,
				cwe: f.cwe ?? "",
			});
		}
	}

	const families: ComplianceResult["nist80053"]["families"] = {};
	for (const [controlId, findings] of Object.entries(violatedControls)) {
		const family = controlId.split("-")[0] ?? controlId;
		if (!families[family]) {
			families[family] = { total_violated: 0, controls: [], max_severity: "LOW" };
		}
		families[family].total_violated++;
		families[family].controls.push({ controlId, findings });
		for (const f of findings) {
			families[family].max_severity = maxSeverity(families[family].max_severity, f.severity);
		}
	}

	return {
		totalViolatedControls: Object.keys(violatedControls).length,
		violatedControls,
		families,
	};
}

// ─── NIST CSF ─────────────────────────────────────────────────────────────────

const CSF_FUNCTIONS = ["Identify", "Protect", "Detect", "Respond", "Recover"] as const;

const ASSESSABLE_FROM_CODE: Record<string, boolean> = {
	Identify: false,
	Protect: true,
	Detect: true,
	Respond: false,
	Recover: false,
};

function calculateNISTCSF(mapped: MappedFinding[]): ComplianceResult["nistCSF"] {
	const functionFindings: Record<string, MappedFinding[]> = {
		Identify: [],
		Protect: [],
		Detect: [],
		Respond: [],
		Recover: [],
	};
	const categoryFindings: Record<string, MappedFinding[]> = {};

	for (const f of mapped) {
		const cweEntry = f.cwe ? cweMapTyped[f.cwe] : null;
		if (!cweEntry?.nist_csf) continue;

		const fn = cweEntry.nist_csf.function;
		const cat = cweEntry.nist_csf.category;

		if (functionFindings[fn]) {
			functionFindings[fn].push(f);
		}
		if (!categoryFindings[cat]) categoryFindings[cat] = [];
		categoryFindings[cat].push(f);
	}

	const scores: Record<string, number | "N/A"> = {};
	for (const fn of CSF_FUNCTIONS) {
		if (!ASSESSABLE_FROM_CODE[fn] && (functionFindings[fn]?.length ?? 0) === 0) {
			scores[fn] = "N/A";
			continue;
		}
		let score = 100;
		const penalty: Record<string, number> = { CRITICAL: 15, HIGH: 10, MEDIUM: 5, LOW: 2 };
		for (const f of functionFindings[fn] ?? []) {
			score -= penalty[f.severity] ?? 3;
		}
		scores[fn] = Math.max(0, Math.min(100, score));
	}

	return { scores, assessableFromCode: ASSESSABLE_FROM_CODE, functionFindings, categoryFindings };
}

// ─── NIS2 ─────────────────────────────────────────────────────────────────────

function calculateNIS2(mapped: MappedFinding[]): ComplianceResult["nis2"] {
	const articles: Record<string, NIS2ArticleStatus> = {};

	for (const art of nis2Articles.articles) {
		if (art.assessable_from_code) {
			const related = mapped.filter((f) =>
				f.compliance.nis2_articles.some((a) => a.startsWith(art.article.split(" - ")[0] ?? art.article))
			);

			let status: string;
			if (related.length === 0) {
				status = "Pass";
			} else {
				const hasCritical = related.some((f) => f.severity === "CRITICAL");
				const hasHigh = related.some((f) => f.severity === "HIGH");
				status = hasCritical ? "Non-Compliant" : hasHigh ? "Partial" : "Needs Improvement";
			}

			articles[art.id] = {
				id: art.id,
				article: art.article,
				title: art.title,
				description: art.description,
				assessable_from_code: true,
				status,
				findings: related.map((f) => ({
					name: f.name,
					severity: f.severity,
					cwe: f.cwe ?? "",
					file: f.file,
				})),
				finding_count: related.length,
			};
		} else {
			articles[art.id] = {
				id: art.id,
				article: art.article,
				title: art.title,
				description: art.description,
				assessable_from_code: false,
				status: "Not Assessed",
				statusNote: (art as { fallback_status?: string }).fallback_status ?? "Not Assessed - Requires manual review",
				findings: [],
				finding_count: 0,
			};
		}
	}

	const allArticles = Object.values(articles);
	const assessed = allArticles.filter((a) => a.assessable_from_code);
	const passing = assessed.filter((a) => a.status === "Pass");
	const readinessPercent = assessed.length > 0 ? Math.round((passing.length / assessed.length) * 100) : 0;

	return {
		articles,
		readinessPercent,
		totalArticles: nis2Articles.articles.length,
		assessedFromCode: assessed.length,
		notAssessed: nis2Articles.articles.length - assessed.length,
	};
}

// ─── Risk Score ───────────────────────────────────────────────────────────────

function calculateRiskScore(
	findings: AgenticFinding[],
	nist80053: ComplianceResult["nist80053"],
	nistCSF: ComplianceResult["nistCSF"],
): number {
	let score = 100;
	const penalty: Record<string, number> = { CRITICAL: 8, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
	for (const f of findings) {
		score -= penalty[f.severity] ?? 1;
	}
	score -= nist80053.totalViolatedControls * 1.5;

	const nums = Object.values(nistCSF.scores).filter((s): s is number => typeof s === "number");
	if (nums.length > 0) {
		const csfAvg = nums.reduce((a, b) => a + b, 0) / nums.length;
		score += csfAvg * 0.1;
	}

	return Math.max(0, Math.min(100, Math.round(score)));
}

// ─── Recommendations ──────────────────────────────────────────────────────────

const REC_TEMPLATES: Record<
	string,
	{ action: string; affectedControls: string[] }
> = {
	secrets: {
		action:
			"Implement secrets management (e.g., HashiCorp Vault, AWS Secrets Manager). Remove all hardcoded credentials and rotate compromised keys immediately.",
		affectedControls: ["IA-5", "SC-12"],
	},
	injection: {
		action:
			"Implement parameterized queries and input validation across all data entry points. Conduct developer training on secure coding practices.",
		affectedControls: ["SI-10", "SA-11"],
	},
	auth: {
		action:
			"Implement proper authentication and authorization framework. Add multi-factor authentication for privileged operations. Review access control model.",
		affectedControls: ["IA-2", "AC-3", "AC-6"],
	},
	crypto: {
		action:
			"Upgrade all cryptographic implementations to current standards (AES-256, SHA-256+). Replace weak hash algorithms. Enforce TLS 1.2+ for all communications.",
		affectedControls: ["SC-12", "SC-13"],
	},
	transport: {
		action:
			"Enforce HTTPS/TLS for all network communications. Implement HSTS headers. Remove all plaintext HTTP endpoints.",
		affectedControls: ["SC-8", "SC-23"],
	},
	data: {
		action:
			"Implement data classification and handling procedures. Add input validation for all deserialization and file handling operations.",
		affectedControls: ["SI-10", "MP-4"],
	},
	config: {
		action:
			"Disable debug mode in production. Implement security configuration baseline. Add automated configuration compliance checking.",
		affectedControls: ["CM-6", "CM-7"],
	},
	logic: {
		action:
			"Conduct thorough security design review of authentication and authorization flows. Implement automated security testing in CI/CD pipeline.",
		affectedControls: ["SA-11", "SA-15"],
	},
};

function generateRecommendations(
	mapped: MappedFinding[],
): ComplianceResult["recommendations"] {
	const categories: Record<string, { count: number; maxSeverity: string }> = {};
	for (const f of mapped) {
		const cat = f.category;
		if (!categories[cat]) categories[cat] = { count: 0, maxSeverity: "LOW" };
		categories[cat].count++;
		categories[cat].maxSeverity = maxSeverity(categories[cat].maxSeverity, f.severity);
	}

	const recs: ComplianceResult["recommendations"] = [];
	for (const [cat, data] of Object.entries(categories).sort((a, b) => b[1].count - a[1].count)) {
		const tmpl = REC_TEMPLATES[cat];
		if (!tmpl) continue;
		recs.push({
			priority: recs.length + 1,
			category: cat,
			action: tmpl.action,
			affectedControls: tmpl.affectedControls,
			findingCount: data.count,
			impact: data.count >= 3 ? "High" : data.count >= 2 ? "Medium" : "Low",
		});
		if (recs.length >= 5) break;
	}

	return recs;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Map AgenticFinding[] → ComplianceResult.
 * Filters out FALSE_POSITIVE verdicts before mapping.
 */
export function mapToCompliance(findings: AgenticFinding[]): ComplianceResult {
	// Exclude false positives
	const confirmed = findings.filter((f) => f.verdict !== "FALSE_POSITIVE");

	// Attach compliance tags to each finding via CWE bridge
	const mapped: MappedFinding[] = confirmed.map((f) => {
		const cweEntry = f.cwe ? cweMapTyped[f.cwe] ?? null : null;
		return {
			...f,
			compliance: {
				nist_800_53: cweEntry?.nist_800_53 ?? [],
				nis2_articles: cweEntry?.nis2_articles ?? [],
			},
		};
	});

	const nist80053 = calculateNIST80053(mapped);
	const nistCSF = calculateNISTCSF(mapped);
	const nis2 = calculateNIS2(mapped);
	const riskScore = calculateRiskScore(confirmed, nist80053, nistCSF);
	const recommendations = generateRecommendations(mapped);

	return { riskScore, mappedFindings: mapped, recommendations, nist80053, nistCSF, nis2 };
}

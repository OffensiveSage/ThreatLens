/**
 * Security Report Generator — PDF + Markdown export.
 * Designed for non-technical stakeholders AND security teams:
 *   - Plain-English "what it means / why it matters / how to fix" for every finding
 *   - Visual risk level on cover page
 *   - Priority action plan upfront (most urgent first)
 *   - Consistent card layout per finding
 */

import type { Message } from "@/app/[owner]/[repo]/types";

export interface ReportMetadata {
	target?: string;
	sources: string[];
	date?: string;
}

export interface Finding {
	title: string;
	description: string;
	location: string;
	recommendation: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

const SEVERITY_COLORS_RGB: Record<string, [number, number, number]> = {
	CRITICAL: [220, 53, 69],
	HIGH: [230, 140, 20],
	MEDIUM: [200, 155, 0],
	LOW: [40, 167, 69],
	INFO: [23, 162, 184],
};

/** What the severity label says to a non-technical reader */
const PRIORITY_LABELS: Record<string, string> = {
	CRITICAL: "Fix Immediately",
	HIGH: "Fix This Week",
	MEDIUM: "Fix This Month",
	LOW: "Review When Possible",
	INFO: "For Your Information",
};

/** Headline risk level label for the cover page */
const RISK_LABELS: Record<string, string> = {
	CRITICAL: "CRITICAL RISK",
	HIGH: "HIGH RISK",
	MEDIUM: "MODERATE RISK",
	LOW: "LOW RISK",
	INFO: "INFORMATIONAL",
};

// ─── Severity helpers ─────────────────────────────────────────────────────────

function normalizeSeverity(raw: string): Finding["severity"] {
	const s = raw.trim().toUpperCase();
	if (s === "CRITICAL") return "CRITICAL";
	if (s === "HIGH") return "HIGH";
	if (s === "MEDIUM") return "MEDIUM";
	if (s === "LOW") return "LOW";
	return "INFO";
}

function inferSeverity(text: string): Finding["severity"] {
	const lower = text.toLowerCase();
	if (
		lower.includes("critical") ||
		lower.includes("rce") ||
		lower.includes("remote code execution") ||
		lower.includes("unauthenticated")
	)
		return "CRITICAL";
	if (
		lower.includes("sql injection") ||
		lower.includes("authentication bypass") ||
		lower.includes("high severity") ||
		lower.includes("privilege escalat")
	)
		return "HIGH";
	if (
		lower.includes("xss") ||
		lower.includes("insecure") ||
		lower.includes("missing") ||
		lower.includes("medium severity")
	)
		return "MEDIUM";
	if (
		lower.includes("info") ||
		lower.includes("best practice") ||
		lower.includes("low severity")
	)
		return "LOW";
	return "MEDIUM";
}

function computeOverallRisk(findings: Finding[]): Finding["severity"] {
	for (const sev of SEVERITY_ORDER) {
		if (findings.some((f) => f.severity === sev)) return sev;
	}
	return "INFO";
}

/**
 * Returns a plain-English business impact sentence for a finding.
 * No security jargon — written for a non-technical reader.
 */
function getBusinessImpact(finding: Finding): string {
	const text = (finding.title + " " + finding.description).toLowerCase();

	if (text.includes("sql injection") || text.includes("sqli"))
		return "An attacker could read, modify, or delete all data in your database — including passwords, user accounts, and private records.";
	if (text.includes("xss") || text.includes("cross-site scripting"))
		return "Attackers could steal users' login sessions or trick them into taking actions they didn't intend, without ever knowing it happened.";
	if (text.includes("rce") || text.includes("remote code execution"))
		return "An attacker could run any program on your server. This gives them full control over your system and everything on it.";
	if (text.includes("authentication bypass") || text.includes("auth bypass") || text.includes("broken auth"))
		return "Someone could log into protected accounts or admin areas without knowing the password.";
	if (text.includes("ssrf"))
		return "Attackers could make your server talk to internal systems that should never be exposed — potentially leaking private data.";
	if (text.includes("idor") || text.includes("insecure direct object"))
		return "Users could view or modify other users' private data just by changing a number in the web address. No hacking needed.";
	if (text.includes("path traversal") || text.includes("directory traversal"))
		return "Attackers could read sensitive files on your server — like passwords, configuration, and private keys.";
	if (text.includes("csrf") || text.includes("cross-site request forgery"))
		return "Attackers could trick your users into accidentally doing things — like changing passwords, making purchases, or deleting data.";
	if (
		text.includes("hardcoded") ||
		text.includes("api key") ||
		(text.includes("secret") && text.includes("code")) ||
		(text.includes("credential") && text.includes("source"))
	)
		return "Passwords or private keys are stored directly in your code. Anyone who reads your code can access your services — no hacking required.";
	if (text.includes("dos") || text.includes("denial of service"))
		return "An attacker could crash your application or make it too slow to use, blocking all legitimate users.";
	if (text.includes("open redirect"))
		return "Attackers can use your website to redirect users to fake sites — making phishing attacks much easier to pull off.";
	if (text.includes("xxe") || text.includes("xml external"))
		return "Attackers could read your server's internal files or reach internal systems by sending specially crafted data.";
	if (text.includes("insecure deserialization"))
		return "Attackers could manipulate data sent to your server to run malicious code or bypass security checks entirely.";
	if (text.includes("broken access") || text.includes("missing authoriz"))
		return "Users may be able to access features or data they're not supposed to — such as other users' accounts or admin pages.";
	if (text.includes("outdated") || text.includes("vulnerable component") || text.includes("dependency"))
		return "Your application uses old software with known security holes. Attackers regularly scan for these and have ready-made exploits.";
	if (text.includes("logging") || text.includes("monitoring"))
		return "If an attack happens, you may not be able to detect it or understand what happened — making recovery much harder.";

	// Severity-based fallbacks
	if (finding.severity === "CRITICAL")
		return "This is a serious problem. An attacker could use it to take over your system or access all your data.";
	if (finding.severity === "HIGH")
		return "This issue could be exploited to gain unauthorized access to sensitive data or key functionality.";
	if (finding.severity === "MEDIUM")
		return "This is a moderate risk that could be combined with other issues. It should be fixed in your next release.";
	return "This is a low-risk concern. Fixing it is good security hygiene but does not require urgent action.";
}

// ─── Finding extraction ────────────────────────────────────────────────────────

function parseSeverityTable(content: string): Record<string, Finding["severity"]> {
	const map: Record<string, Finding["severity"]> = {};
	const tableRe = /Severity\s+Level\s+of\s+Findings:[\s\S]*?(?=\n\n|\n[A-Z]{2,}|$)/i;
	const block = content.match(tableRe)?.[0] ?? "";
	const lineRe = /^(.+?):\s*(Critical|High|Medium|Low|Info(?:rmational)?)\s*$/gim;
	let m;
	while ((m = lineRe.exec(block)) !== null) {
		const key = m[1].trim().toLowerCase().replace(/^no\s+/i, "");
		const sev = normalizeSeverity(m[2]);
		if (sev !== "INFO" || m[2].toLowerCase().startsWith("info")) {
			map[key] = sev;
		}
	}
	return map;
}

export function extractFindings(messages: Message[]): Finding[] {
	const findings: Finding[] = [];

	for (const msg of messages) {
		if (msg.role !== "assistant") continue;
		const content = msg.content;
		const severityTable = parseSeverityTable(content);

		// Format 1: Structured numbered findings with Description:/Location: sub-fields
		const numberedSplit = content.split(/\n(?=\d+\.\s+\S)/);
		let structuredCount = 0;

		for (const section of numberedSplit) {
			const titleMatch = section.match(/^\d+\.\s+\*{0,2}([^*\n]+?)\*{0,2}\s*$/m);
			if (!titleMatch) continue;
			const title = titleMatch[1].trim();
			if (title.length < 4) continue;

			const descMatch = section.match(
				/Description:\s*([\s\S]+?)(?=\n(?:Location|Recommendation|Severity|Evidence|Impact|References|$))/i
			);
			const locMatch = section.match(
				/Location:\s*([\s\S]+?)(?=\n(?:Description|Recommendation|Severity|Evidence|References|$))/i
			);
			const recMatch = section.match(
				/Recommendation:\s*([\s\S]+?)(?=\n(?:Location|Description|Severity|Evidence|References|$))/i
			);

			const desc = descMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";
			const loc = locMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";
			const rec = recMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";

			if (!desc && !loc) continue;

			const tableKey = title.toLowerCase().replace(/^no\s+/i, "");
			const tableSev = Object.entries(severityTable).find(
				([k]) => tableKey.includes(k) || k.includes(tableKey.split(" ")[0] ?? "")
			)?.[1];

			findings.push({
				title,
				description: desc || rec || title,
				location: loc,
				recommendation: rec,
				severity: tableSev ?? inferSeverity(title + " " + desc),
			});
			structuredCount++;
		}

		// Format 2: Markdown bold  "**Title**: description"
		if (structuredCount === 0) {
			const boldRe = /(?:\d+\.\s+)?\*\*([^*\n]{3,})\*\*[:\s–-]+([^\n]{10,})/g;
			let m;
			while ((m = boldRe.exec(content)) !== null) {
				const title = m[1].trim();
				const description = m[2].trim();
				const tableKey = title.toLowerCase();
				const tableSev = Object.entries(severityTable).find(
					([k]) => tableKey.includes(k) || k.includes(tableKey.split(" ")[0] ?? "")
				)?.[1];
				findings.push({
					title,
					description,
					location: "",
					recommendation: "",
					severity: tableSev ?? inferSeverity(title + " " + description),
				});
			}
		}

		// Format 3: Bullet list under "Summary of Findings:"
		if (findings.length === 0) {
			const summaryMatch = content.match(
				/Summary of Findings:[\s\S]+?(?=\n\n[A-Z]|\nDetailed|$)/i
			);
			if (summaryMatch) {
				const bulletRe = /-\s+\*{0,2}([^*:\n]+?)\*{0,2}:\s*(.+)/g;
				let bm;
				while ((bm = bulletRe.exec(summaryMatch[0])) !== null) {
					findings.push({
						title: bm[1].trim(),
						description: bm[2].trim(),
						location: "",
						recommendation: "",
						severity: inferSeverity(bm[1] + " " + bm[2]),
					});
				}
			}
		}
	}

	// Deduplicate
	const seen = new Set<string>();
	return findings.filter((f) => {
		const key = f.title.toLowerCase();
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

// ─── Section parser for fallback rendering ───────────────────────────────────

interface ReportSection {
	heading: string;
	level: 1 | 2 | 3;
	body: string;
}

function parseReportSections(content: string): ReportSection[] {
	const sections: ReportSection[] = [];
	const lines = content.split("\n");
	let current: ReportSection | null = null;
	const bodyLines: string[] = [];

	const flush = () => {
		if (current) {
			current.body = bodyLines.join("\n").trim();
			sections.push(current);
			bodyLines.length = 0;
		}
	};

	for (const line of lines) {
		const mdHeading = line.match(/^(#{1,3})\s+(.+)/);
		const colonHeading = line.match(/^([A-Z][A-Za-z\s&/]+):?\s*$/);

		if (mdHeading) {
			flush();
			current = {
				heading: mdHeading[2].trim(),
				level: Math.min(mdHeading[1].length, 3) as 1 | 2 | 3,
				body: "",
			};
		} else if (colonHeading && line.trim().length > 3 && line.trim().length < 60) {
			flush();
			current = { heading: colonHeading[1].trim(), level: 2, body: "" };
		} else {
			if (!current) current = { heading: "", level: 3, body: "" };
			bodyLines.push(line);
		}
	}
	flush();
	return sections.filter((s) => s.heading || s.body);
}

// ─── PDF Export ────────────────────────────────────────────────────────────────

export async function generatePDFReport(
	messages: Message[],
	metadata: ReportMetadata
): Promise<void> {
	try {
		const { jsPDF } = await import("jspdf");
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const autoTable = (await import("jspdf-autotable")).default as any;

		const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
		const pageW = doc.internal.pageSize.getWidth();
		const pageH = doc.internal.pageSize.getHeight();
		const margin = 18;
		const contentW = pageW - margin * 2;
		let y = margin;

		const addPage = () => {
			doc.addPage();
			y = margin;
		};

		const checkPageBreak = (needed = 12) => {
			if (y + needed > pageH - 22) addPage();
		};

		const assistantMessages = messages.filter((m) => m.role === "assistant");
		const findings = extractFindings(messages);
		const overallRisk = findings.length > 0 ? computeOverallRisk(findings) : "INFO";
		const [rR, rG, rB] = SEVERITY_COLORS_RGB[overallRisk];
		const riskLabel = RISK_LABELS[overallRisk];

		const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
		for (const f of findings) counts[f.severity]++;

		// ── COVER: dark header banner ──────────────────────────────────────────────
		doc.setFillColor(15, 15, 15);
		doc.rect(0, 0, pageW, 58, "F");
		doc.setFillColor(rR, rG, rB);
		doc.rect(0, 58, pageW, 3, "F");

		doc.setFontSize(22);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(245, 166, 35);
		doc.text("THREATLENS", margin, 20);

		doc.setFontSize(11);
		doc.setFont("helvetica", "normal");
		doc.setTextColor(200, 200, 200);
		doc.text("SECURITY INTELLIGENCE REPORT", margin, 30);

		doc.setFontSize(8);
		doc.setTextColor(130, 130, 130);
		doc.text(`Generated: ${metadata.date ?? new Date().toLocaleDateString()}`, margin, 40);
		if (metadata.target) doc.text(`Target: ${metadata.target}`, margin, 47);
		doc.text(`Sources: ${metadata.sources.join(" · ")}`, margin, metadata.target ? 54 : 47);

		y = 72;

		// ── RISK BADGE ─────────────────────────────────────────────────────────────
		const badgeW = 88;
		const badgeH = 20;
		const badgeX = (pageW - badgeW) / 2;
		doc.setFillColor(rR, rG, rB);
		doc.rect(badgeX, y, badgeW, badgeH, "F");

		doc.setFontSize(13);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(255, 255, 255);
		doc.text(riskLabel, pageW / 2, y + 13, { align: "center" });
		y += badgeH + 8;

		// ── FINDING COUNTS ROW ─────────────────────────────────────────────────────
		if (findings.length > 0) {
			const statSevs = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).filter(
				(s) => counts[s] > 0
			);
			const colCount = Math.max(statSevs.length, 1);
			const colW = contentW / colCount;

			for (let idx = 0; idx < statSevs.length; idx++) {
				const sev = statSevs[idx];
				const [cr, cg, cb] = SEVERITY_COLORS_RGB[sev];
				const cx = margin + idx * colW;

				doc.setFillColor(240, 240, 240);
				doc.setDrawColor(cr, cg, cb);
				doc.setLineWidth(0.6);
				doc.rect(cx + 2, y, colW - 8, 20, "FD");

				doc.setFontSize(16);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(cr, cg, cb);
				doc.text(String(counts[sev]), cx + (colW - 6) / 2, y + 12, { align: "center" });

				doc.setFontSize(6.5);
				doc.setFont("helvetica", "normal");
				doc.setTextColor(90, 90, 90);
				doc.text(sev, cx + (colW - 6) / 2, y + 18, { align: "center" });
			}
			y += 28;
		}

		// ── "WHAT THIS MEANS" plain-English box ───────────────────────────────────
		const totalHigh = counts.CRITICAL + counts.HIGH;
		let plainSummary: string;
		if (findings.length === 0) {
			plainSummary =
				"No structured findings were extracted from this analysis. See the full content below for details.";
		} else if (overallRisk === "CRITICAL") {
			plainSummary = `This assessment found ${findings.length} security issue${findings.length !== 1 ? "s" : ""} including ${counts.CRITICAL} CRITICAL problem${counts.CRITICAL !== 1 ? "s" : ""}. These issues could allow attackers to take control of your system or steal data. Immediate action is required.`;
		} else if (overallRisk === "HIGH") {
			plainSummary = `This assessment found ${findings.length} security issue${findings.length !== 1 ? "s" : ""} including ${totalHigh} high-risk problem${totalHigh !== 1 ? "s" : ""}. These should be fixed as soon as possible — ideally within the next few days.`;
		} else if (overallRisk === "MEDIUM") {
			plainSummary = `This assessment found ${findings.length} security issue${findings.length !== 1 ? "s" : ""} at moderate severity. These won't cause immediate harm but should be addressed in your next development sprint.`;
		} else {
			plainSummary = `This assessment found ${findings.length} low-risk issue${findings.length !== 1 ? "s" : ""}. No urgent action is needed, but addressing these will improve your overall security posture.`;
		}

		doc.setFillColor(248, 248, 248);
		doc.setDrawColor(200, 200, 200);
		doc.setLineWidth(0.3);
		doc.setFontSize(8.5);
		doc.setFont("helvetica", "normal");
		const summaryWrapped = doc.splitTextToSize(plainSummary, contentW - 12);
		const summaryBoxH = summaryWrapped.length * 4.8 + 14;
		doc.rect(margin, y, contentW, summaryBoxH, "FD");
		doc.setFillColor(rR, rG, rB);
		doc.rect(margin, y, 3, summaryBoxH, "F");

		doc.setFontSize(7);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(100, 100, 100);
		doc.text("WHAT THIS MEANS", margin + 7, y + 7);

		doc.setFontSize(8.5);
		doc.setFont("helvetica", "normal");
		doc.setTextColor(30, 30, 30);
		doc.text(summaryWrapped, margin + 7, y + 13);
		y += summaryBoxH + 10;

		// ── PRIORITY ACTION PLAN ──────────────────────────────────────────────────
		if (findings.length > 0) {
			checkPageBreak(32);

			doc.setFontSize(11);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("PRIORITY ACTION PLAN", margin, y);
			y += 3;
			doc.setDrawColor(245, 166, 35);
			doc.setLineWidth(0.7);
			doc.line(margin, y, margin + contentW, y);
			y += 5;

			doc.setFontSize(8);
			doc.setFont("helvetica", "normal");
			doc.setTextColor(100, 100, 100);
			doc.text(
				"The issues below are listed in order of urgency. Start from the top.",
				margin,
				y
			);
			y += 8;

			const sortedActions = [...findings].sort(
				(a, b) =>
					SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
			);

			for (let i = 0; i < Math.min(sortedActions.length, 10); i++) {
				const f = sortedActions[i];
				const [cr, cg, cb] = SEVERITY_COLORS_RGB[f.severity];
				checkPageBreak(16);

				// Colored number circle
				doc.setFillColor(cr, cg, cb);
				doc.circle(margin + 4.5, y + 3, 4, "F");
				doc.setFontSize(7.5);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(255, 255, 255);
				doc.text(String(i + 1), margin + 4.5, y + 4.5, { align: "center" });

				// Priority label in color
				doc.setFontSize(6.5);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(cr, cg, cb);
				doc.text(PRIORITY_LABELS[f.severity].toUpperCase(), margin + 12, y + 1.5);

				// Finding title
				doc.setFontSize(9);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(20, 20, 20);
				doc.text(f.title, margin + 12, y + 7);

				// Short recommendation
				if (f.recommendation) {
					const shortRec =
						f.recommendation.slice(0, 100) +
						(f.recommendation.length > 100 ? "…" : "");
					doc.setFontSize(7.5);
					doc.setFont("helvetica", "normal");
					doc.setTextColor(80, 80, 80);
					const recW = doc.splitTextToSize(shortRec, contentW - 16);
					doc.text(recW, margin + 12, y + 12.5);
					y += recW.length * 4 + 14;
				} else {
					y += 14;
				}

				// Separator
				doc.setDrawColor(225, 225, 225);
				doc.setLineWidth(0.15);
				doc.line(margin + 10, y - 2, margin + contentW, y - 2);
			}

			if (sortedActions.length > 10) {
				doc.setFontSize(7.5);
				doc.setFont("helvetica", "italic");
				doc.setTextColor(140, 140, 140);
				doc.text(
					`+ ${sortedActions.length - 10} more findings detailed on the next page`,
					margin + 12,
					y
				);
				y += 6;
			}
			y += 4;
		}

		// ── DETAILED FINDINGS (one "card" per finding) ────────────────────────────
		if (findings.length > 0) {
			addPage();

			doc.setFontSize(13);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("DETAILED FINDINGS", margin, y);
			y += 3;
			doc.setDrawColor(245, 166, 35);
			doc.setLineWidth(0.8);
			doc.line(margin, y, margin + contentW, y);
			y += 5;

			doc.setFontSize(7.5);
			doc.setFont("helvetica", "normal");
			doc.setTextColor(130, 130, 130);
			doc.text(
				"Each finding explains what it is, why it matters in plain English, and exactly what to do about it.",
				margin,
				y
			);
			y += 10;

			for (let i = 0; i < findings.length; i++) {
				const f = findings[i];
				const [cr, cg, cb] = SEVERITY_COLORS_RGB[f.severity];
				const impact = getBusinessImpact(f);

				// Pre-measure card content height
				doc.setFontSize(8.5);
				doc.setFont("helvetica", "normal");
				const descText = f.description || "No description provided.";
				const descLines = doc.splitTextToSize(descText, contentW - 22);
				const impactLines = doc.splitTextToSize(impact, contentW - 22);
				const recLines = f.recommendation
					? doc.splitTextToSize(f.recommendation, contentW - 22)
					: [];

				const cardH =
					18 + // header
					6 + // divider gap
					7 + descLines.length * 4.8 + // WHAT IS THIS
					7 + impactLines.length * 4.8 + // WHY IT MATTERS
					(recLines.length > 0 ? 7 + recLines.length * 4.8 : 0) + // HOW TO FIX
					(f.location ? 8 : 0) + // location
					10; // padding

				checkPageBreak(cardH + 4);

				const cardStartY = y;

				// Card background + border
				doc.setFillColor(252, 252, 252);
				doc.setDrawColor(215, 215, 215);
				doc.setLineWidth(0.3);
				doc.rect(margin, cardStartY, contentW, cardH, "FD");

				// Severity color bar (left edge)
				doc.setFillColor(cr, cg, cb);
				doc.rect(margin, cardStartY, 4, cardH, "F");

				// Finding number
				doc.setFontSize(7.5);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(cr, cg, cb);
				doc.text(`#${i + 1}`, margin + 8, cardStartY + 9);

				// Title
				doc.setFontSize(10.5);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(20, 20, 20);
				const titleMaxW = contentW - 60;
				const titleLines = doc.splitTextToSize(f.title, titleMaxW);
				doc.text(titleLines, margin + 18, cardStartY + 9);

				// Severity + priority badge (right side of header)
				const badgeLabel = `${f.severity}  ·  ${PRIORITY_LABELS[f.severity]}`;
				const bw = doc.getTextWidth(badgeLabel) + 8;
				doc.setFillColor(cr, cg, cb);
				doc.rect(pageW - margin - bw, cardStartY + 3, bw, 7, "F");
				doc.setFontSize(6.5);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(255, 255, 255);
				doc.text(badgeLabel, pageW - margin - bw + 4, cardStartY + 8.5);

				// Divider under header
				y = cardStartY + 18;
				doc.setDrawColor(215, 215, 215);
				doc.setLineWidth(0.2);
				doc.line(margin + 6, y, margin + contentW - 4, y);
				y += 5;

				// ── WHAT IS THIS? ──
				doc.setFontSize(7);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(cr, cg, cb);
				doc.text("WHAT IS THIS?", margin + 8, y);
				y += 4.5;

				doc.setFontSize(8.5);
				doc.setFont("helvetica", "normal");
				doc.setTextColor(35, 35, 35);
				doc.text(descLines, margin + 8, y);
				y += descLines.length * 4.8 + 5;

				// ── WHY IT MATTERS ──
				doc.setFontSize(7);
				doc.setFont("helvetica", "bold");
				doc.setTextColor(100, 100, 100);
				doc.text("WHY IT MATTERS", margin + 8, y);
				y += 4.5;

				doc.setFontSize(8.5);
				doc.setFont("helvetica", "normal");
				doc.setTextColor(35, 35, 35);
				doc.text(impactLines, margin + 8, y);
				y += impactLines.length * 4.8 + 5;

				// ── HOW TO FIX IT ──
				if (recLines.length > 0) {
					doc.setFontSize(7);
					doc.setFont("helvetica", "bold");
					doc.setTextColor(40, 167, 69);
					doc.text("HOW TO FIX IT", margin + 8, y);
					y += 4.5;

					doc.setFontSize(8.5);
					doc.setFont("helvetica", "normal");
					doc.setTextColor(35, 35, 35);
					doc.text(recLines, margin + 8, y);
					y += recLines.length * 4.8 + 5;
				}

				// ── TECHNICAL LOCATION ──
				if (f.location) {
					doc.setFontSize(7);
					doc.setFont("helvetica", "bold");
					doc.setTextColor(130, 130, 130);
					doc.text("LOCATION  ", margin + 8, y);
					const locOffset = doc.getTextWidth("LOCATION  ");
					doc.setFont("courier", "normal");
					doc.setFontSize(7);
					doc.text(f.location.slice(0, 90), margin + 8 + locOffset, y);
					y += 6;
				}

				y = cardStartY + cardH + 6; // ensure we always end at card bottom + gap
			}
		} else {
			// ── Fallback: render full assistant content section-by-section ──────────
			addPage();

			doc.setFontSize(11);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("FULL ANALYSIS", margin, y);
			y += 3;
			doc.setDrawColor(245, 166, 35);
			doc.setLineWidth(0.7);
			doc.line(margin, y, margin + contentW, y);
			y += 8;

			for (const msg of assistantMessages) {
				const sections = parseReportSections(
					msg.content
						.replace(/\*\*([^*]+)\*\*/g, "$1")
						.replace(/\*([^*]+)\*/g, "$1")
				);

				for (const section of sections) {
					if (section.heading) {
						checkPageBreak(section.level === 1 ? 16 : 12);
						const fs = section.level === 1 ? 12 : section.level === 2 ? 10.5 : 9.5;
						doc.setFontSize(fs);
						doc.setFont("helvetica", "bold");
						doc.setTextColor(20, 20, 20);
						doc.text(section.heading.toUpperCase(), margin, y);
						y += 3;
						if (section.level <= 2) {
							doc.setDrawColor(245, 166, 35);
							doc.setLineWidth(0.5);
							doc.line(margin, y, margin + contentW, y);
						}
						y += 5;
					}

					if (section.body) {
						checkPageBreak(10);
						doc.setFontSize(8.5);
						doc.setFont("helvetica", "normal");
						doc.setTextColor(50, 50, 50);

						for (const line of section.body.split("\n")) {
							if (!line.trim()) {
								y += 2.5;
								continue;
							}
							const bullet = line.match(/^[-•]\s+(.+)/);
							const numbered = line.match(/^\d+\.\s+(.+)/);
							let prefix = "";
							let text = line.trim();
							if (bullet) {
								prefix = "•  ";
								text = bullet[1];
							} else if (numbered) {
								prefix = (line.match(/^(\d+\.)\s+/)?.[1] ?? "") + "  ";
								text = numbered[1];
							}
							const wrapped = doc.splitTextToSize(
								prefix + text,
								contentW - (prefix ? 6 : 0)
							);
							checkPageBreak(wrapped.length * 4.5);
							doc.text(wrapped, margin + (prefix ? 4 : 0), y);
							y += wrapped.length * 4.2 + 1.5;
						}
						y += 4;
					}
				}
			}
		}

		// ── FOOTER on every page ──────────────────────────────────────────────────
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pageCount: number =
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(doc as any).getNumberOfPages?.() ??
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			(doc.internal as any).getNumberOfPages?.() ??
			1;

		for (let pg = 1; pg <= pageCount; pg++) {
			doc.setPage(pg);
			doc.setFontSize(7);
			doc.setTextColor(160);
			doc.setDrawColor(210);
			doc.setLineWidth(0.2);
			doc.line(margin, pageH - 10, pageW - margin, pageH - 10);
			doc.text(
				"Generated by ThreatLens  ·  github.com/OffensiveSage/ThreatLens",
				margin,
				pageH - 6
			);
			doc.text(`Page ${pg} / ${pageCount}`, pageW - margin - 14, pageH - 6);
		}

		const dateStr = new Date().toISOString().split("T")[0];
		doc.save(`ThreatLens-Report-${dateStr}.pdf`);
	} catch (err) {
		console.error("PDF generation failed:", err);
		alert(
			`PDF generation failed: ${err instanceof Error ? err.message : String(err)}`
		);
	}
}

// ─── Markdown Export ──────────────────────────────────────────────────────────

export function generateMarkdownReport(
	messages: Message[],
	metadata: ReportMetadata
): void {
	try {
		const date = metadata.date ?? new Date().toLocaleDateString();
		const findings = extractFindings(messages);
		const overallRisk = findings.length > 0 ? computeOverallRisk(findings) : "INFO";

		let md = `# ThreatLens Security Intelligence Report\n\n`;
		md += `| | |\n|---|---|\n`;
		md += `| **Generated** | ${date} |\n`;
		md += `| **Target** | ${metadata.target ?? "Multiple Sources"} |\n`;
		md += `| **Sources** | ${metadata.sources.join(", ")} |\n`;
		md += `| **Overall Risk** | **${RISK_LABELS[overallRisk]}** |\n\n`;
		md += `---\n\n`;

		if (findings.length > 0) {
			const counts: Record<string, number> = {
				CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
			};
			for (const f of findings) counts[f.severity]++;

			md += `## Summary\n\n`;
			const statRow = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
				.filter((s) => counts[s] > 0)
				.map((s) => `${counts[s]} ${s}`)
				.join("  ·  ");
			md += `**${findings.length} findings:** ${statRow}\n\n`;

			// Plain-English overview paragraph
			md += `> **What this means:** `;
			if (overallRisk === "CRITICAL")
				md += `Critical issues were found that could allow attackers to take over your system or steal all data. Immediate action required.\n\n`;
			else if (overallRisk === "HIGH")
				md += `High-severity issues were found. These should be fixed within days, not weeks.\n\n`;
			else if (overallRisk === "MEDIUM")
				md += `Moderate issues were found. Address these in your next development sprint.\n\n`;
			else
				md += `Only low-risk issues were found. No urgent action required, but reviewing these will improve your security.\n\n`;

			md += `---\n\n`;

			// Priority action plan
			md += `## Priority Action Plan\n\n`;
			md += `> Start from the top — these are ordered by urgency.\n\n`;
			const sorted = [...findings].sort(
				(a, b) =>
					SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
			);
			for (let i = 0; i < sorted.length; i++) {
				const f = sorted[i];
				md += `${i + 1}. **[${f.severity}]** ${f.title}  \n`;
				md += `   *${PRIORITY_LABELS[f.severity]}*  \n`;
				if (f.recommendation)
					md += `   **Fix:** ${f.recommendation}\n\n`;
				else
					md += `\n`;
			}
			md += `---\n\n`;

			// Detailed findings
			md += `## Detailed Findings\n\n`;
			for (const sev of SEVERITY_ORDER) {
				const sevF = findings.filter((f) => f.severity === sev);
				if (sevF.length === 0) continue;
				md += `### ${sev} — ${PRIORITY_LABELS[sev]}\n\n`;
				for (const f of sevF) {
					md += `#### ${f.title}\n\n`;
					md += `**What is this?**  \n${f.description}\n\n`;
					md += `**Why it matters**  \n${getBusinessImpact(f)}\n\n`;
					if (f.recommendation)
						md += `**How to fix it**  \n${f.recommendation}\n\n`;
					if (f.location)
						md += `**Location:** \`${f.location}\`\n\n`;
					md += `---\n\n`;
				}
			}
		}

		md += `## Full Analysis\n\n`;
		for (const msg of messages) {
			if (msg.role === "user") {
				md += `> **Query:** ${msg.content}\n\n`;
			} else {
				md += `${msg.content}\n\n---\n\n`;
			}
		}

		md += `*Generated by [ThreatLens](https://github.com/OffensiveSage/ThreatLens)*\n`;

		const blob = new Blob([md], { type: "text/markdown" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `ThreatLens-Report-${new Date().toISOString().split("T")[0]}.md`;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	} catch (err) {
		console.error("Markdown export failed:", err);
		alert(
			`Markdown export failed: ${err instanceof Error ? err.message : String(err)}`
		);
	}
}

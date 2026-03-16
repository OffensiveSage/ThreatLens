/**
 * Security Report Generator — PDF + Markdown export.
 * Uses jsPDF + jspdf-autotable for PDF, and Blob download for Markdown.
 */

import type { Message } from "@/app/[owner]/[repo]/types";

export interface ReportMetadata {
	target?: string;
	sources: string[];
	date?: string;
}

// ─── Finding extraction ────────────────────────────────────────────────────────

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
	HIGH: [245, 166, 35],
	MEDIUM: [255, 193, 7],
	LOW: [40, 167, 69],
	INFO: [23, 162, 184],
};

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
	if (lower.includes("critical") || lower.includes("rce") || lower.includes("remote code execution") || lower.includes("unauthenticated")) return "CRITICAL";
	if (lower.includes("sql injection") || lower.includes("authentication bypass") || lower.includes("high severity") || lower.includes("privilege escalat")) return "HIGH";
	if (lower.includes("xss") || lower.includes("insecure") || lower.includes("missing") || lower.includes("medium severity")) return "MEDIUM";
	if (lower.includes("info") || lower.includes("best practice") || lower.includes("low severity")) return "LOW";
	return "MEDIUM";
}

/**
 * Parse the "Severity Level of Findings:" table that appears in structured reports.
 * Returns a map of lowercased title → severity.
 */
function parseSeverityTable(content: string): Record<string, Finding["severity"]> {
	const map: Record<string, Finding["severity"]> = {};
	// Match a block like:
	// Severity Level of Findings:\n
	// Finding Title: High\n
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

/**
 * Multi-format finding extractor. Handles:
 *   1. Markdown bold:  1. **Title**: description
 *   2. Structured:     1. Title\nDescription: ...\nLocation: ...\nRecommendation: ...
 *   3. Section-based:  ## Title\ndescription
 */
export function extractFindings(messages: Message[]): Finding[] {
	const findings: Finding[] = [];

	for (const msg of messages) {
		if (msg.role !== "assistant") continue;
		const content = msg.content;

		// Parse severity override table first
		const severityTable = parseSeverityTable(content);

		// ── Format 1: Structured numbered findings with Description:/Location: fields ──
		// Split the content on numbered items
		const numberedSplit = content.split(/\n(?=\d+\.\s+\S)/);
		let structuredCount = 0;

		for (const section of numberedSplit) {
			const titleMatch = section.match(/^\d+\.\s+\*{0,2}([^*\n]+?)\*{0,2}\s*$/m);
			if (!titleMatch) continue;

			const title = titleMatch[1].trim();
			if (title.length < 4) continue;

			// Extract sub-fields
			const descMatch = section.match(/Description:\s*([\s\S]+?)(?=\n(?:Location|Recommendation|Severity|Evidence|Impact|References|$))/i);
			const locMatch = section.match(/Location:\s*([\s\S]+?)(?=\n(?:Description|Recommendation|Severity|Evidence|References|$))/i);
			const recMatch = section.match(/Recommendation:\s*([\s\S]+?)(?=\n(?:Location|Description|Severity|Evidence|References|$))/i);

			const desc = descMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";
			const loc = locMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";
			const rec = recMatch?.[1]?.replace(/\n\s*/g, " ").trim() ?? "";

			if (!desc && !loc) continue;

			// Look up severity from table, fallback to inference
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

		// ── Format 2: Markdown bold  "1. **Title**: description" ──
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

		// ── Format 3: Bullet-list under "Summary of Findings:" ──
		if (findings.length === 0) {
			const summaryMatch = content.match(/Summary of Findings:[\s\S]+?(?=\n\n[A-Z]|\nDetailed|$)/i);
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

	// Deduplicate by title
	const seen = new Set<string>();
	return findings.filter((f) => {
		const key = f.title.toLowerCase();
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

// ─── Section parser for full-content PDF rendering ───────────────────────────

interface ReportSection {
	heading: string;
	level: 1 | 2 | 3;
	body: string;
}

function parseReportSections(content: string): ReportSection[] {
	const sections: ReportSection[] = [];
	// Split on lines that look like section headers (ends with : or starts with #)
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
			if (!current) {
				current = { heading: "", level: 3, body: "" };
			}
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
			if (y + needed > pageH - 20) addPage();
		};

		// ── Dark title block ──
		doc.setFillColor(15, 15, 15);
		doc.rect(0, 0, pageW, 54, "F");
		doc.setFillColor(245, 166, 35);
		doc.rect(0, 54, pageW, 2, "F");

		doc.setFontSize(24);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(245, 166, 35);
		doc.text("THREATLENS", margin, 22);

		doc.setFontSize(12);
		doc.setTextColor(200, 200, 200);
		doc.text("SECURITY INTELLIGENCE REPORT", margin, 32);

		doc.setFontSize(8.5);
		doc.setFont("helvetica", "normal");
		doc.setTextColor(140, 140, 140);
		doc.text(`Generated: ${metadata.date ?? new Date().toLocaleDateString()}`, margin, 42);
		if (metadata.target) doc.text(`Target: ${metadata.target}`, margin, 48);
		doc.text(`Sources: ${metadata.sources.join(" · ")}`, pageW - margin - 60, 42);

		y = 66;

		const assistantMessages = messages.filter((m) => m.role === "assistant");

		// ── Try to extract structured findings ──
		const findings = extractFindings(messages);

		// ── If findings parsed → render as structured report ──
		if (findings.length > 0) {
			// Executive summary from first message (first 500 chars)
			const summaryRaw = assistantMessages[0]?.content
				.replace(/\*\*([^*]+)\*\*/g, "$1")
				.replace(/#{1,3}\s*/g, "")
				.replace(/\n{3,}/g, "\n\n")
				.slice(0, 500) ?? "";

			doc.setFontSize(11);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("EXECUTIVE SUMMARY", margin, y);
			y += 4;
			doc.setDrawColor(245, 166, 35);
			doc.setLineWidth(0.7);
			doc.line(margin, y, margin + contentW, y);
			y += 5;

			doc.setFontSize(8.5);
			doc.setFont("helvetica", "normal");
			doc.setTextColor(50, 50, 50);
			const sumLines = doc.splitTextToSize(summaryRaw, contentW);
			doc.text(sumLines, margin, y);
			y += sumLines.length * 4.2 + 10;
			checkPageBreak(20);

			// Findings by severity
			doc.setFontSize(11);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("FINDINGS BY SEVERITY", margin, y);
			y += 4;
			doc.setDrawColor(245, 166, 35);
			doc.line(margin, y, margin + contentW, y);
			y += 6;

			for (const sev of SEVERITY_ORDER) {
				const sevFindings = findings.filter((f) => f.severity === sev);
				if (sevFindings.length === 0) continue;

				checkPageBreak(30);

				autoTable(doc, {
					startY: y,
					head: [[`${sev}  (${sevFindings.length})`, "Description", "Location"]],
					body: sevFindings.map((f) => [
						f.title,
						(f.description + (f.recommendation ? "\n→ " + f.recommendation : "")).slice(0, 250),
						f.location.slice(0, 80),
					]),
					headStyles: {
						fillColor: SEVERITY_COLORS_RGB[sev],
						textColor: [255, 255, 255],
						fontStyle: "bold",
						fontSize: 8.5,
					},
					bodyStyles: { fontSize: 8, textColor: [40, 40, 40], cellPadding: 3 },
					columnStyles: {
						0: { cellWidth: 48 },
						1: { cellWidth: 100 },
						2: { cellWidth: 32 },
					},
					styles: {
						overflow: "linebreak",
						lineColor: [210, 210, 210],
						lineWidth: 0.2,
					},
					theme: "grid",
					margin: { left: margin, right: margin },
				});

				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				y = ((doc as any).lastAutoTable?.finalY ?? y + 20) + 8;
			}

			// Recommendations section
			checkPageBreak(20);
			doc.setFontSize(11);
			doc.setFont("helvetica", "bold");
			doc.setTextColor(20, 20, 20);
			doc.text("RECOMMENDATIONS", margin, y);
			y += 4;
			doc.setDrawColor(245, 166, 35);
			doc.line(margin, y, margin + contentW, y);
			y += 6;

			doc.setFontSize(8.5);
			doc.setFont("helvetica", "normal");
			doc.setTextColor(50, 50, 50);
			findings.filter((f) => f.recommendation).forEach((f, i) => {
				checkPageBreak(10);
				const recText = `${i + 1}. ${f.title}: ${f.recommendation}`;
				const recLines = doc.splitTextToSize(recText, contentW);
				doc.text(recLines, margin, y);
				y += recLines.length * 4.2 + 3;
			});

		} else {
			// ── Fallback: render full content section by section ──
			for (const msg of assistantMessages) {
				const sections = parseReportSections(
					msg.content
						.replace(/\*\*([^*]+)\*\*/g, "$1") // strip bold
						.replace(/\*([^*]+)\*/g, "$1") // strip italic
				);

				for (const section of sections) {
					if (section.heading) {
						checkPageBreak(section.level === 1 ? 16 : 12);
						const fontSize = section.level === 1 ? 12 : section.level === 2 ? 10.5 : 9.5;
						doc.setFontSize(fontSize);
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

						// Render line by line to preserve structure
						const bodyLines = section.body.split("\n");
						for (const line of bodyLines) {
							if (!line.trim()) { y += 2.5; continue; }

							// Bullet points
							const bullet = line.match(/^[-•]\s+(.+)/);
							const numbered = line.match(/^\d+\.\s+(.+)/);

							let prefix = "";
							let text = line.trim();

							if (bullet) {
								prefix = "•  ";
								text = bullet[1];
							} else if (numbered) {
								prefix = line.match(/^(\d+\.)\s+/)?.[1] + "  ";
								text = numbered[1];
							}

							const wrapped = doc.splitTextToSize(prefix + text, contentW - (prefix ? 6 : 0));
							checkPageBreak(wrapped.length * 4.5);
							doc.text(wrapped, margin + (prefix ? 4 : 0), y);
							y += wrapped.length * 4.2 + 1.5;
						}
						y += 4;
					}
				}
			}
		}

		// ── Footer on all pages ──
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const pageCount: number = (doc as any).getNumberOfPages?.() ?? (doc.internal as any).getNumberOfPages?.() ?? 1;
		for (let i = 1; i <= pageCount; i++) {
			doc.setPage(i);
			doc.setFontSize(7);
			doc.setTextColor(150);
			doc.setDrawColor(210);
			doc.setLineWidth(0.2);
			doc.line(margin, pageH - 10, pageW - margin, pageH - 10);
			doc.text(
				"Generated by ThreatLens  ·  github.com/OffensiveSage/ThreatLens",
				margin,
				pageH - 6
			);
			doc.text(`Page ${i} / ${pageCount}`, pageW - margin - 14, pageH - 6);
		}

		const dateStr = new Date().toISOString().split("T")[0];
		doc.save(`ThreatLens-Report-${dateStr}.pdf`);
	} catch (err) {
		console.error("PDF generation failed:", err);
		alert(`PDF generation failed: ${err instanceof Error ? err.message : String(err)}`);
	}
}

// ─── Markdown Export ──────────────────────────────────────────────────────────

export function generateMarkdownReport(
	messages: Message[],
	metadata: ReportMetadata
): void {
	try {
		const date = metadata.date ?? new Date().toLocaleDateString();
		let md = `# ThreatLens Security Intelligence Report\n\n`;
		md += `**Generated:** ${date}  \n`;
		md += `**Target:** ${metadata.target ?? "Multiple Sources"}  \n`;
		md += `**Sources:** ${metadata.sources.join(", ")}\n\n`;
		md += `---\n\n`;

		const findings = extractFindings(messages);
		if (findings.length > 0) {
			md += `## Findings\n\n`;
			for (const sev of SEVERITY_ORDER) {
				const sevF = findings.filter((f) => f.severity === sev);
				if (sevF.length === 0) continue;
				md += `### ${sev} (${sevF.length})\n\n`;
				for (const f of sevF) {
					md += `#### ${f.title}\n\n`;
					if (f.description) md += `**Description:** ${f.description}\n\n`;
					if (f.location) md += `**Location:** \`${f.location}\`\n\n`;
					if (f.recommendation) md += `**Recommendation:** ${f.recommendation}\n\n`;
				}
			}
			md += `---\n\n`;
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
		alert(`Markdown export failed: ${err instanceof Error ? err.message : String(err)}`);
	}
}

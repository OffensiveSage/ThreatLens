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
	evidence: string;
	severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

const SEVERITY_COLORS_RGB: Record<string, [number, number, number]> = {
	CRITICAL: [255, 68, 68],
	HIGH: [245, 166, 35],
	MEDIUM: [255, 217, 102],
	LOW: [102, 187, 106],
	INFO: [100, 181, 246],
};

function inferSeverity(text: string): Finding["severity"] {
	const lower = text.toLowerCase();
	if (lower.includes("critical") || lower.includes("rce") || lower.includes("remote code execution")) return "CRITICAL";
	if (lower.includes("sql injection") || lower.includes("authentication bypass") || lower.includes("credential") || lower.includes(" high")) return "HIGH";
	if (lower.includes("xss") || lower.includes("insecure") || lower.includes("missing") || lower.includes(" medium")) return "MEDIUM";
	if (lower.includes("informational") || lower.includes("best practice") || lower.includes("info")) return "INFO";
	return "MEDIUM";
}

export function extractFindings(messages: Message[]): Finding[] {
	const findings: Finding[] = [];
	for (const msg of messages) {
		if (msg.role !== "assistant") continue;
		// Match numbered findings: "1. **Title**: description (evidence)"
		const findingRe = /\d+\.\s+\*\*([^*]+)\*\*[:\s]+([^\n]+)(?:\n.*?\(([^)]+)\))?/g;
		let match;
		while ((match = findingRe.exec(msg.content)) !== null) {
			const title = match[1].trim();
			const description = match[2].trim();
			const evidence = match[3]?.trim() ?? "";
			findings.push({
				title,
				description,
				evidence,
				severity: inferSeverity(title + " " + description),
			});
		}
	}
	return findings;
}

// ─── PDF Export ────────────────────────────────────────────────────────────────

export async function generatePDFReport(
	messages: Message[],
	metadata: ReportMetadata
): Promise<void> {
	// Dynamic import to avoid SSR issues
	const { jsPDF } = await import("jspdf");
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const autoTable = (await import("jspdf-autotable")).default as any;

	const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
	const pageW = doc.internal.pageSize.getWidth();
	const margin = 20;
	const contentW = pageW - margin * 2;
	let y = margin;

	// ── Title block ──
	doc.setFillColor(15, 15, 15);
	doc.rect(0, 0, pageW, 50, "F");
	doc.setFontSize(22);
	doc.setFont("helvetica", "bold");
	doc.setTextColor(245, 166, 35);
	doc.text("THREATLENS", margin, 22);
	doc.setFontSize(13);
	doc.setTextColor(200, 200, 200);
	doc.text("SECURITY INTELLIGENCE REPORT", margin, 31);
	doc.setFontSize(9);
	doc.setFont("helvetica", "normal");
	doc.setTextColor(150, 150, 150);
	doc.text(
		`Generated: ${metadata.date ?? new Date().toLocaleDateString()}   |   Target: ${metadata.target ?? "Multiple Sources"}`,
		margin,
		40
	);
	doc.text(`Sources: ${metadata.sources.join(" · ")}`, margin, 46);

	y = 62;

	// ── Executive Summary ──
	doc.setFontSize(12);
	doc.setFont("helvetica", "bold");
	doc.setTextColor(30, 30, 30);
	doc.text("EXECUTIVE SUMMARY", margin, y);
	y += 6;
	doc.setDrawColor(245, 166, 35);
	doc.setLineWidth(0.8);
	doc.line(margin, y, margin + contentW, y);
	y += 6;

	const assistantMessages = messages.filter((m) => m.role === "assistant");
	const firstMsg = assistantMessages[0]?.content ?? "No analysis available.";
	const summaryText = firstMsg.replace(/\*\*([^*]+)\*\*/g, "$1").slice(0, 400);
	doc.setFontSize(9);
	doc.setFont("helvetica", "normal");
	doc.setTextColor(40, 40, 40);
	const summaryLines = doc.splitTextToSize(summaryText, contentW);
	doc.text(summaryLines, margin, y);
	y += summaryLines.length * 4.5 + 10;

	// ── Findings ──
	const findings = extractFindings(messages);

	if (findings.length === 0) {
		// Fallback: dump all assistant messages as content
		doc.setFontSize(12);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(30, 30, 30);
		doc.text("ANALYSIS", margin, y);
		y += 10;

		for (const msg of assistantMessages) {
			const clean = msg.content.replace(/\*\*([^*]+)\*\*/g, "$1").replace(/#{1,3}\s*/g, "");
			const lines = doc.splitTextToSize(clean.slice(0, 2000), contentW);
			doc.setFontSize(8.5);
			doc.setFont("helvetica", "normal");
			doc.setTextColor(40, 40, 40);
			doc.text(lines, margin, y);
			y += lines.length * 4.2 + 8;
			if (y > 265) { doc.addPage(); y = 20; }
		}
	} else {
		doc.setFontSize(12);
		doc.setFont("helvetica", "bold");
		doc.setTextColor(30, 30, 30);
		doc.text("FINDINGS BY SEVERITY", margin, y);
		y += 6;
		doc.setDrawColor(245, 166, 35);
		doc.line(margin, y, margin + contentW, y);
		y += 8;

		for (const sev of SEVERITY_ORDER) {
			const sevFindings = findings.filter((f) => f.severity === sev);
			if (sevFindings.length === 0) continue;

			autoTable(doc, {
				startY: y,
				head: [[`${sev}  (${sevFindings.length} finding${sevFindings.length > 1 ? "s" : ""})`, "Description", "Evidence"]],
				body: sevFindings.map((f) => [f.title, f.description.slice(0, 150), f.evidence.slice(0, 80)]),
				headStyles: {
					fillColor: SEVERITY_COLORS_RGB[sev],
					textColor: sev === "MEDIUM" ? [0, 0, 0] : [0, 0, 0],
					fontStyle: "bold",
					fontSize: 9,
				},
				bodyStyles: { fontSize: 8, textColor: [40, 40, 40], cellPadding: 3 },
				columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 90 }, 2: { cellWidth: 40 } },
				styles: { overflow: "linebreak", lineColor: [200, 200, 200], lineWidth: 0.2 },
				theme: "grid",
				margin: { left: margin, right: margin },
			});

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		y = ((doc as any).lastAutoTable?.finalY ?? y) + 8;
			if (y > 265) { doc.addPage(); y = 20; }
		}
	}

	// ── Footer on all pages ──
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const pageCount = (doc as any).getNumberOfPages?.() ?? (doc.internal as any).getNumberOfPages?.() ?? 1;
	for (let i = 1; i <= pageCount; i++) {
		doc.setPage(i);
		doc.setFontSize(7.5);
		doc.setTextColor(150);
		doc.setDrawColor(200);
		doc.setLineWidth(0.3);
		doc.line(margin, 285, pageW - margin, 285);
		doc.text(
			"Generated by ThreatLens  ·  github.com/OffensiveSage/ThreatLens",
			margin,
			290
		);
		doc.text(`Page ${i} of ${pageCount}`, pageW - margin - 16, 290);
	}

	const dateStr = new Date().toISOString().split("T")[0];
	doc.save(`ThreatLens-Report-${dateStr}.pdf`);
}

// ─── Markdown Export ──────────────────────────────────────────────────────────

export function generateMarkdownReport(
	messages: Message[],
	metadata: ReportMetadata
): void {
	const date = metadata.date ?? new Date().toLocaleDateString();
	let md = `# ThreatLens Security Intelligence Report\n\n`;
	md += `**Generated:** ${date}\n`;
	md += `**Target:** ${metadata.target ?? "Multiple Sources"}\n`;
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
				md += `- **${f.title}**: ${f.description}`;
				if (f.evidence) md += ` *(${f.evidence})*`;
				md += "\n";
			}
			md += "\n";
		}
	}

	md += `## Full Analysis\n\n`;
	for (const msg of messages) {
		if (msg.role === "user") {
			md += `**Query:** ${msg.content}\n\n`;
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
	a.click();
	URL.revokeObjectURL(url);
}

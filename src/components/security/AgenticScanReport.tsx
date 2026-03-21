"use client";

import { useState, useCallback } from "react";
import type {
	AgenticReport,
	AgenticFinding,
	DependencyFinding,
	InventorySummary,
	ScanStepProgress,
} from "@/lib/agenticScan";
import {
	DetailPanel,
	GitHubFileLink,
	CweBadge,
	SeverityFilterBadge,
	type PanelState,
	type CwePanelData,
} from "./DeepLinkPanel";

// ─── Severity helpers ─────────────────────────────────────────────────────────

function sevColor(sev: string): string {
	switch (sev.toUpperCase()) {
		case "CRITICAL": return "#B71C1C";
		case "HIGH":     return "#E65100";
		case "MEDIUM":   return "#F57F17";
		case "LOW":      return "#2E7D32";
		default:         return "#5B7FA5";
	}
}

function gradeColor(grade: string): string {
	switch (grade) {
		case "A": return "#2E7D32";
		case "B": return "#558B2F";
		case "C": return "#F57F17";
		case "D": return "#E65100";
		default:  return "#B71C1C";
	}
}

// ─── SVG Donut Chart ─────────────────────────────────────────────────────────

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
	const rad = ((angleDeg - 90) * Math.PI) / 180;
	return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function describeArc(cx: number, cy: number, r: number, startDeg: number, endDeg: number): string {
	const gap = 0.5;
	const s = polarToCartesian(cx, cy, r, startDeg + gap);
	const e = polarToCartesian(cx, cy, r, endDeg - gap);
	const largeArc = endDeg - startDeg - 2 * gap > 180 ? 1 : 0;
	return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function DonutChart({ counts, total }: { counts: Record<string, number>; total: number }) {
	const cx = 80, cy = 80, r = 58, strokeW = 18;
	const innerR = r - strokeW / 2;

	if (total === 0) {
		return (
			<svg width={160} height={160} viewBox="0 0 160 160">
				<circle cx={cx} cy={cy} r={innerR} fill="none" stroke="#D0D0D0" strokeWidth={strokeW} />
				<text x={cx} y={cy + 5} textAnchor="middle" fontSize={14} fill="#888" fontFamily="monospace">0</text>
			</svg>
		);
	}

	const slices: { sev: string; startDeg: number; endDeg: number }[] = [];
	let cursor = 0;
	for (const sev of SEV_ORDER) {
		const count = counts[sev] || 0;
		if (count === 0) continue;
		const span = (count / total) * 360;
		slices.push({ sev, startDeg: cursor, endDeg: cursor + span });
		cursor += span;
	}

	return (
		<svg width={160} height={160} viewBox="0 0 160 160">
			<circle cx={cx} cy={cy} r={innerR} fill="none" stroke="#D0D0D0" strokeWidth={strokeW} />
			{slices.map(({ sev, startDeg, endDeg }) => (
				<path key={sev} d={describeArc(cx, cy, innerR, startDeg, endDeg)}
					fill="none" stroke={sevColor(sev)} strokeWidth={strokeW} strokeLinecap="butt" />
			))}
			<text x={cx} y={cy - 8} textAnchor="middle" fontSize={24} fontWeight={700}
				fill="var(--ink-black)" fontFamily="var(--font-mono)">{total}</text>
			<text x={cx} y={cy + 12} textAnchor="middle" fontSize={10} fill="var(--ink-medium)"
				fontFamily="var(--font-sans)" style={{ textTransform: "uppercase", letterSpacing: "0.06em" }}>
				findings
			</text>
		</svg>
	);
}

// ─── Category Bar ─────────────────────────────────────────────────────────────

function CategoryBar({ label, count, maxCount, color }: { label: string; count: number; maxCount: number; color: string }) {
	const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
	return (
		<div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
			<span style={{ width: 170, fontSize: 12, fontFamily: "var(--font-sans)", color: "var(--ink-medium)", flexShrink: 0, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
				{label}
			</span>
			<div style={{ flex: 1, height: 14, background: "#D8D8D8", borderRadius: 2, overflow: "hidden", border: "1px solid #BBBBBB" }}>
				<div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2 }} />
			</div>
			<span style={{ width: 28, fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--ink-black)", fontWeight: 800, textAlign: "right", flexShrink: 0 }}>
				{count}
			</span>
		</div>
	);
}

// ─── Risk Hero ────────────────────────────────────────────────────────────────

function RiskHero({ report }: { report: AgenticReport }) {
	const { score, grade, counts } = report.summary;
	const color = gradeColor(grade);
	return (
		<div style={{ display: "flex", alignItems: "center", gap: 28, padding: "20px 28px", border: "2.5px solid var(--border-black)", background: "var(--bg-paper)", boxShadow: "var(--shadow-layer-2)", marginBottom: 24 }}>
			<div style={{ textAlign: "center", flexShrink: 0 }}>
				<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: 56, lineHeight: 1, color, letterSpacing: "-0.04em" }}>
					{grade}
				</div>
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-medium)", marginTop: 4 }}>
					{score}/100
				</div>
			</div>
			<div style={{ width: 2, height: 64, background: "var(--border-black)", flexShrink: 0 }} />
			<div style={{ flex: 1 }}>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 10 }}>
					Risk Breakdown
				</div>
				<div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
					{SEV_ORDER.map((sev) => (
						<div key={sev} style={{ textAlign: "center" }}>
							<div style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 800, color: (counts[sev] || 0) > 0 ? sevColor(sev) : "var(--ink-light)" }}>
								{counts[sev] || 0}
							</div>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-light)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
								{sev.toLowerCase()}
							</div>
						</div>
					))}
				</div>
			</div>
			{!report.llmUsed && (
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", padding: "6px 10px", border: "1.5px solid var(--border-black)", borderRadius: 2, flexShrink: 0, textAlign: "center", maxWidth: 140 }}>
					Pattern scan only — add Groq/Gemini key for deep analysis
				</div>
			)}
		</div>
	);
}

// ─── Inventory Summary ────────────────────────────────────────────────────────

function InventoryCard({ inventory }: { inventory: InventorySummary }) {
	const topLangs = Object.entries(inventory.languages)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 6);
	return (
		<div style={{ border: "2px solid var(--border-black)", background: "var(--bg-paper)", padding: "16px 20px", marginBottom: 24, display: "flex", gap: 24, flexWrap: "wrap" }}>
			<div>
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 800, color: "var(--ink-black)" }}>{inventory.totalFiles}</div>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-light)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Files Scanned</div>
			</div>
			<div style={{ width: 1, background: "var(--border-black)" }} />
			<div>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-medium)", marginBottom: 6 }}>
					Languages
				</div>
				<div style={{ display: "flex", flexWrap: "wrap", gap: "4px 10px" }}>
					{topLangs.map(([lang, count]) => (
						<span key={lang} style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)" }}>
							{lang} <strong style={{ color: "var(--ink-black)" }}>{count}</strong>
						</span>
					))}
				</div>
			</div>
			{inventory.packageFiles.length > 0 && (
				<>
					<div style={{ width: 1, background: "var(--border-black)" }} />
					<div>
						<div style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 800, color: "var(--accent-amber)" }}>{inventory.packageFiles.length}</div>
						<div style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-light)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Package Files</div>
					</div>
				</>
			)}
		</div>
	);
}

// ─── Dependency Table ─────────────────────────────────────────────────────────

function DepsSection({ deps }: { deps: DependencyFinding[] }) {
	if (deps.length === 0) return null;
	const [expanded, setExpanded] = useState(false);
	const toShow = expanded ? deps : deps.slice(0, 8);
	return (
		<div className="finding-section" style={{ marginBottom: 28 }}>
			<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 12, display: "flex", alignItems: "center", gap: 10 }}>
				<span>Dependencies</span>
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-light)", fontWeight: 400 }}>({deps.length} packages)</span>
			</div>
			<div style={{ border: "1.5px solid var(--border-black)", borderRadius: 2, overflow: "hidden" }}>
				{toShow.map((dep, i) => (
					<div key={`${dep.package}-${i}`} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 14px", background: i % 2 === 0 ? "var(--bg-paper)" : "var(--bg-paper-alt)", borderBottom: i < toShow.length - 1 ? "1px solid var(--border-black)" : "none" }}>
						<span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-black)", flex: "0 0 200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
							{dep.package}
						</span>
						<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-light)", flex: "0 0 120px" }}>
							{dep.version}
						</span>
						<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-medium)", padding: "2px 7px", border: "1px solid var(--border-black)", borderRadius: 2 }}>
							{dep.ecosystem}
						</span>
						<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
							{dep.file}
						</span>
					</div>
				))}
			</div>
			{deps.length > 8 && (
				<button onClick={() => setExpanded(!expanded)} style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", background: "none", border: "none", cursor: "pointer", padding: 0 }}>
					{expanded ? "↑ Show fewer" : `↓ Show all ${deps.length} packages`}
				</button>
			)}
		</div>
	);
}

// ─── Finding Card ─────────────────────────────────────────────────────────────

function AgenticFindingCard({
	finding,
	owner,
	repo,
	onCweClick,
}: {
	finding: AgenticFinding;
	owner: string;
	repo: string;
	onCweClick?: (data: CwePanelData) => void;
}) {
	const [expanded, setExpanded] = useState(false);
	const color = sevColor(finding.severity);
	const hasAnalysis = finding.verdict && finding.verdict !== "UNANALYZED";

	return (
		<div style={{ border: "2px solid var(--border-black)", borderLeft: `4px solid ${color}`, background: "var(--bg-paper)", marginBottom: 10, borderRadius: 2, overflow: "hidden" }}>
			{/* Card header */}
			<div
				onClick={() => setExpanded(!expanded)}
				style={{ padding: "12px 16px", cursor: "pointer", display: "flex", alignItems: "flex-start", gap: 10 }}
			>
				{/* Severity badge */}
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color, border: `1.5px solid ${color}`, padding: "2px 7px", borderRadius: 2, flexShrink: 0 }}>
					{finding.severity}
				</span>
				{/* Confidence badge */}
				{hasAnalysis && finding.confidence && (
					<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--ink-medium)", border: "1.5px solid var(--border-black)", padding: "2px 7px", borderRadius: 2, flexShrink: 0 }}>
						{finding.confidence}
					</span>
				)}
				{/* CWE badge — clickable to open detail panel */}
				{finding.cwe && (
					<CweBadge
						cweId={finding.cwe}
						onClick={() => onCweClick?.({
							cweId: finding.cwe!,
							findingName: finding.name,
							explanation: finding.explanation,
							file: finding.file,
							line: finding.line,
							owner,
							repo,
						})}
					/>
				)}
				{/* Title */}
				<span style={{ fontFamily: "var(--font-sans)", fontSize: 13, fontWeight: 600, color: "var(--ink-black)", lineHeight: 1.35, flex: 1 }}>
					{finding.name}
				</span>
				{/* Expand indicator */}
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-light)", flexShrink: 0 }}>
					{expanded ? "↑" : "↓"}
				</span>
			</div>

			{/* File + line */}
			<div style={{ paddingLeft: 16, paddingRight: 16, paddingBottom: expanded ? 0 : 12, display: "flex", gap: 12, alignItems: "center" }}>
				{finding.file && (
					<GitHubFileLink owner={owner} repo={repo} file={finding.file} line={finding.line} />
				)}
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", padding: "1px 6px", border: "1px solid var(--border-black)", borderRadius: 2 }}>
					{finding.category}
				</span>
				{finding.verdict === "TRUE_POSITIVE" && (
					<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#2E7D32", padding: "1px 6px", border: "1px solid #2E7D32", borderRadius: 2 }}>
						✓ CONFIRMED
					</span>
				)}
			</div>

			{/* Expanded body */}
			{expanded && (
				<div style={{ padding: "12px 16px 16px", borderTop: "1.5px solid var(--border-black)" }}>
					{/* UNANALYZED: show "pattern match only" note instead of placeholder */}
					{finding.verdict === "UNANALYZED" ? (
						<div style={{ marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
							<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", padding: "3px 9px", border: "1.5px solid var(--border-black)", borderRadius: 2 }}>
								Pattern match · LLM deep analysis not run
							</span>
							{!finding.cwe && (
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-light)" }}>
									Add a Groq or Gemini key for confirmed verdict, CWE, and remediation.
								</span>
							)}
						</div>
					) : (
						finding.explanation && (
							<div style={{ marginBottom: 14 }}>
								<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-light)", marginBottom: 5 }}>
									EXPLANATION
								</div>
								<div style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--ink-black)", lineHeight: 1.6 }}>
									{finding.explanation}
								</div>
							</div>
						)
					)}

					{finding.exploitability && (
						<div style={{ marginBottom: 14 }}>
							<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-light)", marginBottom: 5 }}>
								EXPLOITABILITY
							</div>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--ink-black)", lineHeight: 1.6, borderLeft: "3px solid var(--high-amber, #E65100)", paddingLeft: 10 }}>
								{finding.exploitability}
							</div>
						</div>
					)}

					{finding.remediation && (
						<div style={{ marginBottom: 14 }}>
							<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-light)", marginBottom: 5 }}>
								REMEDIATION
							</div>
							<div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.6, background: "var(--bg-paper-alt)", padding: "8px 12px", borderRadius: 2, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
								{finding.remediation}
							</div>
						</div>
					)}

					{finding.context && (
						<div style={{ marginBottom: 8 }}>
							<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-light)", marginBottom: 5 }}>
								CODE CONTEXT
							</div>
							<pre style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", background: "var(--bg-paper-alt)", padding: "10px 12px", borderRadius: 2, margin: 0, overflow: "auto", maxHeight: 180, lineHeight: 1.5 }}>
								{finding.context}
							</pre>
						</div>
					)}

					{/* Cross-domain tags */}
					{(finding.attack_techniques.length > 0 || finding.sigma_rules.length > 0 || finding.compliance_controls.length > 0) && (
						<div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
							{finding.attack_techniques.map((t) => (
								<span key={t.technique_id} className="tag-attack" style={{ fontSize: 10, padding: "2px 8px" }}>
									{t.technique_id}
								</span>
							))}
							{finding.sigma_rules.map((r) => (
								<span key={r.rule_id} className="tag-sigma" style={{ fontSize: 10, padding: "2px 8px" }}>
									{r.title}
								</span>
							))}
							{finding.compliance_controls.map((c) => (
								<span key={c.control_id} className="tag-compliance" style={{ fontSize: 10, padding: "2px 8px" }}>
									{c.control_id}
								</span>
							))}
						</div>
					)}
				</div>
			)}
		</div>
	);
}

// ─── Main AgenticScanReport ───────────────────────────────────────────────────

export interface AgenticScanReportProps {
	owner: string;
	repo: string;
	report: AgenticReport;
	scanSteps?: ScanStepProgress[];
	onClose: () => void;
	onPrint: () => void;
}

export function AgenticScanReport({ owner, repo, report, scanSteps, onClose, onPrint }: AgenticScanReportProps) {
	const { summary, findings, dependencies, inventory } = report;
	const [panelState, setPanelState] = useState<PanelState>(null);
	const [severityFilter, setSeverityFilter] = useState<string | null>(null);

	const handleCweClick = useCallback((data: CwePanelData) => {
		setPanelState({ type: "cwe", data });
	}, []);

	const toggleSevFilter = useCallback((sev: string) => {
		setSeverityFilter((f) => f === sev ? null : sev);
	}, []);

	// Group findings by category for the bar chart
	const byCategory: Record<string, AgenticFinding[]> = {};
	for (const f of findings) {
		if (!byCategory[f.category]) byCategory[f.category] = [];
		byCategory[f.category].push(f);
	}
	const catNames = Object.keys(byCategory);
	const catCounts = catNames.map((c) => byCategory[c].length);
	const maxCatCount = Math.max(1, ...catCounts);

	function catTopColor(catFindings: AgenticFinding[]): string {
		for (const sev of SEV_ORDER) {
			if (catFindings.some((f) => f.severity === sev)) return sevColor(sev);
		}
		return sevColor("LOW");
	}

	return (
		<>
		<div
			id="scan-report-printable"
			style={{ fontFamily: "var(--font-sans)", color: "var(--ink-black)", maxWidth: 800, margin: "0 auto", padding: "0 0 40px" }}
		>
			{/* ── Header ── */}
			<div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", paddingBottom: 16, marginBottom: 20, borderBottom: "2.5px solid var(--border-black)" }}>
				<div>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.3rem", letterSpacing: "-0.02em" }}>
						Security Scan Report
					</div>
					<div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", marginTop: 4 }}>
						{owner}/{repo} · {report.scannedAt.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })} {report.scannedAt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
						{" · "}
						<span style={{ textTransform: "uppercase" }}>{report.mode}</span> scan
						{report.llmUsed && " · LLM-verified"}
					</div>
				</div>
				<div className="no-print" style={{ display: "flex", gap: 10 }}>
					<button onClick={onPrint} style={{ padding: "7px 16px", border: "2.5px solid var(--border-black)", background: "var(--ink-black)", color: "var(--bg-paper)", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, cursor: "pointer", letterSpacing: "0.04em", textTransform: "uppercase", borderRadius: 2 }}>
						Export PDF
					</button>
					<button onClick={onClose} style={{ padding: "7px 14px", border: "2.5px solid var(--border-black)", background: "var(--bg-paper)", color: "var(--ink-medium)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", borderRadius: 2 }}>
						✕ Close
					</button>
				</div>
			</div>

			{/* ── Risk Hero ── */}
			<RiskHero report={report} />

			{/* ── Inventory ── */}
			<InventoryCard inventory={inventory} />

			{/* ── Pipeline Step Log ── */}
			{scanSteps && scanSteps.length > 0 && (
				<div style={{ border: "1.5px solid var(--border-black)", background: "var(--bg-paper)", marginBottom: 24, borderRadius: 2, overflow: "hidden" }}>
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-light)", padding: "8px 16px", borderBottom: "1px solid var(--border-black)", background: "var(--bg-paper-alt)" }}>
						Pipeline Steps
					</div>
					<div style={{ padding: "10px 0" }}>
						{scanSteps.map((s) => (
							<div key={s.step} style={{ display: "flex", alignItems: "baseline", gap: 10, padding: "4px 16px" }}>
								{/* Step status icon */}
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, flexShrink: 0, color: s.status === "done" ? "#2E7D32" : s.status === "error" ? "#B71C1C" : "var(--ink-light)" }}>
									{s.status === "done" ? "✓" : s.status === "error" ? "✗" : "○"}
								</span>
								{/* Step number + label */}
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", flexShrink: 0, minWidth: 100 }}>
									{s.step}. {s.label}
								</span>
								{/* Detail */}
								{s.detail && (
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: s.status === "error" ? "#B71C1C" : "var(--ink-light)" }}>
										{s.detail}
									</span>
								)}
							</div>
						))}
					</div>
				</div>
			)}

			{/* ── Charts row ── */}
			<div style={{ display: "flex", gap: 24, marginBottom: 28, flexWrap: "wrap" }}>
				{/* Severity donut */}
				<div style={{ flex: "0 0 auto", border: "2.5px solid var(--border-black)", background: "var(--bg-paper)", padding: "20px 24px", display: "flex", flexDirection: "column", alignItems: "center", borderRadius: 2 }}>
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 12 }}>
						Severity Distribution
					</div>
					<DonutChart counts={summary.counts} total={summary.totalFindings} />
					<div style={{ display: "flex", flexWrap: "wrap", gap: "8px 16px", marginTop: 14 }}>
						{SEV_ORDER.map((sev) => (
							<div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
								<div style={{ width: 12, height: 12, borderRadius: 2, background: sevColor(sev), flexShrink: 0 }} />
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", fontWeight: (summary.counts[sev] || 0) > 0 ? 600 : 400 }}>
									{sev} <strong style={{ color: (summary.counts[sev] || 0) > 0 ? sevColor(sev) : "inherit" }}>{summary.counts[sev] || 0}</strong>
								</span>
							</div>
						))}
					</div>
				</div>

				{/* Category bars */}
				{catNames.length > 0 && (
					<div style={{ flex: 1, minWidth: 260, border: "2.5px solid var(--border-black)", background: "var(--bg-paper)", padding: "20px 24px", borderRadius: 2 }}>
						<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 16 }}>
							Findings by Category
						</div>
						{catNames.map((name, i) => (
							<CategoryBar key={name} label={name} count={catCounts[i]} maxCount={maxCatCount} color={catTopColor(byCategory[name])} />
						))}
					</div>
				)}
			</div>

			{/* ── Dependencies ── */}
			<DepsSection deps={dependencies} />

			{/* ── All Findings ── */}
			{summary.totalFindings === 0 ? (
				<div style={{ border: "2.5px solid var(--border-black)", background: "var(--bg-paper)", padding: "32px 28px", textAlign: "center" }}>
					<div style={{ fontSize: 32, marginBottom: 12 }}>✓</div>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "1.1rem", marginBottom: 8 }}>
						No findings detected
					</div>
					<div style={{ color: "var(--ink-medium)", fontSize: 14 }}>
						{report.llmUsed
							? "The scan found no security issues after pattern detection and LLM verification."
							: "The pattern scan found no suspicious patterns. Add a Groq or Gemini key for deeper LLM analysis."}
					</div>
				</div>
			) : (
				<div>
					<div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, borderBottom: "1.5px solid var(--border-black)", paddingBottom: 8, flexWrap: "wrap", gap: 10 }}>
						<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)" }}>
							All Findings ({summary.totalFindings})
						</div>
						{/* Severity filter chips */}
						<div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
							<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Filter:</span>
							{SEV_ORDER.filter((s) => (summary.counts[s] || 0) > 0).map((sev) => (
								<SeverityFilterBadge
									key={sev}
									severity={sev}
									count={summary.counts[sev] || 0}
									active={severityFilter === sev}
									onClick={() => toggleSevFilter(sev)}
								/>
							))}
							{severityFilter && (
								<button onClick={() => setSeverityFilter(null)} style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", background: "none", border: "none", cursor: "pointer", padding: "0 4px" }}>
									✕ Clear
								</button>
							)}
						</div>
					</div>

					{/* Group by severity, respecting filter */}
					{SEV_ORDER.map((sev) => {
						if (severityFilter && severityFilter !== sev) return null;
						const sevFindings = findings.filter((f) => f.severity === sev);
						if (sevFindings.length === 0) return null;
						return (
							<div key={sev} className="finding-section" style={{ marginBottom: 24 }}>
								<div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700, color: sevColor(sev) }}>
									<span style={{ display: "inline-block", width: 10, height: 10, background: sevColor(sev), flexShrink: 0 }} />
									{sev}
									<span style={{ fontWeight: 400, color: "var(--ink-light)" }}>({sevFindings.length})</span>
								</div>
								{sevFindings.map((f, i) => (
									<AgenticFindingCard
										key={`${sev}-${i}`}
										finding={f}
										owner={owner}
										repo={repo}
										onCweClick={handleCweClick}
									/>
								))}
							</div>
						);
					})}
				</div>
			)}

			{/* ── Footer ── */}
			<div style={{ marginTop: 32, paddingTop: 16, borderTop: "1.5px solid var(--border-black)", fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-light)", lineHeight: 1.6 }}>
				<strong>Disclaimer:</strong> This report was generated by an agentic security pipeline using deterministic pattern scanning
				{report.llmUsed ? " and LLM deep analysis (Groq/Gemini)." : "."} Results are indicative only — confirm findings manually before acting.
				Generated by ThreatLens.
			</div>
		</div>

		{/* Deep-link detail panel (CWE) */}
		<DetailPanel panel={panelState} onClose={() => setPanelState(null)} />
		</>
	);
}

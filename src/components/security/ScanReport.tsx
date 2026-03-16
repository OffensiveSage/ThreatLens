"use client";

import {
	type ScanFinding,
	type SeverityCounts,
	type RiskGrade,
	type Severity,
	calcRiskScore,
	riskGrade,
	gradeColor,
	severityColor,
	severityBg,
	countSeverities,
} from "@/lib/scanParser";

// ─── SVG Donut Chart ──────────────────────────────────────────────────────

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
	const rad = ((angleDeg - 90) * Math.PI) / 180;
	return {
		x: cx + r * Math.cos(rad),
		y: cy + r * Math.sin(rad),
	};
}

function describeArc(cx: number, cy: number, r: number, startDeg: number, endDeg: number): string {
	const gap = 0.5; // tiny gap between segments
	const s = polarToCartesian(cx, cy, r, startDeg + gap);
	const e = polarToCartesian(cx, cy, r, endDeg - gap);
	const largeArc = endDeg - startDeg - 2 * gap > 180 ? 1 : 0;
	return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
}

interface DonutChartProps {
	counts: SeverityCounts;
	total: number;
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<Severity, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info",
};

function DonutChart({ counts, total }: DonutChartProps) {
	const cx = 60, cy = 60, r = 44, strokeW = 14;
	const innerR = r - strokeW / 2;

	if (total === 0) {
		return (
			<svg width={120} height={120} viewBox="0 0 120 120">
				<circle cx={cx} cy={cy} r={innerR} fill="none" stroke="var(--bg-paper-alt)" strokeWidth={strokeW} />
				<text x={cx} y={cy + 5} textAnchor="middle" fontSize={12} fill="var(--ink-light)" fontFamily="var(--font-mono)">
					0
				</text>
			</svg>
		);
	}

	const slices: { sev: Severity; startDeg: number; endDeg: number }[] = [];
	let cursor = 0;
	for (const sev of SEV_ORDER) {
		const count = counts[sev];
		if (count === 0) continue;
		const span = (count / total) * 360;
		slices.push({ sev, startDeg: cursor, endDeg: cursor + span });
		cursor += span;
	}

	return (
		<svg width={120} height={120} viewBox="0 0 120 120">
			{/* Background ring */}
			<circle cx={cx} cy={cy} r={innerR} fill="none" stroke="var(--bg-paper-alt)" strokeWidth={strokeW} />
			{/* Colored arcs */}
			{slices.map(({ sev, startDeg, endDeg }) => (
				<path
					key={sev}
					d={describeArc(cx, cy, innerR, startDeg, endDeg)}
					fill="none"
					stroke={severityColor(sev)}
					strokeWidth={strokeW}
					strokeLinecap="butt"
				/>
			))}
			{/* Center total */}
			<text x={cx} y={cy - 6} textAnchor="middle" fontSize={18} fontWeight={700} fill="var(--ink-black)" fontFamily="var(--font-mono)">
				{total}
			</text>
			<text x={cx} y={cy + 10} textAnchor="middle" fontSize={9} fill="var(--ink-medium)" fontFamily="var(--font-sans)" style={{ textTransform: "uppercase", letterSpacing: "0.05em" }}>
				findings
			</text>
		</svg>
	);
}

// ─── Category Bar Chart ───────────────────────────────────────────────────

interface CategoryBarProps {
	label: string;
	count: number;
	maxCount: number;
	color: string;
}

function CategoryBar({ label, count, maxCount, color }: CategoryBarProps) {
	const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
	return (
		<div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
			<span style={{ width: 160, fontSize: 11, fontFamily: "var(--font-sans)", color: "var(--ink-medium)", flexShrink: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
				{label}
			</span>
			<div style={{ flex: 1, height: 10, background: "var(--bg-paper-alt)", borderRadius: 1, overflow: "hidden" }}>
				<div
					style={{
						width: `${pct}%`,
						height: "100%",
						background: color,
						transition: "width 0.6s ease",
						borderRadius: 1,
					}}
				/>
			</div>
			<span style={{ width: 24, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--ink-black)", fontWeight: 700, textAlign: "right", flexShrink: 0 }}>
				{count}
			</span>
		</div>
	);
}

// ─── Risk Score Hero ──────────────────────────────────────────────────────

interface RiskHeroProps {
	score: number;
	grade: RiskGrade;
	counts: SeverityCounts;
}

function RiskHero({ score, grade, counts }: RiskHeroProps) {
	const color = gradeColor(grade);
	return (
		<div style={{
			display: "flex",
			alignItems: "center",
			gap: 28,
			padding: "24px 28px",
			border: "2.5px solid var(--border-black)",
			background: "var(--bg-paper)",
			boxShadow: "var(--shadow-layer-2)",
			marginBottom: 24,
		}}>
			{/* Grade + score */}
			<div style={{ textAlign: "center", flexShrink: 0 }}>
				<div style={{
					fontFamily: "var(--font-display)",
					fontWeight: 900,
					fontSize: 56,
					lineHeight: 1,
					color,
					letterSpacing: "-0.04em",
				}}>
					{grade}
				</div>
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--ink-medium)", marginTop: 4 }}>
					{score}/100
				</div>
			</div>

			{/* Divider */}
			<div style={{ width: 2, height: 64, background: "var(--border-black)", flexShrink: 0 }} />

			{/* Breakdown */}
			<div style={{ flex: 1 }}>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 10 }}>
					Risk Breakdown
				</div>
				<div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
					{(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
						<div key={sev} style={{ textAlign: "center" }}>
							<div style={{
								fontFamily: "var(--font-mono)",
								fontSize: 20,
								fontWeight: 800,
								color: counts[sev] > 0 ? severityColor(sev) : "var(--ink-light)",
							}}>
								{counts[sev]}
							</div>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-light)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
								{sev}
							</div>
						</div>
					))}
				</div>
			</div>
		</div>
	);
}

// ─── Severity Legend ──────────────────────────────────────────────────────

function SeverityLegend({ counts }: { counts: SeverityCounts }) {
	return (
		<div style={{ display: "flex", flexWrap: "wrap", gap: "10px 18px", marginTop: 12 }}>
			{(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
				<div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
					<div style={{ width: 10, height: 10, borderRadius: 1, background: severityColor(sev) }} />
					<span style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-medium)" }}>
						{SEV_LABEL[sev]} ({counts[sev]})
					</span>
				</div>
			))}
		</div>
	);
}

// ─── Finding Card ─────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: ScanFinding }) {
	return (
		<div style={{
			border: "2px solid var(--border-black)",
			background: severityBg(finding.severity),
			padding: "12px 16px",
			marginBottom: 10,
			borderRadius: 2,
		}}>
			<div style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 6 }}>
				{/* Severity badge */}
				<span style={{
					fontFamily: "var(--font-mono)",
					fontSize: 10,
					fontWeight: 700,
					textTransform: "uppercase",
					letterSpacing: "0.06em",
					color: severityColor(finding.severity),
					border: `1.5px solid ${severityColor(finding.severity)}`,
					padding: "2px 7px",
					borderRadius: 2,
					flexShrink: 0,
					whiteSpace: "nowrap",
				}}>
					{finding.severity}
				</span>
				{/* Status badge */}
				<span style={{
					fontFamily: "var(--font-mono)",
					fontSize: 10,
					textTransform: "uppercase",
					letterSpacing: "0.04em",
					color: "var(--ink-medium)",
					border: "1.5px solid var(--border-black)",
					padding: "2px 7px",
					borderRadius: 2,
					flexShrink: 0,
					background: "var(--bg-paper)",
				}}>
					{finding.status}
				</span>
				{/* Title */}
				<span style={{ fontFamily: "var(--font-sans)", fontSize: 13, fontWeight: 600, color: "var(--ink-black)", lineHeight: 1.35 }}>
					{finding.title}
				</span>
			</div>
			{finding.file && (
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", marginBottom: 6, wordBreak: "break-all" }}>
					📄 {finding.file}
				</div>
			)}
			<div style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--ink-black)", lineHeight: 1.55 }}>
				{finding.detail}
			</div>
		</div>
	);
}

// ─── Main ScanReport ──────────────────────────────────────────────────────

export interface ScanReportProps {
	owner: string;
	repo: string;
	findings: ScanFinding[];
	scannedAt: Date;
	onClose: () => void;
	onPrint: () => void;
}

export function ScanReport({ owner, repo, findings, scannedAt, onClose, onPrint }: ScanReportProps) {
	const counts = countSeverities(findings);
	const total = findings.length;
	const score = calcRiskScore(counts);
	const grade = riskGrade(score);

	// Group findings by section
	const bySection: Record<string, ScanFinding[]> = {};
	for (const f of findings) {
		if (!bySection[f.section]) bySection[f.section] = [];
		bySection[f.section].push(f);
	}

	// Section bar chart data
	const sectionNames = Object.keys(bySection);
	const sectionCounts = sectionNames.map((s) => bySection[s].length);
	const maxSectionCount = Math.max(1, ...sectionCounts);

	// Section colors (top severity in that section)
	function sectionTopColor(sectionFindings: ScanFinding[]): string {
		const sev = (["critical", "high", "medium", "low", "info"] as Severity[]).find(
			(s) => sectionFindings.some((f) => f.severity === s)
		);
		return severityColor(sev ?? "info");
	}

	return (
		<div
			id="scan-report-printable"
			style={{
				fontFamily: "var(--font-sans)",
				color: "var(--ink-black)",
				maxWidth: 780,
				margin: "0 auto",
				padding: "0 0 40px",
			}}
		>
			{/* Header */}
			<div style={{
				display: "flex",
				alignItems: "center",
				justifyContent: "space-between",
				paddingBottom: 16,
				marginBottom: 20,
				borderBottom: "2.5px solid var(--border-black)",
			}}>
				<div>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.3rem", letterSpacing: "-0.02em" }}>
						Security Scan Report
					</div>
					<div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", marginTop: 4 }}>
						{owner}/{repo} · {scannedAt.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })} {scannedAt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
					</div>
				</div>
				{/* Action buttons (hidden in print) */}
				<div className="no-print" style={{ display: "flex", gap: 10 }}>
					<button
						onClick={onPrint}
						style={{
							padding: "7px 16px",
							border: "2.5px solid var(--border-black)",
							background: "var(--ink-black)",
							color: "var(--bg-paper)",
							fontFamily: "var(--font-mono)",
							fontSize: 11,
							fontWeight: 700,
							cursor: "pointer",
							letterSpacing: "0.04em",
							textTransform: "uppercase",
							borderRadius: 2,
						}}
					>
						Export PDF
					</button>
					<button
						onClick={onClose}
						style={{
							padding: "7px 14px",
							border: "2.5px solid var(--border-black)",
							background: "var(--bg-paper)",
							color: "var(--ink-medium)",
							fontFamily: "var(--font-mono)",
							fontSize: 11,
							cursor: "pointer",
							borderRadius: 2,
						}}
					>
						✕ Close
					</button>
				</div>
			</div>

			{/* Risk Score Hero */}
			<RiskHero score={score} grade={grade} counts={counts} />

			{/* Charts row */}
			<div style={{ display: "flex", gap: 24, marginBottom: 28, flexWrap: "wrap" }}>
				{/* Donut */}
				<div style={{
					flex: "0 0 auto",
					border: "2.5px solid var(--border-black)",
					background: "var(--bg-paper)",
					padding: "20px 24px",
					display: "flex",
					flexDirection: "column",
					alignItems: "center",
					boxShadow: "var(--shadow-subtle)",
					borderRadius: 2,
				}}>
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 12 }}>
						Severity Distribution
					</div>
					<DonutChart counts={counts} total={total} />
					<SeverityLegend counts={counts} />
				</div>

				{/* Category bars */}
				{sectionNames.length > 0 && (
					<div style={{
						flex: 1,
						minWidth: 260,
						border: "2.5px solid var(--border-black)",
						background: "var(--bg-paper)",
						padding: "20px 24px",
						boxShadow: "var(--shadow-subtle)",
						borderRadius: 2,
					}}>
						<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 16 }}>
							Findings by Category
						</div>
						{sectionNames.map((name, i) => (
							<CategoryBar
								key={name}
								label={name}
								count={sectionCounts[i]}
								maxCount={maxSectionCount}
								color={sectionTopColor(bySection[name])}
							/>
						))}
					</div>
				)}
			</div>

			{/* Findings by section */}
			{total === 0 ? (
				<div style={{
					border: "2.5px solid var(--border-black)",
					background: "var(--bg-paper)",
					padding: "32px 28px",
					textAlign: "center",
					boxShadow: "var(--shadow-subtle)",
				}}>
					<div style={{ fontSize: 32, marginBottom: 12 }}>✓</div>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "1.1rem", marginBottom: 8 }}>
						No findings detected
					</div>
					<div style={{ color: "var(--ink-medium)", fontSize: 14 }}>
						The scan found no security issues in the indexed codebase. Results are based on what was indexed.
					</div>
				</div>
			) : (
				<div>
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 16, borderBottom: "1.5px solid var(--border-black)", paddingBottom: 8 }}>
						All Findings ({total})
					</div>
					{sectionNames.map((sectionName) => (
						<div key={sectionName} style={{ marginBottom: 28 }}>
							<div style={{
								fontFamily: "var(--font-mono)",
								fontSize: 12,
								fontWeight: 700,
								color: "var(--ink-black)",
								marginBottom: 12,
								display: "flex",
								alignItems: "center",
								gap: 10,
							}}>
								<span style={{
									display: "inline-block",
									width: 10,
									height: 10,
									background: sectionTopColor(bySection[sectionName]),
									flexShrink: 0,
								}} />
								{sectionName}
								<span style={{ fontWeight: 400, color: "var(--ink-light)" }}>
									({bySection[sectionName].length})
								</span>
							</div>
							{bySection[sectionName]
								.sort((a, b) => {
									const order: Severity[] = ["critical", "high", "medium", "low", "info"];
									return order.indexOf(a.severity) - order.indexOf(b.severity);
								})
								.map((f, i) => (
									<FindingCard key={`${sectionName}-${i}`} finding={f} />
								))}
						</div>
					))}
				</div>
			)}

			{/* Footer disclaimer */}
			<div style={{
				marginTop: 32,
				paddingTop: 16,
				borderTop: "1.5px solid var(--border-black)",
				fontFamily: "var(--font-sans)",
				fontSize: 11,
				color: "var(--ink-light)",
				lineHeight: 1.6,
			}}>
				<strong>Disclaimer:</strong> This report was generated by an AI-assisted static analysis scan of indexed source code. Results are indicative only — confirm findings manually before acting. Findings marked INFERRED or POTENTIAL require additional review. Generated by SecAsk.
			</div>
		</div>
	);
}

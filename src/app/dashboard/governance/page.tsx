"use client";

/**
 * /dashboard/governance — Governance Dashboard
 *
 * Reads structured scan results from the agentic pipeline (saved in localStorage
 * by SecurityScanModal after a scan completes). Maps findings to NIST 800-53,
 * NIST CSF, and NIS2 using the CWE ID as the bridge.
 *
 * NO chat messages or RAG responses are used — all data comes directly from
 * the AgenticReport produced by runSecurityScan().
 */

import { useState, useEffect, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Shield, FileText, ChevronDown, ChevronUp, Database } from "lucide-react";
import { loadLastScan } from "@/lib/scanStorage";
import { mapToCompliance, type ComplianceResult } from "@/lib/complianceMapper";
import { isNistIndexed, loadNistControlDescriptions } from "@/lib/nistControlEnrichment";
import type { AgenticFinding } from "@/lib/agenticScan";
import type { StoredScan } from "@/lib/scanStorage";
import {
	DetailPanel,
	GitHubFileLink,
	CweBadge,
	NistBadge,
	Nis2Badge,
	SeverityFilterBadge,
	type PanelState,
} from "@/components/security/DeepLinkPanel";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sevColor(sev: string): string {
	switch (sev?.toUpperCase()) {
		case "CRITICAL": return "#B71C1C";
		case "HIGH":     return "#E65100";
		case "MEDIUM":   return "#F57F17";
		case "LOW":      return "#2E7D32";
		default:         return "#5B7FA5";
	}
}

function statusColor(status: string): string {
	switch (status) {
		case "Non-Compliant":    return "#B71C1C";
		case "Partial":          return "#E65100";
		case "Needs Improvement":return "#F57F17";
		case "Pass":             return "#2E7D32";
		default:                 return "#5B7FA5";
	}
}

function statusIcon(status: string): string {
	switch (status) {
		case "Non-Compliant":    return "🔴";
		case "Partial":          return "🟡";
		case "Needs Improvement":return "🟡";
		case "Pass":             return "✅";
		default:                 return "⬜";
	}
}

function timeAgo(ts: number): string {
	const diff = Date.now() - ts;
	if (diff < 60_000) return "just now";
	if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
	if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} hr ago`;
	return `${Math.floor(diff / 86_400_000)} days ago`;
}

function scoreColor(score: number): string {
	if (score >= 75) return "#2E7D32";
	if (score >= 50) return "#F57F17";
	return "#B71C1C";
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
	return (
		<div className="paper-card" style={{ padding: "18px 20px", flex: 1, minWidth: 120, textAlign: "center" }}>
			<div style={{ fontFamily: "var(--font-display)", fontSize: "clamp(1.4rem,2.5vw,2rem)", fontWeight: 900, color: color ?? "var(--accent-amber)", lineHeight: 1, marginBottom: 4 }}>
				{value}
			</div>
			<div style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 2 }}>
				{label}
			</div>
			{sub && <div style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-light)" }}>{sub}</div>}
		</div>
	);
}

function SectionTitle({ children }: { children: React.ReactNode }) {
	return (
		<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--accent-amber)", marginBottom: 12, paddingBottom: 6, borderBottom: "2px solid var(--accent-amber)" }}>
			{children}
		</div>
	);
}

function NistControlRow({
	controlId,
	findings,
	nistDesc,
	owner,
	repo,
	nistIndexed,
	onControlClick,
}: {
	controlId: string;
	findings: Array<{ finding: string; severity: string; file: string; line?: number; cwe: string }>;
	nistDesc: string | undefined;
	owner: string;
	repo: string;
	nistIndexed: boolean;
	onControlClick?: () => void;
}) {
	const [open, setOpen] = useState(false);
	const family = controlId.split("-")[0];
	const maxSev = findings.reduce<string>((acc, f) => {
		const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
		return (rank[f.severity] ?? 0) > (rank[acc] ?? 0) ? f.severity : acc;
	}, "LOW");

	return (
		<div style={{ border: "1.5px solid var(--bg-paper-alt)", borderRadius: 2, overflow: "hidden", marginBottom: 6 }}>
			<button
				onClick={() => setOpen((v) => !v)}
				style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%", padding: "10px 14px", background: "var(--bg-paper)", border: "none", cursor: "pointer", textAlign: "left" }}
			>
				<div style={{ display: "flex", alignItems: "center", gap: 10 }}>
					{/* Control ID — clickable to open NIST panel */}
					<NistBadge
						controlId={controlId}
						onClick={() => onControlClick?.()}
					/>
					<span style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: "var(--ink-medium)", background: "var(--bg-paper-alt)", padding: "2px 8px", borderRadius: 2 }}>{family}</span>
					<span style={{ fontFamily: "var(--font-sans)", fontSize: 10, color: sevColor(maxSev), fontWeight: 700 }}>{maxSev}</span>
				</div>
				<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
					<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)" }}>{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
					{open ? <ChevronUp size={14} color="var(--ink-light)" /> : <ChevronDown size={14} color="var(--ink-light)" />}
				</div>
			</button>

			{open && (
				<div style={{ padding: "12px 14px", background: "var(--bg-paper-alt)", borderTop: "1.5px solid var(--bg-paper-alt)" }}>
					{/* Control Requirement */}
					<div style={{ marginBottom: 12 }}>
						<div style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-amber)", marginBottom: 4 }}>
							Control Requirement
						</div>
						{nistIndexed && nistDesc ? (
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.6, padding: "8px 12px", background: "var(--bg-paper)", border: "1px solid var(--border-black)", borderLeft: "3px solid var(--accent-amber)", borderRadius: 2 }}>
								{nistDesc}
							</div>
						) : (
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-light)", fontStyle: "italic" }}>
								{nistIndexed
									? `${controlId} — description not found in indexed data`
									: `${controlId} — Index NIST 800-53 in ThreatLens for full control descriptions`}
							</div>
						)}
					</div>

					{/* Findings */}
					{findings.map((f, i) => (
						<div key={i} style={{ marginBottom: 10, paddingBottom: 10, borderBottom: i < findings.length - 1 ? "1px solid var(--bg-paper)" : "none" }}>
							<div style={{ marginBottom: 4 }}>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)" }}>
									Violation
								</span>
								<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", marginTop: 2 }}>
									<span style={{ color: sevColor(f.severity), fontWeight: 700 }}>[{f.severity}]</span>{" "}
									{f.finding}
									{f.cwe && <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", marginLeft: 6 }}>{f.cwe}</span>}
								</div>
							</div>
							{f.file && (
								<div>
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)" }}>
										Evidence
									</span>
									<div style={{ marginTop: 2 }}>
										<GitHubFileLink owner={owner} repo={repo} file={f.file} line={f.line} />
									</div>
								</div>
							)}
						</div>
					))}
				</div>
			)}
		</div>
	);
}

function FindingDetailRow({
	finding, owner, repo, onCweClick, onNistClick, onNis2Click,
}: {
	finding: AgenticFinding & { compliance: { nist_800_53: string[]; nis2_articles: string[] } };
	owner: string;
	repo: string;
	onCweClick?: (cweId: string) => void;
	onNistClick?: (controlId: string) => void;
	onNis2Click?: (articleId: string) => void;
}) {
	const [open, setOpen] = useState(false);
	const sev = finding.severity;

	return (
		<div style={{ border: "1.5px solid var(--bg-paper-alt)", borderRadius: 2, marginBottom: 4, overflow: "hidden" }}>
			<button
				onClick={() => setOpen((v) => !v)}
				style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 12px", background: "var(--bg-paper)", border: "none", cursor: "pointer", textAlign: "left" }}
			>
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 900, color: "white", background: sevColor(sev), padding: "2px 6px", borderRadius: 2, flexShrink: 0, minWidth: 56, textAlign: "center" }}>
					{sev}
				</span>
				<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, fontWeight: 600, color: "var(--ink-black)", flex: 1 }}>{finding.name}</span>
				{finding.cwe
					? <CweBadge cweId={finding.cwe} onClick={() => onCweClick?.(finding.cwe!)} />
					: <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", flexShrink: 0 }}>—</span>
				}
				<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", flexShrink: 0 }}>{finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "—"}</span>
				{open ? <ChevronUp size={13} color="var(--ink-light)" /> : <ChevronDown size={13} color="var(--ink-light)" />}
			</button>

			{open && (
				<div style={{ padding: "12px 14px", background: "var(--bg-paper-alt)", borderTop: "1.5px solid var(--bg-paper)" }}>
					{/* Evidence */}
					{finding.file && (
						<div style={{ marginBottom: 10 }}>
							<Label>Evidence</Label>
							<GitHubFileLink owner={owner} repo={repo} file={finding.file} line={finding.line} />
						</div>
					)}

					{/* Code snippet */}
					{finding.context && (
						<div style={{ marginBottom: 10 }}>
							<Label>Code Context</Label>
							<pre style={{ fontFamily: "var(--font-mono)", fontSize: 10, background: "var(--bg-paper)", border: "1.5px solid var(--border-black)", borderLeft: `3px solid ${sevColor(sev)}`, padding: "8px 10px", borderRadius: 2, overflowX: "auto", color: "var(--ink-black)", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
								{finding.context}
							</pre>
						</div>
					)}

					{/* Explanation */}
					{finding.explanation && (
						<div style={{ marginBottom: 10 }}>
							<Label>Explanation</Label>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.6 }}>{finding.explanation}</div>
						</div>
					)}

					{/* Remediation */}
					{finding.remediation && (
						<div style={{ marginBottom: 10 }}>
							<Label>Remediation</Label>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.6, padding: "8px 12px", background: "var(--bg-paper)", border: "1px solid var(--border-black)", borderLeft: "3px solid #2E7D32", borderRadius: 2 }}>
								{finding.remediation}
							</div>
						</div>
					)}

					{/* NIST + NIS2 tags — clickable to open detail panels */}
					<div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
						{finding.compliance.nist_800_53.map((c) => (
							<NistBadge key={c} controlId={c} onClick={() => onNistClick?.(c)} />
						))}
						{finding.compliance.nis2_articles.map((a) => (
							<Nis2Badge key={a} label={a.split(" - ")[0]} onClick={() => onNis2Click?.(a.split(" - ")[0])} />
						))}
					</div>
				</div>
			)}
		</div>
	);
}

function Label({ children }: { children: React.ReactNode }) {
	return (
		<div style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 4 }}>
			{children}
		</div>
	);
}

// ─── Nav Bar ──────────────────────────────────────────────────────────────────

function GovernanceNav({ hasScanData }: { hasScanData: boolean }) {
	const router = useRouter();
	const navBtn = (label: string, href: string, active = false) => (
		<button
			key={href}
			onClick={() => router.push(href)}
			style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", padding: "6px 14px", border: active ? "2px solid var(--accent-amber)" : "2px solid transparent", background: active ? "var(--accent-amber)" : "transparent", color: active ? "#0F0F0F" : "var(--ink-medium)", cursor: "pointer", borderRadius: 2, transition: "all 0.1s" }}
		>
			{label}
		</button>
	);

	return (
		<nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 24px", background: "var(--bg-paper)", borderBottom: "2px solid var(--border-black)", position: "sticky", top: 0, zIndex: 40 }}>
			<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
				<Shield size={18} color="var(--accent-amber)" />
				<span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", letterSpacing: "-0.02em", color: "var(--ink-black)" }}>
					THREATLENS
				</span>
			</div>
			<div style={{ display: "flex", gap: 4 }}>
				{navBtn("Scan", "/")}
				{navBtn("Dashboard", "/dashboard")}
				<div style={{ position: "relative" }}>
					{navBtn("Governance", "/dashboard/governance", true)}
					<span style={{ position: "absolute", top: -6, right: -6, fontFamily: "var(--font-mono)", fontSize: 8, fontWeight: 700, padding: "1px 5px", borderRadius: 10, background: hasScanData ? "var(--accent-amber)" : "var(--bg-paper-alt)", color: hasScanData ? "#0F0F0F" : "var(--ink-light)", border: "1.5px solid var(--border-black)" }}>
						{hasScanData ? "READY" : "NO DATA"}
					</span>
				</div>
			</div>
		</nav>
	);
}

// ─── Empty State ──────────────────────────────────────────────────────────────

function EmptyState() {
	const router = useRouter();
	return (
		<div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "60vh", gap: 20, textAlign: "center", padding: 40 }}>
			<div style={{ width: 64, height: 64, borderRadius: "50%", background: "var(--bg-paper-alt)", display: "flex", alignItems: "center", justifyContent: "center", border: "2px solid var(--border-black)" }}>
				<Shield size={28} color="var(--ink-light)" />
			</div>
			<div>
				<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.2rem", color: "var(--ink-black)", marginBottom: 8 }}>No scan data available</div>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--ink-medium)", lineHeight: 1.6, maxWidth: 400 }}>
					Scan a GitHub repository first to generate your governance dashboard. The agentic pipeline maps real code findings to NIST 800-53, NIST CSF, and NIS2.
				</div>
			</div>
			<button
				onClick={() => router.push("/")}
				style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "10px 22px", border: "2.5px solid var(--border-black)", background: "var(--accent-amber)", color: "#0F0F0F", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, cursor: "pointer", letterSpacing: "0.06em", textTransform: "uppercase", borderRadius: 2, boxShadow: "var(--shadow-layer-1)" }}
			>
				<Shield size={14} /> Go to Scanner
			</button>
		</div>
	);
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function GovernancePage() {
	const router = useRouter();
	const [scanData, setScanData] = useState<StoredScan | null>(null);
	const [compliance, setCompliance] = useState<ComplianceResult | null>(null);
	const [nistIndexed, setNistIndexed] = useState(false);
	const [nistDescriptions, setNistDescriptions] = useState<Record<string, string>>({});
	const [generatingPdf, setGeneratingPdf] = useState(false);
	const [sortCol, setSortCol] = useState<"severity" | "name" | "cwe">("severity");
	const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
	const [expandedFamily, setExpandedFamily] = useState<string | null>(null);
	const [activeTab, setActiveTab] = useState<"overview" | "nist53" | "csf" | "nis2" | "findings">("overview");
	const [panelState, setPanelState] = useState<PanelState>(null);
	const [severityFilter, setSeverityFilter] = useState<string | null>(null);

	// Load scan data + compute compliance on mount
	useEffect(() => {
		const stored = loadLastScan();
		if (!stored) return;
		setScanData(stored);

		const result = mapToCompliance(stored.report.findings);
		setCompliance(result);

		// Check NIST indexing and load descriptions
		void isNistIndexed().then(async (indexed) => {
			setNistIndexed(indexed);
			if (indexed && result) {
				const allControls = Object.keys(result.nist80053.violatedControls);
				const descs = await loadNistControlDescriptions(allControls);
				setNistDescriptions(descs);
			}
		});
	}, []);

	const handleGeneratePdf = useCallback(async () => {
		if (!scanData || !compliance) return;
		setGeneratingPdf(true);
		try {
			const { generateGovernancePDF } = await import("@/lib/governancePdfReport");
			await generateGovernancePDF(
				scanData.owner,
				scanData.repo,
				scanData.report,
				compliance,
				nistDescriptions,
				nistIndexed
			);
		} finally {
			setGeneratingPdf(false);
		}
	}, [scanData, compliance, nistDescriptions, nistIndexed]);

	// ─── Deep-link panel handlers ────────────────────────────────────────────────

	const openCwePanel = useCallback((cweId: string, finding?: AgenticFinding) => {
		if (!scanData) return;
		setPanelState({
			type: "cwe",
			data: {
				cweId,
				findingName: finding?.name,
				explanation: finding?.explanation,
				file: finding?.file,
				line: finding?.line,
				owner: scanData.owner,
				repo: scanData.repo,
			},
		});
	}, [scanData]);

	const openNistPanel = useCallback((controlId: string) => {
		if (!compliance || !scanData) return;
		const findings = compliance.nist80053.violatedControls[controlId] ?? [];
		setPanelState({
			type: "nist",
			data: {
				controlId,
				nistDesc: nistDescriptions[controlId],
				nistIndexed,
				findings,
				owner: scanData.owner,
				repo: scanData.repo,
			},
		});
	}, [compliance, nistDescriptions, nistIndexed, scanData]);

	const openNis2Panel = useCallback((articleIdOrPrefix: string) => {
		if (!compliance || !scanData) return;
		// Match by article ID or by article prefix (e.g. "Article 21(2)(d)")
		const article = Object.values(compliance.nis2.articles).find(
			(a) => a.id === articleIdOrPrefix || a.article.startsWith(articleIdOrPrefix) || articleIdOrPrefix.startsWith(a.article.split(" - ")[0])
		);
		if (!article) return;
		setPanelState({
			type: "nis2",
			data: { article, owner: scanData.owner, repo: scanData.repo },
		});
	}, [compliance, scanData]);

	const avgCsfScore = useMemo(() => {
		if (!compliance) return "N/A";
		const nums = Object.values(compliance.nistCSF.scores).filter((s): s is number => typeof s === "number");
		return nums.length > 0 ? `${Math.round(nums.reduce((a, b) => a + b, 0) / nums.length)}%` : "N/A";
	}, [compliance]);

	const sortedFindings = useMemo(() => {
		if (!compliance) return [];
		const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
		return [...compliance.mappedFindings]
			.filter((f) => !severityFilter || f.severity === severityFilter)
			.sort((a, b) => {
				let cmp = 0;
				if (sortCol === "severity") cmp = (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0);
				else if (sortCol === "name") cmp = a.name.localeCompare(b.name);
				else if (sortCol === "cwe") cmp = (a.cwe ?? "").localeCompare(b.cwe ?? "");
				return sortDir === "asc" ? -cmp : cmp;
			});
	}, [compliance, sortCol, sortDir, severityFilter]);

	const tabStyle = (tab: typeof activeTab): React.CSSProperties => ({
		fontFamily: "var(--font-mono)",
		fontSize: 10,
		fontWeight: 700,
		textTransform: "uppercase",
		letterSpacing: "0.06em",
		padding: "8px 16px",
		border: "none",
		borderBottom: activeTab === tab ? "2px solid var(--accent-amber)" : "2px solid transparent",
		background: "transparent",
		color: activeTab === tab ? "var(--accent-amber)" : "var(--ink-medium)",
		cursor: "pointer",
		transition: "all 0.1s",
	});

	if (!scanData || !compliance) {
		return (
			<div style={{ minHeight: "100vh", background: "var(--bg-cream)" }}>
				<GovernanceNav hasScanData={false} />
				<EmptyState />
			</div>
		);
	}

	const { report } = scanData;
	const counts = report.summary.counts;

	return (
		<>
		<div style={{ minHeight: "100vh", background: "var(--bg-cream)", fontFamily: "var(--font-sans)" }}>
			<GovernanceNav hasScanData={true} />

			{/* Page header */}
			<div style={{ padding: "24px 24px 0", background: "var(--bg-paper)", borderBottom: "2px solid var(--border-black)" }}>
				<div style={{ maxWidth: 1200, margin: "0 auto" }}>
					<div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 16 }}>
						<div>
							<div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
								<span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.3rem", color: "var(--ink-black)" }}>
									{scanData.owner}/{scanData.repo}
								</span>
								{nistIndexed && (
									<span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontFamily: "var(--font-mono)", fontSize: 8, padding: "2px 7px", background: "rgba(100,181,246,0.15)", border: "1px solid rgba(100,181,246,0.4)", color: "#64B5F6", borderRadius: 2 }}>
										<Database size={9} /> NIST indexed
									</span>
								)}
							</div>
							<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)" }}>
								Last scan: {timeAgo(scanData.savedAt)}  ·  {report.summary.filesScanned} files  ·  {report.summary.languages.join(", ")}
							</div>
						</div>
						<div style={{ display: "flex", gap: 8 }}>
							<button
								onClick={() => router.push("/")}
								style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "8px 16px", border: "2px solid var(--border-black)", background: "var(--bg-paper-alt)", color: "var(--ink-medium)", fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, cursor: "pointer", letterSpacing: "0.04em", textTransform: "uppercase", borderRadius: 2 }}
							>
								<Shield size={12} /> Re-scan
							</button>
							<button
								onClick={() => void handleGeneratePdf()}
								disabled={generatingPdf}
								title={!scanData ? "Scan a repository first to generate a report." : undefined}
								style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "8px 16px", border: "2px solid var(--border-black)", background: generatingPdf ? "var(--bg-paper-alt)" : "var(--accent-amber)", color: generatingPdf ? "var(--ink-light)" : "#0F0F0F", fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, cursor: generatingPdf ? "wait" : "pointer", letterSpacing: "0.04em", textTransform: "uppercase", borderRadius: 2, boxShadow: "var(--shadow-layer-1)" }}
							>
								<FileText size={12} /> {generatingPdf ? "Generating…" : "Generate PDF Report"}
							</button>
						</div>
					</div>

					{/* Tabs */}
					<div style={{ display: "flex", gap: 0, borderTop: "1px solid var(--bg-paper-alt)", marginTop: 4 }}>
						{(["overview", "nist53", "csf", "nis2", "findings"] as const).map((tab) => (
							<button key={tab} style={tabStyle(tab)} onClick={() => setActiveTab(tab)}>
								{tab === "nist53" ? "NIST 800-53" : tab === "csf" ? "NIST CSF" : tab === "nis2" ? "NIS2" : tab}
							</button>
						))}
					</div>
				</div>
			</div>

			<div style={{ maxWidth: 1200, margin: "0 auto", padding: "24px" }}>

				{/* ── OVERVIEW TAB ───────────────────────────────────────────── */}
				{activeTab === "overview" && (
					<>
						{/* Executive Summary stat cards */}
						<div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
							<StatCard label="Risk Score" value={String(compliance.riskScore)} sub="/100 (higher is better)" color={scoreColor(compliance.riskScore)} />
							<StatCard label="Findings" value={String(report.summary.totalFindings)} sub="confirmed" />
							<StatCard label="CSF Score" value={avgCsfScore} sub="code-assessable avg" />
							<StatCard label="NIS2 Ready" value={`${compliance.nis2.readinessPercent}%`} sub={`${compliance.nis2.assessedFromCode} articles assessed`} />
							<StatCard label="Controls Violated" value={String(compliance.nist80053.totalViolatedControls)} sub="NIST 800-53" color="#E65100" />
						</div>

						{/* Severity bar chart */}
						<div className="paper-card" style={{ padding: 20, marginBottom: 20 }}>
							<SectionTitle>Findings by Severity</SectionTitle>
							{(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
								const cnt = counts[sev] ?? 0;
								const maxCnt = Math.max(...(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => counts[s] ?? 0), 1);
								return (
									<div key={sev} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
										<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, color: sevColor(sev), width: 60, textAlign: "right" }}>{sev}</span>
										<div style={{ flex: 1, height: 10, background: "var(--bg-paper-alt)", borderRadius: 1 }}>
											<div style={{ width: `${(cnt / maxCnt) * 100}%`, height: "100%", background: sevColor(sev), borderRadius: 1, transition: "width 0.5s ease" }} />
										</div>
										<span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700, color: sevColor(sev), width: 24 }}>{cnt}</span>
									</div>
								);
							})}
						</div>

						{/* Top findings */}
						<div className="paper-card" style={{ padding: 20, marginBottom: 20 }}>
							<SectionTitle>Top Findings</SectionTitle>
							{sortedFindings.slice(0, 5).map((f, i) => (
								<div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: i < 4 ? "1px solid var(--bg-paper-alt)" : "none" }}>
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 900, color: "white", background: sevColor(f.severity), padding: "2px 6px", borderRadius: 2, flexShrink: 0 }}>{f.severity}</span>
									<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, fontWeight: 600, color: "var(--ink-black)", flex: 1 }}>{f.name}</span>
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)" }}>{f.cwe ?? "—"}</span>
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file}</span>
								</div>
							))}
						</div>

						{/* Recommendations */}
						<div className="paper-card" style={{ padding: 20 }}>
							<SectionTitle>Prioritized Recommendations</SectionTitle>
							{compliance.recommendations.map((rec, i) => (
								<div key={i} style={{ display: "flex", gap: 14, marginBottom: 16, paddingBottom: 16, borderBottom: i < compliance.recommendations.length - 1 ? "1px solid var(--bg-paper-alt)" : "none" }}>
									<div style={{ width: 28, height: 28, borderRadius: "50%", background: rec.impact === "High" ? "#B71C1C" : rec.impact === "Medium" ? "#F57F17" : "#2E7D32", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
										<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: "white" }}>{rec.priority}</span>
									</div>
									<div style={{ flex: 1 }}>
										<div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
											<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: "var(--ink-black)" }}>{rec.category}</span>
											<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "1px 6px", background: "var(--bg-paper-alt)", color: "var(--ink-medium)", borderRadius: 2 }}>{rec.impact} impact</span>
											<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)" }}>{rec.findingCount} findings</span>
										</div>
										<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", lineHeight: 1.6, marginBottom: 6 }}>{rec.action}</div>
										<div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
											{rec.affectedControls.map((c) => (
												<span key={c} style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "1px 6px", background: "rgba(100,181,246,0.15)", border: "1px solid rgba(100,181,246,0.4)", color: "#64B5F6", borderRadius: 2 }}>{c}</span>
											))}
										</div>
									</div>
								</div>
							))}
						</div>
					</>
				)}

				{/* ── NIST 800-53 TAB ───────────────────────────────────────── */}
				{activeTab === "nist53" && (
					<div className="paper-card" style={{ padding: 20 }}>
						<SectionTitle>NIST 800-53 Violated Controls ({compliance.nist80053.totalViolatedControls} total)</SectionTitle>
						{!nistIndexed && (
							<div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", background: "rgba(100,181,246,0.08)", border: "1px solid rgba(100,181,246,0.3)", borderRadius: 2, marginBottom: 14, fontFamily: "var(--font-sans)", fontSize: 12, color: "#64B5F6" }}>
								<Database size={13} /> Index <strong>NIST 800-53</strong> in ThreatLens to see full control requirement text alongside each violation.
							</div>
						)}

						{/* Group by family */}
						{Object.entries(compliance.nist80053.families)
							.sort((a, b) => b[1].total_violated - a[1].total_violated)
							.map(([family, data]) => (
								<div key={family} style={{ marginBottom: 16 }}>
									<button
										onClick={() => setExpandedFamily(expandedFamily === family ? null : family)}
										style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "8px 12px", background: "var(--bg-paper-alt)", border: "1.5px solid var(--border-black)", borderRadius: 2, cursor: "pointer", marginBottom: 6 }}
									>
										<span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", color: "var(--ink-black)", width: 32 }}>{family}</span>
										<span style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-medium)", flex: 1, textAlign: "left" }}>{data.total_violated} control{data.total_violated !== 1 ? "s" : ""} violated</span>
										<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, color: sevColor(data.max_severity), background: "var(--bg-paper)", padding: "2px 8px", borderRadius: 2 }}>{data.max_severity}</span>
										{expandedFamily === family ? <ChevronUp size={13} color="var(--ink-light)" /> : <ChevronDown size={13} color="var(--ink-light)" />}
									</button>

									{expandedFamily === family && (
										<div style={{ paddingLeft: 8 }}>
											{data.controls.map((ctrl) => (
												<NistControlRow
													key={ctrl.controlId}
													controlId={ctrl.controlId}
													findings={ctrl.findings}
													nistDesc={nistDescriptions[ctrl.controlId]}
													owner={scanData.owner}
													repo={scanData.repo}
													nistIndexed={nistIndexed}
													onControlClick={() => openNistPanel(ctrl.controlId)}
												/>
											))}
										</div>
									)}
								</div>
							))}
					</div>
				)}

				{/* ── CSF TAB ──────────────────────────────────────────────── */}
				{activeTab === "csf" && (
					<div className="paper-card" style={{ padding: 20 }}>
						<SectionTitle>NIST CSF Maturity by Function</SectionTitle>
						<div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
							{(["Identify", "Protect", "Detect", "Respond", "Recover"] as const).map((fn) => {
								const score = compliance.nistCSF.scores[fn];
								const isNA = score === "N/A";
								const numScore = isNA ? 0 : (score as number);
								const fnColors: Record<string, string> = { Identify: "#64B5F6", Protect: "#F5A623", Detect: "#66BB6A", Respond: "#FF8A65", Recover: "#CE93D8" };
								const col = fnColors[fn] ?? "var(--accent-amber)";
								return (
									<div key={fn} className="paper-card" style={{ flex: 1, minWidth: 120, padding: 16, textAlign: "center" }}>
										<div style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: col, marginBottom: 8 }}>{fn}</div>
										{isNA ? (
											<div style={{ fontFamily: "var(--font-display)", fontSize: "1.4rem", fontWeight: 900, color: "var(--ink-light)" }}>N/A</div>
										) : (
											<>
												<div style={{ fontFamily: "var(--font-display)", fontSize: "1.4rem", fontWeight: 900, color: col }}>{numScore}%</div>
												<div style={{ height: 6, background: "var(--bg-paper-alt)", borderRadius: 1, marginTop: 6 }}>
													<div style={{ width: `${numScore}%`, height: "100%", background: col, borderRadius: 1 }} />
												</div>
											</>
										)}
										{isNA && <div style={{ fontFamily: "var(--font-sans)", fontSize: 9, color: "var(--ink-light)", marginTop: 4 }}>Policy review required</div>}
									</div>
								);
							})}
						</div>

						<SectionTitle>Category Breakdown</SectionTitle>
						{Object.entries(compliance.nistCSF.categoryFindings).map(([cat, findings]) => (
							<div key={cat} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: "1px solid var(--bg-paper-alt)" }}>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, color: "var(--ink-black)", width: 64 }}>{cat}</span>
								<div style={{ flex: 1, height: 8, background: "var(--bg-paper-alt)", borderRadius: 1 }}>
									<div style={{ width: `${Math.min(100, findings.length * 15)}%`, height: "100%", background: "var(--accent-amber)", borderRadius: 1 }} />
								</div>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", width: 80 }}>{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
							</div>
						))}
					</div>
				)}

				{/* ── NIS2 TAB ─────────────────────────────────────────────── */}
				{activeTab === "nis2" && (
					<div className="paper-card" style={{ padding: 20 }}>
						<SectionTitle>NIS2 Compliance Tracker</SectionTitle>

						{/* Readiness bar */}
						<div style={{ marginBottom: 20 }}>
							<div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)" }}>Overall Readiness (code-assessable)</span>
								<span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.1rem", color: scoreColor(compliance.nis2.readinessPercent) }}>{compliance.nis2.readinessPercent}%</span>
							</div>
							<div style={{ height: 10, background: "var(--bg-paper-alt)", border: "1.5px solid var(--border-black)", borderRadius: 2 }}>
								<div style={{ width: `${compliance.nis2.readinessPercent}%`, height: "100%", background: "#2E7D32", borderRadius: 2, transition: "width 0.5s" }} />
							</div>
							<div style={{ display: "flex", gap: 16, marginTop: 8 }}>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)" }}>{compliance.nis2.assessedFromCode} articles assessable from code</span>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)" }}>{compliance.nis2.notAssessed} require policy review</span>
							</div>
						</div>

						{/* Article list */}
						{Object.values(compliance.nis2.articles).map((art) => (
							<div key={art.id} style={{ marginBottom: 10, padding: "12px 14px", background: "var(--bg-paper)", border: "1.5px solid var(--bg-paper-alt)", borderLeft: `3px solid ${statusColor(art.status)}`, borderRadius: 2 }}>
								<div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
									<span style={{ fontSize: 14, flexShrink: 0 }}>{statusIcon(art.status)}</span>
									<div style={{ flex: 1 }}>
										<div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
											<button
											onClick={() => openNis2Panel(art.id)}
											style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, color: "#CE93D8", background: "none", border: "none", cursor: "pointer", padding: 0 }}
											onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.textDecoration = "underline"; }}
											onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.textDecoration = "none"; }}
										>
											{art.article}
										</button>
											<span style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-medium)" }}>{art.title}</span>
											<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, color: statusColor(art.status), marginLeft: "auto" }}>{art.status.toUpperCase()}</span>
										</div>
										{art.assessable_from_code && art.findings.length > 0 && (
											<div style={{ marginTop: 6 }}>
												{art.findings.map((f, i) => (
													<div key={i} style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-medium)", marginTop: 2, display: "flex", alignItems: "center", gap: 6 }}>
														<span style={{ color: sevColor(f.severity), fontWeight: 700 }}>→</span>
														<span>{f.name}</span>
														<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)" }}>{f.cwe}</span>
														<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--ink-light)" }}>{f.file}</span>
													</div>
												))}
											</div>
										)}
										{!art.assessable_from_code && (
											<div style={{ marginTop: 4, fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-light)", fontStyle: "italic" }}>
												{art.statusNote}
											</div>
										)}
									</div>
								</div>
							</div>
						))}

						{/* Legend */}
						<div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 16, padding: "10px 14px", background: "var(--bg-paper-alt)", borderRadius: 2 }}>
							{[["✅", "Pass / Not Assessed"], ["🟡", "Partial / Needs Improvement"], ["🔴", "Non-Compliant"]].map(([icon, label]) => (
								<span key={label} style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--ink-medium)" }}>{icon} {label}</span>
							))}
						</div>
					</div>
				)}

				{/* ── FINDINGS TAB ─────────────────────────────────────────── */}
				{activeTab === "findings" && (
					<div className="paper-card" style={{ padding: 20 }}>
						<div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
							<SectionTitle>All Findings ({compliance.mappedFindings.length})</SectionTitle>
							<div style={{ display: "flex", gap: 8 }}>
								{(["severity", "name", "cwe"] as const).map((col) => (
									<button
										key={col}
										onClick={() => { if (sortCol === col) setSortDir((d) => d === "asc" ? "desc" : "asc"); else { setSortCol(col); setSortDir("desc"); } }}
										style={{ fontFamily: "var(--font-mono)", fontSize: 9, padding: "4px 10px", border: "1.5px solid var(--border-black)", background: sortCol === col ? "var(--accent-amber)" : "var(--bg-paper-alt)", color: sortCol === col ? "#0F0F0F" : "var(--ink-medium)", cursor: "pointer", borderRadius: 2, textTransform: "uppercase", letterSpacing: "0.04em" }}
									>
										{col} {sortCol === col ? (sortDir === "asc" ? "↑" : "↓") : ""}
									</button>
								))}
							</div>
						</div>

						{sortedFindings.map((f, i) => (
							<FindingDetailRow
								key={i}
								finding={f}
								owner={scanData.owner}
								repo={scanData.repo}
								onCweClick={(cweId) => openCwePanel(cweId, f)}
								onNistClick={(controlId) => openNistPanel(controlId)}
								onNis2Click={(articleId) => openNis2Panel(articleId)}
							/>
						))}
					</div>
				)}
			</div>
		</div>
		<DetailPanel panel={panelState} onClose={() => setPanelState(null)} />
		</>
	);
}

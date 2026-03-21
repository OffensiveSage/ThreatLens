"use client";

/**
 * DeepLinkPanel — shared slide-out detail panels for CWE, NIST 800-53 controls,
 * and NIS2 articles. Also exports small reusable link/badge primitives used
 * throughout the scan report and governance dashboard.
 */

import { useEffect } from "react";
import { ExternalLink } from "lucide-react";
import cweMap from "@/data/cweComplianceMap.json";
import type { NIS2ArticleStatus } from "@/lib/complianceMapper";

// ─── Types ────────────────────────────────────────────────────────────────────

type CWEEntry = {
	name: string;
	nist_800_53: string[];
	nist_csf: { function: string; category: string; subcategory: string };
	nis2_articles: string[];
};

const cweMapTyped = cweMap as Record<string, CWEEntry>;

export interface CwePanelData {
	cweId: string;
	findingName?: string;
	explanation?: string;
	file?: string;
	line?: number;
	owner: string;
	repo: string;
}

export interface NistPanelData {
	controlId: string;
	nistDesc?: string;
	nistIndexed: boolean;
	findings: Array<{ finding: string; severity: string; file: string; line?: number; cwe: string }>;
	owner: string;
	repo: string;
}

export interface Nis2PanelData {
	article: NIS2ArticleStatus;
	owner: string;
	repo: string;
}

export type PanelState =
	| { type: "cwe"; data: CwePanelData }
	| { type: "nist"; data: NistPanelData }
	| { type: "nis2"; data: Nis2PanelData }
	| null;

// ─── Static lookups ───────────────────────────────────────────────────────────

export const CWE_DESCRIPTIONS: Record<string, string> = {
	"CWE-20":  "The software does not validate or incorrectly validates input that can affect the control flow or data flow of a program, allowing attackers to supply crafted input to affect unintended operations.",
	"CWE-22":  "The software uses external input to construct a pathname to a file or directory under a restricted parent, but does not neutralize special elements (e.g. '../') that can cause the pathname to resolve to a location outside that directory.",
	"CWE-78":  "The software constructs all or part of an OS command using externally-influenced input, but does not neutralize special elements that could modify the intended command, enabling command injection.",
	"CWE-79":  "The software does not neutralize user-controllable input before it is placed in HTML output, allowing attackers to inject scripts that execute in other users' browsers (Cross-Site Scripting).",
	"CWE-89":  "The software constructs an SQL command using externally-influenced input without neutralizing special elements, allowing attackers to modify the intended SQL query (SQL Injection).",
	"CWE-94":  "The software constructs code using externally-influenced input without neutralizing special elements that could modify the syntax or behavior of the intended code segment.",
	"CWE-200": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
	"CWE-284": "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor (Improper Access Control).",
	"CWE-287": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct (Authentication Failure).",
	"CWE-295": "The software does not validate, or incorrectly validates, a certificate, enabling man-in-the-middle attacks.",
	"CWE-311": "The software does not encrypt sensitive or critical information before storage or transmission.",
	"CWE-312": "The application stores sensitive information (passwords, keys, PII) in cleartext within a resource accessible to other control spheres.",
	"CWE-319": "The software transmits sensitive data in cleartext in a communication channel that can be sniffed by unauthorized actors (Cleartext Transmission).",
	"CWE-326": "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound but not strong enough for the level of protection required.",
	"CWE-327": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
	"CWE-330": "The software uses insufficiently random numbers or values in a security context, making them predictable.",
	"CWE-352": "The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted it (CSRF).",
	"CWE-434": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
	"CWE-502": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
	"CWE-532": "Information written to log files can be of a sensitive nature, giving valuable guidance to an attacker or exposing user credentials.",
	"CWE-601": "A web application accepts a user-controlled input that specifies a link to an external site and uses that link in a redirect (Open Redirect).",
	"CWE-693": "The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks.",
	"CWE-798": "The software contains hard-coded credentials (password, cryptographic key) which it uses for inbound authentication or to authenticate with external components, creating a significant authentication bypass hole.",
};

export const NIST_CONTROL_TITLES: Record<string, string> = {
	"AC-1":  "Access Control Policy and Procedures",
	"AC-2":  "Account Management",
	"AC-3":  "Access Enforcement",
	"AC-4":  "Information Flow Enforcement",
	"AC-6":  "Least Privilege",
	"AC-17": "Remote Access",
	"AU-2":  "Event Logging",
	"AU-9":  "Protection of Audit Information",
	"CA-7":  "Continuous Monitoring",
	"CM-2":  "Baseline Configuration",
	"CM-6":  "Configuration Settings",
	"CM-7":  "Least Functionality",
	"IA-2":  "Identification and Authentication (Organizational Users)",
	"IA-5":  "Authenticator Management",
	"IA-8":  "Identification and Authentication (Non-Organizational Users)",
	"IR-4":  "Incident Handling",
	"IR-5":  "Incident Monitoring",
	"MP-4":  "Media Storage",
	"RA-5":  "Vulnerability Monitoring and Scanning",
	"SA-3":  "System Development Life Cycle",
	"SA-8":  "Security and Privacy Engineering Principles",
	"SA-11": "Developer Testing and Evaluation",
	"SA-15": "Development Process, Standards, and Tools",
	"SC-5":  "Denial-of-Service Protection",
	"SC-8":  "Transmission Confidentiality and Integrity",
	"SC-12": "Cryptographic Key Establishment and Management",
	"SC-13": "Cryptographic Protection",
	"SC-23": "Session Authenticity",
	"SC-28": "Protection of Information at Rest",
	"SC-39": "Process Isolation",
	"SI-2":  "Flaw Remediation",
	"SI-3":  "Malicious Code Protection",
	"SI-10": "Information Input Validation",
};

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
		case "Non-Compliant":     return "#B71C1C";
		case "Partial":           return "#E65100";
		case "Needs Improvement": return "#F57F17";
		case "Pass":              return "#2E7D32";
		default:                  return "#5B7FA5";
	}
}

// ─── Reusable primitives ──────────────────────────────────────────────────────

export function githubFileUrl(owner: string, repo: string, file: string, line?: number): string {
	return `https://github.com/${owner}/${repo}/blob/main/${file}${line ? `#L${line}` : ""}`;
}

/** Clickable file:line link → GitHub. Stops click propagation so it works inside collapsible rows. */
export function GitHubFileLink({
	owner, repo, file, line,
}: { owner: string; repo: string; file: string; line?: number }) {
	return (
		<a
			href={githubFileUrl(owner, repo, file, line)}
			target="_blank"
			rel="noopener noreferrer"
			onClick={(e) => e.stopPropagation()}
			style={{
				fontFamily: "var(--font-mono)",
				fontSize: 11,
				color: "var(--accent-amber)",
				textDecoration: "none",
				display: "inline-flex",
				alignItems: "center",
				gap: 4,
				cursor: "pointer",
			}}
			onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "underline"; }}
			onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "none"; }}
		>
			📄 {file}{line ? `:${line}` : ""} <ExternalLink size={10} />
		</a>
	);
}

/** CWE badge that opens the detail panel on click. */
export function CweBadge({ cweId, onClick }: { cweId: string; onClick: () => void }) {
	return (
		<button
			onClick={(e) => { e.stopPropagation(); onClick(); }}
			title={`View ${cweId} details`}
			style={{
				fontFamily: "var(--font-mono)",
				fontSize: 10,
				color: "var(--accent-amber)",
				border: "1.5px solid var(--accent-amber)",
				padding: "2px 7px",
				borderRadius: 2,
				flexShrink: 0,
				background: "transparent",
				cursor: "pointer",
				transition: "background 0.1s",
			}}
			onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(245,166,35,0.14)"; }}
			onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; }}
		>
			{cweId}
		</button>
	);
}

/** NIST 800-53 control tag that opens the detail panel on click. */
export function NistBadge({ controlId, onClick }: { controlId: string; onClick: () => void }) {
	return (
		<button
			onClick={(e) => { e.stopPropagation(); onClick(); }}
			title={`View ${controlId} details`}
			style={{
				fontFamily: "var(--font-mono)",
				fontSize: 9,
				padding: "2px 7px",
				background: "rgba(100,181,246,0.15)",
				border: "1px solid rgba(100,181,246,0.4)",
				color: "#64B5F6",
				borderRadius: 2,
				cursor: "pointer",
				transition: "background 0.1s",
			}}
			onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(100,181,246,0.3)"; }}
			onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(100,181,246,0.15)"; }}
		>
			{controlId}
		</button>
	);
}

/** NIS2 article tag that opens the detail panel on click. */
export function Nis2Badge({ label, onClick }: { label: string; onClick: () => void }) {
	return (
		<button
			onClick={(e) => { e.stopPropagation(); onClick(); }}
			title={`View ${label} details`}
			style={{
				fontFamily: "var(--font-mono)",
				fontSize: 9,
				padding: "2px 7px",
				background: "rgba(206,147,216,0.15)",
				border: "1px solid rgba(206,147,216,0.4)",
				color: "#CE93D8",
				borderRadius: 2,
				cursor: "pointer",
				transition: "background 0.1s",
			}}
			onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(206,147,216,0.3)"; }}
			onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(206,147,216,0.15)"; }}
		>
			{label}
		</button>
	);
}

/** Clickable severity badge. Highlights when active. */
export function SeverityFilterBadge({
	severity, count, active, onClick,
}: { severity: string; count: number; active: boolean; onClick: () => void }) {
	const color = sevColor(severity);
	return (
		<button
			onClick={(e) => { e.stopPropagation(); onClick(); }}
			style={{
				fontFamily: "var(--font-mono)",
				fontSize: 10,
				fontWeight: 700,
				padding: "3px 10px",
				border: `1.5px solid ${color}`,
				background: active ? color : "transparent",
				color: active ? "white" : color,
				cursor: "pointer",
				borderRadius: 2,
				textTransform: "uppercase" as const,
				letterSpacing: "0.04em",
				transition: "all 0.1s",
			}}
		>
			{severity} ({count})
		</button>
	);
}

// ─── Panel section label ──────────────────────────────────────────────────────

function PanelSection({ label, children }: { label: string; children: React.ReactNode }) {
	return (
		<div style={{ marginBottom: 18 }}>
			<div style={{
				fontFamily: "var(--font-mono)",
				fontSize: 9,
				fontWeight: 700,
				textTransform: "uppercase" as const,
				letterSpacing: "0.08em",
				color: "var(--accent-amber)",
				marginBottom: 7,
				paddingBottom: 4,
				borderBottom: "1px solid rgba(245,166,35,0.2)",
			}}>
				{label}
			</div>
			{children}
		</div>
	);
}

// ─── CWE Panel content ────────────────────────────────────────────────────────

function CwePanelContent({ data }: { data: CwePanelData }) {
	const entry = cweMapTyped[data.cweId];
	const num = data.cweId.replace("CWE-", "");
	const mitreUrl = `https://cwe.mitre.org/data/definitions/${num}.html`;
	const desc = CWE_DESCRIPTIONS[data.cweId];

	return (
		<>
			<div style={{ marginBottom: 20 }}>
				<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.3rem", color: "var(--accent-amber)", letterSpacing: "-0.02em" }}>
					{data.cweId}
				</div>
				{entry && (
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 15, fontWeight: 700, color: "var(--ink-black)", marginTop: 4 }}>
						{entry.name}
					</div>
				)}
				<a
					href={mitreUrl}
					target="_blank"
					rel="noopener noreferrer"
					style={{ display: "inline-flex", alignItems: "center", gap: 4, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--accent-amber)", textDecoration: "none", marginTop: 8 }}
					onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "underline"; }}
					onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "none"; }}
				>
					View on MITRE CWE <ExternalLink size={10} />
				</a>
			</div>

			{desc && (
				<PanelSection label="What is this weakness?">
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", lineHeight: 1.7, padding: "10px 12px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderLeft: "3px solid var(--accent-amber)", borderRadius: 2 }}>
						{desc}
					</div>
				</PanelSection>
			)}

			{(data.findingName || data.file) && (
				<PanelSection label="Why ThreatLens flagged this">
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.6 }}>
						{data.findingName && <strong>{data.findingName}</strong>}
						{data.file && (
							<div style={{ marginTop: 6 }}>
								<GitHubFileLink owner={data.owner} repo={data.repo} file={data.file} line={data.line} />
							</div>
						)}
					</div>
					{data.explanation && (
						<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", lineHeight: 1.6, marginTop: 8 }}>
							{data.explanation}
						</div>
					)}
				</PanelSection>
			)}

			{entry?.nist_800_53 && entry.nist_800_53.length > 0 && (
				<PanelSection label="NIST 800-53 Controls Affected">
					<div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
						{entry.nist_800_53.map((c) => (
							<div key={c} style={{ fontFamily: "var(--font-mono)", fontSize: 10, padding: "4px 10px", background: "rgba(100,181,246,0.1)", border: "1px solid rgba(100,181,246,0.3)", color: "#64B5F6", borderRadius: 2 }}>
								<strong>{c}</strong>{NIST_CONTROL_TITLES[c] ? ` — ${NIST_CONTROL_TITLES[c]}` : ""}
							</div>
						))}
					</div>
				</PanelSection>
			)}

			{entry?.nis2_articles && entry.nis2_articles.length > 0 && (
				<PanelSection label="NIS2 Articles Affected">
					<div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
						{entry.nis2_articles.map((a) => (
							<div key={a} style={{ fontFamily: "var(--font-mono)", fontSize: 10, padding: "4px 10px", background: "rgba(206,147,216,0.1)", border: "1px solid rgba(206,147,216,0.3)", color: "#CE93D8", borderRadius: 2 }}>
								{a.split(" - ")[0]}
							</div>
						))}
					</div>
				</PanelSection>
			)}

			{entry?.nist_csf && (
				<PanelSection label="NIST CSF Mapping">
					<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-medium)", padding: "6px 10px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderRadius: 2, lineHeight: 1.8 }}>
						<div><span style={{ color: "var(--ink-light)" }}>Function:</span> {entry.nist_csf.function}</div>
						<div><span style={{ color: "var(--ink-light)" }}>Category:</span> {entry.nist_csf.category}</div>
						<div><span style={{ color: "var(--ink-light)" }}>Subcategory:</span> {entry.nist_csf.subcategory}</div>
					</div>
				</PanelSection>
			)}
		</>
	);
}

// ─── NIST Control Panel content ───────────────────────────────────────────────

function NistPanelContent({ data }: { data: NistPanelData }) {
	const family = data.controlId.split("-")[0];
	const title = NIST_CONTROL_TITLES[data.controlId];
	const csfToolsUrl = `https://csf.tools/reference/nist-sp-800-53/r5/${family.toLowerCase()}/${data.controlId.toLowerCase()}/`;

	return (
		<>
			<div style={{ marginBottom: 20 }}>
				<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.3rem", color: "#64B5F6", letterSpacing: "-0.02em" }}>
					{data.controlId}
				</div>
				{title && (
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 15, fontWeight: 700, color: "var(--ink-black)", marginTop: 4 }}>
						{title}
					</div>
				)}
				<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", marginTop: 4 }}>
					Control Family: {family}
				</div>
				<a
					href={csfToolsUrl}
					target="_blank"
					rel="noopener noreferrer"
					style={{ display: "inline-flex", alignItems: "center", gap: 4, fontFamily: "var(--font-mono)", fontSize: 10, color: "#64B5F6", textDecoration: "none", marginTop: 8 }}
					onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "underline"; }}
					onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = "none"; }}
				>
					View on csf.tools <ExternalLink size={10} />
				</a>
			</div>

			<PanelSection label="Control Requirement">
				{data.nistIndexed && data.nistDesc ? (
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-black)", lineHeight: 1.7, padding: "10px 12px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderLeft: "3px solid #64B5F6", borderRadius: 2 }}>
						{data.nistDesc}
					</div>
				) : (
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", fontStyle: "italic", padding: "10px 12px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderRadius: 2 }}>
						{data.nistIndexed
							? `${data.controlId} — description not found in indexed NIST data`
							: "Index NIST 800-53 in ThreatLens to see the full control requirement text."}
					</div>
				)}
			</PanelSection>

			{data.findings.length > 0 && (
				<PanelSection label={`Findings in Violation (${data.findings.length})`}>
					{data.findings.map((f, i) => (
						<div key={i} style={{ marginBottom: 8, padding: "8px 10px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderLeft: `3px solid ${sevColor(f.severity)}`, borderRadius: 2 }}>
							<div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, color: sevColor(f.severity) }}>{f.severity}</span>
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, fontWeight: 600, color: "var(--ink-black)", flex: 1 }}>{f.finding}</span>
								{f.cwe && <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--accent-amber)" }}>{f.cwe}</span>}
							</div>
							{f.file && <GitHubFileLink owner={data.owner} repo={data.repo} file={f.file} line={f.line} />}
						</div>
					))}
				</PanelSection>
			)}
		</>
	);
}

// ─── NIS2 Article Panel content ───────────────────────────────────────────────

function Nis2PanelContent({ data }: { data: Nis2PanelData }) {
	const { article } = data;
	const color = statusColor(article.status);

	return (
		<>
			<div style={{ marginBottom: 20 }}>
				<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.1rem", color: "#CE93D8", letterSpacing: "-0.01em" }}>
					{article.article}
				</div>
				<div style={{ fontFamily: "var(--font-sans)", fontSize: 15, fontWeight: 700, color: "var(--ink-black)", marginTop: 4, marginBottom: 10 }}>
					{article.title}
				</div>
				<span style={{
					fontFamily: "var(--font-mono)",
					fontSize: 10,
					fontWeight: 700,
					color: color,
					border: `1.5px solid ${color}`,
					padding: "3px 10px",
					borderRadius: 2,
				}}>
					{article.status.toUpperCase()}
				</span>
			</div>

			{article.description && (
				<PanelSection label="Article Description">
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", lineHeight: 1.7, padding: "10px 12px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderLeft: "3px solid #CE93D8", borderRadius: 2 }}>
						{article.description}
					</div>
				</PanelSection>
			)}

			{article.assessable_from_code && article.findings.length > 0 && (
				<PanelSection label={`Code Violations (${article.findings.length})`}>
					{article.findings.map((f, i) => (
						<div key={i} style={{ marginBottom: 8, padding: "8px 10px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderLeft: `3px solid ${sevColor(f.severity)}`, borderRadius: 2 }}>
							<div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, color: sevColor(f.severity) }}>{f.severity}</span>
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 12, fontWeight: 600, color: "var(--ink-black)", flex: 1 }}>{f.name}</span>
								{f.cwe && <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--accent-amber)" }}>{f.cwe}</span>}
							</div>
							{f.file && <GitHubFileLink owner={data.owner} repo={data.repo} file={f.file} />}
						</div>
					))}
				</PanelSection>
			)}

			{article.assessable_from_code && article.findings.length === 0 && (
				<PanelSection label="Compliance Status">
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "#2E7D32", lineHeight: 1.6, padding: "10px 12px", background: "rgba(46,125,50,0.08)", border: "1px solid rgba(46,125,50,0.4)", borderRadius: 2 }}>
						✓ No code-level violations detected for this article.
					</div>
				</PanelSection>
			)}

			{!article.assessable_from_code && (
				<PanelSection label="Assessment Note">
					<div style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--ink-medium)", lineHeight: 1.6, padding: "10px 12px", background: "var(--bg-paper-alt)", border: "1px solid var(--border-black)", borderRadius: 2 }}>
						<strong style={{ color: "var(--ink-black)" }}>This article cannot be fully assessed from code alone.</strong>
						{article.statusNote && <div style={{ marginTop: 6 }}>{article.statusNote}</div>}
					</div>
				</PanelSection>
			)}
		</>
	);
}

// ─── Main Detail Panel ────────────────────────────────────────────────────────

export function DetailPanel({ panel, onClose }: { panel: PanelState; onClose: () => void }) {
	useEffect(() => {
		if (!panel) return;
		const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
		window.addEventListener("keydown", handler);
		return () => window.removeEventListener("keydown", handler);
	}, [panel, onClose]);

	if (!panel) return null;

	const accentColor =
		panel.type === "cwe"  ? "var(--accent-amber)" :
		panel.type === "nist" ? "#64B5F6" :
		"#CE93D8";

	const title =
		panel.type === "cwe"  ? `${panel.data.cweId} — Detail` :
		panel.type === "nist" ? `${panel.data.controlId} — Control Detail` :
		panel.data.article.article;

	return (
		<>
			{/* Backdrop */}
			<div
				onClick={onClose}
				style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", zIndex: 200 }}
			/>

			{/* Slide-in panel */}
			<div style={{
				position: "fixed",
				top: 0,
				right: 0,
				bottom: 0,
				width: "min(520px, 100vw)",
				background: "var(--bg-paper)",
				borderLeft: `3px solid ${accentColor}`,
				zIndex: 201,
				display: "flex",
				flexDirection: "column",
				boxShadow: "-6px 0 32px rgba(0,0,0,0.5)",
			}}>
				{/* Header */}
				<div style={{
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					padding: "14px 18px",
					borderBottom: `2px solid ${accentColor}`,
					background: "var(--bg-paper-alt)",
					flexShrink: 0,
				}}>
					<span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: accentColor }}>
						{title}
					</span>
					<button
						onClick={onClose}
						style={{ background: "none", border: "1.5px solid var(--border-black)", color: "var(--ink-medium)", cursor: "pointer", padding: "4px 10px", borderRadius: 2, fontFamily: "var(--font-mono)", fontSize: 12, transition: "all 0.1s" }}
						onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--accent-amber)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--accent-amber)"; }}
						onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--border-black)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--ink-medium)"; }}
					>
						✕
					</button>
				</div>

				{/* Scrollable body */}
				<div style={{ flex: 1, overflowY: "auto", padding: "20px 18px" }}>
					{panel.type === "cwe"  && <CwePanelContent  data={panel.data} />}
					{panel.type === "nist" && <NistPanelContent data={panel.data} />}
					{panel.type === "nis2" && <Nis2PanelContent data={panel.data} />}
				</div>
			</div>
		</>
	);
}

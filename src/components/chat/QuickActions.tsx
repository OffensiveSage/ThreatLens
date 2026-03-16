"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import {
	Shield, Package, Key, Globe, ArrowUpCircle,
	Target, BarChart2, Users,
	SearchX, AlertTriangle, Zap,
	Bug, List, ClipboardList, CheckSquare,
	type LucideIcon,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface QuickAction {
	id: string;
	label: string;
	Icon: LucideIcon;
	prompt: string;
	nvdRequired?: boolean;
}

// ─── Action definitions ───────────────────────────────────────────────────────

const REPO_ACTIONS: QuickAction[] = [
	{
		id: "scan",
		label: "Scan Vulnerabilities",
		Icon: Shield,
		prompt:
			"Perform a comprehensive security vulnerability scan of this codebase. Check for injection flaws, authentication issues, insecure data handling, hardcoded secrets, and insecure configurations. Only report findings with evidence from the actual code. Mark each as CONFIRMED or INFERRED.",
	},
	{
		id: "deps",
		label: "Check Dependencies",
		Icon: Package,
		prompt:
			"Cross-reference all dependencies and packages in this repo against known CVEs. List each vulnerable dependency with its CVE ID, severity, and the file where it is imported.",
		nvdRequired: true,
	},
	{
		id: "secrets",
		label: "Find Secrets",
		Icon: Key,
		prompt:
			"Search this codebase for hardcoded secrets, API keys, tokens, passwords, and credentials. Check environment files, configuration files, and source code. Show the exact file and line for each finding.",
	},
	{
		id: "attack-surface",
		label: "Map Attack Surface",
		Icon: Globe,
		prompt:
			"Map the attack surface of this application. Identify all external-facing endpoints, API routes, user input handlers, file upload mechanisms, and network calls. For each entry point, assess the security risk.",
	},
	{
		id: "improve",
		label: "Security Improvements",
		Icon: ArrowUpCircle,
		prompt:
			"Based on the codebase, suggest the top 10 security improvements ranked by impact. For each suggestion, reference the specific code that needs to change and explain the risk if left unfixed.",
	},
];

const ATTACK_ACTIONS: QuickAction[] = [
	{
		id: "kill-chain",
		label: "Map Kill Chain",
		Icon: Target,
		prompt:
			"Walk through a complete attack kill chain from initial access to impact, citing specific ATT&CK techniques at each stage with their IDs and descriptions.",
	},
	{
		id: "top-techniques",
		label: "Top Techniques",
		Icon: BarChart2,
		prompt:
			"List the top 10 most commonly used ATT&CK techniques across all threat groups in the indexed data, ordered by frequency of group usage.",
	},
	{
		id: "group-analysis",
		label: "Group Analysis",
		Icon: Users,
		prompt:
			"Analyze the threat groups in the indexed data. For each group, summarize their primary tactics, most-used techniques, and known target sectors.",
	},
];

const SIGMA_ACTIONS: QuickAction[] = [
	{
		id: "coverage-gaps",
		label: "Coverage Gaps",
		Icon: SearchX,
		prompt:
			"Identify gaps in detection coverage. List ATT&CK techniques and tactics that have no Sigma rules in the indexed data.",
	},
	{
		id: "critical-rules",
		label: "Critical Rules",
		Icon: AlertTriangle,
		prompt:
			"List all Sigma rules with critical or high severity. For each, show the rule title, log source, ATT&CK technique coverage, and a summary of the detection logic.",
	},
	{
		id: "generate-rule",
		label: "Generate New Rule",
		Icon: Zap,
		prompt:
			"Based on the indexed Sigma rules, suggest 3 new detection rules for high-impact ATT&CK techniques that currently lack coverage. Include the log source, detection logic, and ATT&CK mapping.",
	},
];

const NVD_ACTIONS: QuickAction[] = [
	{
		id: "critical-cves",
		label: "Critical CVEs",
		Icon: AlertTriangle,
		prompt:
			"List all critical severity CVEs (CVSS 9.0+) in the indexed data. For each, show the CVE ID, CVSS score, affected software, and a brief description of the vulnerability.",
	},
	{
		id: "exploitable",
		label: "Exploitable Vulns",
		Icon: Bug,
		prompt:
			"Which CVEs in the indexed data have known public exploits or exploit code available? List them with their CVE ID, CVSS score, and exploitation details.",
	},
	{
		id: "patch-priorities",
		label: "Patch Priorities",
		Icon: List,
		prompt:
			"Prioritize the top 10 CVEs that organizations should patch first, ranked by CVSS score and exploitability. Include patch availability status for each.",
	},
];

const NIST_ACTIONS: QuickAction[] = [
	{
		id: "gap-analysis",
		label: "Gap Analysis",
		Icon: SearchX,
		prompt:
			"Identify the most commonly missing or weak security controls for a typical organization. Highlight controls that are frequently overlooked but have high security impact.",
	},
	{
		id: "high-baseline",
		label: "High Baseline Controls",
		Icon: CheckSquare,
		prompt:
			"List all controls required in the HIGH security baseline that are not in the LOW baseline. Explain why each was elevated and its security significance.",
	},
	{
		id: "audit-checklist",
		label: "Audit Checklist",
		Icon: ClipboardList,
		prompt:
			"Generate a security audit checklist based on the NIST 800-53 HIGH baseline. Group controls by family and include the key questions an auditor should verify for each.",
	},
];

export const DOMAIN_QUICK_ACTIONS: Record<string, QuickAction[]> = {
	attack: ATTACK_ACTIONS,
	sigma: SIGMA_ACTIONS,
	nvd: NVD_ACTIONS,
	nist: NIST_ACTIONS,
};

// ─── NVD indexed check ────────────────────────────────────────────────────────

/** Async check against IndexedDB — resolves true if any NVD cache blob exists. */
export async function checkNvdIndexed(): Promise<boolean> {
	return new Promise((resolve) => {
		try {
			const req = indexedDB.open("gitask-cache", 1);
			req.onsuccess = () => {
				const db = req.result;
				if (!db.objectStoreNames.contains("repos")) { resolve(false); return; }
				const tx = db.transaction("repos", "readonly");
				const store = tx.objectStore("repos");
				const keysReq = store.getAllKeys();
				keysReq.onsuccess = () => {
					resolve((keysReq.result as string[]).some((k) => k.startsWith("secask/nvd")));
				};
				keysReq.onerror = () => resolve(false);
			};
			req.onerror = () => resolve(false);
		} catch {
			resolve(false);
		}
	});
}

// ─── Component ────────────────────────────────────────────────────────────────

interface QuickActionsProps {
	source: "repo" | "attack" | "sigma" | "nvd" | "nist" | "custom";
	onSend: (prompt: string) => void;
	isNvdIndexed?: boolean;
}

export function QuickActions({ source, onSend, isNvdIndexed = false }: QuickActionsProps) {
	const router = useRouter();
	const [nvdPopoverOpen, setNvdPopoverOpen] = useState(false);
	const popoverContainerRef = useRef<HTMLDivElement>(null);

	// Close NVD popover on outside click
	useEffect(() => {
		if (!nvdPopoverOpen) return;
		const handler = (e: MouseEvent) => {
			if (
				popoverContainerRef.current &&
				!popoverContainerRef.current.contains(e.target as Node)
			) {
				setNvdPopoverOpen(false);
			}
		};
		document.addEventListener("mousedown", handler);
		return () => document.removeEventListener("mousedown", handler);
	}, [nvdPopoverOpen]);

	const actions = source === "repo" ? REPO_ACTIONS : (DOMAIN_QUICK_ACTIONS[source] ?? []);
	if (actions.length === 0) return null;

	return (
		<div
			style={{
				borderTop: "1.5px solid var(--bg-paper-alt)",
				background: "var(--bg-cream)",
				flexShrink: 0,
				padding: "8px 20px 8px",
			}}
		>
			{/* Scrollable chip row */}
			<div
				style={{
					display: "flex",
					gap: 8,
					alignItems: "center",
					overflowX: "auto",
					scrollbarWidth: "none",
					WebkitOverflowScrolling: "touch",
				} as React.CSSProperties}
			>
				{/* Row label */}
				<span
					style={{
						fontFamily: "var(--font-mono)",
						fontSize: "9px",
						fontWeight: 700,
						textTransform: "uppercase",
						letterSpacing: "0.1em",
						color: "var(--ink-light)",
						flexShrink: 0,
						userSelect: "none",
					}}
				>
					Quick:
				</span>

				{actions.map((action) => {
					const isGated = action.nvdRequired && !isNvdIndexed;
					const isThisPopoverOpen = nvdPopoverOpen && action.id === "deps";

					return (
						<div
							key={action.id}
							style={{ position: "relative", flexShrink: 0 }}
							ref={action.id === "deps" ? popoverContainerRef : undefined}
						>
							<button
								onClick={() => {
									if (isGated) {
										setNvdPopoverOpen((v) => !v);
									} else {
										onSend(action.prompt);
									}
								}}
								style={{
									display: "inline-flex",
									alignItems: "center",
									gap: 6,
									padding: "5px 12px",
									border: isGated ? "2.5px solid var(--border-black)" : "2.5px solid var(--accent-amber)",
									background: isGated ? "var(--bg-paper-alt)" : "var(--bg-paper)",
									boxShadow: "var(--shadow-subtle)",
									cursor: "pointer",
									fontFamily: "var(--font-sans)",
									fontSize: "12px",
									fontWeight: 600,
									color: isGated ? "var(--ink-light)" : "var(--accent-amber)",
									borderRadius: 2,
									transition: "transform 0.1s ease, box-shadow 0.1s ease",
									whiteSpace: "nowrap",
								}}
								onMouseEnter={(e) => {
									if (!isGated) {
										e.currentTarget.style.transform = "translate(-1px, -1px)";
										e.currentTarget.style.boxShadow = "var(--shadow-hover)";
										e.currentTarget.style.background = "var(--accent-amber)";
										e.currentTarget.style.color = "#0F0F0F";
									}
								}}
								onMouseLeave={(e) => {
									e.currentTarget.style.transform = "";
									e.currentTarget.style.boxShadow = "var(--shadow-subtle)";
									e.currentTarget.style.background = "var(--bg-paper)";
									e.currentTarget.style.color = "var(--accent-amber)";
								}}
								onMouseDown={(e) => {
									if (!isGated) {
										e.currentTarget.style.transform = "translate(2px, 2px)";
										e.currentTarget.style.boxShadow = "none";
										e.currentTarget.style.background = "var(--accent-amber-dim)";
									}
								}}
								onMouseUp={(e) => {
									if (!isGated) {
										e.currentTarget.style.transform = "translate(-1px, -1px)";
										e.currentTarget.style.boxShadow = "var(--shadow-layer-1)";
									}
								}}
								title={isGated ? "Index NVD first to enable dependency scanning" : undefined}
							>
								<action.Icon size={13} strokeWidth={2.5} />
								{action.label}
								{isGated && (
									<span style={{ fontSize: "10px", opacity: 0.5, marginLeft: 2 }}>
										—
									</span>
								)}
							</button>

							{/* NVD-not-indexed popover */}
							{isGated && isThisPopoverOpen && (
								<div
									style={{
										position: "absolute",
										bottom: "calc(100% + 10px)",
										left: 0,
										background: "var(--bg-paper)",
										border: "2.5px solid var(--border-black)",
										boxShadow: "var(--shadow-layer-2)",
										padding: "14px 16px",
										width: 272,
										zIndex: 80,
										borderRadius: 2,
									}}
								>
									{/* Triangle caret */}
									<div
										style={{
											position: "absolute",
											bottom: -10,
											left: 16,
											width: 0,
											height: 0,
											borderLeft: "8px solid transparent",
											borderRight: "8px solid transparent",
											borderTop: "8px solid var(--border-black)",
										}}
									/>
									<div
										style={{
											position: "absolute",
											bottom: -7,
											left: 18,
											width: 0,
											height: 0,
											borderLeft: "6px solid transparent",
											borderRight: "6px solid transparent",
											borderTop: "6px solid var(--bg-paper)",
										}}
									/>

									<p
										style={{
											fontFamily: "var(--font-sans)",
											fontSize: "13px",
											color: "var(--ink-black)",
											margin: "0 0 12px",
											lineHeight: 1.55,
										}}
									>
										Index <strong>NVD</strong> first to scan dependencies against known CVEs.
									</p>
									<button
										onClick={() => router.push("/")}
										style={{
											display: "inline-flex",
											alignItems: "center",
											gap: 6,
											padding: "6px 14px",
											border: "2.5px solid var(--border-black)",
											background: "var(--accent-amber)",
											color: "#0F0F0F",
											fontFamily: "var(--font-mono)",
											fontSize: "11px",
											fontWeight: 700,
											cursor: "pointer",
											letterSpacing: "0.04em",
											textTransform: "uppercase",
											borderRadius: 2,
											boxShadow: "var(--shadow-layer-1)",
										}}
									>
										← Index NVD
									</button>
								</div>
							)}
						</div>
					);
				})}
			</div>
		</div>
	);
}

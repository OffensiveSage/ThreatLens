"use client";

import { useRef, useState, useEffect } from "react";
import { ModelSettings } from "@/components/ModelSettings";
import { getLLMConfig, type LLMStatus } from "@/lib/llm";
import type { Message } from "@/app/[owner]/[repo]/types";

const PROJECT_REPO_URL = "https://github.com/FloareDor/gitask";

const overflowItemStyle: React.CSSProperties = {
	fontSize: "13px",
	padding: "8px 14px",
	justifyContent: "flex-start",
	width: "100%",
	border: "none",
	boxShadow: "none",
	background: "transparent",
	cursor: "pointer",
	color: "var(--ink-medium)",
	textAlign: "left",
};

interface RepoHeaderProps {
	owner: string;
	repo: string;
	isIndexed: boolean;
	repoStale: boolean;
	llmStatus: LLMStatus;
	sidebarCollapsed: boolean;
	showContext: boolean;
	coveEnabled: boolean;
	queryExpansionEnabled: boolean;
	isLocalProvider: boolean;
	isGenerating: boolean;
	messages: Message[];
	fileBrowserOpen: boolean;
	onExpandSidebar: () => void;
	onReindex: () => void;
	onToggleTokenInput: () => void;
	onToggleContext: () => void;
	onToggleCove: () => void;
	onToggleQueryExpansion: () => void;
	onClearChat: () => void;
	onDeleteEmbeddings: () => void;
	onToggleFileBrowser: () => void;
	onShowDiagram: () => void;
	onRunScan?: () => void;
}

export function RepoHeader({
	owner,
	repo,
	isIndexed,
	repoStale,
	llmStatus,
	sidebarCollapsed,
	showContext,
	coveEnabled,
	queryExpansionEnabled,
	isLocalProvider,
	isGenerating,
	messages,
	fileBrowserOpen,
	onExpandSidebar,
	onReindex,
	onToggleTokenInput,
	onToggleContext,
	onToggleCove,
	onToggleQueryExpansion,
	onClearChat,
	onDeleteEmbeddings,
	onToggleFileBrowser,
	onShowDiagram,
	onRunScan,
}: RepoHeaderProps) {
	const overflowRef = useRef<HTMLDivElement>(null);
	const [showOverflow, setShowOverflow] = useState(false);

	useEffect(() => {
		if (!showOverflow) return;
		const handleClick = (e: MouseEvent) => {
			if (overflowRef.current && !overflowRef.current.contains(e.target as Node)) {
				setShowOverflow(false);
			}
		};
		document.addEventListener("mousedown", handleClick);
		return () => document.removeEventListener("mousedown", handleClick);
	}, [showOverflow]);

	return (
		<nav style={{
			display: "flex", alignItems: "center", justifyContent: "space-between",
			padding: "0 20px", height: 52,
			background: "var(--bg-paper)", borderBottom: "2.5px solid var(--border-black)",
			flexShrink: 0, zIndex: 30,
		}}>
			<div style={{ display: "flex", alignItems: "center", gap: 12 }}>
				{sidebarCollapsed && (
					<button
						onClick={onExpandSidebar}
						style={{ background: "transparent", border: "none", color: "var(--ink-medium)", cursor: "pointer", fontSize: "14px", padding: "4px 6px" }}
						title="Expand sidebar"
					>
						→
					</button>
				)}
				<a href="/" style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "0.95rem", color: "var(--ink-black)", textDecoration: "none", textTransform: "uppercase" }}>
					ThreatLens
				</a>
				<span style={{ color: "var(--ink-medium)", fontSize: "0.9rem" }}>/</span>
				<span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--ink-medium)", padding: "2px 8px", border: "1.5px solid var(--border-black)", background: "var(--bg-paper-alt)" }}>
					{owner}/{repo}
				</span>
				{isIndexed && repoStale && (
					<span
						style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--high-amber)", padding: "2px 8px", border: "1.5px solid var(--high-amber)", background: "rgba(217,119,6,0.08)", cursor: "pointer" }}
						onClick={onReindex}
						title="Repository changed on GitHub. Click to re-index."
					>
						stale — re-index
					</span>
				)}
			</div>
			<div style={{ display: "flex", alignItems: "center", gap: 10 }}>
				<div style={{
					width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
					background: llmStatus === "ready" ? "var(--low-sage)" : llmStatus === "generating" ? "var(--high-amber)" : llmStatus === "loading" ? "var(--info-slate)" : "var(--ink-light)",
				}} className={llmStatus === "loading" ? "pulse" : undefined} title={`LLM: ${llmStatus}`} />
				<ModelSettings />
				<div ref={overflowRef} style={{ position: "relative" }}>
					<button
						style={{ fontSize: "16px", padding: "4px 10px", lineHeight: 1, background: "transparent", border: "1.5px solid var(--border-black)", color: "var(--ink-medium)", cursor: "pointer" }}
						onClick={() => setShowOverflow(v => !v)}
						title="More options"
						aria-label="More options"
					>
						⋯
					</button>
					{showOverflow && (
						<div style={{
							position: "absolute", top: "calc(100% + 6px)", right: 0,
							background: "var(--bg-paper)", border: "2.5px solid var(--border-black)",
							boxShadow: "var(--shadow-layer-1)", padding: "6px",
							display: "flex", flexDirection: "column", gap: "2px",
							zIndex: 30, minWidth: "200px",
						}}>
							<button style={overflowItemStyle} onClick={() => { onToggleTokenInput(); setShowOverflow(false); }}>
								GH Token
							</button>
							{isIndexed && (
								<button style={overflowItemStyle} onClick={() => { onToggleContext(); setShowOverflow(false); }}>
									{showContext ? "Hide context" : "View context"}
								</button>
							)}
							<button
								style={{ ...overflowItemStyle, color: coveEnabled ? "var(--low-sage)" : "var(--ink-black)" }}
								onClick={onToggleCove}
								title="Chain-of-Verification (adds ~2-4s latency)"
							>
								CoVE {coveEnabled ? "on" : "off"}
							</button>
							<button
								style={{
									...overflowItemStyle,
									color: isLocalProvider ? "var(--ink-light)" : queryExpansionEnabled ? "var(--low-sage)" : "var(--ink-black)",
									opacity: isLocalProvider ? 0.45 : 1,
									cursor: isLocalProvider ? "default" : "pointer",
								}}
								onClick={isLocalProvider ? undefined : onToggleQueryExpansion}
								title={isLocalProvider ? "not available with local model" : "expand each query into multiple variants for broader retrieval"}
							>
								multi-query {isLocalProvider ? "—" : queryExpansionEnabled ? "on" : "off"}
							</button>
							{isIndexed && (
								<button style={overflowItemStyle} onClick={() => { onReindex(); setShowOverflow(false); }}>
									Re-index
								</button>
							)}
							{messages.length > 0 && (
								<button style={overflowItemStyle} onClick={() => { onClearChat(); setShowOverflow(false); }} disabled={isGenerating}>
									Clear chat
								</button>
							)}
							<div style={{ height: "1px", background: "var(--border-black)", margin: "4px 0" }} />
							{owner && repo && (
								<button style={{ ...overflowItemStyle, color: "var(--critical-red)" }} onClick={() => { onDeleteEmbeddings(); setShowOverflow(false); }}>
									Delete embeddings
								</button>
							)}
							<div style={{ height: "1px", background: "var(--border-black)", margin: "4px 0" }} />
							<a href="/metrics" style={{ ...overflowItemStyle, textDecoration: "none", color: "var(--ink-medium)", display: "flex" }}>
								Metrics
							</a>
							<a href={PROJECT_REPO_URL} target="_blank" rel="noopener noreferrer" style={{ ...overflowItemStyle, textDecoration: "none", color: "var(--ink-medium)", display: "flex" }}>
								Star on GitHub
							</a>
						</div>
					)}
				</div>
				{isIndexed && onRunScan && (
					<button
						onClick={onRunScan}
						title="Run AI-powered security scan"
						style={{
							display: "inline-flex",
							alignItems: "center",
							gap: 6,
							padding: "6px 12px",
							border: "2.5px solid var(--border-black)",
							background: "var(--ink-black)",
							color: "var(--bg-paper)",
							cursor: "pointer",
							fontSize: "12px",
							fontFamily: "var(--font-mono)",
							fontWeight: 700,
							letterSpacing: "0.04em",
						}}
					>
						<svg width={12} height={12} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
						Scan
					</button>
				)}
				{isIndexed && (
					<button
						onClick={onToggleFileBrowser}
						style={{ padding: "6px 12px", border: "2.5px solid var(--border-black)", background: "transparent", color: "var(--ink-medium)", cursor: "pointer", fontSize: "12px", fontFamily: "var(--font-mono)" }}
					>
						{fileBrowserOpen ? "Hide files" : "Browse files"}
					</button>
				)}
			</div>
		</nav>
	);
}

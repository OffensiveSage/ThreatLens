"use client";

import { useState, useRef, useCallback } from "react";
import { VectorStore } from "@/lib/vectorStore";
import { multiPathHybridSearch } from "@/lib/search";
import { generate, getLLMConfig } from "@/lib/llm";
import { buildSafeContext, scanChunksForInjection } from "@/lib/promptSafety";
import { buildChatRequestMessages } from "@/lib/chatHistory";
import { defaultLimitsForProvider } from "@/lib/contextAssembly";
import {
	parseFindings,
	type ScanFinding,
	SCAN_SECTIONS,
} from "@/lib/scanParser";
import { ScanReport } from "./ScanReport";

// ─── Types ────────────────────────────────────────────────────────────────

type ScanPhase = "idle" | "scanning" | "done" | "error";

interface SectionState {
	id: string;
	label: string;
	status: "pending" | "running" | "done" | "error";
	output: string;
}

// ─── Prompt template ──────────────────────────────────────────────────────

function buildScanSystemPrompt(sectionLabel: string, owner: string, repo: string): string {
	return `You are a security code auditor performing a focused scan of the ${owner}/${repo} codebase.

Your task: Identify all security issues in the category "${sectionLabel}" based ONLY on the code context provided below.

STRICT OUTPUT FORMAT — use EXACTLY this format for each finding:
FINDING: <concise title describing the vulnerability>
SEVERITY: CRITICAL|HIGH|MEDIUM|LOW|INFO
STATUS: CONFIRMED|INFERRED|POTENTIAL
FILE: <file path, or — if unknown>
DETAIL: <one paragraph explaining the issue, where it is in the code, and why it is a risk>
---

Rules:
- CONFIRMED = you can see the exact vulnerable code in the context
- INFERRED = there is strong indirect evidence from the code structure
- POTENTIAL = you see patterns that suggest risk but cannot confirm without more code
- Only report issues you can ground in the provided code context
- If there are NO findings, respond with exactly: NO_FINDINGS
- Do not include generic advice — only concrete, evidence-based findings
- Order by severity (CRITICAL first)`;
}

function buildScanUserPrompt(sectionLabel: string, codeContext: string): string {
	return `Scan the following code for "${sectionLabel}" issues:\n\n${codeContext}\n\nReport all findings in the required format. If no issues found, respond with NO_FINDINGS.`;
}

// ─── Component ────────────────────────────────────────────────────────────

interface SecurityScanModalProps {
	owner: string;
	repo: string;
	store: VectorStore;
	onClose: () => void;
}

export function SecurityScanModal({ owner, repo, store, onClose }: SecurityScanModalProps) {
	const [phase, setPhase] = useState<ScanPhase>("idle");
	const [sections, setSections] = useState<SectionState[]>(
		SCAN_SECTIONS.map((s) => ({ id: s.id, label: s.label, status: "pending", output: "" }))
	);
	const [allFindings, setAllFindings] = useState<ScanFinding[]>([]);
	const [scannedAt, setScannedAt] = useState<Date>(new Date());
	const [errorMsg, setErrorMsg] = useState<string | null>(null);
	const abortRef = useRef(false);

	const updateSection = useCallback((id: string, patch: Partial<SectionState>) => {
		setSections((prev) => prev.map((s) => s.id === id ? { ...s, ...patch } : s));
	}, []);

	const runScan = useCallback(async () => {
		abortRef.current = false;
		setPhase("scanning");
		setErrorMsg(null);
		setAllFindings([]);
		setScannedAt(new Date());
		setSections(SCAN_SECTIONS.map((s) => ({ id: s.id, label: s.label, status: "pending", output: "" })));

		const config = getLLMConfig();
		const provider = config.provider === "gemini" || config.provider === "groq" ? config.provider : "mlc";
		const limits = defaultLimitsForProvider(provider);

		const accumulated: ScanFinding[] = [];

		for (const section of SCAN_SECTIONS) {
			if (abortRef.current) break;

			updateSection(section.id, { status: "running" });

			try {
				// Retrieve relevant chunks for this section
				const results = await multiPathHybridSearch(store, section.queries, { limit: 12 });

				if (results.length === 0) {
					updateSection(section.id, { status: "done", output: "NO_FINDINGS" });
					continue;
				}

				// Safety scan + context assembly
				const injectionScan = scanChunksForInjection(results);
				const { safeContext } = buildSafeContext(results, limits, injectionScan);

				if (!safeContext.trim()) {
					updateSection(section.id, { status: "done", output: "NO_FINDINGS" });
					continue;
				}

				// Build messages
				const systemPrompt = buildScanSystemPrompt(section.label, owner, repo);
				const userPrompt = buildScanUserPrompt(section.label, safeContext);
				const messages = buildChatRequestMessages({
					provider,
					systemPrompt,
					priorMessages: [],
					userMessage: userPrompt,
				});

				// Stream response
				let fullOutput = "";
				for await (const token of generate(messages)) {
					if (abortRef.current) break;
					fullOutput += token;
					updateSection(section.id, { output: fullOutput });
				}

				// Parse findings
				const sectionFindings = parseFindings(fullOutput, section.label);
				accumulated.push(...sectionFindings);
				setAllFindings([...accumulated]);
				updateSection(section.id, { status: "done", output: fullOutput });

			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				updateSection(section.id, { status: "error", output: `Error: ${msg}` });
				// Continue other sections despite one error
			}
		}

		if (!abortRef.current) {
			setPhase("done");
		}
	}, [store, owner, repo, updateSection]);

	const handlePrint = useCallback(() => {
		const style = document.createElement("style");
		style.id = "__scan-print-style";
		style.textContent = `
			@media print {
				body * { visibility: hidden !important; }
				#scan-report-printable,
				#scan-report-printable * { visibility: visible !important; }
				#scan-report-printable { position: fixed !important; top: 0; left: 0; width: 100%; padding: 24px; }
				.no-print { display: none !important; }
			}
		`;
		document.head.appendChild(style);
		window.print();
		// Remove style after print dialog closes
		setTimeout(() => {
			const el = document.getElementById("__scan-print-style");
			if (el) el.remove();
		}, 3000);
	}, []);

	// ─── Idle state ────────────────────────────────────────────────────────

	if (phase === "idle") {
		return (
			<ModalShell onClose={onClose}>
				<div style={{ padding: "40px 40px 36px", textAlign: "center", maxWidth: 480, margin: "0 auto" }}>
					<div style={{
						width: 56, height: 56, borderRadius: "50%",
						background: "var(--accent-amber)", display: "flex", alignItems: "center", justifyContent: "center",
						margin: "0 auto 20px",
					}}>
						<svg width={24} height={24} viewBox="0 0 24 24" fill="none" stroke="#0F0F0F" strokeWidth={2} strokeLinecap="round">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
					</div>
					<h2 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.4rem", letterSpacing: "-0.02em", margin: "0 0 10px" }}>
						Security Scan
					</h2>
					<p style={{ color: "var(--ink-medium)", fontSize: 14, lineHeight: 1.65, margin: "0 0 24px" }}>
						Runs <strong>4 focused analysis passes</strong> over the indexed codebase — injection flaws, secrets, attack surface, and configuration hardening. Results include a risk score and visualized findings.
					</p>
					<div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap", marginBottom: 28 }}>
						{SCAN_SECTIONS.map((s) => (
							<span key={s.id} style={{
								fontFamily: "var(--font-mono)",
								fontSize: 10,
								padding: "4px 10px",
								border: "1.5px solid var(--border-black)",
								background: "var(--bg-paper-alt)",
								color: "var(--ink-medium)",
								borderRadius: 2,
								textTransform: "uppercase",
								letterSpacing: "0.04em",
							}}>
								{s.label}
							</span>
						))}
					</div>
					<button
						onClick={() => void runScan()}
						style={{
							display: "inline-flex", alignItems: "center", gap: 10,
							padding: "12px 28px",
							border: "2.5px solid var(--border-black)",
							background: "var(--ink-black)",
							color: "var(--bg-paper)",
							fontFamily: "var(--font-mono)",
							fontSize: 13,
							fontWeight: 700,
							cursor: "pointer",
							letterSpacing: "0.05em",
							textTransform: "uppercase",
							borderRadius: 2,
							boxShadow: "var(--shadow-layer-1)",
						}}
					>
						<svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round">
							<circle cx={11} cy={11} r={8} /><path d="m21 21-4.35-4.35" />
						</svg>
						Run Security Scan
					</button>
				</div>
			</ModalShell>
		);
	}

	// ─── Scanning state ────────────────────────────────────────────────────

	if (phase === "scanning") {
		const doneCount = sections.filter((s) => s.status === "done" || s.status === "error").length;
		const pct = Math.round((doneCount / sections.length) * 100);

		return (
			<ModalShell onClose={() => { abortRef.current = true; onClose(); }}>
				<div style={{ padding: "36px 40px", maxWidth: 520, margin: "0 auto" }}>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.2rem", letterSpacing: "-0.02em", marginBottom: 8 }}>
						Scanning codebase…
					</div>
					<div style={{ color: "var(--ink-medium)", fontSize: 13, marginBottom: 24 }}>
						{doneCount} of {sections.length} passes complete
					</div>

					{/* Progress bar */}
					<div style={{ height: 6, background: "var(--bg-paper-alt)", border: "1.5px solid var(--border-black)", marginBottom: 24, borderRadius: 1 }}>
						<div style={{ height: "100%", width: `${pct}%`, background: "var(--accent-amber)", transition: "width 0.5s ease", borderRadius: 1 }} />
					</div>

					{/* Section checklist */}
					<div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
						{sections.map((s) => (
							<div key={s.id} style={{ display: "flex", alignItems: "center", gap: 12 }}>
								<StatusDot status={s.status} />
								<span style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: s.status === "running" ? "var(--ink-black)" : "var(--ink-medium)", fontWeight: s.status === "running" ? 600 : 400 }}>
									{s.label}
								</span>
								{s.status === "running" && (
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)" }}>
										analyzing…
									</span>
								)}
								{(s.status === "done" || s.status === "error") && (
									<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: s.status === "error" ? "var(--critical-red)" : "var(--low-sage)" }}>
										{s.status === "error" ? "error" : "done"}
									</span>
								)}
							</div>
						))}
					</div>

					{/* Live findings count */}
					{allFindings.length > 0 && (
						<div style={{
							marginTop: 24, padding: "10px 16px",
							border: "1.5px solid var(--border-black)",
							background: "var(--bg-paper-alt)",
							fontFamily: "var(--font-mono)",
							fontSize: 12,
							color: "var(--ink-medium)",
						}}>
							{allFindings.length} finding{allFindings.length !== 1 ? "s" : ""} so far
						</div>
					)}
				</div>
			</ModalShell>
		);
	}

	// ─── Done state — full report ──────────────────────────────────────────

	if (phase === "done") {
		return (
			<ModalShell onClose={onClose} fullHeight>
				<div style={{ padding: "28px 32px", overflowY: "auto", flex: 1 }}>
					<ScanReport
						owner={owner}
						repo={repo}
						findings={allFindings}
						scannedAt={scannedAt}
						onClose={onClose}
						onPrint={handlePrint}
					/>
					<div className="no-print" style={{ marginTop: 20, textAlign: "center" }}>
						<button
							onClick={() => { setPhase("idle"); setAllFindings([]); }}
							style={{
								padding: "8px 20px",
								border: "2px solid var(--border-black)",
								background: "var(--bg-paper)",
								color: "var(--ink-medium)",
								fontFamily: "var(--font-mono)",
								fontSize: 11,
								cursor: "pointer",
								borderRadius: 2,
							}}
						>
							↩ Run again
						</button>
					</div>
				</div>
			</ModalShell>
		);
	}

	return null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: SectionState["status"] }) {
	const base: React.CSSProperties = {
		width: 10,
		height: 10,
		borderRadius: "50%",
		flexShrink: 0,
		border: "1.5px solid var(--border-black)",
	};
	if (status === "pending") return <div style={{ ...base, background: "var(--bg-paper-alt)" }} />;
	if (status === "running") return <div style={{ ...base, background: "var(--high-amber)" }} className="pulse" />;
	if (status === "done") return <div style={{ ...base, background: "var(--low-sage)", border: "1.5px solid var(--low-sage)" }} />;
	return <div style={{ ...base, background: "var(--critical-red)", border: "1.5px solid var(--critical-red)" }} />;
}

interface ModalShellProps {
	children: React.ReactNode;
	onClose: () => void;
	fullHeight?: boolean;
}

function ModalShell({ children, onClose, fullHeight }: ModalShellProps) {
	return (
		<div
			style={{
				position: "fixed",
				inset: 0,
				zIndex: 500,
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				padding: "20px 16px",
				background: "rgba(26,26,26,0.55)",
				backdropFilter: "blur(2px)",
			}}
			onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
		>
			<div
				style={{
					background: "var(--bg-cream)",
					border: "2.5px solid var(--border-black)",
					boxShadow: "var(--shadow-layer-3)",
					width: "100%",
					maxWidth: fullHeight ? 860 : 560,
					maxHeight: "90vh",
					display: "flex",
					flexDirection: "column",
					overflow: "hidden",
					borderRadius: 2,
				}}
			>
				{children}
			</div>
		</div>
	);
}

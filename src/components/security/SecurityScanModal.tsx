"use client";

import { useState, useRef, useCallback } from "react";
import { VectorStore } from "@/lib/vectorStore";
import { generate } from "@/lib/llm";
import { getLLMConfig } from "@/lib/llm";
import { buildChatRequestMessages } from "@/lib/chatHistory";
import { defaultLimitsForProvider } from "@/lib/contextAssembly";
import {
	runSecurityScan,
	type AgenticReport,
	type ScanStepProgress,
	type ScanMode,
	type LLMCallFn,
	STEP_LABELS,
} from "@/lib/agenticScan";
import { AgenticScanReport } from "./AgenticScanReport";
import { saveLastScan } from "@/lib/scanStorage";

// ─── Types ────────────────────────────────────────────────────────────────────

type ScanPhase = "idle" | "scanning" | "done" | "error";

// ─── Component ────────────────────────────────────────────────────────────────

interface SecurityScanModalProps {
	owner: string;
	repo: string;
	store: VectorStore;
	onClose: () => void;
	scanMode?: ScanMode;
}

const TOTAL_STEPS = 6;

export function SecurityScanModal({ owner, repo, store, onClose, scanMode = "full" }: SecurityScanModalProps) {
	const [phase, setPhase] = useState<ScanPhase>("idle");
	const [steps, setSteps] = useState<ScanStepProgress[]>(
		Array.from({ length: TOTAL_STEPS }, (_, i) => ({
			step: i + 1,
			label: STEP_LABELS[i + 1],
			status: "pending" as const,
		})),
	);
	const [report, setReport] = useState<AgenticReport | null>(null);
	const [errorMsg, setErrorMsg] = useState<string | null>(null);
	const abortRef = useRef({ aborted: false });

	const updateStep = useCallback((progress: ScanStepProgress) => {
		setSteps((prev) =>
			prev.map((s) => (s.step === progress.step ? { ...s, ...progress } : s)),
		);
	}, []);

	const runScan = useCallback(async () => {
		abortRef.current = { aborted: false };
		setPhase("scanning");
		setErrorMsg(null);
		setReport(null);
		setSteps(
			Array.from({ length: TOTAL_STEPS }, (_, i) => ({
				step: i + 1,
				label: STEP_LABELS[i + 1],
				status: "pending" as const,
			})),
		);

		const config = getLLMConfig();
		const provider = config.provider;

		// Build callLLM — only for cloud providers; skip LLM deep analysis for mlc
		let callLLM: LLMCallFn | null = null;
		if (provider === "gemini" || provider === "groq") {
			const limits = defaultLimitsForProvider(provider);
			callLLM = async (systemPrompt: string, userPrompt: string): Promise<string> => {
				if (abortRef.current.aborted) return "";
				const messages = buildChatRequestMessages({
					provider,
					systemPrompt,
					priorMessages: [],
					userMessage: userPrompt,
				});
				let output = "";
				for await (const token of generate(messages, 0.1)) {
					if (abortRef.current.aborted) break;
					output += token;
				}
				// Suppress unused-variable warning for limits
				void limits;
				return output;
			};
		}

		try {
			const chunks = store.getAll();
			if (chunks.length === 0) {
				setErrorMsg("Repository not indexed. Please index the repository first.");
				setPhase("error");
				return;
			}

			const result = await runSecurityScan(
				chunks,
				callLLM,
				updateStep,
				scanMode,
				abortRef.current,
			);

			if (!abortRef.current.aborted) {
				setReport(result);
				setPhase("done");
				// Persist to localStorage so the Governance Dashboard can read it
				saveLastScan(owner, repo, result);
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			setErrorMsg(msg);
			setPhase("error");
		}
	}, [store, scanMode, updateStep]);

	const handlePrint = useCallback(() => {
		const style = document.createElement("style");
		style.id = "__scan-print-style";
		style.textContent = `
			@media print {
				:root {
					--bg-cream:     #FFFFFF !important;
					--bg-paper:     #F6F6F6 !important;
					--bg-paper-alt: #E8E8E8 !important;
					--ink-black:    #111111 !important;
					--ink-medium:   #444444 !important;
					--ink-light:    #888888 !important;
					--border-black: #2A2A2A !important;
					--accent-amber: #D97706 !important;
					--shadow-layer-1: none !important;
					--shadow-layer-2: none !important;
					--shadow-layer-3: none !important;
					--shadow-subtle:  none !important;
				}
				body * { visibility: hidden !important; }
				#scan-report-printable,
				#scan-report-printable * { visibility: visible !important; }
				#scan-report-printable {
					position: absolute !important;
					top: 0 !important; left: 0 !important;
					width: 100% !important;
					padding: 40px !important;
					background: #FFFFFF !important;
					color: #111111 !important;
					box-sizing: border-box !important;
				}
				.no-print { display: none !important; }
				.finding-section { page-break-inside: avoid; }
			}
		`;
		document.head.appendChild(style);
		window.print();
		setTimeout(() => {
			document.getElementById("__scan-print-style")?.remove();
		}, 3000);
	}, []);

	// ─── Idle ─────────────────────────────────────────────────────────────────

	if (phase === "idle") {
		const modeLabels: Record<ScanMode, { title: string; desc: string }> = {
			full: { title: "Security Scan", desc: "Full 6-step agentic pipeline: inventory → dependencies → pattern detection → LLM deep analysis → cross-reference → report." },
			deps: { title: "Dependency Audit", desc: "Parses all package files (npm, pip, go, cargo) and audits dependencies. Fast, no LLM required." },
			secrets: { title: "Find Secrets", desc: "Scans all code for hardcoded API keys, passwords, tokens, and credentials using deterministic regex patterns." },
			"attack-surface": { title: "Map Attack Surface", desc: "Full scan with focus on entry points, API routes, and external-facing handlers." },
			improvements: { title: "Security Improvements", desc: "Full scan to identify the top improvement opportunities across the codebase." },
		};
		const { title, desc } = modeLabels[scanMode];

		return (
			<ModalShell onClose={onClose}>
				<div style={{ padding: "40px 40px 36px", textAlign: "center", maxWidth: 480, margin: "0 auto" }}>
					<div style={{ width: 56, height: 56, borderRadius: "50%", background: "var(--accent-amber)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
						<svg width={24} height={24} viewBox="0 0 24 24" fill="none" stroke="#0F0F0F" strokeWidth={2} strokeLinecap="round">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
					</div>
					<h2 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.4rem", letterSpacing: "-0.02em", margin: "0 0 10px" }}>
						{title}
					</h2>
					<p style={{ color: "var(--ink-medium)", fontSize: 14, lineHeight: 1.65, margin: "0 0 24px" }}>
						{desc}
					</p>

					{/* Step preview chips */}
					{scanMode === "full" && (
						<div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap", marginBottom: 28 }}>
							{Object.values(STEP_LABELS).map((label, i) => (
								<span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 10, padding: "4px 10px", border: "1.5px solid var(--border-black)", background: "var(--bg-paper-alt)", color: "var(--ink-medium)", borderRadius: 2, textTransform: "uppercase", letterSpacing: "0.04em" }}>
									{label}
								</span>
							))}
						</div>
					)}

					<button
						onClick={() => void runScan()}
						style={{ display: "inline-flex", alignItems: "center", gap: 10, padding: "12px 28px", border: "2.5px solid var(--border-black)", background: "var(--ink-black)", color: "var(--bg-paper)", fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700, cursor: "pointer", letterSpacing: "0.05em", textTransform: "uppercase", borderRadius: 2, boxShadow: "var(--shadow-layer-1)" }}
					>
						<svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round">
							<circle cx={11} cy={11} r={8} /><path d="m21 21-4.35-4.35" />
						</svg>
						Run {title}
					</button>
				</div>
			</ModalShell>
		);
	}

	// ─── Scanning ─────────────────────────────────────────────────────────────

	if (phase === "scanning") {
		const doneCount = steps.filter((s) => s.status === "done" || s.status === "error").length;
		const pct = Math.round((doneCount / TOTAL_STEPS) * 100);
		const running = steps.find((s) => s.status === "running");

		return (
			<ModalShell onClose={() => { abortRef.current.aborted = true; onClose(); }}>
				<div style={{ padding: "36px 40px", maxWidth: 540, margin: "0 auto" }}>
					<div style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.2rem", letterSpacing: "-0.02em", marginBottom: 8 }}>
						Scanning codebase…
					</div>
					<div style={{ color: "var(--ink-medium)", fontSize: 13, marginBottom: 20 }}>
						{doneCount} of {TOTAL_STEPS} steps complete
					</div>

					{/* Progress bar */}
					<div style={{ height: 6, background: "var(--bg-paper-alt)", border: "1.5px solid var(--border-black)", marginBottom: 24, borderRadius: 1 }}>
						<div style={{ height: "100%", width: `${pct}%`, background: "var(--accent-amber)", transition: "width 0.5s ease", borderRadius: 1 }} />
					</div>

					{/* Step list */}
					<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
						{steps.map((s) => (
							<div key={s.step} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
								<StepIcon status={s.status} />
								<div style={{ flex: 1 }}>
									<div style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: s.status === "running" ? "var(--ink-black)" : s.status === "done" ? "var(--ink-medium)" : "var(--ink-light)", fontWeight: s.status === "running" ? 600 : 400, lineHeight: 1.4 }}>
										<span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700, marginRight: 6, opacity: 0.6 }}>
											{s.step}.
										</span>
										{s.label}
									</div>
									{s.detail && (
										<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", marginTop: 2 }}>
											{s.detail}
										</div>
									)}
									{s.status === "running" && !s.detail && (
										<div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--ink-light)", marginTop: 2 }}>
											analyzing…
										</div>
									)}
								</div>
							</div>
						))}
					</div>

					{/* Live finding count */}
					{running?.step === 4 && running.detail && (
						<div style={{ marginTop: 20, padding: "8px 14px", border: "1.5px solid var(--border-black)", background: "var(--bg-paper-alt)", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-medium)", borderRadius: 2 }}>
							{running.detail}
						</div>
					)}

					<button
						onClick={() => { abortRef.current.aborted = true; onClose(); }}
						style={{ marginTop: 24, padding: "7px 18px", border: "1.5px solid var(--border-black)", background: "var(--bg-paper)", color: "var(--ink-medium)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", borderRadius: 2 }}
					>
						Cancel Scan
					</button>
				</div>
			</ModalShell>
		);
	}

	// ─── Error ────────────────────────────────────────────────────────────────

	if (phase === "error") {
		return (
			<ModalShell onClose={onClose}>
				<div style={{ padding: "40px", textAlign: "center", maxWidth: 480, margin: "0 auto" }}>
					<div style={{ width: 48, height: 48, borderRadius: "50%", background: "#B71C1C", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px" }}>
						<svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={2.5} strokeLinecap="round">
							<circle cx={12} cy={12} r={10} /><line x1={12} y1={8} x2={12} y2={12} /><line x1={12} y1={16} x2={12.01} y2={16} />
						</svg>
					</div>
					<h2 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.1rem", margin: "0 0 10px" }}>
						Scan Failed
					</h2>
					<p style={{ color: "var(--ink-medium)", fontSize: 13, lineHeight: 1.6, margin: "0 0 8px" }}>
						{errorMsg ?? "An error occurred during the scan."}
					</p>
					<p style={{ color: "var(--ink-light)", fontSize: 12, fontFamily: "var(--font-mono)", margin: "0 0 24px" }}>
						Steps 1–3 work without an API key. Add a Groq or Gemini key for deep analysis.
					</p>
					<div style={{ display: "flex", gap: 10, justifyContent: "center" }}>
						<button
							onClick={() => void runScan()}
							style={{ padding: "9px 20px", border: "2px solid var(--border-black)", background: "var(--accent-amber)", color: "#0F0F0F", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, cursor: "pointer", borderRadius: 2 }}
						>
							Retry
						</button>
						<button
							onClick={() => setPhase("idle")}
							style={{ padding: "9px 20px", border: "2px solid var(--border-black)", background: "var(--bg-paper)", color: "var(--ink-medium)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", borderRadius: 2 }}
						>
							← Back
						</button>
					</div>
				</div>
			</ModalShell>
		);
	}

	// ─── Done ─────────────────────────────────────────────────────────────────

	if (phase === "done" && report) {
		return (
			<ModalShell onClose={onClose} fullHeight>
				<div style={{ padding: "28px 32px", overflowY: "auto", flex: 1 }}>
					<AgenticScanReport
						owner={owner}
						repo={repo}
						report={report}
						scanSteps={steps}
						onClose={onClose}
						onPrint={handlePrint}
					/>
					<div className="no-print" style={{ marginTop: 20, textAlign: "center" }}>
						<button
							onClick={() => { setPhase("idle"); setReport(null); }}
							style={{ padding: "8px 20px", border: "2px solid var(--border-black)", background: "var(--bg-paper)", color: "var(--ink-medium)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", borderRadius: 2 }}
						>
							↩ Run again
						</button>
						<a
							href="/dashboard/governance"
							style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "8px 20px", border: "2px solid var(--border-black)", background: "var(--accent-amber)", color: "#0F0F0F", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, cursor: "pointer", borderRadius: 2, textDecoration: "none" }}
						>
							View Governance Dashboard →
						</a>
					</div>
				</div>
			</ModalShell>
		);
	}

	return null;
}

// ─── Step Icon ────────────────────────────────────────────────────────────────

function StepIcon({ status }: { status: ScanStepProgress["status"] }) {
	const base: React.CSSProperties = { width: 20, height: 20, borderRadius: "50%", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", marginTop: 1 };

	if (status === "done") {
		return (
			<div style={{ ...base, background: "#2E7D32" }}>
				<svg width={10} height={10} viewBox="0 0 12 12" fill="none" stroke="#fff" strokeWidth={2.5} strokeLinecap="round">
					<polyline points="2,6 5,9 10,3" />
				</svg>
			</div>
		);
	}
	if (status === "running") {
		return (
			<div style={{ ...base, background: "var(--accent-amber)" }} className="pulse">
				<div style={{ width: 6, height: 6, borderRadius: "50%", background: "#0F0F0F" }} />
			</div>
		);
	}
	if (status === "error") {
		return (
			<div style={{ ...base, background: "#B71C1C" }}>
				<svg width={10} height={10} viewBox="0 0 12 12" fill="none" stroke="#fff" strokeWidth={2.5} strokeLinecap="round">
					<line x1={3} y1={3} x2={9} y2={9} /><line x1={9} y1={3} x2={3} y2={9} />
				</svg>
			</div>
		);
	}
	// pending
	return (
		<div style={{ ...base, background: "var(--bg-paper-alt)", border: "1.5px solid var(--border-black)" }}>
			<div style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--ink-light)" }} />
		</div>
	);
}

// ─── Modal Shell ──────────────────────────────────────────────────────────────

interface ModalShellProps {
	children: React.ReactNode;
	onClose: () => void;
	fullHeight?: boolean;
}

function ModalShell({ children, onClose, fullHeight }: ModalShellProps) {
	return (
		<div
			style={{ position: "fixed", inset: 0, zIndex: 500, display: "flex", alignItems: "center", justifyContent: "center", padding: "20px 16px", background: "rgba(26,26,26,0.55)", backdropFilter: "blur(2px)" }}
			onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
		>
			<div
				style={{ background: "var(--bg-cream)", border: "2.5px solid var(--border-black)", boxShadow: "var(--shadow-layer-3)", width: "100%", maxWidth: fullHeight ? 860 : 560, maxHeight: "90vh", display: "flex", flexDirection: "column", overflow: "hidden", borderRadius: 2 }}
			>
				{children}
			</div>
		</div>
	);
}

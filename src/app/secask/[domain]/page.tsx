"use client";

/**
 * Security Domain Chat Page
 *
 * Handles all 5 security connectors:
 *   /secask/attack  → MITRE ATT&CK
 *   /secask/sigma   → Sigma Rules
 *   /secask/nvd     → NVD / CVEs
 *   /secask/nist    → NIST 800-53
 *   /secask/custom  → Custom Upload
 *
 * Pattern mirrors [owner]/[repo]/page.tsx:
 *   1. Load from cache OR run connector indexer
 *   2. Show IndexingOverlay during indexing
 *   3. Show chat interface after indexing completes
 *
 * Uses lightweight inline chat UI (message bubbles, sidebar, input)
 * rather than the GitHub-repo-coupled existing chat components.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { QuickActions } from "@/components/chat/QuickActions";
import ReactMarkdown from "react-markdown";
import { VectorStore } from "@/lib/vectorStore";
import { multiPathHybridSearch } from "@/lib/search";
import {
	getRetrievalRefinement,
	buildContextualQuery,
} from "@/lib/queryExpansion";
import {
	generateSecurityQueryVariants,
	expandSecurityQuery,
} from "@/lib/securityQueryExpansion";
import {
	selectMode,
	DOMAIN_DEFAULT_MODE,
	SECURITY_MODE_PROMPTS,
	MODE_META,
	ALL_MODES,
	type SecurityMode,
} from "@/lib/securityModes";
import { defaultLimitsForProvider } from "@/lib/contextAssembly";
import {
	initLLM,
	generate,
	getLLMStatus,
	getLLMConfig,
	onStatusChange,
	type LLMStatus,
} from "@/lib/llm";
import { recordSearch } from "@/lib/metrics";
import { buildSafeContext, scanChunksForInjection } from "@/lib/promptSafety";

import type { Message, ContextChunk, ChatSession } from "@/app/[owner]/[repo]/types";
import {
	makeMessageId,
	makeNewChat,
	areMessagesEqual,
	normalizeMessage,
	buildMessageCitations,
	deriveChatTitle,
	shouldPromptForLLMSettings,
} from "@/lib/chatUtils";
import { buildChatRequestMessages } from "@/lib/chatHistory";
import {
	extractEvidenceTerms,
	buildGroundedCitationResults,
	buildCorrelatedCitationResults,
	evaluateEvidenceCoverage,
} from "@/lib/citationUtils";
import { isFactSeekingQuery } from "@/lib/queryUtils";

import { IndexingOverlay } from "@/components/chat/IndexingOverlay";
import type { IndexProgress } from "@/lib/indexer";

import { indexAttack } from "@/lib/connectors/attack";
import { indexSigma } from "@/lib/connectors/sigma";
import { indexNVD } from "@/lib/connectors/nvd";
import { indexNIST } from "@/lib/connectors/nist";
import { indexUpload } from "@/lib/connectors/upload";
import type { ConnectorProgress } from "@/lib/connectors/attack";

// ─── Domain config ────────────────────────────────────────────────────────────

const DOMAIN_META: Record<string, { label: string; tag: string; tagClass: string; suggestions: string[] }> = {
	attack: {
		label: "MITRE ATT&CK",
		tag: "ATT&CK",
		tagClass: "tag-attack",
		suggestions: [
			"What techniques use PowerShell?",
			"Describe APT29 tactics and tools",
			"What mitigations exist for credential dumping?",
			"Map the ransomware kill chain",
			"Which groups target financial sector?",
			"What sub-techniques fall under T1059?",
			"List persistence techniques on Windows",
			"Which techniques are used by Lazarus Group?",
		],
	},
	sigma: {
		label: "Sigma Rules",
		tag: "SIGMA",
		tagClass: "tag-sigma",
		suggestions: [
			"Show detection rules for lateral movement",
			"What rules cover privilege escalation?",
			"Find rules for suspicious PowerShell execution",
			"What log sources are needed for T1053 detection?",
			"Show critical severity rules",
			"Which rules have ATT&CK T1078 coverage?",
			"Find rules that detect Cobalt Strike",
			"Show rules targeting Windows event log manipulation",
		],
	},
	nvd: {
		label: "NVD / CVEs",
		tag: "NVD",
		tagClass: "tag-nvd",
		suggestions: [
			"Show critical severity CVEs",
			"Find RCE vulnerabilities in Apache",
			"What CVEs have public exploits?",
			"List authentication bypass vulnerabilities",
			"Show recent high-severity CVEs",
			"Find CVEs with CVSS score above 9",
			"What CWEs appear most frequently?",
			"Show vulnerabilities affecting Linux kernel",
		],
	},
	nist: {
		label: "NIST 800-53",
		tag: "NIST",
		tagClass: "tag-compliance",
		suggestions: [
			"What controls address access management?",
			"Map AC-2 account management requirements",
			"What controls are in the HIGH baseline?",
			"Show audit logging requirements",
			"Find controls for incident response",
			"What does IA-5 require for authenticators?",
			"Which controls cover supply chain risk?",
			"Show controls related to multi-factor authentication",
		],
	},
	custom: {
		label: "Custom Upload",
		tag: "CUSTOM",
		tagClass: "tag-custom",
		suggestions: [
			"Summarize the key findings",
			"What are the main recommendations?",
			"Find references to incident response",
			"What policies are covered?",
			"List all action items",
			"What are the highest-priority risks?",
			"What tools or technologies are mentioned?",
			"Find any compliance or regulatory references",
		],
	},
};

/** Fisher-Yates shuffle — returns a new array */
function shuffleArray<T>(arr: T[]): T[] {
	const out = [...arr];
	for (let i = out.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[out[i], out[j]] = [out[j], out[i]];
	}
	return out;
}

// Connector progress → IndexProgress shape cast
function toIndexProgress(p: ConnectorProgress): IndexProgress {
	return {
		phase: p.phase as IndexProgress["phase"],
		message: p.message,
		current: p.current,
		total: p.total,
	};
}

// ─── Domain color map for citation chips ─────────────────────────────────────

const DOMAIN_CHIP_COLORS: Record<string, { bg: string; color: string; border: string }> = {
	attack:  { bg: "var(--attack-bg, rgba(245, 166, 35, 0.15))",  color: "var(--attack-fg, #E65100)",  border: "var(--attack-border, #E65100)" },
	sigma:   { bg: "var(--sigma-bg, #E8F5E9)",   color: "var(--sigma-fg, #2E7D32)",   border: "var(--sigma-border, #2E7D32)" },
	nvd:     { bg: "var(--nvd-bg, #FCE4EC)",     color: "var(--nvd-fg, #C62828)",     border: "var(--nvd-border, #C62828)" },
	nist:    { bg: "var(--nist-bg, #E3F2FD)",    color: "var(--nist-fg, #1565C0)",    border: "var(--nist-border, #1565C0)" },
	custom:  { bg: "var(--bg-paper-alt)",        color: "var(--info-slate)",           border: "var(--border-black)" },
};

// ─── Inline citation chip ─────────────────────────────────────────────────────

function CitationChip({
	filePath,
	score,
	onClick,
}: {
	filePath: string;
	score: number;
	onClick?: () => void;
}) {
	// Parse domain prefix from filePath e.g. "attack://technique/T1059.001"
	const domainMatch = filePath.match(/^([a-z]+):\/\//);
	const domain = domainMatch?.[1] ?? "custom";
	const colors = DOMAIN_CHIP_COLORS[domain] ?? DOMAIN_CHIP_COLORS.custom;
	const label = filePath.split("/").pop() ?? filePath;
	return (
		<motion.span
			initial={{ opacity: 0, scale: 0.85 }}
			animate={{ opacity: 1, scale: 1 }}
			transition={{ duration: 0.2 }}
			style={{
				display: "inline-flex",
				alignItems: "center",
				gap: 4,
				padding: "2px 8px",
				fontFamily: "var(--font-mono)",
				fontSize: "10px",
				fontWeight: 600,
				background: colors.bg,
				border: `1.5px solid ${colors.border}`,
				borderRadius: 2,
				color: colors.color,
				cursor: onClick ? "pointer" : "default",
				letterSpacing: "0.04em",
				textTransform: "uppercase",
			}}
			title={`${filePath} (score: ${score.toFixed(2)})`}
			onClick={onClick}
		>
			↑ {label}
		</motion.span>
	);
}

// ─── Mode indicator component ─────────────────────────────────────────────────

function ModeIndicator({
	activeMode,
	modeOverride,
	isAuto,
	open,
	onToggle,
	onSelect,
}: {
	activeMode: SecurityMode;
	modeOverride: SecurityMode | null;
	isAuto: boolean;
	open: boolean;
	onToggle: () => void;
	onSelect: (mode: SecurityMode | null) => void;
}) {
	const meta = MODE_META[activeMode];
	return (
		<div style={{ position: "relative", display: "inline-block" }}>
			<button
				onClick={onToggle}
				style={{
					display: "inline-flex",
					alignItems: "center",
					gap: 6,
					padding: "3px 10px",
					fontFamily: "var(--font-mono)",
					fontSize: "10px",
					fontWeight: 700,
					letterSpacing: "0.06em",
					textTransform: "uppercase",
					background: "var(--bg-paper-alt)",
					border: "1.5px solid var(--border-black)",
					borderRadius: 2,
					cursor: "pointer",
					color: "var(--ink-medium)",
				}}
			>
				<span style={{ color: "var(--ink-light)" }}>{isAuto ? "[auto]" : "[manual]"}</span>
				<span>Mode:</span>
				<span className={meta.tagClass} style={{
					fontFamily: "var(--font-mono)",
					fontSize: "10px",
					fontWeight: 700,
					color: "inherit",
				}}>
					{meta.shortLabel}
				</span>
				<span style={{ fontSize: "8px" }}>▾</span>
			</button>

			{open && (
				<div
					style={{
						position: "absolute",
						bottom: "calc(100% + 6px)",
						left: 0,
						background: "var(--bg-paper)",
						border: "2px solid var(--border-black)",
						boxShadow: "var(--shadow-layer-2)",
						zIndex: 50,
						minWidth: 200,
					}}
				>
					<div
						style={{
							padding: "4px 10px",
							fontFamily: "var(--font-mono)",
							fontSize: "9px",
							fontWeight: 700,
							textTransform: "uppercase",
							letterSpacing: "0.1em",
							color: "var(--ink-light)",
							borderBottom: "1px solid var(--border-black)",
						}}
					>
						Analyst Mode
					</div>
					{/* Auto option */}
					<button
						onClick={() => { onSelect(null); onToggle(); }}
						style={{
							display: "block",
							width: "100%",
							textAlign: "left",
							padding: "6px 10px",
							fontFamily: "var(--font-mono)",
							fontSize: "10px",
							fontWeight: modeOverride === null ? 700 : 400,
							background: modeOverride === null ? "var(--bg-paper-alt)" : "transparent",
							border: "none",
							cursor: "pointer",
							color: "var(--ink-black)",
							letterSpacing: "0.04em",
						}}
					>
						Auto (detect from query)
					</button>
					{ALL_MODES.map((m) => (
						<button
							key={m}
							onClick={() => { onSelect(m); onToggle(); }}
							style={{
								display: "block",
								width: "100%",
								textAlign: "left",
								padding: "6px 10px",
								fontFamily: "var(--font-mono)",
								fontSize: "10px",
								fontWeight: modeOverride === m ? 700 : 400,
								background: modeOverride === m ? "var(--bg-paper-alt)" : "transparent",
								border: "none",
								cursor: "pointer",
								color: "var(--ink-black)",
								letterSpacing: "0.04em",
							}}
						>
							{MODE_META[m].label}
						</button>
					))}
				</div>
			)}
		</div>
	);
}

// ─── Inline message bubble ────────────────────────────────────────────────────

function MessageBubble({
	msg,
	isLast,
	usedMode,
	onOpenContext,
	isMobile,
}: {
	msg: Message;
	isLast: boolean;
	usedMode?: SecurityMode;
	onOpenContext?: () => void;
	isMobile?: boolean;
}) {
	const isUser = msg.role === "user";
	const isThinking = isLast && !isUser && msg.content === "";

	return (
		<motion.div
			initial={{ opacity: 0, y: 10 }}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.28, ease: [0.25, 0.1, 0.25, 1] }}
			style={{
				display: "flex",
				flexDirection: "column",
				alignItems: isUser ? "flex-end" : "flex-start",
				gap: 6,
			}}
		>
			{/* Role label + mode tag for assistant */}
			<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
				<span
					style={{
						fontFamily: "var(--font-mono)",
						fontSize: "10px",
						fontWeight: 700,
						textTransform: "uppercase",
						letterSpacing: "0.08em",
						color: "var(--ink-light)",
					}}
				>
					{isUser ? "you" : "✦ secask"}
				</span>
				{!isUser && usedMode && (
					<span style={{
						fontFamily: "var(--font-mono)",
						fontSize: "9px",
						fontWeight: 600,
						letterSpacing: "0.06em",
						textTransform: "uppercase",
						color: "var(--ink-light)",
						padding: "1px 5px",
						background: "var(--bg-paper-alt)",
						border: "1px solid var(--border-black)",
						borderRadius: 2,
					}}>
						Used: {MODE_META[usedMode].shortLabel}
					</span>
				)}
			</div>

			{/* Bubble */}
			<div
				style={{
					maxWidth: isMobile ? "100%" : "80%",
					background: isUser ? "var(--bg-paper-alt)" : "var(--bg-paper)",
					border: "2px solid var(--border-black)",
					borderRadius: 2,
					padding: "12px 16px",
					boxShadow: "var(--shadow-layer-1)",
				}}
			>
				{isThinking ? (
					<span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--ink-light)" }}>
						Thinking…
					</span>
				) : (
					<div
						style={{
							fontFamily: "var(--font-sans)",
							fontSize: "0.875rem",
							lineHeight: 1.65,
							color: "var(--ink-black)",
						}}
					>
						<ReactMarkdown>{msg.content}</ReactMarkdown>
					</div>
				)}
			</div>

			{/* Citations */}
			{msg.citations && msg.citations.length > 0 && (
				<div style={{ display: "flex", flexWrap: "wrap", gap: 4, maxWidth: isMobile ? "100%" : "80%" }}>
					{msg.citations.slice(0, 6).map((c, i) => (
						<CitationChip
							key={i}
							filePath={c.filePath}
							score={c.score}
							onClick={onOpenContext}
						/>
					))}
				</div>
			)}
		</motion.div>
	);
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function SecurityDomainPage({
	params,
}: {
	params: Promise<{ domain: string }>;
}) {
	const router = useRouter();
	const [domain, setDomain] = useState("");

	// Indexing state
	const [indexProgress, setIndexProgress] = useState<IndexProgress | null>(null);
	const [isIndexed, setIsIndexed] = useState(false);
	const [isError, setIsError] = useState(false);
	const [reindexKey, setReindexKey] = useState(0);

	// Upload-specific state
	const [pendingFiles, setPendingFiles] = useState<File[] | null>(null);
	const [showFilePicker, setShowFilePicker] = useState(false);
	const fileInputRef = useRef<HTMLInputElement>(null);

	// Chat state
	const [llmStatus, setLlmStatus] = useState<LLMStatus>("idle");
	const [llmProvider, setLlmProvider] = useState(() => getLLMConfig().provider);
	const [messages, setMessages] = useState<Message[]>([]);
	const [chatSessions, setChatSessions] = useState<ChatSession[]>([]);
	const [activeChatId, setActiveChatId] = useState<string | null>(null);
	const [input, setInput] = useState("");
	const [isGenerating, setIsGenerating] = useState(false);
	const [contextChunks, setContextChunks] = useState<ContextChunk[]>([]);
	const [showContext, setShowContext] = useState(false);
	const [toastMessage, setToastMessage] = useState<string | null>(null);
	const [queryExpansionEnabled, setQueryExpansionEnabled] = useState(
		() => getLLMConfig().provider !== "mlc"
	);

	// Mobile / UI state
	const [isMobile, setIsMobile] = useState(false);
	const [sidebarOpen, setSidebarOpen] = useState(false);
	const [indexJustCompleted, setIndexJustCompleted] = useState(false);
	const [displayedSuggestions, setDisplayedSuggestions] = useState<string[]>([]);

	// Mode state
	const [detectedMode, setDetectedMode] = useState<SecurityMode>("cross-domain");
	const [modeOverride, setModeOverride] = useState<SecurityMode | null>(null);
	const [modeMenuOpen, setModeMenuOpen] = useState(false);
	const activeMode = modeOverride ?? detectedMode;

	const storeRef = useRef(new VectorStore());
	const messagesRef = useRef<Message[]>([]);
	const chatSessionsRef = useRef<ChatSession[]>([]);
	const isGeneratingRef = useRef(false);
	const chatLoadedRef = useRef(false);
	const pendingChatSwitchRef = useRef<string | null>(null);
	const chatEndRef = useRef<HTMLDivElement>(null);
	const prevMessageCountRef = useRef(0);
	const textareaRef = useRef<HTMLTextAreaElement>(null);

	// Resolve domain from params
	useEffect(() => {
		params.then((p) => setDomain(p.domain));
	}, [params]);

	// Mobile detection
	useEffect(() => {
		const check = () => setIsMobile(window.innerWidth < 768);
		check();
		window.addEventListener("resize", check);
		return () => window.removeEventListener("resize", check);
	}, []);

	// Close sidebar when generating
	useEffect(() => {
		if (isGenerating) setSidebarOpen(false);
	}, [isGenerating]);

	// LLM status sync
	useEffect(() => {
		return onStatusChange((s) => {
			setLlmStatus(s);
			setLlmProvider(getLLMConfig().provider);
		});
	}, []);

	// Toast auto-dismiss
	useEffect(() => {
		if (!toastMessage) return;
		const timer = setTimeout(() => setToastMessage(null), 4000);
		return () => clearTimeout(timer);
	}, [toastMessage]);

	// Scroll to bottom on new messages
	useEffect(() => {
		const countChanged = messages.length !== prevMessageCountRef.current;
		prevMessageCountRef.current = messages.length;
		if (isGenerating || countChanged) {
			chatEndRef.current?.scrollIntoView({ behavior: isGenerating ? "auto" : "smooth" });
		}
	}, [messages, isGenerating]);

	// Sync messages ref
	useEffect(() => { messagesRef.current = messages; }, [messages]);
	chatSessionsRef.current = chatSessions;

	// ─── Chat session storage ─────────────────────────────────────────────

	const chatStorageKey = domain ? `gitask-chat-secask/${domain}` : null;

	useEffect(() => {
		chatLoadedRef.current = false;
		setMessages([]);
		setChatSessions([]);
		setActiveChatId(null);
		if (!chatStorageKey) return;

		try {
			const saved = localStorage.getItem(chatStorageKey);
			if (saved) {
				const parsed = JSON.parse(saved) as {
					sessions?: Array<Omit<ChatSession, "messages"> & { messages?: unknown[] }>;
					activeChatId?: string;
				};

				if (parsed && Array.isArray(parsed.sessions) && parsed.sessions.length > 0) {
					const sessions = parsed.sessions
						.filter((s) => s && typeof s.chat_id === "string")
						.map((s, idx) => ({
							chat_id: s.chat_id,
							title: typeof s.title === "string" ? s.title : `Chat ${idx + 1}`,
							messages: Array.isArray(s.messages)
								? s.messages
									.map((m) => normalizeMessage(m))
									.filter((m): m is Message => m !== null)
									.slice(-50)
								: [],
							updatedAt: typeof s.updatedAt === "number" ? s.updatedAt : Date.now(),
						}));

					if (sessions.length > 0) {
						const selectedId = sessions.some((s) => s.chat_id === parsed.activeChatId)
							? parsed.activeChatId!
							: sessions[0].chat_id;
						const selected = sessions.find((s) => s.chat_id === selectedId);
						setChatSessions(sessions);
						pendingChatSwitchRef.current = selectedId;
						setActiveChatId(selectedId);
						setMessages(selected?.messages ?? []);
						chatLoadedRef.current = true;
						return;
					}
				}
			}
		} catch { /* corrupted */ }

		const fresh = makeNewChat("Chat 1");
		setChatSessions([fresh]);
		pendingChatSwitchRef.current = fresh.chat_id;
		setActiveChatId(fresh.chat_id);
		setMessages([]);
		chatLoadedRef.current = true;
	}, [chatStorageKey]);

	// Persist sessions to localStorage
	useEffect(() => {
		if (!chatStorageKey || !chatLoadedRef.current || chatSessions.length === 0) return;
		try {
			localStorage.setItem(chatStorageKey, JSON.stringify({ activeChatId, sessions: chatSessions }));
		} catch {
			setToastMessage("Warning: chat history could not be saved.");
		}
	}, [chatStorageKey, chatSessions, activeChatId]);

	// Sync session messages on session change
	useEffect(() => {
		if (!chatLoadedRef.current || !activeChatId || isGenerating) return;
		if (pendingChatSwitchRef.current === activeChatId) {
			const active = chatSessions.find((s) => s.chat_id === activeChatId);
			if (areMessagesEqual(messages, active?.messages ?? [])) {
				pendingChatSwitchRef.current = null;
			}
			return;
		}
		const trimmed = messages.slice(-50);
		setChatSessions((prev) => {
			let changed = false;
			const next = prev.map((s) => {
				if (s.chat_id !== activeChatId) return s;
				const nextTitle = deriveChatTitle(trimmed, s.title || "New Chat");
				if (areMessagesEqual(s.messages, trimmed) && s.title === nextTitle) return s;
				changed = true;
				return { ...s, title: nextTitle, messages: trimmed, updatedAt: Date.now() };
			});
			return changed ? next : prev;
		});
	}, [messages, activeChatId, isGenerating]);

	// ─── Indexing ─────────────────────────────────────────────────────────

	useEffect(() => {
		if (!domain) return;
		if (domain === "custom" && !pendingFiles) {
			setShowFilePicker(true);
			return;
		}

		setIsError(false);
		setIsIndexed(false);
		const controller = new AbortController();
		let aborted = false;

		const progress = (p: ConnectorProgress) => {
			if (aborted) return;
			setIndexProgress(toIndexProgress(p));
		};

		(async () => {
			try {
				// Storage availability check
				if (typeof navigator !== "undefined" && navigator.storage?.estimate) {
					const est = await navigator.storage.estimate();
					const availMB = ((est.quota ?? 0) - (est.usage ?? 0)) / (1024 * 1024);
					if (availMB < 50) {
						setToastMessage(`Warning: Only ${Math.round(availMB)}MB browser storage remaining. Indexing may fail.`);
					}
				}

				const store = storeRef.current;

				switch (domain) {
					case "attack":
						await indexAttack(store, progress, controller.signal);
						break;
					case "sigma":
						await indexSigma(store, {}, progress, controller.signal);
						break;
					case "nvd":
						await indexNVD(store, {}, progress, controller.signal);
						break;
					case "nist":
						await indexNIST(store, progress, controller.signal);
						break;
					case "custom":
						if (pendingFiles) {
							await indexUpload(pendingFiles, store, progress, controller.signal);
						}
						break;
					default:
						throw new Error(`Unknown security domain: ${domain}`);
				}

				if (aborted) return;
				setIsIndexed(true);
				setIndexJustCompleted(true);
				setTimeout(() => setIndexJustCompleted(false), 1200);
				// Pick 5 shuffled suggestions from the domain pool
				const domainSuggestions = DOMAIN_META[domain]?.suggestions ?? [];
				setDisplayedSuggestions(shuffleArray(domainSuggestions).slice(0, 5));

				initLLM((msg) => {
					if (aborted) return;
					setIndexProgress((prev) => ({
						phase: "done",
						message: msg,
						current: prev?.current ?? 0,
						total: prev?.total ?? 0,
					}));
				}).catch((err) => {
					if (aborted) return;
					const msg = err instanceof Error ? err.message : String(err);
					setToastMessage(msg);
					if (typeof window !== "undefined" && shouldPromptForLLMSettings(msg)) {
						window.dispatchEvent(new Event("gitask-open-llm-settings"));
					}
				});
			} catch (err) {
				if (aborted || (err instanceof DOMException && err.name === "AbortError")) return;
				const msg = err instanceof Error ? err.message : String(err);
				setIsError(true);
				setIndexProgress({ phase: "done", message: `Error: ${msg}`, current: 0, total: 0 });
			}
		})();

		return () => {
			aborted = true;
			controller.abort();
		};
	}, [domain, pendingFiles, reindexKey]);

	// ─── Handlers ─────────────────────────────────────────────────────────

	const handleRetry = useCallback(async () => {
		setIsError(false);
		setIsIndexed(false);
		storeRef.current.clear();
		if (domain !== "custom") {
			await storeRef.current.clearCache("secask", domain);
		}
		setReindexKey((k) => k + 1);
	}, [domain]);

	const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
		const files = e.target.files;
		if (!files || files.length === 0) return;
		setPendingFiles(Array.from(files));
		setShowFilePicker(false);
	}, []);

	const handleCreateChat = useCallback(() => {
		if (isGeneratingRef.current) return;
		const fresh = makeNewChat(`Chat ${chatSessions.length + 1}`);
		setChatSessions((prev) => [fresh, ...prev]);
		pendingChatSwitchRef.current = fresh.chat_id;
		setActiveChatId(fresh.chat_id);
		setMessages([]);
		setInput("");
		setContextChunks([]);
	}, [chatSessions.length]);

	const handleSelectChat = useCallback((chatId: string) => {
		if (isGeneratingRef.current || chatId === activeChatId) return;
		const target = chatSessions.find((s) => s.chat_id === chatId);
		pendingChatSwitchRef.current = chatId;
		setActiveChatId(chatId);
		setMessages(target?.messages ?? []);
		setInput("");
		setContextChunks([]);
	}, [activeChatId, chatSessions]);

	const handleDeleteChat = useCallback((chatId: string) => {
		if (isGeneratingRef.current) return;
		const current = chatSessions.find((s) => s.chat_id === chatId);
		if (!current) return;
		const isLast = chatSessions.length <= 1;
		const confirmed = typeof window === "undefined" || window.confirm(
			isLast ? `Delete "${current.title}"? A new empty chat will be created.` : `Delete "${current.title}"?`
		);
		if (!confirmed) return;

		if (isLast) {
			const fresh = makeNewChat("Chat 1");
			pendingChatSwitchRef.current = fresh.chat_id;
			setChatSessions([fresh]);
			setActiveChatId(fresh.chat_id);
			setMessages([]);
			setContextChunks([]);
			return;
		}

		const idx = chatSessions.findIndex((s) => s.chat_id === chatId);
		const next = chatSessions.filter((s) => s.chat_id !== chatId);
		const deletingActive = chatId === activeChatId;
		const fallback = deletingActive ? next[Math.max(0, idx - 1)] ?? next[0] ?? null : null;
		setChatSessions(next);
		if (deletingActive && fallback) {
			pendingChatSwitchRef.current = fallback.chat_id;
			setActiveChatId(fallback.chat_id);
			setMessages(fallback.messages ?? []);
		}
	}, [activeChatId, chatSessions]);

	const handleDeleteEmbeddings = useCallback(async () => {
		const meta = DOMAIN_META[domain] ?? { label: domain };
		const confirmed = typeof window !== "undefined" && window.confirm(
			`Delete stored index for ${meta.label}? You will be returned to the home page.`
		);
		if (!confirmed) return;
		await storeRef.current.clearCache("secask", domain);
		storeRef.current.clear();
		if (chatStorageKey) {
			try { localStorage.removeItem(chatStorageKey); } catch { /* ignore */ }
		}
		router.push("/");
	}, [domain, chatStorageKey, router]);

	// ─── handleSend ───────────────────────────────────────────────────────

	const handleSend = useCallback(async (overrideText?: string) => {
		const rawInput = (overrideText ?? input).trim();
		if (!rawInput || isGeneratingRef.current || !isIndexed) return;

		isGeneratingRef.current = true;
		setIsGenerating(true);
		setInput("");

		const newUserMsg: Message = { id: makeMessageId(), role: "user", content: rawInput };
		setMessages((prev) => [...prev, newUserMsg]);

		const placeholderMsgId = makeMessageId();
		setMessages((prev) => [
			...prev,
			{ id: placeholderMsgId, role: "assistant", content: "", ui: { sourcesExpanded: false } },
		]);

		try {
			const config = getLLMConfig();
			const isLocalLLM = config.provider === "mlc";
			const limits = defaultLimitsForProvider(config.provider);

			// Security query expansion
			const queryVariants = !isLocalLLM && queryExpansionEnabled
				? await generateSecurityQueryVariants(rawInput, messagesRef.current)
				: expandSecurityQuery(buildContextualQuery(rawInput, messagesRef.current));

			setMessages((prev) =>
				prev.map((m) =>
					m.id !== placeholderMsgId
						? m
						: { ...m, retrieval: { variants: queryVariants, loadingPhase: "searching" } }
				)
			);

			// Retrieval
			const searchStart = performance.now();
			let results = await multiPathHybridSearch(storeRef.current, queryVariants, { limit: 5 });

			// Retrieval refinement (cloud LLMs only)
			if (!isLocalLLM && queryExpansionEnabled) {
				const rq = await getRetrievalRefinement(
					rawInput,
					results.map((r) => ({ filePath: r.chunk.filePath, code: r.chunk.code, score: r.score }))
				);
				if (rq) {
					const refined = await multiPathHybridSearch(storeRef.current, [rq], { limit: 5 });
					const merged = new Map<string, (typeof results)[0]>();
					for (const r of [...results, ...refined]) {
						const ex = merged.get(r.chunk.id);
						if (!ex || r.score > ex.score) merged.set(r.chunk.id, r);
					}
					results = [...merged.values()].sort((a, b) => b.score - a.score).slice(0, 8);
				}
			}

			recordSearch(performance.now() - searchStart);

			// Mode detection
			const newMode = modeOverride ?? selectMode(rawInput) ?? DOMAIN_DEFAULT_MODE[domain] ?? "cross-domain";
			setDetectedMode(modeOverride ? detectedMode : newMode);

			// Cross-domain expansion: parse relationship hints from chunk content
			{
				const crossTerms: string[] = [];
				for (const r of results.slice(0, 6)) {
					const text = r.chunk.code;
					// Parse ATT&CK technique refs from Sigma/any chunk
					const techniqueMatches = text.match(/T\d{4}(?:\.\d{3})?/g) ?? [];
					for (const t of techniqueMatches.slice(0, 3)) crossTerms.push(t);
					// Parse ATT&CK Tags in Sigma chunks
					const attackTagMatches = text.match(/attack\.t\d{4}(?:\.\d{3})?/gi) ?? [];
					for (const t of attackTagMatches.slice(0, 3)) crossTerms.push(t.replace(/^attack\./i, "").toUpperCase());
					// Parse Related Controls in NIST chunks
					const controlMatches = text.match(/[A-Z]{2}-\d+(?:\(\d+\))?/g) ?? [];
					for (const c of controlMatches.slice(0, 3)) crossTerms.push(c);
				}
				const uniqueCrossTerms = [...new Set(crossTerms)].slice(0, 5);
				if (uniqueCrossTerms.length > 0) {
					const crossResults = await multiPathHybridSearch(
						storeRef.current, uniqueCrossTerms, { limit: 3 }
					);
					const merged = new Map<string, (typeof results)[0]>();
					for (const r of results) merged.set(r.chunk.id, r);
					for (const r of crossResults) {
						if (!merged.has(r.chunk.id)) {
							merged.set(r.chunk.id, { ...r, score: r.score * 0.5 });
						}
					}
					results = [...merged.values()].sort((a, b) => b.score - a.score).slice(0, 15);
				}
			}

			// Safety scan
			const evidenceTerms = extractEvidenceTerms(rawInput);
			const injectionScan = scanChunksForInjection(results);
			const safeCtx = buildSafeContext(results, limits, injectionScan);

			// Citations
			const groundedCitations = buildGroundedCitationResults(results, evidenceTerms)
				.filter((r) => !safeCtx.excludedCitationIds.has(r.chunk.id));
			const citations =
				groundedCitations.length > 0 ? buildMessageCitations(groundedCitations) : [];

			// Evidence coverage check
			const evidenceCoverage = evaluateEvidenceCoverage(evidenceTerms, results);
			const weakCoverage =
				evidenceTerms.length >= 3 &&
				evidenceCoverage.matched.length < Math.ceil(evidenceTerms.length / 3);
			const weakSignal = evidenceCoverage.maxScore < 0.35;
			const shouldBlock = isFactSeekingQuery(rawInput) && weakSignal && weakCoverage;

			if (shouldBlock) {
				setMessages((prev) =>
					prev.map((m) =>
						m.id !== placeholderMsgId
							? m
							: {
								...m,
								content:
									"I can't find sufficient grounded evidence in the indexed data for this request. Try re-phrasing with more specific terms, or [index more sources](/) to broaden coverage.",
								citations: citations.length > 0 ? citations : undefined,
							}
					)
				);
				return;
			}

			setContextChunks(
				safeCtx.safeResults.map((r) => ({
					filePath: r.chunk.filePath,
					code: r.chunk.code,
					score: r.score,
					nodeType: r.chunk.nodeType,
				}))
			);

			// LLM status check
			if (getLLMStatus() === "error") {
				throw new Error(
					"LLM failed to initialize. Open LLM Settings and switch to Gemini or Groq with a valid API key."
				);
			}

			if (getLLMStatus() !== "ready" && getLLMStatus() !== "generating") {
				setMessages((prev) =>
					prev.map((m) =>
						m.id !== placeholderMsgId
							? m
							: {
								...m,
								content: `**LLM is still loading (${llmStatus}). Here are the most relevant results:**\n\n${safeCtx.safeContext}`,
								citations: citations.length > 0 ? citations : undefined,
							}
					)
				);
				return;
			}

			// Build system prompt using active analyst mode
			const modePrompt = SECURITY_MODE_PROMPTS[activeMode];
			const systemPrompt = `${modePrompt}\n\nSecurity knowledge context:\n${safeCtx.safeContext}`;

			const chatMessages = buildChatRequestMessages({
				provider: config.provider,
				systemPrompt,
				priorMessages: messagesRef.current.map((m) => ({
					role: m.role as "user" | "assistant",
					content: m.content,
				})),
				userMessage: rawInput,
			});

			setMessages((prev) =>
				prev.map((m) =>
					m.id !== placeholderMsgId
						? m
						: {
							...m,
							citations: citations.length > 0 ? citations : undefined,
							retrieval:
								queryVariants.length > 1 ? { variants: queryVariants } : undefined,
						}
				)
			);

			// Stream generation
			let fullResponse = "";
			for await (const token of generate(chatMessages)) {
				fullResponse += token;
				setMessages((prev) => {
					let changed = false;
					const updated = prev.map((m) => {
						if (m.id !== placeholderMsgId) return m;
						changed = true;
						return {
							...m,
							role: "assistant" as const,
							content: fullResponse,
							citations: citations.length > 0 ? citations : undefined,
						};
					});
					return changed ? updated : prev;
				});
			}

			// Final citation correlation
			if (fullResponse && results.length > 0) {
				const correlated = buildCorrelatedCitationResults(results, rawInput, fullResponse);
				const finalCitations =
					correlated.length > 0 ? buildMessageCitations(correlated) : citations;
				setMessages((prev) =>
					prev.map((m) =>
						m.id !== placeholderMsgId
							? m
							: {
								...m,
								content: fullResponse,
								citations: finalCitations.length > 0 ? finalCitations : undefined,
							}
					)
				);
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			setMessages((prev) =>
				prev.map((m) =>
					m.id !== placeholderMsgId
						? m
						: { ...m, content: `Error: ${msg}` }
				)
			);
		} finally {
			isGeneratingRef.current = false;
			setIsGenerating(false);
		}
	}, [input, isIndexed, queryExpansionEnabled, domain, llmStatus, modeOverride, detectedMode, activeMode]);

	// ─── Computed values ──────────────────────────────────────────────────

	const progressPercent = indexProgress
		? indexProgress.total > 0
			? Math.round((indexProgress.current / indexProgress.total) * 100)
			: indexProgress.phase === "done" || indexProgress.phase === "cached"
				? 100
				: 0
		: 0;

	const meta = DOMAIN_META[domain] ?? {
		label: domain,
		tag: domain.toUpperCase(),
		tagClass: "tag-custom",
		suggestions: [],
	};

	// ─── Upload file picker screen ────────────────────────────────────────

	if (domain === "custom" && showFilePicker && !pendingFiles) {
		return (
			<div
				style={{
					minHeight: "100vh",
					background: "var(--bg-cream)",
					display: "flex",
					flexDirection: "column",
					alignItems: "center",
					justifyContent: "center",
					padding: 24,
				}}
			>
				<div
					style={{
						border: "2.5px solid var(--border-black)",
						padding: "40px 48px",
						background: "var(--bg-paper)",
						boxShadow: "var(--shadow-layer-2)",
						maxWidth: 480,
						width: "100%",
						textAlign: "center",
					}}
				>
					<span className="tag tag-custom" style={{ marginBottom: 16, display: "inline-block" }}>
						CUSTOM
					</span>
					<h1
						style={{
							fontFamily: "var(--font-display)",
							fontSize: "1.5rem",
							fontWeight: 900,
							marginBottom: 12,
							textTransform: "uppercase",
							letterSpacing: "0.02em",
						}}
					>
						Upload Document
					</h1>
					<p
						style={{
							color: "var(--ink-medium)",
							fontSize: "0.9rem",
							lineHeight: 1.6,
							marginBottom: 28,
							fontFamily: "var(--font-sans)",
						}}
					>
						Select one or more files to index. Supported: TXT, MD, JSON, YAML, PDF.
					</p>
					<input
						ref={fileInputRef}
						type="file"
						multiple
						accept=".txt,.md,.markdown,.json,.yaml,.yml,.pdf,.csv"
						onChange={handleFileSelect}
						style={{ display: "none" }}
					/>
					<div
						style={{
							border: "2px dashed var(--border-black)",
							background: "var(--bg-paper-alt)",
							padding: "32px 24px",
							marginBottom: 20,
							cursor: "pointer",
							fontFamily: "var(--font-mono)",
							fontSize: "0.8rem",
							color: "var(--ink-medium)",
							letterSpacing: "0.04em",
						}}
						onClick={() => fileInputRef.current?.click()}
					>
						DROP FILES HERE OR CLICK TO BROWSE
					</div>
					<button
						className="btn btn-primary"
						onClick={() => fileInputRef.current?.click()}
						style={{ width: "100%", marginBottom: 12 }}
					>
						Browse Files →
					</button>
					<button
						className="btn btn-secondary"
						onClick={() => router.push("/")}
						style={{ width: "100%", fontSize: "0.8rem" }}
					>
						← Back
					</button>
				</div>
			</div>
		);
	}

	// ─── Render ───────────────────────────────────────────────────────────

	return (
		<div
			style={{
				display: "flex",
				flexDirection: "column",
				height: "100vh",
				background: "var(--bg-cream)",
				overflow: "hidden",
			}}
		>
			{/* ── Header ── */}
			<div
				style={{
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					padding: "12px 20px",
					borderBottom: "2.5px solid var(--border-black)",
					background: "var(--bg-paper)",
					boxShadow: "var(--shadow-subtle)",
					flexShrink: 0,
				}}
			>
				<div style={{ display: "flex", alignItems: "center", gap: 10 }}>
					{/* Mobile hamburger */}
					{isMobile && (
						<button
							onClick={() => setSidebarOpen((v) => !v)}
							aria-label="Toggle chat sessions"
							style={{
								background: "none",
								border: "1.5px solid var(--border-black)",
								padding: "4px 8px",
								fontSize: "1rem",
								cursor: "pointer",
								lineHeight: 1,
								minHeight: 32,
							}}
						>
							☰
						</button>
					)}
					<button
						onClick={() => router.push("/")}
						style={{
							background: "none",
							border: "none",
							fontFamily: "var(--font-display)",
							fontWeight: 900,
							fontSize: "1rem",
							color: "var(--ink-black)",
							cursor: "pointer",
							textTransform: "uppercase",
							letterSpacing: "0.04em",
							padding: 0,
						}}
					>
						SecAsk
					</button>
					<span style={{ color: "var(--ink-light)" }}>/</span>
					<span className={`tag ${meta.tagClass}${indexJustCompleted ? " index-complete-flash" : ""}`}>
						{meta.tag}
					</span>
					<span
						style={{
							fontFamily: "var(--font-display)",
							fontWeight: 700,
							fontSize: "0.85rem",
							color: "var(--ink-medium)",
							textTransform: "uppercase",
							letterSpacing: "0.03em",
						}}
					>
						{meta.label}
					</span>
					{isIndexed && (
						<span
							style={{
								fontFamily: "var(--font-mono)",
								fontSize: "0.7rem",
								color: "var(--low-sage)",
								letterSpacing: "0.06em",
							}}
						>
							● {storeRef.current.size} chunks
						</span>
					)}
				</div>
				<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
					{isIndexed && (
						<button
							onClick={() => setShowContext((v) => !v)}
							style={{
								background: showContext ? "var(--ink-black)" : "var(--bg-paper)",
								color: showContext ? "var(--bg-paper)" : "var(--ink-black)",
								border: "2px solid var(--border-black)",
								padding: "4px 10px",
								fontFamily: "var(--font-mono)",
								fontSize: "0.68rem",
								cursor: "pointer",
								fontWeight: 700,
								letterSpacing: "0.04em",
								textTransform: "uppercase",
							}}
						>
							CONTEXT {contextChunks.length > 0 ? `(${contextChunks.length})` : ""}
						</button>
					)}
					{isIndexed && (
						<button
							onClick={handleCreateChat}
							style={{
								background: "var(--bg-paper)",
								color: "var(--ink-black)",
								border: "2px solid var(--border-black)",
								padding: "4px 10px",
								fontFamily: "var(--font-mono)",
								fontSize: "0.68rem",
								cursor: "pointer",
								fontWeight: 700,
								letterSpacing: "0.04em",
								textTransform: "uppercase",
							}}
						>
							+ NEW CHAT
						</button>
					)}
					<button
						onClick={handleDeleteEmbeddings}
						style={{
							background: "none",
							border: "2px solid var(--critical-red)",
							color: "var(--critical-red)",
							padding: "4px 10px",
							fontFamily: "var(--font-mono)",
							fontSize: "0.68rem",
							cursor: "pointer",
							fontWeight: 700,
							letterSpacing: "0.04em",
							textTransform: "uppercase",
						}}
					>
						CLEAR
					</button>
				</div>
			</div>

			{/* ── Main layout ── */}
			<div style={{ flex: 1, display: "flex", overflow: "hidden" }}>

				{/* ── Sidebar ── */}
				{/* Desktop sidebar (always visible) / Mobile overlay (when sidebarOpen) */}
				{(sidebarOpen && isMobile) && (
					<div
						onClick={() => setSidebarOpen(false)}
						style={{
							position: "fixed",
							inset: 0,
							background: "rgba(26,26,26,0.35)",
							zIndex: 190,
						}}
					/>
				)}
				<div
					style={isMobile ? {
						position: "fixed",
						top: 0,
						left: 0,
						width: 280,
						height: "100%",
						zIndex: 200,
						background: "var(--bg-paper)",
						borderRight: "2.5px solid var(--border-black)",
						display: sidebarOpen ? "flex" : "none",
						flexDirection: "column",
						overflow: "hidden",
						boxShadow: "var(--shadow-layer-3)",
					} : {
						width: 220,
						flexShrink: 0,
						borderRight: "2.5px solid var(--border-black)",
						background: "var(--bg-paper)",
						display: "flex",
						flexDirection: "column",
						overflow: "hidden",
					}}
				>
					<div
						style={{
							padding: "12px 14px 8px",
							fontFamily: "var(--font-mono)",
							fontSize: "9px",
							fontWeight: 700,
							textTransform: "uppercase",
							letterSpacing: "0.12em",
							color: "var(--ink-medium)",
							borderBottom: "1.5px solid var(--border-black)",
						}}
					>
						Chat Sessions
					</div>
					<div style={{ flex: 1, overflowY: "auto" }}>
						{chatSessions.map((session) => (
							<div
								key={session.chat_id}
								onClick={() => handleSelectChat(session.chat_id)}
								style={{
									padding: "10px 14px",
									cursor: "pointer",
									background:
										session.chat_id === activeChatId
											? "var(--bg-paper-alt)"
											: "transparent",
									borderBottom: "1px solid var(--bg-paper-alt)",
									display: "flex",
									justifyContent: "space-between",
									alignItems: "center",
									gap: 6,
								}}
							>
								<span
									style={{
										fontFamily: "var(--font-sans)",
										fontSize: "0.78rem",
										color: "var(--ink-black)",
										flex: 1,
										overflow: "hidden",
										textOverflow: "ellipsis",
										whiteSpace: "nowrap",
									}}
								>
									{session.title}
								</span>
								<button
									onClick={(e) => { e.stopPropagation(); handleDeleteChat(session.chat_id); }}
									style={{
										background: "none",
										border: "none",
										cursor: "pointer",
										color: "var(--ink-light)",
										fontSize: "0.7rem",
										padding: "2px 4px",
										flexShrink: 0,
										fontFamily: "var(--font-mono)",
									}}
								>
									✕
								</button>
							</div>
						))}
					</div>
				</div>

				{/* ── Main area ── */}
				<div
					style={{
						flex: 1,
						display: "flex",
						flexDirection: "column",
						overflow: "hidden",
						position: "relative",
					}}
				>
					{/* Indexing overlay */}
					{!isIndexed && (
						<IndexingOverlay
							indexProgress={indexProgress}
							progressPercent={progressPercent}
							timeRemaining={null}
							onRetry={handleRetry}
							isError={isError}
						/>
					)}

					{/* Chat messages */}
					{isIndexed && (
						<div
							style={{
								flex: 1,
								overflowY: "auto",
								padding: "20px 28px",
								display: "flex",
								flexDirection: "column",
								gap: 20,
							}}
						>
							{messages.length === 0 && (
								<div
									style={{
										display: "flex",
										flexDirection: "column",
										alignItems: "center",
										justifyContent: "center",
										flex: 1,
										gap: 20,
										textAlign: "center",
									}}
								>
									<div>
										<span
											style={{
												fontFamily: "var(--font-mono)",
												fontSize: "11px",
												textTransform: "uppercase",
												letterSpacing: "0.08em",
												color: "var(--ink-medium)",
												display: "block",
												marginBottom: 10,
											}}
										>
											{storeRef.current.size} chunks indexed
										</span>
										<h2
											style={{
												fontFamily: "var(--font-display)",
												fontWeight: 800,
												fontSize: "clamp(1.2rem, 3vw, 1.75rem)",
												color: "var(--ink-black)",
												letterSpacing: "-0.01em",
												margin: 0,
											}}
										>
											What do you want to know?
										</h2>
									</div>
									<div
										style={{
											display: "flex",
											flexWrap: "wrap",
											gap: 8,
											justifyContent: "center",
											maxWidth: 560,
										}}
									>
										{displayedSuggestions.map((s) => (
											<button
												key={s}
												className="query-chip"
												onClick={() => handleSend(s)}
											>
												{s}
											</button>
										))}
									</div>
								</div>
							)}

							{messages.map((msg, idx) => (
								<MessageBubble
									key={msg.id}
									msg={msg}
									isLast={idx === messages.length - 1}
									usedMode={msg.role === "assistant" ? activeMode : undefined}
									onOpenContext={() => setShowContext(true)}
									isMobile={isMobile}
								/>
							))}
							<div ref={chatEndRef} />
						</div>
					)}

					{/* Quick actions */}
					{isIndexed && domain && (
						<QuickActions
							source={domain as "attack" | "sigma" | "nvd" | "nist" | "custom"}
							onSend={(prompt) => { void handleSend(prompt); }}
						/>
					)}
					{/* Input bar */}
					{isIndexed && (
						<div
							style={{
								borderTop: "2.5px solid var(--border-black)",
								background: "var(--bg-cream)",
								flexShrink: 0,
							}}
						>
							<form
								onSubmit={(e) => { e.preventDefault(); handleSend(); }}
								style={{
									padding: "14px 20px",
									paddingBottom: "max(8px, env(safe-area-inset-bottom))",
									display: "flex",
									gap: 10,
									alignItems: "flex-end",
								}}
							>
								<textarea
									ref={textareaRef}
									value={input}
									onChange={(e) => setInput(e.target.value)}
									onKeyDown={(e) => {
										if (e.key === "Enter" && !e.shiftKey) {
											e.preventDefault();
											handleSend();
										}
									}}
									placeholder={`Ask anything about ${meta.label}…`}
									disabled={isGenerating}
									rows={1}
									style={{
										flex: 1,
										padding: "10px 14px",
										background: "var(--bg-paper)",
										color: "var(--ink-black)",
										border: "2.5px solid var(--border-black)",
										outline: "none",
										resize: "none",
										fontFamily: "var(--font-sans)",
										fontSize: "0.9rem",
										lineHeight: 1.5,
										minHeight: 42,
										maxHeight: 160,
										boxSizing: "border-box",
									}}
								/>
								<button
									type="submit"
									disabled={isGenerating || !input.trim()}
									className="btn btn-primary"
									style={{ flexShrink: 0, padding: "10px 20px" }}
								>
									{isGenerating ? "…" : "Send"}
								</button>
							</form>
							{/* Mode indicator row */}
							<div style={{ padding: "0 20px 10px", display: "flex", alignItems: "center" }}>
								<ModeIndicator
									activeMode={activeMode}
									modeOverride={modeOverride}
									isAuto={modeOverride === null}
									open={modeMenuOpen}
									onToggle={() => setModeMenuOpen((v) => !v)}
									onSelect={(m) => {
										setModeOverride(m);
										setModeMenuOpen(false);
									}}
								/>
							</div>
						</div>
					)}
				</div>

				{/* Context panel (slide-in) */}
				{showContext && isIndexed && contextChunks.length > 0 && (
					<div
						style={isMobile ? {
							position: "fixed",
							bottom: 0,
							left: 0,
							right: 0,
							height: "70vh",
							zIndex: 100,
							background: "var(--bg-paper)",
							borderTop: "2.5px solid var(--border-black)",
							boxShadow: "var(--shadow-layer-2)",
							display: "flex",
							flexDirection: "column",
							overflow: "hidden",
						} : {
							width: 340,
							flexShrink: 0,
							borderLeft: "2.5px solid var(--border-black)",
							background: "var(--bg-paper)",
							display: "flex",
							flexDirection: "column",
							overflow: "hidden",
						}}
					>
						<div
							style={{
								padding: "10px 14px",
								borderBottom: "1.5px solid var(--border-black)",
								fontFamily: "var(--font-mono)",
								fontSize: "9px",
								fontWeight: 700,
								textTransform: "uppercase",
								letterSpacing: "0.12em",
								color: "var(--ink-medium)",
								display: "flex",
								justifyContent: "space-between",
								alignItems: "center",
							}}
						>
							<span>Retrieved Context ({contextChunks.length})</span>
							<button
								onClick={() => setShowContext(false)}
								style={{
									background: "none",
									border: "none",
									cursor: "pointer",
									color: "var(--ink-medium)",
									fontSize: "0.8rem",
									padding: 0,
								}}
							>
								✕
							</button>
						</div>
						<div style={{ flex: 1, overflowY: "auto", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 12 }}>
							{contextChunks.map((chunk, i) => (
								<div
									key={i}
									style={{
										border: "1.5px solid var(--border-black)",
										background: "var(--bg-cream)",
										padding: "10px 12px",
									}}
								>
									<div
										style={{
											fontFamily: "var(--font-mono)",
											fontSize: "9px",
											fontWeight: 700,
											textTransform: "uppercase",
											letterSpacing: "0.06em",
											color: "var(--info-slate)",
											marginBottom: 6,
										}}
									>
										{chunk.filePath.split("/").pop()} · score {chunk.score.toFixed(2)}
									</div>
									<pre
										style={{
											fontFamily: "var(--font-mono)",
											fontSize: "0.72rem",
											color: "var(--ink-medium)",
											whiteSpace: "pre-wrap",
											wordBreak: "break-word",
											margin: 0,
											maxHeight: 200,
											overflow: "auto",
											lineHeight: 1.5,
										}}
									>
										{chunk.code.slice(0, 600)}
										{chunk.code.length > 600 ? "…" : ""}
									</pre>
								</div>
							))}
						</div>
					</div>
				)}
			</div>

			{/* Toast */}
			{toastMessage && (
				<div
					style={{
						position: "fixed",
						bottom: 24,
						left: "50%",
						transform: "translateX(-50%)",
						background: "var(--ink-black)",
						color: "var(--bg-paper)",
						padding: "10px 20px",
						fontFamily: "var(--font-sans)",
						fontSize: "0.85rem",
						border: "2px solid var(--border-black)",
						boxShadow: "var(--shadow-layer-2)",
						zIndex: 999,
						maxWidth: "90vw",
					}}
				>
					{toastMessage}
				</div>
			)}
		</div>
	);
}

"use client";

import { useState } from "react";
import AstTreeView from "@/components/AstTreeView";
import type { ChatSession } from "@/app/[owner]/[repo]/types";
import type { IndexProgress, AstNode } from "@/lib/indexer";

interface ChatSidebarProps {
	isIndexed: boolean;
	isIndexing: boolean;
	indexingFailed: boolean;
	indexProgress: IndexProgress | null;
	progressPercent: number;
	timeRemaining: string | null;
	notificationPermission: NotificationPermission | null;
	chunkCount: number;
	orderedChatSessions: ChatSession[];
	activeChatId: string | null;
	astNodes: AstNode[];
	textChunkCounts: Record<string, number>;
	sidebarCollapsed: boolean;
	onSelectChat: (id: string) => void;
	onDeleteChat: (id: string) => void;
	onCreateChat: () => void;
	onCollapse: () => void;
	onRequestNotification: () => void;
}

export function ChatSidebar({
	isIndexed,
	isIndexing,
	indexingFailed,
	indexProgress,
	progressPercent,
	timeRemaining,
	notificationPermission,
	chunkCount,
	orderedChatSessions,
	activeChatId,
	astNodes,
	textChunkCounts,
	sidebarCollapsed,
	onSelectChat,
	onDeleteChat,
	onCreateChat,
	onCollapse,
	onRequestNotification,
}: ChatSidebarProps) {
	const [interactiveChatId, setInteractiveChatId] = useState<string | null>(null);

	return (
		<aside style={{
			width: sidebarCollapsed ? 0 : 220,
			minWidth: sidebarCollapsed ? 0 : 220,
			background: "var(--bg-paper-alt)",
			borderRight: "2.5px solid var(--border-black)",
			display: "flex",
			flexDirection: "column",
			overflow: "hidden",
			transition: "width 0.2s ease, min-width 0.2s ease",
			flexShrink: 0,
		}}>
			<div style={{ padding: "16px", overflowY: "auto", flex: 1 }}>
				{/* Index status */}
				<div style={{ marginBottom: 16 }}>
					<p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 8, margin: "0 0 8px 0" }}>Status</p>
					{!isIndexed && !indexProgress && <span style={{ fontSize: "12px", color: "var(--ink-medium)" }}>Not indexed</span>}
					{isIndexing && (
						<div>
							<span style={{ fontSize: "12px", color: "var(--high-amber)", display: "block", marginBottom: 6 }}>● Indexing...</span>
							<div style={{ height: 4, background: "var(--bg-paper-alt)", marginBottom: 6 }}>
								<div style={{ height: "100%", background: "var(--info-slate)", width: `${progressPercent}%`, transition: "width 0.3s" }} />
							</div>
							<span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--ink-medium)" }}>
								{indexProgress?.message ?? ""}
							</span>
							{timeRemaining && (
								<span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--ink-medium)", display: "block", marginTop: 4 }}>
									{timeRemaining} remaining
								</span>
							)}
							{typeof Notification !== "undefined" && notificationPermission === "default" && (
								<button
									type="button"
									style={{ marginTop: 8, fontSize: "10px", padding: "2px 6px", background: "transparent", border: "1.5px solid var(--border-black)", color: "var(--ink-medium)", cursor: "pointer", fontFamily: "var(--font-mono)" }}
									onClick={onRequestNotification}
									title="Get a system notification when indexing completes"
								>
									Notify when ready
								</button>
							)}
						</div>
					)}
					{isIndexed && <span style={{ fontSize: "12px", color: "var(--low-sage)" }}>● Indexed</span>}
					{indexingFailed && <span style={{ fontSize: "12px", color: "var(--critical-red)" }}>● Error</span>}
				</div>

				{/* Stats */}
				{isIndexed && (
					<div style={{ marginBottom: 16 }}>
						<p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 8, margin: "0 0 8px 0" }}>Index</p>
						<div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
							<div style={{ display: "flex", justifyContent: "space-between" }}>
								<span style={{ fontSize: "11px", color: "var(--ink-medium)" }}>Chunks</span>
								<span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--ink-medium)" }}>{chunkCount}</span>
							</div>
						</div>
					</div>
				)}

				{/* Chat sessions list */}
				{orderedChatSessions.length > 0 && (
					<div>
						<p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 8, margin: "0 0 8px 0" }}>Chats</p>
						<div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
							{orderedChatSessions.map((session) => {
								const isActive = activeChatId === session.chat_id;
								const showDelete = interactiveChatId === session.chat_id;
								return (
									<div
										key={session.chat_id}
										onMouseEnter={() => setInteractiveChatId(session.chat_id)}
										onMouseLeave={() => setInteractiveChatId((current) => current === session.chat_id ? null : current)}
										onFocusCapture={() => setInteractiveChatId(session.chat_id)}
										onBlurCapture={() => setInteractiveChatId((current) => current === session.chat_id ? null : current)}
										style={{
											display: "flex",
											alignItems: "center",
											gap: 6,
											background: isActive ? "var(--bg-paper)" : "transparent",
											border: isActive ? "2px solid var(--border-black)" : "1px solid transparent",
											borderLeft: isActive ? "3px solid var(--info-slate)" : "1px solid transparent",
											boxShadow: isActive ? "var(--shadow-subtle)" : "none",
											padding: 2,
										}}
									>
										<button
											onClick={() => onSelectChat(session.chat_id)}
											style={{
												flex: 1,
												minWidth: 0,
												textAlign: "left",
												background: "transparent",
												border: "none",
												padding: "6px 6px",
												cursor: "pointer",
												color: isActive ? "var(--ink-black)" : "var(--ink-medium)",
												fontSize: "11px",
												fontFamily: "var(--font-mono)",
												overflow: "hidden",
												textOverflow: "ellipsis",
												whiteSpace: "nowrap",
											}}
										>
											{session.title}
										</button>
										<button
											type="button"
											onClick={(event) => {
												event.stopPropagation();
												onDeleteChat(session.chat_id);
											}}
											aria-label={`Delete ${session.title}`}
											title={`Delete ${session.title}`}
											style={{
												flexShrink: 0,
												padding: "4px 8px",
												border: "1px solid rgba(220,38,38,0.45)",
												background: showDelete ? "rgba(220,38,38,0.12)" : "transparent",
												color: showDelete ? "var(--critical-red)" : "rgba(252,165,165,0.0)",
												cursor: showDelete ? "pointer" : "default",
												fontSize: "10px",
												fontFamily: "var(--font-mono)",
												textTransform: "uppercase",
												letterSpacing: "0.06em",
												opacity: showDelete ? 1 : 0,
												pointerEvents: showDelete ? "auto" : "none",
												transition: "opacity 0.16s ease, background 0.16s ease, color 0.16s ease",
											}}
										>
											Del
										</button>
									</div>
								);
							})}
							<button
								onClick={onCreateChat}
								style={{ textAlign: "left", background: "transparent", border: "2px solid var(--border-black)", padding: "6px 8px", cursor: "pointer", color: "var(--ink-medium)", fontSize: "11px", fontFamily: "var(--font-mono)" }}
							>
								+ New chat
							</button>
						</div>
					</div>
				)}

				{/* AST tree during indexing */}
				{isIndexing && astNodes.length > 0 && (
					<div style={{ marginTop: 16 }}>
						<p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--ink-medium)", marginBottom: 8, margin: "0 0 8px 0" }}>Files</p>
						<AstTreeView astNodes={astNodes} textChunkCounts={textChunkCounts} />
					</div>
				)}
			</div>

			<button
				onClick={onCollapse}
				style={{ padding: "10px", background: "transparent", color: "var(--ink-medium)", cursor: "pointer", fontSize: "12px", textAlign: "center", border: "none", borderTop: "2px solid var(--border-black)" }}
			>
				←
			</button>
		</aside>
	);
}

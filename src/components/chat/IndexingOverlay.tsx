"use client";

import type { IndexProgress } from "@/lib/indexer";

interface IndexingOverlayProps {
	indexProgress: IndexProgress | null;
	progressPercent: number;
	timeRemaining: string | null;
	onRetry: () => void;
	isError?: boolean;
}

function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function IndexingOverlay({
	indexProgress,
	progressPercent,
	timeRemaining,
	onRetry,
	isError,
}: IndexingOverlayProps) {
	if (isError && indexProgress?.message) {
		return (
			<div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
				<div style={{ border: "2.5px solid var(--critical-red)", padding: "24px 28px", background: "var(--bg-paper)", maxWidth: 420, width: "100%", boxShadow: "4px 4px 0 var(--critical-red)" }}>
					<p style={{ fontWeight: 700, color: "var(--critical-red)", marginBottom: 8, fontFamily: "var(--font-display)", margin: "0 0 8px 0" }}>Indexing failed</p>
					<p style={{ fontSize: "13px", color: "var(--ink-medium)", marginBottom: 16, lineHeight: 1.5 }}>{indexProgress.message}</p>
					<button onClick={onRetry} style={{ background: "var(--ink-black)", color: "var(--bg-paper)", border: "2.5px solid var(--border-black)", padding: "10px 20px", cursor: "pointer", fontWeight: 700, fontSize: "13px" }}>
						Retry
					</button>
				</div>
			</div>
		);
	}

	return (
		<div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
			<div style={{ border: "2.5px solid var(--border-black)", padding: "28px 32px", background: "var(--bg-paper)", maxWidth: 420, width: "100%", boxShadow: "var(--shadow-layer-1)" }}>
				<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
					<span style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: "0.9rem", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--ink-black)" }}>
						Indexing
					</span>
					<span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "1.1rem", color: "var(--info-slate)" }}>
						{progressPercent}%
					</span>
				</div>
				<div style={{ height: 6, background: "var(--bg-paper-alt)", marginBottom: 14, border: "1.5px solid var(--border-subtle)" }}>
					<div style={{ height: "100%", background: "var(--info-slate)", width: `${progressPercent}%`, transition: "width 0.3s" }} />
				</div>
				<p style={{ fontSize: "0.85rem", color: "var(--ink-medium)", marginBottom: 0 }}>
					{indexProgress?.message ?? "Starting..."}
				</p>
				{indexProgress?.estimatedSizeBytes != null && indexProgress.estimatedSizeBytes > 0 && (
					<p style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--ink-medium)", margin: "4px 0 0 0" }}>
						~{formatBytes(indexProgress.estimatedSizeBytes)}
					</p>
				)}
				{timeRemaining && (
					<p style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--ink-medium)", margin: "4px 0 0 0" }}>
						{timeRemaining} remaining
					</p>
				)}
			</div>
		</div>
	);
}

"use client";

import { useMemo, useState } from "react";
import type { CodeChunk } from "@/lib/chunker";
import {
	extractAttackId,
	extractTactics,
	extractSigmaAttackTags,
	TACTIC_ORDER,
	TACTIC_LABELS,
} from "@/lib/dashboardData";

interface Props {
	attackChunks: CodeChunk[];
	sigmaChunks: CodeChunk[];
}

interface TechniqueCell {
	id: string;
	name: string;
	code: string;
	sigmaCount: number;
	filePath: string;
}

function getCoverageColor(count: number): string {
	if (count >= 3) return "#66BB6A"; // Covered
	if (count >= 1) return "#F5A623"; // Partial
	return "rgba(255,68,68,0.35)"; // No coverage
}

function getCoverageLabel(count: number): string {
	if (count >= 3) return "Covered";
	if (count >= 1) return "Partial";
	return "No coverage";
}

export function ATTACKHeatmap({ attackChunks, sigmaChunks }: Props) {
	const [tooltip, setTooltip] = useState<{
		x: number;
		y: number;
		cell: TechniqueCell;
	} | null>(null);
	const [selected, setSelected] = useState<TechniqueCell | null>(null);

	// Build sigma coverage map: technique_id → count
	const sigmaMap = useMemo(() => {
		const map: Record<string, number> = {};
		for (const c of sigmaChunks) {
			for (const tag of extractSigmaAttackTags(c.code)) {
				map[tag] = (map[tag] || 0) + 1;
			}
		}
		return map;
	}, [sigmaChunks]);

	// Build tactic → techniques map
	const tacticMap = useMemo(() => {
		const map: Record<string, TechniqueCell[]> = {};
		for (const chunk of attackChunks) {
			if (
				chunk.nodeType !== "technique" &&
				chunk.nodeType !== "sub-technique"
			)
				continue;
			const id = extractAttackId(chunk.filePath);
			if (!id) continue;
			const tactics = extractTactics(chunk.code);
			if (tactics.length === 0) continue;
			const cell: TechniqueCell = {
				id,
				name: chunk.name,
				code: chunk.code,
				sigmaCount: sigmaMap[id] || 0,
				filePath: chunk.filePath,
			};
			for (const tactic of tactics) {
				if (!map[tactic]) map[tactic] = [];
				// Deduplicate
				if (!map[tactic].some((c) => c.id === id)) {
					map[tactic].push(cell);
				}
			}
		}
		return map;
	}, [attackChunks, sigmaMap]);

	const orderedTactics = TACTIC_ORDER.filter((t) => tacticMap[t]?.length > 0);

	const totalTechs = useMemo(() => {
		const ids = new Set<string>();
		for (const cells of Object.values(tacticMap))
			for (const c of cells) ids.add(c.id);
		return ids.size;
	}, [tacticMap]);

	const coveredCount = useMemo(() => {
		const ids = new Set<string>();
		for (const cells of Object.values(tacticMap))
			for (const c of cells) if (c.sigmaCount > 0) ids.add(c.id);
		return ids.size;
	}, [tacticMap]);

	const coveragePct =
		totalTechs > 0 ? Math.round((coveredCount / totalTechs) * 100) : 0;

	if (attackChunks.length === 0)
		return (
			<div
				className="paper-card"
				style={{ padding: 24, color: "var(--ink-light)", fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}
			>
				ATT&CK not indexed — connect the ATT&CK source to see coverage.
			</div>
		);

	return (
		<div
			className="paper-card"
			style={{ padding: 24, position: "relative" }}
		>
			{/* Header */}
			<div
				style={{
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
					marginBottom: 20,
					flexWrap: "wrap",
					gap: 12,
				}}
			>
				<div>
					<h2
						style={{
							fontFamily: "var(--font-display)",
							fontSize: "1rem",
							fontWeight: 900,
							textTransform: "uppercase",
							letterSpacing: "0.06em",
							color: "var(--ink-black)",
							margin: 0,
						}}
					>
						ATT&CK Detection Coverage
					</h2>
					<p
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: "0.75rem",
							color: "var(--ink-medium)",
							margin: "4px 0 0",
						}}
					>
						{coveredCount}/{totalTechs} techniques ({coveragePct}%)
						{sigmaChunks.length === 0 && " · Index Sigma rules to see coverage"}
					</p>
				</div>
				{/* Legend */}
				<div
					style={{
						display: "flex",
						gap: 16,
						fontFamily: "var(--font-mono)",
						fontSize: "10px",
						color: "var(--ink-medium)",
					}}
				>
					<span>
						<span
							style={{
								display: "inline-block",
								width: 12,
								height: 12,
								background: "#66BB6A",
								border: "1px solid #333",
								marginRight: 4,
								verticalAlign: "middle",
							}}
						/>
						3+ rules
					</span>
					<span>
						<span
							style={{
								display: "inline-block",
								width: 12,
								height: 12,
								background: "#F5A623",
								border: "1px solid #333",
								marginRight: 4,
								verticalAlign: "middle",
							}}
						/>
						1-2 rules
					</span>
					<span>
						<span
							style={{
								display: "inline-block",
								width: 12,
								height: 12,
								background: "rgba(255,68,68,0.35)",
								border: "1px solid #333",
								marginRight: 4,
								verticalAlign: "middle",
							}}
						/>
						No rule
					</span>
				</div>
			</div>

			{/* Heatmap grid */}
			<div style={{ overflowX: "auto" }}>
				<div style={{ display: "flex", gap: 8, minWidth: "max-content" }}>
					{orderedTactics.map((tactic) => {
						const cells = tacticMap[tactic] ?? [];
						return (
							<div key={tactic} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
								{/* Tactic header */}
								<div
									style={{
										fontFamily: "var(--font-mono)",
										fontSize: "9px",
										fontWeight: 700,
										textTransform: "uppercase",
										letterSpacing: "0.05em",
										color: "var(--ink-medium)",
										padding: "4px 2px",
										writingMode: "vertical-lr",
										transform: "rotate(180deg)",
										height: 80,
										textAlign: "center",
										borderBottom: "1.5px solid var(--border-black)",
										marginBottom: 4,
									}}
								>
									{TACTIC_LABELS[tactic] ?? tactic}
								</div>
								{/* Technique cells */}
								{cells.map((cell) => (
									<div
										key={cell.id}
										onClick={() => setSelected(selected?.id === cell.id ? null : cell)}
										onMouseEnter={(e) => {
											const rect = (e.target as HTMLElement).getBoundingClientRect();
											setTooltip({
												x: rect.right + 8,
												y: rect.top,
												cell,
											});
										}}
										onMouseLeave={() => setTooltip(null)}
										style={{
											width: 38,
											height: 22,
											background: getCoverageColor(cell.sigmaCount),
											border:
												selected?.id === cell.id
													? "2px solid #F5A623"
													: "1px solid rgba(0,0,0,0.4)",
											borderRadius: 1,
											cursor: "pointer",
											display: "flex",
											alignItems: "center",
											justifyContent: "center",
											fontFamily: "var(--font-mono)",
											fontSize: "7.5px",
											color: cell.sigmaCount > 0 ? "#0F0F0F" : "#F5F5F5",
											fontWeight: 700,
											letterSpacing: "-0.02em",
											transition: "transform 0.1s",
											opacity: 0.92,
										}}
										title={`${cell.id}: ${cell.name}\nSigma rules: ${cell.sigmaCount}`}
									>
										{cell.id.length > 9 ? cell.id.slice(0, 9) : cell.id}
									</div>
								))}
							</div>
						);
					})}
				</div>
			</div>

			{/* Hover tooltip */}
			{tooltip && (
				<div
					style={{
						position: "fixed",
						left: Math.min(tooltip.x, window.innerWidth - 280),
						top: tooltip.y,
						background: "#1A1A1A",
						border: "2px solid #333",
						padding: "10px 14px",
						fontFamily: "var(--font-mono)",
						fontSize: "11px",
						color: "var(--ink-black)",
						boxShadow: "4px 4px 0px #000",
						zIndex: 9999,
						maxWidth: 260,
						pointerEvents: "none",
					}}
				>
					<div style={{ fontWeight: 700, color: "#F5A623", marginBottom: 4 }}>
						{tooltip.cell.id}
					</div>
					<div style={{ color: "var(--ink-black)", marginBottom: 6 }}>
						{tooltip.cell.name.replace(/^[^:]+:\s*/, "")}
					</div>
					<div
						style={{
							color: getCoverageColor(tooltip.cell.sigmaCount),
							fontWeight: 700,
						}}
					>
						{getCoverageLabel(tooltip.cell.sigmaCount)}{" "}
						{tooltip.cell.sigmaCount > 0 && `(${tooltip.cell.sigmaCount} rules)`}
					</div>
				</div>
			)}

			{/* Selected detail panel */}
			{selected && (
				<div
					style={{
						marginTop: 20,
						padding: 16,
						background: "var(--bg-paper-alt)",
						border: "2px solid var(--accent-amber)",
						borderRadius: 2,
					}}
				>
					<div
						style={{
							display: "flex",
							justifyContent: "space-between",
							alignItems: "flex-start",
							marginBottom: 8,
						}}
					>
						<div>
							<span
								style={{
									fontFamily: "var(--font-mono)",
									fontSize: "11px",
									color: "var(--accent-amber)",
									fontWeight: 700,
								}}
							>
								{selected.id}
							</span>
							<span
								style={{
									fontFamily: "var(--font-sans)",
									fontSize: "13px",
									color: "var(--ink-black)",
									marginLeft: 8,
								}}
							>
								{selected.name.replace(/^[^:]+:\s*/, "")}
							</span>
						</div>
						<button
							onClick={() => setSelected(null)}
							style={{
								background: "none",
								border: "none",
								color: "var(--ink-light)",
								cursor: "pointer",
								fontSize: "14px",
							}}
						>
							✕
						</button>
					</div>
					<div
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: "11px",
							color:
								selected.sigmaCount > 0
									? getCoverageColor(selected.sigmaCount)
									: "var(--critical-red)",
							marginBottom: 8,
						}}
					>
						{selected.sigmaCount === 0
							? "⚠ No Sigma detection rules — coverage gap"
							: `✓ ${selected.sigmaCount} Sigma rule${selected.sigmaCount > 1 ? "s" : ""} cover this technique`}
					</div>
					<pre
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: "10px",
							color: "var(--ink-medium)",
							whiteSpace: "pre-wrap",
							margin: 0,
							maxHeight: 120,
							overflowY: "auto",
						}}
					>
						{selected.code.slice(0, 600)}
						{selected.code.length > 600 ? "…" : ""}
					</pre>
				</div>
			)}
		</div>
	);
}

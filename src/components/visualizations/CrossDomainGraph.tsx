"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import * as d3 from "d3";
import type { CodeChunk } from "@/lib/chunker";
import {
	extractAttackId,
	extractSigmaAttackTags,
} from "@/lib/dashboardData";

interface GraphNode extends d3.SimulationNodeDatum {
	id: string;
	label: string;
	type: "technique" | "group" | "sigma" | "cve" | "control";
	domain: string;
	color: string;
	radius: number;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
	source: string | GraphNode;
	target: string | GraphNode;
	type: "detects" | "uses" | "related" | "mitigates";
	color: string;
}

interface Props {
	attackChunks: CodeChunk[];
	sigmaChunks: CodeChunk[];
	nvdChunks: CodeChunk[];
	nistChunks: CodeChunk[];
}

const DOMAIN_FILTERS = [
	{ key: "attack", label: "ATT&CK", color: "#F5A623" },
	{ key: "sigma", label: "Sigma", color: "#66BB6A" },
	{ key: "nvd", label: "CVEs", color: "#FF4444" },
	{ key: "nist", label: "NIST", color: "#64B5F6" },
] as const;

const MAX_NODES = 200;

export function CrossDomainGraph({
	attackChunks,
	sigmaChunks,
	nvdChunks,
	nistChunks,
}: Props) {
	const svgRef = useRef<SVGSVGElement>(null);
	const containerRef = useRef<HTMLDivElement>(null);
	const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null);
	const [activeFilters, setActiveFilters] = useState<Set<string>>(
		new Set(["attack", "sigma", "nvd", "nist"])
	);
	const [searchQuery, setSearchQuery] = useState("");
	const [nodeCount, setNodeCount] = useState(0);
	const [tooltipContent, setTooltipContent] = useState<{
		x: number;
		y: number;
		node: GraphNode;
	} | null>(null);
	const [totalNodeCount, setTotalNodeCount] = useState(0);

	const buildGraph = useCallback(
		(filters: Set<string>) => {
			const allNodes: GraphNode[] = [];
			const allLinks: GraphLink[] = [];
			const nodeIdSet = new Set<string>();

			const addNode = (n: GraphNode) => {
				if (!nodeIdSet.has(n.id)) {
					allNodes.push(n);
					nodeIdSet.add(n.id);
				}
			};

			// ATT&CK techniques + groups
			if (filters.has("attack")) {
				for (const c of attackChunks) {
					const id = extractAttackId(c.filePath);
					if (!id) continue;
					if (c.nodeType === "technique" || c.nodeType === "sub-technique") {
						addNode({
							id,
							label: c.name,
							type: "technique",
							domain: "attack",
							color: "#F5A623",
							radius: 7,
						});
					} else if (c.nodeType === "group") {
						addNode({
							id,
							label: c.name,
							type: "group",
							domain: "attack",
							color: "#FF8A65",
							radius: 10,
						});
					}
				}
			}

			// Sigma rules → link to ATT&CK techniques
			if (filters.has("sigma")) {
				let sigmaCount = 0;
				for (const c of sigmaChunks) {
					const ruleId = c.filePath.replace("sigma://rule/", "");
					const nodeId = `sigma-${ruleId}`;
					const attackTags = extractSigmaAttackTags(c.code);
					// Only add sigma nodes that have ATT&CK links
					if (attackTags.length > 0) {
						addNode({
							id: nodeId,
							label: c.name,
							type: "sigma",
							domain: "sigma",
							color: "#66BB6A",
							radius: 5,
						});
						sigmaCount++;
						for (const tag of attackTags) {
							if (nodeIdSet.has(tag) || filters.has("attack")) {
								allLinks.push({
									source: nodeId,
									target: tag,
									type: "detects",
									color: "#66BB6A",
								});
							}
						}
					}
					if (sigmaCount >= 500) break; // Limit sigma nodes
				}
			}

			// CVEs
			if (filters.has("nvd")) {
				for (const c of nvdChunks.slice(0, 300)) {
					const cveId = c.name;
					const scoreMatch = c.code.match(/CVSS\s+[\d.]+:\s+([\d.]+)/);
					const score = scoreMatch ? parseFloat(scoreMatch[1]) : 5;
					addNode({
						id: cveId,
						label: cveId,
						type: "cve",
						domain: "nvd",
						color: "#FF4444",
						radius: Math.max(4, Math.min(12, score * 1.2)),
					});
				}
			}

			// NIST controls
			if (filters.has("nist")) {
				for (const c of nistChunks.slice(0, 200)) {
					const ctrlId = c.filePath.replace("nist://control/", "");
					addNode({
						id: ctrlId,
						label: c.name,
						type: "control",
						domain: "nist",
						color: "#64B5F6",
						radius: 6,
					});
				}
			}

			// Filter links to only include existing nodes
			const finalNodeIds = new Set(allNodes.map((n) => n.id));
			const validLinks = allLinks.filter(
				(l) =>
					finalNodeIds.has(l.source as string) &&
					finalNodeIds.has(l.target as string)
			);

			// Compute degree for each node
			const degree: Record<string, number> = {};
			for (const l of validLinks) {
				const s = l.source as string;
				const t = l.target as string;
				degree[s] = (degree[s] || 0) + 1;
				degree[t] = (degree[t] || 0) + 1;
			}

			setTotalNodeCount(allNodes.length);

			// Limit to MAX_NODES most-connected
			const sortedNodes = [...allNodes].sort(
				(a, b) => (degree[b.id] || 0) - (degree[a.id] || 0)
			);
			const topNodes = sortedNodes.slice(0, MAX_NODES);
			const topIds = new Set(topNodes.map((n) => n.id));
			const topLinks = validLinks.filter(
				(l) =>
					topIds.has(l.source as string) && topIds.has(l.target as string)
			);

			setNodeCount(topNodes.length);
			return { nodes: topNodes, links: topLinks };
		},
		[attackChunks, sigmaChunks, nvdChunks, nistChunks]
	);

	useEffect(() => {
		if (!svgRef.current || !containerRef.current) return;

		const { nodes, links } = buildGraph(activeFilters);
		const width = containerRef.current.clientWidth || 800;
		const height = 480;

		// Clear previous
		const svg = d3.select(svgRef.current);
		svg.selectAll("*").remove();
		if (simulationRef.current) simulationRef.current.stop();

		svg.attr("width", width).attr("height", height);

		// Zoom container
		const g = svg.append("g");

		const zoom = d3
			.zoom<SVGSVGElement, unknown>()
			.scaleExtent([0.1, 4])
			.on("zoom", (event) => {
				g.attr("transform", event.transform.toString());
			});

		svg.call(zoom);

		// Arrow markers
		svg
			.append("defs")
			.append("marker")
			.attr("id", "arrowhead")
			.attr("viewBox", "0 -5 10 10")
			.attr("refX", 16)
			.attr("refY", 0)
			.attr("markerWidth", 6)
			.attr("markerHeight", 6)
			.attr("orient", "auto")
			.append("path")
			.attr("d", "M0,-5L10,0L0,5")
			.attr("fill", "#444");

		// Links
		const link = g
			.append("g")
			.selectAll<SVGLineElement, GraphLink>("line")
			.data(links)
			.join("line")
			.attr("stroke", (d) => d.color)
			.attr("stroke-opacity", 0.35)
			.attr("stroke-width", 1)
			.attr("stroke-dasharray", (d) =>
				d.type === "detects" || d.type === "related" ? "3,3" : "none"
			);

		// Nodes
		const node = g
			.append("g")
			.selectAll<SVGCircleElement, GraphNode>("circle")
			.data(nodes)
			.join("circle")
			.attr("r", (d) => d.radius)
			.attr("fill", (d) => d.color)
			.attr("fill-opacity", 0.85)
			.attr("stroke", "#1A1A1A")
			.attr("stroke-width", 1.5)
			.attr("cursor", "pointer")
			.on("mouseover", function (event, d) {
				d3.select(this).attr("stroke", "#F5A623").attr("stroke-width", 2.5);
				// Highlight connected links
				link
					.attr("stroke-opacity", (l) => {
						const src = typeof l.source === "object" ? l.source.id : l.source;
						const tgt = typeof l.target === "object" ? l.target.id : l.target;
						return src === d.id || tgt === d.id ? 0.85 : 0.08;
					})
					.attr("stroke-width", (l) => {
						const src = typeof l.source === "object" ? l.source.id : l.source;
						const tgt = typeof l.target === "object" ? l.target.id : l.target;
						return src === d.id || tgt === d.id ? 2 : 1;
					});
				node.attr("fill-opacity", (n) => {
					if (n.id === d.id) return 1;
					const connected = links.some((l) => {
						const src = typeof l.source === "object" ? l.source.id : l.source;
						const tgt = typeof l.target === "object" ? l.target.id : l.target;
						return (src === d.id && tgt === n.id) || (tgt === d.id && src === n.id);
					});
					return connected ? 1 : 0.2;
				});
				setTooltipContent({ x: event.pageX + 12, y: event.pageY - 10, node: d });
			})
			.on("mouseout", function () {
				d3.select(this).attr("stroke", "#1A1A1A").attr("stroke-width", 1.5);
				link.attr("stroke-opacity", 0.35).attr("stroke-width", 1);
				node.attr("fill-opacity", 0.85);
				setTooltipContent(null);
			})
			.call(
				d3
					.drag<SVGCircleElement, GraphNode>()
					.on("start", (event, d) => {
						if (!event.active) simulationRef.current?.alphaTarget(0.3).restart();
						d.fx = d.x;
						d.fy = d.y;
					})
					.on("drag", (event, d) => {
						d.fx = event.x;
						d.fy = event.y;
					})
					.on("end", (event, d) => {
						if (!event.active) simulationRef.current?.alphaTarget(0);
						d.fx = null;
						d.fy = null;
					})
			);

		// Labels (only for larger nodes)
		const label = g
			.append("g")
			.selectAll<SVGTextElement, GraphNode>("text")
			.data(nodes.filter((n) => n.radius >= 8 || n.type === "technique"))
			.join("text")
			.attr("fill", "#A0A0A0")
			.attr("font-size", "8px")
			.attr("font-family", "JetBrains Mono, monospace")
			.attr("pointer-events", "none")
			.text((d) => d.id.slice(0, 10));

		// Simulation
		const simulation = d3
			.forceSimulation<GraphNode>(nodes)
			.force(
				"link",
				d3
					.forceLink<GraphNode, GraphLink>(links)
					.id((d) => d.id)
					.distance(70)
					.strength(0.6)
			)
			.force("charge", d3.forceManyBody<GraphNode>().strength(-120))
			.force("center", d3.forceCenter(width / 2, height / 2))
			.force("collision", d3.forceCollide<GraphNode>().radius((d) => d.radius + 3))
			.alpha(0.8)
			.alphaDecay(0.03);

		simulationRef.current = simulation as unknown as d3.Simulation<GraphNode, GraphLink>;

		simulation.on("tick", () => {
			link
				.attr("x1", (d) => (d.source as GraphNode).x ?? 0)
				.attr("y1", (d) => (d.source as GraphNode).y ?? 0)
				.attr("x2", (d) => (d.target as GraphNode).x ?? 0)
				.attr("y2", (d) => (d.target as GraphNode).y ?? 0);
			node.attr("cx", (d) => d.x ?? 0).attr("cy", (d) => d.y ?? 0);
			label
				.attr("x", (d) => (d.x ?? 0) + (d.radius + 2))
				.attr("y", (d) => (d.y ?? 0) + 3);
		});

		// Reset zoom button handler
		const resetBtn = document.getElementById("graph-reset-zoom");
		if (resetBtn) {
			resetBtn.onclick = () => {
				svg
					.transition()
					.duration(400)
					.call(zoom.transform, d3.zoomIdentity);
			};
		}

		return () => {
			simulation.stop();
		};
	}, [activeFilters, buildGraph]);

	// Highlight searched node
	useEffect(() => {
		if (!svgRef.current || !searchQuery) return;
		const q = searchQuery.toLowerCase();
		d3.select(svgRef.current)
			.selectAll<SVGCircleElement, GraphNode>("circle")
			.attr("stroke", (d) =>
				d.id.toLowerCase().includes(q) ||
				d.label.toLowerCase().includes(q)
					? "#F5A623"
					: "#1A1A1A"
			)
			.attr("stroke-width", (d) =>
				d.id.toLowerCase().includes(q) ||
				d.label.toLowerCase().includes(q)
					? 3
					: 1.5
			);
	}, [searchQuery]);

	const totalSources = [
		attackChunks.length > 0,
		sigmaChunks.length > 0,
		nvdChunks.length > 0,
		nistChunks.length > 0,
	].filter(Boolean).length;

	if (totalSources < 2) {
		return (
			<div
				className="paper-card"
				style={{ padding: 24, color: "var(--ink-light)", fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}
			>
				Index 2+ sources to see the cross-domain threat map.
			</div>
		);
	}

	return (
		<div className="paper-card" style={{ padding: 20 }}>
			{/* Header */}
			<div
				style={{
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
					marginBottom: 14,
					flexWrap: "wrap",
					gap: 10,
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
						Cross-Domain Threat Map
					</h2>
					<p
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: "11px",
							color: "var(--ink-light)",
							margin: "4px 0 0",
						}}
					>
						{nodeCount} nodes shown
						{totalNodeCount > MAX_NODES
							? ` (top ${MAX_NODES} of ${totalNodeCount})`
							: ""}{" "}
						· drag · scroll to zoom
					</p>
				</div>
				<input
					placeholder="Search node…"
					value={searchQuery}
					onChange={(e) => setSearchQuery(e.target.value)}
					style={{
						background: "var(--bg-paper-alt)",
						border: "2px solid var(--border-black)",
						color: "var(--ink-black)",
						fontFamily: "var(--font-mono)",
						fontSize: "11px",
						padding: "5px 10px",
						outline: "none",
						width: 160,
					}}
				/>
			</div>

			{/* Domain filter toggles */}
			<div style={{ display: "flex", gap: 6, marginBottom: 12, flexWrap: "wrap" }}>
				{DOMAIN_FILTERS.map(({ key, label, color }) => {
					const active = activeFilters.has(key);
					return (
						<button
							key={key}
							onClick={() => {
								const next = new Set(activeFilters);
								if (active) next.delete(key);
								else next.add(key);
								if (next.size > 0) setActiveFilters(next);
							}}
							style={{
								background: active ? color : "var(--bg-paper-alt)",
								color: active ? "#0F0F0F" : color,
								border: `2px solid ${color}`,
								padding: "3px 10px",
								fontFamily: "var(--font-mono)",
								fontSize: "10px",
								fontWeight: 700,
								textTransform: "uppercase",
								cursor: "pointer",
								letterSpacing: "0.04em",
								transition: "all 0.15s",
							}}
						>
							{label}
						</button>
					);
				})}
				<button
					id="graph-reset-zoom"
					style={{
						background: "var(--bg-paper-alt)",
						color: "var(--ink-medium)",
						border: "2px solid var(--border-black)",
						padding: "3px 10px",
						fontFamily: "var(--font-mono)",
						fontSize: "10px",
						cursor: "pointer",
						marginLeft: "auto",
					}}
				>
					Reset Zoom
				</button>
			</div>

			{/* SVG canvas */}
			<div
				ref={containerRef}
				style={{
					width: "100%",
					background: "#0F0F0F",
					border: "2px solid var(--border-black)",
					overflow: "hidden",
					position: "relative",
				}}
			>
				<svg ref={svgRef} style={{ display: "block", width: "100%", height: 480 }} />
			</div>

			{/* Legend */}
			<div
				style={{
					display: "flex",
					gap: 16,
					marginTop: 12,
					fontFamily: "var(--font-mono)",
					fontSize: "10px",
					color: "var(--ink-medium)",
					flexWrap: "wrap",
				}}
			>
				<span style={{ color: "#F5A623" }}>● ATT&CK Technique</span>
				<span style={{ color: "#FF8A65" }}>● Threat Group</span>
				<span style={{ color: "#66BB6A" }}>● Sigma Rule</span>
				<span style={{ color: "#FF4444" }}>● CVE</span>
				<span style={{ color: "#64B5F6" }}>● NIST Control</span>
			</div>

			{/* Hover tooltip */}
			{tooltipContent && (
				<div
					style={{
						position: "fixed",
						left: tooltipContent.x,
						top: tooltipContent.y,
						background: "#1A1A1A",
						border: "2px solid #333",
						padding: "10px 14px",
						fontFamily: "var(--font-mono)",
						fontSize: "11px",
						color: "var(--ink-black)",
						boxShadow: "3px 3px 0px #000",
						zIndex: 9999,
						maxWidth: 280,
						pointerEvents: "none",
					}}
				>
					<div style={{ color: tooltipContent.node.color, fontWeight: 700, marginBottom: 3 }}>
						{tooltipContent.node.id}
					</div>
					<div style={{ color: "var(--ink-medium)", fontSize: "10px" }}>
						{tooltipContent.node.label.replace(/^[^:]+:\s*/, "").slice(0, 80)}
					</div>
					<div
						style={{
							color: "var(--ink-light)",
							fontSize: "9px",
							textTransform: "uppercase",
							marginTop: 4,
						}}
					>
						{tooltipContent.node.type} · {tooltipContent.node.domain}
					</div>
				</div>
			)}
		</div>
	);
}

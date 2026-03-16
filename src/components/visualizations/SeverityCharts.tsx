"use client";

import { useMemo } from "react";
import {
	BarChart,
	Bar,
	XAxis,
	YAxis,
	Tooltip,
	ResponsiveContainer,
	PieChart,
	Pie,
	Cell,
	Legend,
} from "recharts";
import type { CodeChunk } from "@/lib/chunker";
import {
	extractCVSSSeverity,
	extractSigmaLevel,
	extractTactics,
	extractNISTFamily,
	TACTIC_LABELS,
	NIST_FAMILY_NAMES,
	SEVERITY_COLORS,
} from "@/lib/dashboardData";

// ─── Shared tooltip style ────────────────────────────────────────────────────

const TOOLTIP_STYLE = {
	contentStyle: {
		background: "#1A1A1A",
		border: "2px solid #333333",
		color: "#F5F5F5",
		fontFamily: "var(--font-mono, monospace)",
		fontSize: "11px",
		borderRadius: 0,
		boxShadow: "3px 3px 0px #000",
	},
	labelStyle: { color: "#F5A623", fontWeight: 700 },
	itemStyle: { color: "#F5F5F5" },
	cursor: { fill: "rgba(245,166,35,0.08)" },
};

const AXIS_STYLE = {
	fill: "#A0A0A0",
	fontFamily: "var(--font-mono, monospace)",
	fontSize: 10,
};

// ─── Card wrapper ─────────────────────────────────────────────────────────────

function ChartCard({
	title,
	subtitle,
	children,
}: {
	title: string;
	subtitle?: string;
	children: React.ReactNode;
}) {
	return (
		<div className="paper-card" style={{ padding: 20 }}>
			<h3
				style={{
					fontFamily: "var(--font-display)",
					fontSize: "0.85rem",
					fontWeight: 900,
					textTransform: "uppercase",
					letterSpacing: "0.06em",
					color: "var(--ink-black)",
					margin: "0 0 4px",
				}}
			>
				{title}
			</h3>
			{subtitle && (
				<p
					style={{
						fontFamily: "var(--font-mono)",
						fontSize: "11px",
						color: "var(--ink-light)",
						margin: "0 0 16px",
					}}
				>
					{subtitle}
				</p>
			)}
			{children}
		</div>
	);
}

// ─── Chart 1: CVE Severity Distribution ─────────────────────────────────────

export function CVESeverityChart({ nvdChunks }: { nvdChunks: CodeChunk[] }) {
	const data = useMemo(() => {
		const counts: Record<string, number> = {
			CRITICAL: 0,
			HIGH: 0,
			MEDIUM: 0,
			LOW: 0,
			UNKNOWN: 0,
		};
		for (const c of nvdChunks) {
			const sev = extractCVSSSeverity(c.code);
			if (sev in counts) counts[sev]++;
			else counts.UNKNOWN++;
		}
		return [
			{ name: "CRITICAL", count: counts.CRITICAL, color: SEVERITY_COLORS.CRITICAL },
			{ name: "HIGH", count: counts.HIGH, color: SEVERITY_COLORS.HIGH },
			{ name: "MEDIUM", count: counts.MEDIUM, color: SEVERITY_COLORS.MEDIUM },
			{ name: "LOW", count: counts.LOW, color: SEVERITY_COLORS.LOW },
		].filter((d) => d.count > 0);
	}, [nvdChunks]);

	if (nvdChunks.length === 0) return null;

	return (
		<ChartCard
			title="CVE Severity Distribution"
			subtitle={`${nvdChunks.length} CVEs indexed`}
		>
			<ResponsiveContainer width="100%" height={180}>
				<BarChart data={data} layout="vertical" margin={{ left: 0, right: 20 }}>
					<XAxis type="number" tick={AXIS_STYLE} axisLine={{ stroke: "#333" }} tickLine={false} />
					<YAxis
						dataKey="name"
						type="category"
						tick={AXIS_STYLE}
						axisLine={false}
						tickLine={false}
						width={72}
					/>
					<Tooltip {...TOOLTIP_STYLE} />
					<Bar dataKey="count" radius={0} label={{ position: "right", fill: "#A0A0A0", fontSize: 10 }}>
						{data.map((entry) => (
							<Cell key={entry.name} fill={entry.color} />
						))}
					</Bar>
				</BarChart>
			</ResponsiveContainer>
		</ChartCard>
	);
}

// ─── Chart 2: Sigma Rule Level Donut ─────────────────────────────────────────

export function SigmaLevelChart({ sigmaChunks }: { sigmaChunks: CodeChunk[] }) {
	const data = useMemo(() => {
		const counts: Record<string, number> = {
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
			informational: 0,
		};
		for (const c of sigmaChunks) {
			const level = extractSigmaLevel(c.code);
			if (level in counts) counts[level]++;
			else counts.medium++;
		}
		return [
			{ name: "Critical", value: counts.critical, color: SEVERITY_COLORS.critical },
			{ name: "High", value: counts.high, color: SEVERITY_COLORS.high },
			{ name: "Medium", value: counts.medium, color: SEVERITY_COLORS.medium },
			{ name: "Low", value: counts.low, color: SEVERITY_COLORS.low },
			{ name: "Info", value: counts.informational, color: SEVERITY_COLORS.informational },
		].filter((d) => d.value > 0);
	}, [sigmaChunks]);

	if (sigmaChunks.length === 0) return null;

	const total = sigmaChunks.length;

	return (
		<ChartCard
			title="Sigma Rule Levels"
			subtitle={`${total} rules indexed`}
		>
			<div style={{ position: "relative" }}>
				<ResponsiveContainer width="100%" height={180}>
					<PieChart>
						<Pie
							data={data}
							cx="50%"
							cy="50%"
							innerRadius={52}
							outerRadius={74}
							paddingAngle={2}
							dataKey="value"
						>
							{data.map((entry) => (
								<Cell key={entry.name} fill={entry.color} stroke="#1A1A1A" strokeWidth={2} />
							))}
						</Pie>
						<Tooltip {...TOOLTIP_STYLE} />
						<Legend
							wrapperStyle={{
								fontFamily: "var(--font-mono, monospace)",
								fontSize: "10px",
								color: "#A0A0A0",
							}}
						/>
					</PieChart>
				</ResponsiveContainer>
				{/* Center label */}
				<div
					style={{
						position: "absolute",
						top: "50%",
						left: "50%",
						transform: "translate(-50%, -60%)",
						textAlign: "center",
						pointerEvents: "none",
					}}
				>
					<div
						style={{
							fontFamily: "var(--font-display)",
							fontSize: "1.4rem",
							fontWeight: 900,
							color: "var(--accent-amber)",
						}}
					>
						{total.toLocaleString()}
					</div>
					<div
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: "9px",
							color: "var(--ink-light)",
							textTransform: "uppercase",
						}}
					>
						rules
					</div>
				</div>
			</div>
		</ChartCard>
	);
}

// ─── Chart 3: ATT&CK Techniques by Tactic ────────────────────────────────────

export function ATTACKTacticChart({ attackChunks }: { attackChunks: CodeChunk[] }) {
	const data = useMemo(() => {
		const counts: Record<string, number> = {};
		for (const c of attackChunks) {
			if (c.nodeType !== "technique" && c.nodeType !== "sub-technique") continue;
			for (const tactic of extractTactics(c.code)) {
				counts[tactic] = (counts[tactic] || 0) + 1;
			}
		}
		return Object.entries(counts)
			.map(([tactic, count]) => ({
				name: TACTIC_LABELS[tactic] ?? tactic,
				count,
			}))
			.sort((a, b) => b.count - a.count)
			.slice(0, 14);
	}, [attackChunks]);

	if (attackChunks.length === 0) return null;

	return (
		<ChartCard
			title="ATT&CK Techniques by Tactic"
			subtitle={`${attackChunks.filter((c) => c.nodeType === "technique" || c.nodeType === "sub-technique").length} techniques indexed`}
		>
			<ResponsiveContainer width="100%" height={240}>
				<BarChart data={data} layout="vertical" margin={{ left: 0, right: 24 }}>
					<XAxis type="number" tick={AXIS_STYLE} axisLine={{ stroke: "#333" }} tickLine={false} />
					<YAxis
						dataKey="name"
						type="category"
						tick={AXIS_STYLE}
						axisLine={false}
						tickLine={false}
						width={100}
					/>
					<Tooltip {...TOOLTIP_STYLE} />
					<Bar dataKey="count" fill="#F5A623" radius={0} label={{ position: "right", fill: "#A0A0A0", fontSize: 10 }} />
				</BarChart>
			</ResponsiveContainer>
		</ChartCard>
	);
}

// ─── Chart 4: NIST Control Family Distribution ───────────────────────────────

export function NISTFamilyChart({ nistChunks }: { nistChunks: CodeChunk[] }) {
	const data = useMemo(() => {
		const counts: Record<string, number> = {};
		for (const c of nistChunks) {
			const family = extractNISTFamily(c.filePath);
			if (family) counts[family] = (counts[family] || 0) + 1;
		}
		return Object.entries(counts)
			.map(([family, count]) => ({
				name: family,
				fullName: NIST_FAMILY_NAMES[family] ?? family,
				count,
			}))
			.sort((a, b) => b.count - a.count)
			.slice(0, 20);
	}, [nistChunks]);

	if (nistChunks.length === 0) return null;

	return (
		<ChartCard
			title="NIST 800-53 by Control Family"
			subtitle={`${nistChunks.length} controls indexed`}
		>
			<ResponsiveContainer width="100%" height={240}>
				<BarChart data={data} layout="vertical" margin={{ left: 0, right: 24 }}>
					<XAxis type="number" tick={AXIS_STYLE} axisLine={{ stroke: "#333" }} tickLine={false} />
					<YAxis
						dataKey="name"
						type="category"
						tick={AXIS_STYLE}
						axisLine={false}
						tickLine={false}
						width={36}
					/>
					<Tooltip
						{...TOOLTIP_STYLE}
						formatter={(value, _name, props) => [
							value,
							props.payload?.fullName ?? "",
						]}
					/>
					<Bar dataKey="count" fill="#64B5F6" radius={0} label={{ position: "right", fill: "#A0A0A0", fontSize: 10 }} />
				</BarChart>
			</ResponsiveContainer>
		</ChartCard>
	);
}

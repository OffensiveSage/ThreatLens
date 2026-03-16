"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { loadDashboardData, type DashboardData } from "@/lib/dashboardData";
import { ATTACKHeatmap } from "@/components/visualizations/ATTACKHeatmap";
import {
	CVESeverityChart,
	SigmaLevelChart,
	ATTACKTacticChart,
	NISTFamilyChart,
} from "@/components/visualizations/SeverityCharts";
import { CrossDomainGraph } from "@/components/visualizations/CrossDomainGraph";

const DOMAIN_META: Record<string, { label: string; color: string; tagClass: string }> = {
	attack: { label: "ATT&CK", color: "#F5A623", tagClass: "tag-attack" },
	sigma: { label: "Sigma Rules", color: "#66BB6A", tagClass: "tag-sigma" },
	nvd: { label: "NVD / CVEs", color: "#FF4444", tagClass: "tag-nvd" },
	nist: { label: "NIST 800-53", color: "#64B5F6", tagClass: "tag-compliance" },
	custom: { label: "Custom Upload", color: "#CE93D8", tagClass: "tag-custom" },
};

function StatCard({
	label,
	value,
	sub,
	accent,
}: {
	label: string;
	value: string | number;
	sub?: string;
	accent?: string;
}) {
	return (
		<div
			className="paper-card"
			style={{ padding: "20px 24px", flex: 1, minWidth: 140 }}
		>
			<div
				style={{
					fontFamily: "var(--font-display)",
					fontSize: "clamp(1.6rem, 3vw, 2.2rem)",
					fontWeight: 900,
					color: accent ?? "var(--accent-amber)",
					lineHeight: 1,
					marginBottom: 6,
				}}
			>
				{typeof value === "number" ? value.toLocaleString() : value}
			</div>
			<div
				style={{
					fontFamily: "var(--font-sans)",
					fontSize: "11px",
					fontWeight: 600,
					textTransform: "uppercase",
					letterSpacing: "0.07em",
					color: "var(--ink-medium)",
				}}
			>
				{label}
			</div>
			{sub && (
				<div
					style={{
						fontFamily: "var(--font-mono)",
						fontSize: "10px",
						color: "var(--ink-light)",
						marginTop: 3,
					}}
				>
					{sub}
				</div>
			)}
		</div>
	);
}

export default function DashboardPage() {
	const router = useRouter();
	const [data, setData] = useState<DashboardData | null>(null);
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		loadDashboardData().then((d) => {
			setData(d);
			setLoading(false);
		});
	}, []);

	// Coverage percentage
	const coveragePct = (() => {
		if (!data || data.attack.length === 0 || data.sigma.length === 0) return null;
		const techniqueIds = new Set(
			data.attack
				.filter((c) => c.nodeType === "technique" || c.nodeType === "sub-technique")
				.map((c) => c.filePath.replace(/attack:\/\/[^/]+\//, ""))
		);
		let covered = 0;
		for (const c of data.sigma) {
			const m = c.code.match(/^ATT&CK Techniques:\s*(.+)$/m);
			if (m) {
				for (const tag of m[1].split(",").map((t) => t.trim())) {
					if (techniqueIds.has(tag)) covered++;
				}
			}
		}
		return techniqueIds.size > 0
			? Math.round((covered / techniqueIds.size) * 100)
			: 0;
	})();

	return (
		<div
			style={{
				minHeight: "100vh",
				background: "var(--bg-cream)",
				color: "var(--ink-black)",
				fontFamily: "var(--font-sans)",
			}}
		>
			{/* ── NAV ── */}
			<nav
				style={{
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					padding: "14px 40px",
					borderBottom: "2.5px solid var(--border-black)",
					background: "var(--bg-paper)",
					position: "sticky",
					top: 0,
					zIndex: 40,
					boxShadow: "var(--shadow-layer-1)",
				}}
			>
				<div style={{ display: "flex", alignItems: "center", gap: 16 }}>
					<button
						onClick={() => router.push("/")}
						style={{
							background: "none",
							border: "none",
							fontFamily: "var(--font-display)",
							fontWeight: 900,
							fontSize: "1.1rem",
							color: "var(--ink-black)",
							cursor: "pointer",
							textTransform: "uppercase",
							letterSpacing: "0.04em",
							padding: 0,
						}}
					>
						ThreatLens
					</button>
					<span style={{ color: "var(--ink-light)" }}>/</span>
					<span
						style={{
							fontFamily: "var(--font-display)",
							fontSize: "0.85rem",
							fontWeight: 700,
							color: "var(--accent-amber)",
							textTransform: "uppercase",
							letterSpacing: "0.04em",
						}}
					>
						Dashboard
					</span>
				</div>
				<div style={{ display: "flex", gap: 10, alignItems: "center" }}>
					<button
						onClick={() => router.push("/")}
						style={{
							background: "none",
							border: "2px solid var(--border-black)",
							color: "var(--ink-medium)",
							padding: "5px 12px",
							fontFamily: "var(--font-mono)",
							fontSize: "11px",
							fontWeight: 700,
							cursor: "pointer",
							textTransform: "uppercase",
							letterSpacing: "0.05em",
						}}
					>
						Sources
					</button>
				</div>
			</nav>

			{/* ── CONTENT ── */}
			<main style={{ maxWidth: 1280, margin: "0 auto", padding: "32px 24px" }}>
				{loading ? (
					<div
						style={{
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							minHeight: 300,
							fontFamily: "var(--font-mono)",
							fontSize: "0.85rem",
							color: "var(--ink-light)",
						}}
					>
						<span className="pulse" style={{ marginRight: 8 }}>●</span> Loading indexed data…
					</div>
				) : !data || data.totalChunks === 0 ? (
					<div style={{ textAlign: "center", padding: "80px 24px" }}>
						<div
							style={{
								fontFamily: "var(--font-display)",
								fontSize: "1.2rem",
								color: "var(--ink-medium)",
								textTransform: "uppercase",
								letterSpacing: "0.05em",
								marginBottom: 16,
							}}
						>
							No data indexed yet
						</div>
						<p style={{ color: "var(--ink-light)", fontFamily: "var(--font-mono)", fontSize: "13px" }}>
							Connect a source from the home page to see visualizations here.
						</p>
						<button
							onClick={() => router.push("/")}
							className="btn-primary"
							style={{ marginTop: 24 }}
						>
							Go to Sources →
						</button>
					</div>
				) : (
					<>
						{/* ── Page title ── */}
						<div style={{ marginBottom: 28 }}>
							<h1
								style={{
									fontFamily: "var(--font-display)",
									fontSize: "clamp(1.4rem, 3vw, 2rem)",
									fontWeight: 900,
									textTransform: "uppercase",
									letterSpacing: "0.04em",
									color: "var(--ink-black)",
									margin: "0 0 6px",
								}}
							>
								Security Intelligence Overview
							</h1>
							<p style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--ink-light)", margin: 0 }}>
								Real-time analysis of your indexed security knowledge bases
							</p>
						</div>

						{/* ── Stat cards ── */}
						<div
							style={{
								display: "flex",
								gap: 16,
								marginBottom: 32,
								flexWrap: "wrap",
							}}
						>
							<StatCard
								label="Sources Indexed"
								value={`${data.indexedSources.length} / 5`}
								sub={data.indexedSources.map((s) => DOMAIN_META[s]?.label ?? s).join(" · ")}
							/>
							<StatCard
								label="Total Chunks"
								value={data.totalChunks}
								sub="Indexed knowledge fragments"
							/>
							{coveragePct !== null && (
								<StatCard
									label="Detection Coverage"
									value={`${coveragePct}%`}
									sub="ATT&CK techniques with Sigma rules"
									accent={
										coveragePct >= 60
											? "#66BB6A"
											: coveragePct >= 30
											? "#F5A623"
											: "#FF4444"
									}
								/>
							)}
							{data.nvd.length > 0 && (
								<StatCard
									label="CVEs Indexed"
									value={data.nvd.length}
									sub="From NVD feed"
									accent="#FF4444"
								/>
							)}
							{data.sigma.length > 0 && (
								<StatCard
									label="Sigma Rules"
									value={data.sigma.length}
									sub="Detection rules indexed"
									accent="#66BB6A"
								/>
							)}
						</div>

						{/* ── ATT&CK Heatmap ── */}
						{data.attack.length > 0 && (
							<div style={{ marginBottom: 32 }}>
								<ATTACKHeatmap
									attackChunks={data.attack}
									sigmaChunks={data.sigma}
								/>
							</div>
						)}

						{/* ── Charts grid ── */}
						{(data.nvd.length > 0 ||
							data.sigma.length > 0 ||
							data.attack.length > 0 ||
							data.nist.length > 0) && (
							<div
								style={{
									display: "grid",
									gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
									gap: 20,
									marginBottom: 32,
								}}
							>
								<CVESeverityChart nvdChunks={data.nvd} />
								<SigmaLevelChart sigmaChunks={data.sigma} />
								<ATTACKTacticChart attackChunks={data.attack} />
								<NISTFamilyChart nistChunks={data.nist} />
							</div>
						)}

						{/* ── Cross-domain graph ── */}
						{data.indexedSources.length >= 2 && (
							<div style={{ marginBottom: 32 }}>
								<CrossDomainGraph
									attackChunks={data.attack}
									sigmaChunks={data.sigma}
									nvdChunks={data.nvd}
									nistChunks={data.nist}
								/>
							</div>
						)}

						{/* ── Quick links ── */}
						<div
							style={{
								borderTop: "2px solid var(--border-black)",
								paddingTop: 24,
								display: "flex",
								gap: 12,
								flexWrap: "wrap",
							}}
						>
							{data.indexedSources.map((src) => (
								<button
									key={src}
									onClick={() => router.push(`/threatlens/${src}`)}
									style={{
										background: "var(--bg-paper)",
										border: "2.5px solid var(--border-black)",
										color: DOMAIN_META[src]?.color ?? "var(--ink-black)",
										padding: "8px 18px",
										fontFamily: "var(--font-mono)",
										fontSize: "11px",
										fontWeight: 700,
										textTransform: "uppercase",
										letterSpacing: "0.04em",
										cursor: "pointer",
										boxShadow: "var(--shadow-layer-1)",
										transition: "box-shadow 0.15s",
									}}
									onMouseEnter={(e) => {
										(e.currentTarget as HTMLButtonElement).style.boxShadow = "var(--shadow-hover)";
									}}
									onMouseLeave={(e) => {
										(e.currentTarget as HTMLButtonElement).style.boxShadow = "var(--shadow-layer-1)";
									}}
								>
									Chat with {DOMAIN_META[src]?.label ?? src} →
								</button>
							))}
						</div>
					</>
				)}
			</main>

			{/* ── FOOTER ── */}
			<footer
				style={{
					padding: "20px 40px",
					borderTop: "2.5px solid var(--border-black)",
					background: "var(--bg-paper)",
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
					marginTop: 40,
				}}
			>
				<span
					style={{
						fontFamily: "var(--font-display)",
						fontWeight: 900,
						fontSize: "0.9rem",
						color: "var(--ink-medium)",
						textTransform: "uppercase",
						letterSpacing: "0.05em",
					}}
				>
					ThreatLens
				</span>
				<a
					href="https://github.com/OffensiveSage/ThreatLens"
					target="_blank"
					rel="noopener noreferrer"
					style={{ fontSize: "11px", color: "var(--ink-light)", fontFamily: "var(--font-mono)" }}
				>
					GitHub ↗
				</a>
			</footer>
		</div>
	);
}

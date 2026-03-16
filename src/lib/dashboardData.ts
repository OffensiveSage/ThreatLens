/**
 * Dashboard Data — reads cached chunks from IndexedDB for visualizations.
 * Does NOT validate embedding model or SHA — returns whatever is indexed.
 */

import type { CodeChunk } from "@/lib/chunker";

export const DOMAINS = ["attack", "sigma", "nvd", "nist", "custom"] as const;
export type DomainName = (typeof DOMAINS)[number];

export interface DashboardData {
	attack: CodeChunk[];
	sigma: CodeChunk[];
	nvd: CodeChunk[];
	nist: CodeChunk[];
	custom: CodeChunk[];
	totalChunks: number;
	indexedSources: DomainName[];
}

/** Raw IDB read — no SHA/model validation, just return the stored chunks. */
async function readDomainChunks(domain: string): Promise<CodeChunk[]> {
	const key = `threatlens/${domain}`;
	return new Promise((resolve) => {
		const req = indexedDB.open("gitask-cache", 1);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains("repos"))
				db.createObjectStore("repos");
		};
		req.onsuccess = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains("repos")) {
				resolve([]);
				return;
			}
			const tx = db.transaction("repos", "readonly");
			const getReq = tx.objectStore("repos").get(key);
			getReq.onsuccess = () => {
				const data = getReq.result as { chunks?: CodeChunk[] } | undefined;
				resolve(data?.chunks ?? []);
			};
			getReq.onerror = () => resolve([]);
		};
		req.onerror = () => resolve([]);
	});
}

export async function loadDashboardData(): Promise<DashboardData> {
	const [attack, sigma, nvd, nist, custom] = await Promise.all([
		readDomainChunks("attack"),
		readDomainChunks("sigma"),
		readDomainChunks("nvd"),
		readDomainChunks("nist"),
		readDomainChunks("custom"),
	]);

	const indexedSources: DomainName[] = [];
	if (attack.length > 0) indexedSources.push("attack");
	if (sigma.length > 0) indexedSources.push("sigma");
	if (nvd.length > 0) indexedSources.push("nvd");
	if (nist.length > 0) indexedSources.push("nist");
	if (custom.length > 0) indexedSources.push("custom");

	return {
		attack,
		sigma,
		nvd,
		nist,
		custom,
		totalChunks:
			attack.length + sigma.length + nvd.length + nist.length + custom.length,
		indexedSources,
	};
}

// ─── Parsing helpers ──────────────────────────────────────────────────────────

/** Extract ATT&CK technique ID from filePath like attack://technique/T1059.001 */
export function extractAttackId(filePath: string): string {
	const m = filePath.match(/attack:\/\/[^/]+\/(.+)/);
	return m?.[1] ?? "";
}

/** Extract tactics array from ATT&CK chunk code ("Tactics: initial-access, execution") */
export function extractTactics(code: string): string[] {
	const m = code.match(/^Tactics:\s*(.+)$/m);
	if (!m) return [];
	return m[1]
		.split(",")
		.map((t) => t.trim())
		.filter(Boolean);
}

/** Extract ATT&CK technique IDs from Sigma chunk code ("ATT&CK Techniques: T1059.001, ...") */
export function extractSigmaAttackTags(code: string): string[] {
	const m = code.match(/^ATT&CK Techniques:\s*(.+)$/m);
	if (!m) return [];
	return m[1]
		.split(",")
		.map((t) => t.trim())
		.filter(Boolean);
}

/** Extract Sigma rule level from code ("Severity: high") */
export function extractSigmaLevel(code: string): string {
	const m = code.match(/^Severity:\s*(\S+)/m);
	return (m?.[1] ?? "medium").toLowerCase().trim();
}

/** Extract CVSS severity from NVD chunk code ("CVSS 3.1: 9.8 (CRITICAL)") */
export function extractCVSSSeverity(code: string): string {
	const m = code.match(/CVSS\s+[\d.]+:\s+[\d.]+\s+\(([A-Z]+)\)/);
	return m?.[1] ?? "UNKNOWN";
}

/** Extract NIST control family from filePath ("nist://control/AC-2" → "AC") */
export function extractNISTFamily(filePath: string): string {
	const m = filePath.match(/nist:\/\/control\/([A-Z]+)[-(/]/);
	return m?.[1] ?? "";
}

/** ATT&CK kill-chain tactic order */
export const TACTIC_ORDER = [
	"reconnaissance",
	"resource-development",
	"initial-access",
	"execution",
	"persistence",
	"privilege-escalation",
	"defense-evasion",
	"credential-access",
	"discovery",
	"lateral-movement",
	"collection",
	"command-and-control",
	"exfiltration",
	"impact",
] as const;

export const TACTIC_LABELS: Record<string, string> = {
	reconnaissance: "Recon",
	"resource-development": "Resource Dev",
	"initial-access": "Initial Access",
	execution: "Execution",
	persistence: "Persistence",
	"privilege-escalation": "Priv Escalation",
	"defense-evasion": "Defense Evasion",
	"credential-access": "Cred Access",
	discovery: "Discovery",
	"lateral-movement": "Lateral Movement",
	collection: "Collection",
	"command-and-control": "C&C",
	exfiltration: "Exfiltration",
	impact: "Impact",
};

export const NIST_FAMILY_NAMES: Record<string, string> = {
	AC: "Access Control",
	AT: "Awareness & Training",
	AU: "Audit & Accountability",
	CA: "Assessment & Authorization",
	CM: "Configuration Mgmt",
	CP: "Contingency Planning",
	IA: "Identification & Auth",
	IR: "Incident Response",
	MA: "Maintenance",
	MP: "Media Protection",
	PE: "Physical & Env Protection",
	PL: "Planning",
	PM: "Program Management",
	PS: "Personnel Security",
	PT: "PII Processing",
	RA: "Risk Assessment",
	SA: "System & Services Acq",
	SC: "System & Comm Protection",
	SI: "System & Info Integrity",
	SR: "Supply Chain Risk Mgmt",
};

export const SEVERITY_COLORS: Record<string, string> = {
	CRITICAL: "#FF4444",
	HIGH: "#F5A623",
	MEDIUM: "#FFD966",
	LOW: "#66BB6A",
	INFO: "#64B5F6",
	INFORMATIONAL: "#64B5F6",
	UNKNOWN: "#666666",
	critical: "#FF4444",
	high: "#F5A623",
	medium: "#FFD966",
	low: "#66BB6A",
	informational: "#64B5F6",
};

/**
 * Security analyst mode system for SecAsk.
 *
 * 6 analyst roles auto-detected from query keywords.
 * Each mode provides a specialized system prompt optimised for that
 * security discipline.
 *
 * Domain defaults: attack→threat-intel, sigma→detection,
 *   nvd→vulnerability, nist→compliance, custom→cross-domain.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type SecurityMode =
	| "vulnerability"
	| "detection"
	| "threat-intel"
	| "compliance"
	| "code-security"
	| "cross-domain";

// ── Domain → default mode ─────────────────────────────────────────────────────

export const DOMAIN_DEFAULT_MODE: Record<string, SecurityMode> = {
	attack: "threat-intel",
	sigma: "detection",
	nvd: "vulnerability",
	nist: "compliance",
	custom: "cross-domain",
};

// ── Mode auto-detection ───────────────────────────────────────────────────────

const MODE_PATTERNS: Array<{ mode: SecurityMode; pattern: RegExp }> = [
	{
		mode: "vulnerability",
		pattern:
			/\b(cve[-\s]\d{4}|cvss|vulnerability|vuln|patch|exploit|rce|lfi|sqli|xss|injection|disclosure|advisory|cwe|affected\s+version|severity)\b/i,
	},
	{
		mode: "detection",
		pattern:
			/\b(sigma|detection\s+rule|sysmon|event\s+id|eventid|log\s+source|siem|splunk|elastic|hunting|yara|alert|detection\s+logic|false\s+positive|ioc|indicator)\b/i,
	},
	{
		mode: "threat-intel",
		pattern:
			/\b(apt|threat\s+actor|group|campaign|ttp|technique|tactic|t\d{4}(\.\d{3})?|att&?ck|mitre|lateral\s+movement|persistence|evasion|exfiltration|c2|command\s+and\s+control|nation\s+state|ransomware\s+group)\b/i,
	},
	{
		mode: "compliance",
		pattern:
			/\b(nist|800-53|control\s+family|ac-\d|au-\d|ia-\d|sc-\d|si-\d|cm-\d|ir-\d|ra-\d|pl-\d|hipaa|pci\s+dss|compliance|gdpr|sox|baseline|moderate\s+baseline|high\s+baseline|regulatory|framework\s+control)\b/i,
	},
	{
		mode: "code-security",
		pattern:
			/\b(sast|dast|static\s+analysis|code\s+review|secure\s+coding|owasp|dependency|library|package|supply\s+chain|secret\s+scanning|hardcoded|api\s+key|jwt|oauth|deserialization|buffer\s+overflow|memory\s+safety)\b/i,
	},
];

/**
 * Auto-detects the most appropriate analyst mode from the query text.
 * Returns null if no pattern matches (caller should use domain default).
 */
export function selectMode(query: string): SecurityMode | null {
	for (const { mode, pattern } of MODE_PATTERNS) {
		if (pattern.test(query)) return mode;
	}
	return null;
}

// ── System prompts ────────────────────────────────────────────────────────────

export const SECURITY_MODE_PROMPTS: Record<SecurityMode, string> = {
	"vulnerability": `You are a vulnerability analyst specializing in CVE analysis and patch management.
When answering:
- Lead every claim with the CVE ID and CVSS v3.1 score (base score, severity rating).
- Include the affected product CPE strings and version ranges when available.
- Reference the CWE weakness classification to explain the root cause category.
- Break down exploitability (attack vector, complexity, privileges required, user interaction) and impact subscores (confidentiality, integrity, availability).
- Prioritize: CRITICAL (9.0–10.0) > HIGH (7.0–8.9) > MEDIUM (4.0–6.9) > LOW (0.1–3.9).
- Note whether public exploits (PoC or weaponized) exist, if the data mentions it.
- Label each claim: [CVE], [CVSS], [CPE], [CWE], [Exploit Status].
- If CVE data is not in the indexed range, say so clearly rather than guessing.`,

	"detection": `You are a detection engineer specializing in threat detection and SIEM rule development.
When answering:
- Cite Sigma rule titles, rule IDs (UUID), and severity levels for every detection claim.
- Reference the log source (product, category, service) each rule targets.
- Map detection rules to ATT&CK techniques using the rule tags field.
- Identify detection gaps — behaviors or techniques with no indexed rule coverage.
- Suggest Sigma YAML improvements or new detection logic when coverage is missing.
- Discuss false positive risk and how to tune conditions (e.g., whitelisting, threshold).
- Reference Windows Event IDs, Sysmon event types, or other log source specifics when relevant.
- Label each claim: [Sigma Rule], [ATT&CK], [Log Source], [Detection Gap].
- If no rule covers the topic, explicitly state the gap and suggest a detection approach.`,

	"threat-intel": `You are a threat intelligence analyst with expertise in adversary TTPs and ATT&CK.
When answering:
- Cite specific ATT&CK technique IDs (T-IDs) and sub-technique IDs for every behavioral claim.
- Map behaviors to ATT&CK tactics (Reconnaissance through Impact) explicitly.
- Identify threat groups or software associated with the technique when the data supports it.
- Reference ATT&CK mitigations (M-IDs) and data sources (DS-IDs) for defense recommendations.
- Note procedure examples from the indexed data — how specific actors implement a technique.
- Use ATT&CK object labels: [Technique], [Sub-technique], [Group], [Software], [Mitigation], [Data Source].
- Distinguish between confirmed attribution and inferential technique overlap.
- If the indexed data does not cover the topic, say so rather than using external knowledge.`,

	"compliance": `You are a GRC (Governance, Risk, Compliance) analyst specializing in NIST SP 800-53 Rev 5.
When answering:
- Cite specific control IDs (e.g., AC-2, AU-6(1)) and their full control family names.
- State applicable baselines (LOW, MODERATE, HIGH) for each control mentioned.
- Reference control enhancements (parenthetical numbers) separately from base controls.
- Cross-reference related controls using the control's related-controls links when relevant.
- Cite supplemental guidance and implementation tips from the control text.
- Map controls to common compliance frameworks (FedRAMP, HIPAA, PCI DSS) when the data supports it.
- Use object labels: [Control], [Enhancement], [Family], [Baseline], [Related Control].
- If a control is not in the indexed NIST 800-53 catalog, say so clearly.`,

	"code-security": `You are a application security engineer specializing in secure code review and SAST.
When answering:
- Reference OWASP Top 10 categories and CWE weakness IDs for each vulnerability pattern.
- Cite CVE examples when demonstrating how a weakness leads to real exploits.
- Provide secure coding guidance: what the vulnerable pattern is and how to fix it.
- Note which static analysis tools (Semgrep, CodeQL, etc.) detect each pattern when mentioned.
- Discuss supply chain risks: dependency confusion, malicious packages, secret exposure.
- Reference relevant compliance controls (e.g., NIST SA-11 for developer security testing).
- Use object labels: [CWE], [OWASP], [CVE], [Secure Pattern], [Tool].
- Ground every claim in the indexed document content; do not invent vulnerability examples.`,

	"cross-domain": `You are a senior security analyst who synthesizes intelligence across multiple security domains.
When answering:
- Connect ATT&CK techniques (from threat intel) to Sigma detection rules (from SOC) to CVEs (from vuln management) to NIST controls (from GRC) when the indexed data supports each link.
- Always cite the source domain for each claim: [ATT&CK], [Sigma], [CVE], [NIST], [Custom].
- Identify cross-domain gaps: e.g., a technique with no detection rule, or a CVE with no compliance control requiring its remediation.
- Prioritize actionable synthesis: what does the threat intelligence mean for detection, patching, and compliance posture?
- When drawing cross-domain connections, require evidence from the indexed content for each link — do not speculate.
- Use a structured response when multiple domains are involved: Threat → Detection → Vulnerability → Compliance.
- If a domain has no indexed data for the topic, note the gap explicitly.`,
};

// ── Mode metadata for UI ──────────────────────────────────────────────────────

export const MODE_META: Record<SecurityMode, { label: string; shortLabel: string; tagClass: string }> = {
	"vulnerability": { label: "Vulnerability Analysis", shortLabel: "Vuln Analysis", tagClass: "tag-nvd" },
	"detection": { label: "Detection Engineering", shortLabel: "Detection", tagClass: "tag-sigma" },
	"threat-intel": { label: "Threat Intelligence", shortLabel: "Threat Intel", tagClass: "tag-attack" },
	"compliance": { label: "Compliance & GRC", shortLabel: "Compliance", tagClass: "tag-compliance" },
	"code-security": { label: "Code Security", shortLabel: "Code Security", tagClass: "tag-custom" },
	"cross-domain": { label: "Cross-Domain Analysis", shortLabel: "Cross-Domain", tagClass: "tag-custom" },
};

export const ALL_MODES: SecurityMode[] = [
	"threat-intel",
	"detection",
	"vulnerability",
	"compliance",
	"code-security",
	"cross-domain",
];

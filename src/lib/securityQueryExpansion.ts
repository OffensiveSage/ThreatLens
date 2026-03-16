/**
 * Security-focused query expansion for the SecAsk RAG pipeline.
 *
 * Two modes mirror queryExpansion.ts:
 *  - LLM-powered: generateSecurityQueryVariants — generates a technique-focused
 *    and a detection-focused variant from the user query.
 *  - Heuristic fallback: expandSecurityQuery — maps security keywords to ATT&CK
 *    technique IDs, log-source terms, and compliance control IDs.
 */

// ── Security term keyword map ─────────────────────────────────────────────────

const SECURITY_TERM_MAP: Record<string, string[]> = {
	// ATT&CK technique families
	"lateral movement": ["T1021", "T1047", "T1550", "lateral movement techniques"],
	"lateral": ["T1021", "T1047", "lateral movement techniques"],
	"phishing": ["T1566", "T1566.001", "T1566.002", "spearphishing", "phishing email"],
	"credential": ["T1003", "T1110", "T1555", "credential dumping", "password access"],
	"credential dumping": ["T1003", "T1003.001", "LSASS", "mimikatz", "credential access"],
	"privilege escalation": ["T1068", "T1548", "T1134", "privilege escalation techniques"],
	"persistence": ["T1053", "T1543", "T1547", "persistence techniques", "scheduled task"],
	"defense evasion": ["T1070", "T1562", "T1027", "obfuscation", "log clearing"],
	"discovery": ["T1082", "T1083", "T1018", "system discovery", "network enumeration"],
	"execution": ["T1059", "T1059.001", "T1059.003", "command execution", "script execution"],
	"powershell": ["T1059.001", "PowerShell execution", "powershell.exe", "PSExec"],
	"exfiltration": ["T1041", "T1048", "T1567", "data exfiltration", "data transfer"],
	"command and control": ["T1071", "T1095", "T1572", "C2", "beacon", "callback"],
	"c2": ["T1071", "T1095", "command and control", "beacon", "C2 channel"],
	"ransomware": ["T1486", "T1490", "data encrypted", "ransomware", "T1489"],
	"supply chain": ["T1195", "T1195.002", "software supply chain", "dependency confusion"],
	"injection": ["T1055", "T1055.001", "process injection", "DLL injection"],
	"dll": ["T1055.001", "T1574", "DLL injection", "DLL hijacking", "side-loading"],
	"mimikatz": ["T1003.001", "credential dumping", "LSASS dump", "sekurlsa"],
	"cobalt strike": ["T1071.001", "T1055", "beacon", "Cobalt Strike", "C2 framework"],
	"wmi": ["T1047", "WMI", "Windows Management Instrumentation", "wmiprvse"],
	"rdp": ["T1021.001", "Remote Desktop", "RDP brute force", "remote services"],
	// Detection / log source terms
	"detection": ["detection rule", "Sigma rule", "YARA rule", "log source", "event ID"],
	"sigma": ["Sigma rule", "log source", "detection rule", "sysmon", "windows security"],
	"yara": ["YARA rule", "malware detection", "file scanning", "pattern matching"],
	"sysmon": ["Sysmon", "event ID 1", "process creation", "network connection", "EventID"],
	"windows event": ["Windows Security Log", "EventID", "4624", "4688", "4720"],
	"log": ["log source", "event log", "audit log", "syslog", "SIEM"],
	"alert": ["detection rule", "alert condition", "threshold", "detection logic"],
	// Vulnerability terms
	"cve": ["CVE", "vulnerability", "CVSS", "patch", "exploit"],
	"vulnerability": ["CVE", "CVSS score", "CWE", "vulnerability", "patch"],
	"exploit": ["exploit", "exploitation", "CVE", "PoC", "proof of concept"],
	"patch": ["patch", "remediation", "fix", "vulnerability", "CVE"],
	"rce": ["remote code execution", "CVE", "CVSS 9", "RCE vulnerability"],
	"sql injection": ["SQL injection", "CWE-89", "CVE", "input validation"],
	"xss": ["cross-site scripting", "CWE-79", "XSS", "web vulnerability"],
	// Compliance / NIST terms
	"access control": ["AC", "AC-2", "AC-3", "AC-17", "access control", "authorization"],
	"audit": ["AU", "AU-2", "AU-6", "audit log", "accountability", "logging"],
	"authentication": ["IA", "IA-2", "IA-5", "multi-factor", "MFA", "identity"],
	"mfa": ["IA-2", "IA-5", "multi-factor authentication", "MFA", "two-factor"],
	"encryption": ["SC-8", "SC-28", "encryption", "cryptography", "data protection"],
	"incident response": ["IR", "IR-4", "IR-6", "incident", "response plan"],
	"risk": ["RA", "RA-3", "RA-5", "risk assessment", "vulnerability assessment"],
	"compliance": ["NIST 800-53", "compliance control", "regulatory", "framework"],
	"nist": ["NIST 800-53", "NIST control", "SP 800-53", "security control"],
	"hipaa": ["HIPAA", "AU-2", "AC-3", "SC-28", "healthcare compliance"],
	"pci": ["PCI DSS", "payment card", "SC-8", "AC-7", "compliance"],
};

const STOP_WORDS = new Set([
	"a", "an", "the", "is", "are", "was", "were", "be", "been",
	"have", "has", "had", "do", "does", "did", "will", "would",
	"could", "should", "may", "might", "must", "shall", "can",
	"this", "that", "these", "those", "it", "its",
	"what", "which", "who", "when", "where", "why", "how",
	"and", "or", "but", "not", "so", "for", "in", "on", "at",
	"to", "from", "of", "with", "by", "about", "i", "me", "my",
	"we", "our", "you", "your", "he", "she", "they", "them",
	"any", "all", "some", "show", "find", "list", "get", "give",
	"tell", "explain", "describe", "what", "help", "need", "want",
]);

/**
 * Heuristic security keyword expansion.
 * Checks multi-word phrases first, then single tokens.
 * Returns [originalQuery] or [originalQuery, expandedVariant].
 */
export function expandSecurityQuery(query: string): string[] {
	const lower = query.toLowerCase();

	// Try multi-word phrase matches first (longer matches win)
	const phraseEntries = Object.entries(SECURITY_TERM_MAP)
		.filter(([k]) => k.includes(" "))
		.sort((a, b) => b[0].length - a[0].length);

	for (const [phrase, expansions] of phraseEntries) {
		if (lower.includes(phrase)) {
			const extra = expansions.filter((e) => !lower.includes(e.toLowerCase())).join(" ");
			if (extra) return [query, `${query} ${extra}`];
		}
	}

	// Single-token matches
	const tokens = lower.match(/[a-z][a-z0-9]*/g) ?? [];
	const addedTerms: string[] = [];

	for (const token of tokens) {
		if (token.length < 3 || STOP_WORDS.has(token)) continue;
		const expansions = SECURITY_TERM_MAP[token];
		if (expansions) {
			for (const e of expansions) {
				if (!lower.includes(e.toLowerCase()) && !addedTerms.includes(e)) {
					addedTerms.push(e);
					if (addedTerms.length >= 6) break;
				}
			}
		}
		if (addedTerms.length >= 6) break;
	}

	if (addedTerms.length === 0) return [query];
	return [query, `${query} ${addedTerms.join(" ")}`];
}

/**
 * LLM-powered security query expansion.
 * Generates 2 variants:
 *  1. Technique/ATT&CK/TTP-focused
 *  2. Detection/log-source/event-ID-focused
 *
 * Falls back to [query] if LLM is not ready.
 */
export async function generateSecurityQueryVariants(
	query: string,
	priorMessages: Array<{ role: string; content: string }>
): Promise<string[]> {
	const trimmed = query.trim();
	if (!trimmed) return [trimmed];

	try {
		const { getLLMStatus, generateFull } = await import("./llm");
		if (getLLMStatus() !== "ready") return expandSecurityQuery(trimmed);

		const recentTurns = priorMessages
			.slice(-4)
			.map((m) => `${m.role}: ${m.content.slice(0, 200)}`)
			.join("\n");
		const contextBlock = recentTurns ? `\n\nRecent conversation:\n${recentTurns}` : "";

		const messages = [
			{
				role: "system" as const,
				content:
					"You expand search queries for a security knowledge base (ATT&CK, Sigma rules, CVEs, NIST controls). " +
					"Given a user query, output exactly 2 alternative phrasings on separate lines:\n" +
					"Line 1: Technique/ATT&CK/TTP-focused variant — use ATT&CK technique IDs (T-IDs), tactic names, or threat actor terminology.\n" +
					"Line 2: Detection/log-source/event-ID-focused variant — use Sigma field names, Windows Event IDs, log source types, SIEM query terms.\n" +
					"No numbering. No labels. No explanation. Two lines only.",
			},
			{
				role: "user" as const,
				content: `Query: "${trimmed}"${contextBlock}`,
			},
		];

		const response = (await generateFull(messages)).trim();
		if (!response) return [trimmed];

		const variants = response
			.split("\n")
			.map((l) => l.replace(/^\d+[\.\)]\s*/, "").trim())
			.filter((l) => l.length > 2 && l.length < 300);

		const seen = new Set<string>();
		const all: string[] = [];
		for (const v of [trimmed, ...variants]) {
			const key = v.toLowerCase();
			if (!seen.has(key)) {
				seen.add(key);
				all.push(v);
			}
		}
		return all.slice(0, 3); // original + max 2 security variants
	} catch {
		return expandSecurityQuery(trimmed);
	}
}

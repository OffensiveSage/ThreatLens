/**
 * Derive contextual security-focused query suggestions for a GitHub repo
 * by scanning already-indexed chunk metadata and content.
 *
 * No LLM call — purely conditional logic over file paths, languages, and content.
 * Returns exactly 5 suggestions (or falls back to generics if nothing matches).
 */

import type { CodeChunk } from "./chunker";

interface EmbeddedChunkLike {
  filePath: string;
  language?: string;
  code: string;
}

// ─── Candidate pool ──────────────────────────────────────────────────────────

// Language-specific candidates — keyed by detected language
const LANGUAGE_CANDIDATES: Record<string, string[]> = {
  python: [
    "Find SQL injection in Python database queries",
    "Check for insecure use of subprocess or eval in Python code",
    "Find Python files handling untrusted user input",
  ],
  javascript: [
    "Check for XSS vulnerabilities in JavaScript",
    "Find unsafe use of innerHTML or dangerouslySetInnerHTML",
    "Check for insecure client-side data storage",
  ],
  typescript: [
    "Check for XSS vulnerabilities in TypeScript",
    "Find unsafe use of innerHTML or dangerouslySetInnerHTML",
    "Check for insecure client-side data storage",
  ],
  swift: [
    "Find insecure API calls in Swift code",
    "Check for hardcoded credentials in Swift",
    "Find insecure data storage on iOS",
  ],
  java: [
    "Check for deserialization vulnerabilities in Java",
    "Find SQL injection risks in Java database code",
    "Check for insecure object deserialization",
  ],
  go: [
    "Find command injection risks in Go code",
    "Check for improper error handling exposing sensitive info",
    "Find insecure HTTP clients or TLS configurations in Go",
  ],
  rust: [
    "Check for unsafe blocks that could lead to memory issues",
    "Find error handling that exposes sensitive information",
  ],
  ruby: [
    "Check for SQL injection in Ruby ActiveRecord queries",
    "Find command injection risks in Ruby code",
  ],
  php: [
    "Check for SQL injection in PHP queries",
    "Find XSS vulnerabilities in PHP output",
    "Check for file inclusion vulnerabilities",
  ],
  csharp: [
    "Check for SQL injection in C# database queries",
    "Find insecure deserialization in C# code",
  ],
  cpp: [
    "Find buffer overflow risks in C++ code",
    "Check for unsafe memory operations",
  ],
};

// Filename-based candidates — triggered by path keywords
const FILENAME_CANDIDATES: Array<{ keywords: string[]; suggestion: string }> = [
  {
    keywords: ["auth", "login", "session", "signin", "oauth", "jwt", "token"],
    suggestion: "How does the authentication flow work? Is it secure?",
  },
  {
    keywords: ["api", "route", "endpoint", "router", "controller", "handler"],
    suggestion: "What API endpoints are exposed and are they properly protected?",
  },
  {
    keywords: ["config", "env", "setting", ".env", "secret", "credential"],
    suggestion: "Are there any hardcoded secrets or insecure configurations?",
  },
  {
    keywords: ["database", "db", "query", "model", "orm", "schema", "migration"],
    suggestion: "Check database queries for injection vulnerabilities",
  },
  {
    keywords: ["middleware", "cors", "csp", "helmet", "security"],
    suggestion: "How are security headers and middleware configured?",
  },
  {
    keywords: ["upload", "file", "attachment", "multipart"],
    suggestion: "Are file uploads validated and stored securely?",
  },
  {
    keywords: ["crypto", "hash", "cipher", "encrypt", "decrypt", "hmac"],
    suggestion: "Are cryptographic operations implemented correctly?",
  },
  {
    keywords: ["user", "account", "permission", "role", "access", "acl", "rbac"],
    suggestion: "How are user permissions and access controls enforced?",
  },
];

// Content-pattern candidates — triggered by strings found in chunk code
const CONTENT_CANDIDATES: Array<{ patterns: string[]; suggestion: string }> = [
  {
    patterns: ["process.exec", "child_process", "subprocess", "os.system", "Runtime.exec", "exec(", "spawn(", "execSync"],
    suggestion: "Find command injection risks",
  },
  {
    patterns: ["password", "passwd", "secret", "api_key", "apikey", "access_token", "private_key"],
    suggestion: "Check for exposed credentials or hardcoded secrets",
  },
  {
    patterns: ["http://", "http ://"],
    suggestion: "Find insecure HTTP connections that should use HTTPS",
  },
  {
    patterns: ["localStorage", "sessionStorage", "document.cookie", "NSUserDefaults"],
    suggestion: "Check for insecure client-side data storage",
  },
  {
    patterns: ["eval(", "Function(", "__import__(", "exec(", "compile("],
    suggestion: "Find dangerous use of dynamic code execution",
  },
  {
    patterns: ["innerHTML", "outerHTML", "document.write", "dangerouslySetInnerHTML"],
    suggestion: "Check for XSS risks in HTML rendering",
  },
  {
    patterns: ["pickle.load", "yaml.load(", "unserialize(", "ObjectInputStream", "readObject"],
    suggestion: "Check for insecure deserialization vulnerabilities",
  },
  {
    patterns: ["SSL_VERIFY_NONE", "verify=False", "InsecureRequestWarning", "TrustAllCerts", "checkCertificate(false)"],
    suggestion: "Find disabled TLS certificate validation",
  },
];

// Generic fallbacks — used when nothing specific matches
const FALLBACK_SUGGESTIONS = [
  "Find security vulnerabilities in this code",
  "Check for hardcoded secrets or API keys",
  "What authentication mechanism is used?",
  "Trace how user input flows through the app",
  "What external dependencies are used?",
];

// ─── Main function ────────────────────────────────────────────────────────────

/**
 * Scan indexed chunks and derive up to 5 contextual security query suggestions.
 * Runs synchronously — no I/O, no LLM.
 */
export function deriveRepoSuggestions(chunks: EmbeddedChunkLike[]): string[] {
  if (chunks.length === 0) return [...FALLBACK_SUGGESTIONS];

  const scored: Array<{ suggestion: string; priority: number }> = [];
  const seen = new Set<string>();

  function addCandidate(suggestion: string, priority: number) {
    if (!seen.has(suggestion)) {
      seen.add(suggestion);
      scored.push({ suggestion, priority });
    }
  }

  // ─── Pass 1: languages ───────────────────────────────────────────────────
  const detectedLanguages = new Set<string>();
  for (const chunk of chunks) {
    const lang = (chunk.language ?? "").toLowerCase();
    if (lang && LANGUAGE_CANDIDATES[lang]) {
      detectedLanguages.add(lang);
    }
  }
  for (const lang of detectedLanguages) {
    for (const s of LANGUAGE_CANDIDATES[lang]) {
      addCandidate(s, 10);
    }
  }

  // ─── Pass 2: filenames ───────────────────────────────────────────────────
  // Collect all unique lowercased file paths once
  const allPaths = [...new Set(chunks.map((c) => c.filePath.toLowerCase()))];
  for (const { keywords, suggestion } of FILENAME_CANDIDATES) {
    const matched = allPaths.some((p) => keywords.some((kw) => p.includes(kw)));
    if (matched) addCandidate(suggestion, 20);
  }

  // ─── Pass 3: content patterns ────────────────────────────────────────────
  // Sample up to 300 chunks to keep it fast
  const sample = chunks.length > 300 ? chunks.slice(0, 300) : chunks;
  const combinedContent = sample.map((c) => c.code).join("\n");

  for (const { patterns, suggestion } of CONTENT_CANDIDATES) {
    const matched = patterns.some((p) => combinedContent.includes(p));
    if (matched) addCandidate(suggestion, 30);
  }

  // ─── Pick 5 by priority order, fill with fallbacks ──────────────────────
  // Sort descending by priority (content > filename > language)
  scored.sort((a, b) => b.priority - a.priority);

  const result: string[] = scored.slice(0, 5).map((s) => s.suggestion);

  // Fill remaining slots from fallbacks
  for (const fb of FALLBACK_SUGGESTIONS) {
    if (result.length >= 5) break;
    if (!seen.has(fb)) result.push(fb);
  }

  return result.slice(0, 5);
}

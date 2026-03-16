<div align="center">

# SecAsk

**Ask your security stack anything.**

Browser-native RAG for MITRE ATT&CK, Sigma rules, CVEs, NIST 800-53, and your own docs.
Cross-domain retrieval. No server. No cloud. Everything runs in your tab.

---

[Quick Start](#quick-start) · [Data Sources](#data-sources) · [How It Works](#how-it-works) · [Stack](#stack) · [Contributing](#contributing)

</div>

---

## What is SecAsk?

SecAsk is a local-first security knowledge platform. You pick a data source — MITRE ATT&CK, a Sigma rule corpus, recent CVEs, NIST 800-53 controls, or files you upload yourself — and it indexes everything directly in your browser using WebGPU-accelerated embeddings. Then you chat against it.

No data ever leaves your machine. No API key required to get started (bring your own for cloud LLMs, or run a model locally with WebLLM). Indexes are cached in IndexedDB so subsequent loads are instant.

It's built for detection engineers, threat hunters, vulnerability analysts, and compliance teams who want to ask natural-language questions across security knowledge bases without wiring up a server.

---

## Data Sources

| Source | Route | What gets indexed |
|--------|-------|-------------------|
| **MITRE ATT&CK** | `/secask/attack` | All techniques, sub-techniques, tactics, threat groups, software, mitigations — from the official STIX bundle |
| **Sigma Rules** | `/secask/sigma` | Community detection rules from SigmaHQ (Windows, Linux, Cloud, Network) with ATT&CK tag mapping |
| **NVD / CVEs** | `/secask/nvd` | Recent CVEs from the NIST NVD API — CVSS v3 scores, CWE references, affected products |
| **NIST 800-53** | `/secask/nist` | All control families across LOW / MODERATE / HIGH baselines, control enhancements, supplemental guidance |
| **Custom Upload** | `/secask/custom` | Your own TXT, MD, JSON, YAML, or PDF files — pentest reports, runbooks, policies, anything |

> **First-time indexing** downloads public data directly in your browser (~15–80 MB depending on source). Subsequent loads are served from the local IndexedDB cache.

---

## What You Can Ask

```
"What ATT&CK techniques are used by APT29?"
"Show me Sigma rules that cover T1059.001 PowerShell execution"
"What critical CVEs affect Apache HTTP Server in the last 6 months?"
"Map NIST AC-2 to the relevant ATT&CK mitigations"
"Which detection rules in the index have no ATT&CK coverage?"
"What does control IA-5 require at the HIGH baseline?"
"Find all techniques in my uploaded threat model that overlap with indexed Sigma rules"
```

SecAsk will search across all indexed sources in a single query, automatically correlate ATT&CK IDs ↔ Sigma tags ↔ CVE references ↔ NIST controls, and ground every answer in citations back to the source chunks.

---

## Analyst Modes

SecAsk detects the right mode from your query automatically, or you can pin one manually from the input bar:

| Mode | Best for |
|------|----------|
| **Threat Hunt** | TTP lookups, adversary profiling, technique enumeration |
| **Detection** | Sigma rule coverage, detection gap analysis, rule quality |
| **Vuln Analysis** | CVE triage, CVSS scoring, patch prioritization, exposure scope |
| **Compliance** | NIST control mapping, baseline gaps, audit evidence |
| **Cross-Domain** | Questions that span multiple sources — the default |

---

## Quick Start

```bash
git clone <repo-url>
cd SecAsk
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

1. Click a source card (start with **ATT&CK** or **NIST** — they index fastest)
2. Wait for the progress bar to complete — this embeds the data locally
3. Start asking questions in natural language
4. Click **CONTEXT** in the header to see the raw chunks retrieved for any answer

To use a cloud LLM (faster, better reasoning), open **LLM Settings** and paste a Gemini or Groq API key. Keys are encrypted and never leave your browser.

---

## How It Works

```
Your query
     │
     ▼  Security query expansion
     │  Generate 3–5 semantic variants (e.g. "T1059" → ["PowerShell execution",
     │  "script interpreter abuse", "command-line interface", ...])
     │
     ▼  Multi-path hybrid search
     │  Vector similarity (all-MiniLM-L6-v2) + keyword BM25 across all variants
     │
     ▼  Cross-domain expansion
     │  Parse ATT&CK IDs, Sigma tags, NIST controls from top chunks
     │  Run a second-pass search to pull correlated chunks from other sources
     │
     ▼  Retrieval refinement  (cloud LLMs only)
     │  Re-rank results with a fast LLM call before final assembly
     │
     ▼  Safety scan
     │  Detect prompt injection in retrieved chunks
     │  Evaluate evidence coverage — block if grounding is too weak
     │
     ▼  Context assembly + analyst-mode prompt
     │  Trim to token budget, inject system prompt tuned for active mode
     │
     ▼  LLM generation
     │  Stream tokens from WebLLM (local) or Gemini / Groq (BYOK)
     │
     ▼  Citation correlation
        Ground the response back to source chunks
        Show citation chips with domain color coding
```

Everything from embedding to generation runs **in the browser tab** — no requests to any backend.

---

## Stack

| Layer | Technology |
|-------|------------|
| Framework | Next.js 16 · React 19 |
| Language | TypeScript |
| Embeddings | `@huggingface/transformers` — `all-MiniLM-L6-v2` via WebGPU / WASM fallback |
| Local LLM | `@mlc-ai/web-llm` — Llama, Qwen, Phi quantized models in-browser |
| Cloud LLM | Gemini API · Groq API — BYOK, keys stored via `byok-vault` (never sent anywhere) |
| Vector Store | Custom in-memory store + IndexedDB persistence via `entity-db` |
| Styling | Pure CSS · CSS variables · Papercut Layers design system · no Tailwind |
| Animations | Framer Motion |
| Icons | lucide-react |

---

## Design System

**Papercut Layers** — warm cream, hard ink shadows, sharp edges. Looks like something printed.

```
Background  #F5F0E8  — aged cream
Paper       #FFFDF7  — off-white card surfaces
Ink         #1A1A1A  — near-black text and borders
Accent      #5B7FA5  — info slate (links, metadata)

Shadows     3px 3px 0px #1A1A1A  — no blur, stacked layers
Radius      max 2px everywhere   — paper doesn't have soft corners
Fonts       Archivo Black (headings) · DM Sans (body) · JetBrains Mono (code)
```

No dark mode. Intentional — you should be able to read it in daylight.

---

## Project Structure

```
src/
├── app/
│   ├── page.tsx                    # Landing page — source cards + hero
│   ├── secask/[domain]/page.tsx    # Chat interface for each security source
│   └── globals.css                 # Full design system (~2000 lines)
├── components/
│   ├── SourceCard.tsx              # Landing source connector card
│   ├── ToastNotification.tsx       # Auto-dismiss toast
│   └── chat/                       # IndexingOverlay + shared chat components
└── lib/
    ├── connectors/                 # attack.ts · sigma.ts · nvd.ts · nist.ts · upload.ts
    ├── vectorStore.ts              # In-memory vector store + IndexedDB cache
    ├── search.ts                   # Multi-path hybrid search
    ├── securityModes.ts            # Analyst mode detection + system prompts
    ├── citationUtils.ts            # Grounded citation extraction
    ├── promptSafety.ts             # Injection scan + evidence coverage
    └── llm.ts                      # WebLLM + Gemini + Groq unified interface
```

---

## Adding a New Source

Each connector implements a simple interface:

```typescript
// src/lib/connectors/yourSource.ts
export async function indexYourSource(
  store: VectorStore,
  progress: (p: ConnectorProgress) => void,
  signal: AbortSignal
): Promise<void> {
  // 1. Fetch or receive data
  // 2. Chunk it
  // 3. Call store.addChunks(chunks) — embeddings happen automatically
}
```

Then add a route in `DOMAIN_META` inside `secask/[domain]/page.tsx` and a card on the landing page. That's it.

---

## Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org) — adversary tactics and techniques
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — open community detection rules
- [NIST NVD](https://nvd.nist.gov) — National Vulnerability Database API
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — security and privacy controls
- [GitAsk](https://github.com/babycommando/gitask) — the browser-native RAG foundation this is forked from

---

## Contributing

PRs and issues welcome. The connector pattern is designed to be extended — the hardest part of adding a new source is usually deciding how to chunk the data.

If you find a retrieval quality issue, open an issue with the query and what you expected. Cross-domain correlation is the trickiest part and always has room to improve.

---

## License

MIT

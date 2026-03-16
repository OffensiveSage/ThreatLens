# SecAsk — Complete Project Plan & Build Specification

## Table of Contents

1. Product Vision
2. Architecture Overview
3. Design System: Papercut Layers
4. Page Structure & Components
5. Data Connectors
6. Retrieval & Chat Engine
7. Implementation Roadmap
8. Claude CLI Prompt Reference

---

## 1. Product Vision

### What Is SecAsk?

SecAsk is a unified security knowledge platform built on top of the GitAsk codebase. It takes the same browser-native RAG architecture (local embeddings, hybrid search, IndexedDB persistence, BYOK LLM) and applies it to the security domain.

### The Problem

Security analysts juggle 6-8 disconnected tools during a single incident. They manually cross-reference MITRE ATT&CK, CVE databases, Sigma detection rules, compliance frameworks, and internal playbooks. Each source has a different interface, different search syntax, and different data format. The analyst is doing manual RAG in their head.

### The Solution

One conversational interface that indexes multiple security knowledge domains and retrieves across all of them simultaneously. The user connects their GitHub repo (just like GitAsk) for code security analysis, AND/OR indexes public security data sources (ATT&CK, NVD, Sigma Rules, NIST 800-53), AND/OR uploads their own documents (IR playbooks, policies, vendor advisories).

### Core Principles (Inherited from GitAsk)

- Browser-native: No server. Everything runs locally.
- Keys stay local: BYOK encrypted vault for external LLMs.
- Persistent: IndexedDB stores everything. Close the tab, reopen, resume.
- Fast setup: Click a button or paste a URL. That's it.

### Target Users

- SOC Analysts (incident investigation, threat hunting)
- Detection Engineers (rule coverage analysis, rule generation)
- GRC/Compliance Analysts (control mapping, gap analysis, audit prep)
- Penetration Testers (methodology lookup, vulnerability research)
- Security Engineers (code review, dependency auditing)

---

## 2. Architecture Overview

### What Stays from GitAsk (Zero or Minimal Changes)

| Component | Tech | Notes |
|-----------|------|-------|
| Embedding pipeline | @huggingface/transformers, all-MiniLM-L12-v2, WebGPU/WASM | Domain-agnostic, works on any text |
| Vector store | @babycommando/entity-db on IndexedDB | Handles persistence, binary quantization, hamming distance |
| Binary quantization | Uint32Array sign-bit packing | 32x memory savings |
| Hybrid search | Dense (hamming) + BM25 sparse + RRF fusion | Domain-agnostic retrieval |
| Multi-query expansion | CodeRAG-style | Swap code-focused expansions for security-focused ones |
| Cosine rerank | Matryoshka reranker on candidates | Works on any domain |
| CoVe self-verification | Chain-of-Verification loop | Critical for security accuracy |
| BYOK vault | Encrypted local key storage | Gemini/Groq support |
| WebLLM | @mlc-ai/web-llm, Qwen2-0.5B | Local inference, no server |
| Chat UI | React 19, Framer Motion, Markdown rendering | Multi-session support |
| Framework | Next.js 16, TypeScript | Full stack |

### What Changes

| Component | Change |
|-----------|--------|
| Ingestion layer | Replace GitHub-only fetch with multiple data source connectors |
| AST chunker | Keep for code repos. Add new chunkers for YAML (Sigma), JSON (ATT&CK, NVD), structured text (NIST), and prose (uploaded docs) |
| Multi-query expansion | Security-domain expansions instead of code-symbol expansions |
| Graph expansion | Replace import graph with security relationship graph (technique→rule, CVE→CPE, control→sub-control) |
| Prompt templates | Security-domain system prompts per module |
| Landing page | Replace "paste GitHub URL" with multi-source index panel |
| UI theme | Complete redesign: Papercut Layers neo-brutalism |

### Data Flow

```
[Data Sources]
  ├── GitHub Repo URL → AST Chunker → Embeddings → entity-db (tag: "repo")
  ├── ATT&CK Button → STIX JSON Parser → Embeddings → entity-db (tag: "attack")  
  ├── Sigma Button → YAML Parser → Embeddings → entity-db (tag: "sigma")
  ├── NVD Button → CVE JSON Parser → Embeddings → entity-db (tag: "nvd")
  ├── NIST Button → OSCAL JSON Parser → Embeddings → entity-db (tag: "compliance")
  └── Upload → PDF/MD/TXT Parser → Embeddings → entity-db (tag: "custom")

[Retrieval]
  Query → Multi-query expansion (security-focused)
       → Hybrid search across ALL tagged domains
       → RRF fusion
       → Cross-domain graph expansion
       → Cosine rerank
       → Top-k chunks with domain tags

[Generation]
  Context (with domain labels) → LLM (WebLLM or BYOK)
       → CoVe verification against indexed data
       → Cited, grounded response
```

### Cross-Domain Relationship Graph

The relationship graph (stored alongside vectors in entity-db) enables cross-domain retrieval hops:

- Sigma rule tags ATT&CK technique ID → pull technique description
- CVE references CPE string → pull other CVEs for same product
- ATT&CK group uses technique → pull Sigma rules tagged with that technique
- NIST control cross-references another control → pull related controls
- Code chunk imports vulnerable package → pull matching CVEs from NVD
- ATT&CK technique has data source → suggest detection approach

---

## 3. Design System: Papercut Layers

### Design Philosophy

The "Papercut Layers" theme makes the interface feel like physically stacked paper cutouts. Elements have visible depth through offset shadows. The aesthetic is neo-brutalist (thick borders, bold type, geometric shapes) but softened with warm cream tones, layered card depth, and subtle paper texture. It should feel like a security analyst's physical desk — layered documents, sticky notes, and marked-up reports — but digital and interactive.

### Color Palette

```css
:root {
  /* Base */
  --bg-cream:         #F5F0E8;    /* Main background — warm cream/parchment */
  --bg-paper:         #FFFDF7;    /* Card/paper surface — near white with warmth */
  --bg-paper-alt:     #EDE8DC;    /* Alternate paper layer — slightly darker cream */

  /* Ink & Borders */
  --ink-black:        #1A1A1A;    /* Primary text, thick borders */
  --ink-medium:       #4A4A4A;    /* Secondary text */
  --ink-light:        #8A8A82;    /* Tertiary/muted text */
  --border-black:     #1A1A1A;    /* Thick card borders (2-3px) */

  /* Severity / Status Accents */
  --critical-red:     #D94F3B;    /* Critical severity, active threats */
  --high-amber:       #E8943A;    /* High severity, warnings */
  --medium-gold:      #D4A843;    /* Medium severity */
  --low-sage:         #6B8F71;    /* Low severity, success, safe */
  --info-slate:       #5B7FA5;    /* Informational, links, neutral */

  /* Shadows (Papercut depth effect) */
  --shadow-layer-1:   3px 3px 0px #1A1A1A;     /* Primary card shadow — hard offset */
  --shadow-layer-2:   5px 5px 0px #1A1A1A;     /* Elevated card shadow */
  --shadow-layer-3:   7px 7px 0px #1A1A1A;     /* Highest elevation (modals, popovers) */
  --shadow-hover:     5px 5px 0px #1A1A1A;     /* Card hover state — grows */
  --shadow-subtle:    2px 2px 0px rgba(26,26,26,0.15); /* Subtle depth for small elements */

  /* Paper Texture */
  --texture-noise:    url('/textures/paper-grain.png'); /* Subtle paper grain overlay */
}
```

### Typography

```css
/* Display / Headlines — Bold, geometric, feels stamped */
--font-display: 'Archivo Black', 'Impact', sans-serif;

/* Body / UI — Clean, readable, slightly industrial */
--font-body: 'DM Sans', 'Helvetica Neue', sans-serif;

/* Code / Data — Monospace for technical content */
--font-mono: 'JetBrains Mono', 'Fira Code', monospace;

/* Scale */
--text-xs:    0.75rem;   /* 12px — labels, metadata */
--text-sm:    0.875rem;  /* 14px — secondary text */
--text-base:  1rem;      /* 16px — body text */
--text-lg:    1.25rem;   /* 20px — subheadings */
--text-xl:    1.5rem;    /* 24px — section headers */
--text-2xl:   2rem;      /* 32px — page titles */
--text-3xl:   2.75rem;   /* 44px — hero/landing title */
--text-hero:  4rem;      /* 64px — main hero text */
```

### Core Design Tokens

#### Cards (The "Paper" Element)

Every card looks like a piece of cut paper sitting on top of the background.

```css
.paper-card {
  background: var(--bg-paper);
  border: 2.5px solid var(--border-black);
  box-shadow: var(--shadow-layer-1);     /* 3px 3px hard offset */
  border-radius: 2px;                    /* Near-sharp corners — paper doesn't have rounded edges */
  padding: 1.25rem;
  position: relative;
  transition: box-shadow 0.15s ease, transform 0.15s ease;
}

.paper-card:hover {
  box-shadow: var(--shadow-hover);       /* Shadow grows on hover */
  transform: translate(-1px, -1px);      /* Card lifts slightly */
}

/* Stacked card effect — multiple layers visible behind */
.paper-card-stacked::before {
  content: '';
  position: absolute;
  top: 6px;
  left: 6px;
  right: -6px;
  bottom: -6px;
  background: var(--bg-paper-alt);
  border: 2.5px solid var(--border-black);
  border-radius: 2px;
  z-index: -1;
}

/* Double stacked — three layers visible */
.paper-card-stacked-double::after {
  content: '';
  position: absolute;
  top: 12px;
  left: 12px;
  right: -12px;
  bottom: -12px;
  background: var(--bg-cream);
  border: 2.5px solid var(--border-black);
  border-radius: 2px;
  z-index: -2;
}
```

#### Buttons

```css
.btn-primary {
  background: var(--ink-black);
  color: var(--bg-paper);
  border: 2.5px solid var(--border-black);
  box-shadow: var(--shadow-layer-1);
  padding: 0.625rem 1.25rem;
  font-family: var(--font-body);
  font-weight: 700;
  font-size: var(--text-sm);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-radius: 2px;
  cursor: pointer;
  transition: all 0.1s ease;
}

.btn-primary:hover {
  transform: translate(-1px, -1px);
  box-shadow: var(--shadow-layer-2);
}

.btn-primary:active {
  transform: translate(2px, 2px);
  box-shadow: none;                      /* Pressed flat — no shadow */
}

.btn-secondary {
  background: var(--bg-paper);
  color: var(--ink-black);
  border: 2.5px solid var(--border-black);
  box-shadow: var(--shadow-layer-1);
  /* Same padding, font, transition as primary */
}

.btn-accent {
  background: var(--critical-red);       /* Or any severity color */
  color: var(--bg-paper);
  border: 2.5px solid var(--border-black);
  box-shadow: var(--shadow-layer-1);
}
```

#### Tags / Badges (Domain Labels)

```css
.tag {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.625rem;
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  border: 2px solid var(--border-black);
  border-radius: 2px;
  box-shadow: var(--shadow-subtle);
}

.tag-attack    { background: #FFE0B2; }  /* Warm orange tint */
.tag-sigma     { background: #C8E6C9; }  /* Sage green tint */
.tag-nvd       { background: #FFCDD2; }  /* Soft red tint */
.tag-compliance{ background: #BBDEFB; }  /* Slate blue tint */
.tag-repo      { background: #E1BEE7; }  /* Muted purple tint */
.tag-custom    { background: #FFF9C4; }  /* Light gold tint */
```

#### Severity Indicators

```css
.severity-badge {
  font-family: var(--font-mono);
  font-weight: 800;
  font-size: var(--text-xs);
  padding: 0.2rem 0.5rem;
  border: 2px solid var(--border-black);
  border-radius: 2px;
  text-transform: uppercase;
}

.severity-critical { background: var(--critical-red); color: white; }
.severity-high     { background: var(--high-amber); color: white; }
.severity-medium   { background: var(--medium-gold); color: var(--ink-black); }
.severity-low      { background: var(--low-sage); color: white; }
.severity-info     { background: var(--info-slate); color: white; }
```

#### Input Fields

```css
.input-field {
  background: var(--bg-paper);
  border: 2.5px solid var(--border-black);
  padding: 0.75rem 1rem;
  font-family: var(--font-body);
  font-size: var(--text-base);
  border-radius: 2px;
  box-shadow: inset 2px 2px 0px rgba(26,26,26,0.08);  /* Inset shadow — pressed into paper */
  outline: none;
}

.input-field:focus {
  box-shadow: inset 2px 2px 0px rgba(26,26,26,0.08),
              0 0 0 3px var(--info-slate);  /* Focus ring */
}
```

#### The Chat Bubble

```css
.chat-user {
  background: var(--bg-paper-alt);
  border: 2px solid var(--border-black);
  border-radius: 2px;
  box-shadow: var(--shadow-layer-1);
  padding: 1rem;
  margin-left: 3rem;                     /* Right-aligned feel */
}

.chat-assistant {
  background: var(--bg-paper);
  border: 2px solid var(--border-black);
  border-radius: 2px;
  box-shadow: var(--shadow-layer-1);
  padding: 1rem;
  margin-right: 3rem;
}

/* Citation chip inside assistant message */
.citation-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.15rem 0.5rem;
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  background: var(--bg-cream);
  border: 1.5px solid var(--border-black);
  border-radius: 2px;
  cursor: pointer;
}
```

### Paper Texture Overlay

Apply a subtle noise/grain overlay to the main background to give it a paper feel:

```css
body::before {
  content: '';
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-image: var(--texture-noise);
  opacity: 0.04;                         /* Very subtle */
  pointer-events: none;
  z-index: 9999;
}
```

If no texture image is available, use a CSS noise generator or skip it — the cream background + hard shadows already carry the papercut feel.

### Animation Principles

- **Card entrance**: Slide up 8px + fade in, staggered by 50ms per card
- **Hover lift**: translate(-1px, -1px) + shadow grows — feels like picking up paper
- **Button press**: translate(2px, 2px) + shadow collapses to 0 — feels like stamping
- **Indexing progress**: A progress bar that fills like ink spreading across paper
- **Page transitions**: Cards slide in from bottom, staggered
- **No rounded corners anywhere**: Maximum 2px border-radius. Paper has sharp edges.

### Iconography

Use Lucide React icons (already available in GitAsk's stack). Style them with:
- 2px stroke weight (matches border thickness)
- var(--ink-black) color
- 20px default size

For domain-specific icons:
- ATT&CK: Shield icon
- Sigma: FileCode icon
- NVD: Bug icon
- NIST: ClipboardCheck icon
- Repo: GitBranch icon
- Custom: Upload icon

---

## 4. Page Structure & Components

### 4.1 Landing Page

```
┌─────────────────────────────────────────────────────────┐
│  HEADER: Logo (SecAsk) | GitHub link | Theme toggle     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  HERO (paper-card-stacked-double)               │    │
│  │                                                 │    │
│  │  "Ask your security stack anything."            │    │
│  │  (Archivo Black, var(--text-hero))              │    │
│  │                                                 │    │
│  │  Index any security data source in your         │    │
│  │  browser. Chat with it using your own AI.       │    │
│  │  Embeddings, retrieval, storage — all local.    │    │
│  │                                                 │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ── CONNECT YOUR SOURCES ──                             │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ GitHub   │ │ ATT&CK   │ │ Sigma    │ │ NVD      │  │
│  │ Repo     │ │          │ │ Rules    │ │ CVEs     │  │
│  │ [paste]  │ │ [index]  │ │ [index]  │ │ [index]  │  │
│  │ ○ none   │ │ ○ none   │ │ ○ none   │ │ ○ none   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│                                                         │
│  ┌──────────┐ ┌──────────┐                              │
│  │ NIST     │ │ Upload   │                              │
│  │ 800-53   │ │ Your Own │                              │
│  │ [index]  │ │ [browse] │                              │
│  │ ○ none   │ │ ○ none   │                              │
│  └──────────┘ └──────────┘                              │
│                                                         │
│  Each card shows status: ○ Not indexed | ● Indexed      │
│  (with chunk count and last indexed date)               │
│                                                         │
│  ── HOW IT WORKS ──                                     │
│                                                         │
│  [Three stacked paper cards showing the pipeline]       │
│  1. Choose your sources                                 │
│  2. Index in your browser (all local)                   │
│  3. Ask anything across all sources                     │
│                                                         │
│  ── TRY AN EXAMPLE ──                                   │
│                                                         │
│  [Pre-built example queries as clickable paper tags]    │
│  "What ATT&CK techniques use PowerShell?"               │
│  "Show Sigma rules for lateral movement"                │
│  "Does CVE-2024-3400 have detection coverage?"          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Indexing Page (Per Source)

When user clicks "Index" on a source card:

```
┌─────────────────────────────────────────────────────────┐
│  ← Back to Sources                                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  INDEXING: MITRE ATT&CK                         │    │
│  │                                                 │    │
│  │  ████████████████░░░░░░░░  67%                  │    │
│  │  "Embedding technique T1059.001..."             │    │
│  │                                                 │    │
│  │  Fetched: 847 objects                           │    │
│  │  Chunked: 623 / 847                             │    │
│  │  Embedded: 412 / 623                            │    │
│  │                                                 │    │
│  │  [Cancel]                                       │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Chat Interface

```
┌─────────────────────────────────────────────────────────┐
│  HEADER: SecAsk | [Sources: ●ATT&CK ●Sigma ○NVD]       │
│          | New Chat | Chat History                       │
├───────────────────┬─────────────────────────────────────┤
│                   │                                     │
│  SIDEBAR          │  CHAT AREA                          │
│                   │                                     │
│  Indexed Sources  │  ┌─────────────────────────────┐    │
│  ┌─────────┐     │  │  USER MESSAGE (paper-card)   │    │
│  │ ● ATT&CK│     │  │  "What techniques involve    │    │
│  │   623   │     │  │   scheduled tasks and how    │    │
│  │   chunks│     │  │   do I detect them?"         │    │
│  └─────────┘     │  └─────────────────────────────┘    │
│  ┌─────────┐     │                                     │
│  │ ● Sigma │     │  ┌─────────────────────────────┐    │
│  │   1,247 │     │  │  ASSISTANT (paper-card)      │    │
│  │   chunks│     │  │                             │    │
│  └─────────┘     │  │  Based on your indexed...   │    │
│                   │  │                             │    │
│  Chat Sessions    │  │  [ATT&CK] T1053.005...     │    │
│  ┌─────────┐     │  │  [Sigma] schtask_creation   │    │
│  │ Today   │     │  │                             │    │
│  │ Chat 1  │     │  │  Each claim has a citation  │    │
│  │ Chat 2  │     │  │  chip linking to source     │    │
│  └─────────┘     │  └─────────────────────────────┘    │
│                   │                                     │
│                   │  ┌─────────────────────────────┐    │
│                   │  │  [Ask a question...]  [Send]│    │
│                   │  └─────────────────────────────┘    │
│                   │                                     │
├───────────────────┴─────────────────────────────────────┤
│  FOOTER: Browser-native · No server · Keys stay local   │
└─────────────────────────────────────────────────────────┘
```

### 4.4 Source Detail Panel

When clicking a citation or a source tag, a slide-out panel shows the raw chunk:

```
┌──────────────────────────────────────┐
│  SOURCE: ATT&CK T1053.005           │  ← paper-card with shadow-layer-2
│  Domain: Enterprise                  │
│  Platform: Windows, Linux, macOS     │
│──────────────────────────────────────│
│                                      │
│  [Full technique description in a    │
│   scrollable paper-textured area     │
│   with monospace font for IDs and    │
│   body font for descriptions]        │
│                                      │
│  Related:                            │
│  [tag: Sigma] win_schtask_create     │
│  [tag: ATT&CK] T1053 (parent)       │
│  [tag: NVD] CVE-2023-XXXXX          │
│                                      │
│  [Close]                             │
└──────────────────────────────────────┘
```

---

## 5. Data Connectors

### 5.1 GitHub Repo Connector (Inherited from GitAsk)

- **Source**: GitHub API (public repos, private with token)
- **Parser**: tree-sitter WASM AST chunker (already built)
- **Chunk strategy**: Functions, classes, methods as boundaries
- **Tag**: "repo"
- **Changes needed**: None. This is GitAsk's core functionality.

### 5.2 MITRE ATT&CK Connector

- **Source**: https://github.com/mitre/cti (STIX 2.1 JSON bundles)
  - `enterprise-attack/enterprise-attack.json`
  - `mobile-attack/mobile-attack.json`
  - `ics-attack/ics-attack.json`
- **Parser**: JSON → extract objects by type
- **Chunk strategy**: One chunk per object (technique, group, software, mitigation, data source)
- **Metadata per chunk**:
  - `type`: technique | group | software | mitigation | data-source
  - `attack_id`: T1059.001, G0016, S0154, etc.
  - `name`: Human-readable name
  - `tactics`: Array of tactic names
  - `platforms`: Array of platforms
  - `data_sources`: Array of data source names
  - `related_ids`: Array of related ATT&CK IDs (for graph expansion)
- **Relationships**: Parse STIX relationship objects to build cross-reference graph
- **Tag**: "attack"

### 5.3 Sigma Rules Connector

- **Source**: https://github.com/SigmaHQ/sigma (YAML files in `rules/` directory)
- **Parser**: YAML parser
- **Chunk strategy**: One chunk per rule file
- **Metadata per chunk**:
  - `rule_id`: Sigma rule UUID
  - `title`: Rule title
  - `status`: stable | test | experimental
  - `level`: critical | high | medium | low | informational
  - `logsource_product`: windows, linux, etc.
  - `logsource_service`: sysmon, security, etc.
  - `attack_tags`: Array of ATT&CK technique IDs (from rule tags)
  - `detection_logic`: The detection YAML block as text (for display)
- **Relationships**: `attack_tags` connect to ATT&CK technique chunks
- **Tag**: "sigma"

### 5.4 NVD/CVE Connector

- **Source**: NVD REST API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
  - Supports date range, keyword, CPE filters
  - Rate limit: 5 requests per 30 seconds (without API key), 50 with key
- **Parser**: JSON → extract CVE items
- **Chunk strategy**: One chunk per CVE
- **Metadata per chunk**:
  - `cve_id`: CVE-YYYY-NNNNN
  - `description`: English description text
  - `cvss_score`: Numeric score (from v3.1 or v2.0)
  - `cvss_severity`: CRITICAL | HIGH | MEDIUM | LOW
  - `cvss_vector`: CVSS vector string
  - `cpe_affected`: Array of CPE strings (affected products)
  - `references`: Array of reference URLs
  - `published_date`: ISO date
  - `exploit_available`: Boolean (from CISA KEV cross-reference)
- **Relationships**: CPE strings connect CVEs for the same product
- **Tag**: "nvd"
- **Note**: Allow user to specify filters (date range, keyword, product) to avoid indexing the entire NVD (200k+ CVEs)

### 5.5 NIST 800-53 / Compliance Connector

- **Source**: https://github.com/usnistgov/oscal-content (OSCAL JSON format)
  - NIST 800-53 Rev 5 catalog
  - Potentially add CIS Controls, ISO 27001 in future
- **Parser**: OSCAL JSON → extract controls
- **Chunk strategy**: One chunk per control (including enhancement/sub-control)
- **Metadata per chunk**:
  - `control_id`: AC-2, AC-2(1), AU-6, etc.
  - `family`: Access Control, Audit, etc.
  - `title`: Control title
  - `priority`: P1, P2, P3
  - `baseline`: LOW | MODERATE | HIGH (which baselines include this control)
  - `related_controls`: Array of cross-referenced control IDs
- **Relationships**: `related_controls` for graph expansion
- **Tag**: "compliance"

### 5.6 Custom Upload Connector

- **Source**: User-uploaded files (drag-and-drop)
- **Supported formats**: PDF (via pdf.js), Markdown, plain text, JSON, YAML
- **Parser**: Format-specific text extraction
- **Chunk strategy**: Text splitting with overlap (512 tokens, 64 token overlap) since these are unstructured prose
- **Metadata per chunk**:
  - `filename`: Original filename
  - `page_number`: For PDFs
  - `chunk_index`: Position in document
- **Tag**: "custom"

---

## 6. Retrieval & Chat Engine

### 6.1 Security-Focused Multi-Query Expansion

Replace GitAsk's code-symbol expansion with security-domain expansions:

```
Original: "How do I detect lateral movement via WMI?"

Expansion 1 (technique-focused):
"lateral movement WMI Windows Management Instrumentation T1047 remote execution"

Expansion 2 (detection-focused):
"Sigma rule YARA detection WMI process creation wmic.exe wmiprvse.exe event ID 4648"
```

The expansion strategy should be configurable per query type:
- If query mentions a CVE → expand with product names, affected versions
- If query mentions detection → expand with log source names, event IDs
- If query mentions compliance → expand with control family names, requirement keywords
- If query mentions a threat actor → expand with known technique IDs, tool names

### 6.2 Security-Domain Prompt Templates

```
[System Prompt: Vulnerability Analysis Mode]
You are a security vulnerability analyst. You have access to indexed CVE data, 
ATT&CK techniques, and Sigma detection rules. When answering:
- Cite specific CVE IDs, CVSS scores, and affected products
- Map vulnerabilities to ATT&CK techniques where applicable
- Suggest detection rules from indexed Sigma data
- Prioritize by exploitability and impact
- Always cite the source domain [NVD], [ATT&CK], [Sigma] for each claim

[System Prompt: Threat Intelligence Mode]
You are a threat intelligence analyst. Given indexed ATT&CK data and threat reports:
- Map observed behaviors to specific ATT&CK techniques with IDs
- Identify potential threat groups based on technique overlap
- Suggest detection and mitigation strategies
- Cross-reference with indexed Sigma rules for detection coverage

[System Prompt: Detection Engineering Mode]
You are a detection engineer. Given indexed Sigma rules and ATT&CK techniques:
- Analyze detection coverage against specific techniques
- Identify gaps where no Sigma rule exists
- Suggest new detection rules with proper Sigma YAML syntax
- Map rules to ATT&CK techniques for coverage tracking

[System Prompt: Compliance Analysis Mode]
You are a GRC analyst. Given indexed compliance frameworks and uploaded policies:
- Map controls to specific requirements with control IDs
- Identify coverage gaps between policies and framework requirements
- Suggest implementation guidance for unmet controls
- Cross-reference related controls within the framework

[System Prompt: Code Security Mode]
You are a security code reviewer. Given the indexed codebase:
- Identify potential vulnerabilities (injection, auth bypass, IDOR, etc.)
- Trace data flows from user input to sensitive sinks
- Check for hardcoded secrets and insecure configurations
- Map findings to CWE IDs and suggest remediation
- If NVD is indexed, cross-reference dependencies with known CVEs

[System Prompt: Cross-Domain Mode (Default)]
You are a security analyst with access to multiple knowledge domains: 
ATT&CK techniques, Sigma detection rules, CVE data, compliance frameworks, 
and potentially a code repository. Synthesize across all available domains to 
give comprehensive, cited answers. Tag each claim with its source domain.
```

### 6.3 Cross-Domain Graph Expansion

When a retrieved chunk from one domain has a relationship to another domain, automatically pull the related chunk:

```javascript
// Pseudocode for cross-domain expansion
function expandCrossDomain(chunk) {
  const related = [];
  
  // Sigma rule → ATT&CK technique
  if (chunk.tag === 'sigma' && chunk.metadata.attack_tags) {
    for (const techniqueId of chunk.metadata.attack_tags) {
      related.push(findChunkByMetadata('attack', 'attack_id', techniqueId));
    }
  }
  
  // ATT&CK technique → Sigma rules
  if (chunk.tag === 'attack' && chunk.metadata.type === 'technique') {
    related.push(...findChunksByMetadata('sigma', 'attack_tags', chunk.metadata.attack_id));
  }
  
  // CVE → ATT&CK (via CWE mapping or keyword matching)
  if (chunk.tag === 'nvd') {
    // Map common vulnerability types to ATT&CK techniques
    related.push(...mapCVEtoATTACK(chunk));
  }
  
  // Repo dependency → NVD CVEs
  if (chunk.tag === 'repo' && chunk.metadata.imports) {
    related.push(...findCVEsForPackage(chunk.metadata.imports));
  }
  
  return related;
}
```

---

## 7. Implementation Roadmap

### Phase 1: Fork & Retheme (Week 1)

**Goal**: GitAsk running with the Papercut Layers theme and SecAsk branding.

Tasks:
- [ ] Fork FloareDor/gitask
- [ ] Replace all GitAsk branding with SecAsk
- [ ] Implement Papercut Layers CSS design system (colors, typography, cards, buttons, shadows)
- [ ] Add paper texture overlay to background
- [ ] Restyle the chat interface with paper-card messages and citation chips
- [ ] Restyle the landing page layout (keep GitHub URL input for now)
- [ ] Import Google Fonts: Archivo Black, DM Sans, JetBrains Mono
- [ ] Verify all existing GitAsk functionality still works with new theme

### Phase 2: ATT&CK Connector (Week 2)

**Goal**: Users can index MITRE ATT&CK and ask questions about techniques, groups, and mitigations.

Tasks:
- [ ] Build ATT&CK fetcher (pull STIX JSON from GitHub)
- [ ] Build STIX JSON parser (extract techniques, groups, software, mitigations)
- [ ] Build relationship graph builder (technique→group, technique→mitigation, etc.)
- [ ] Add "Index ATT&CK" button to landing page
- [ ] Add ATT&CK-specific multi-query expansion
- [ ] Add threat intelligence system prompt
- [ ] Add domain tag ("attack") to entity-db storage
- [ ] Test with sample queries

### Phase 3: Sigma Rules Connector (Week 3)

**Goal**: Users can index Sigma rules and query detection coverage. Cross-domain retrieval with ATT&CK.

Tasks:
- [ ] Build Sigma fetcher (pull YAML files from SigmaHQ GitHub)
- [ ] Build YAML parser (extract rule metadata, detection logic, tags)
- [ ] Build ATT&CK tag linker (connect Sigma rules to ATT&CK techniques via tags)
- [ ] Add "Index Sigma Rules" button to landing page
- [ ] Add detection engineering system prompt
- [ ] Implement cross-domain graph expansion (Sigma ↔ ATT&CK)
- [ ] Test cross-domain queries ("What Sigma rules cover T1053?")

### Phase 4: NVD Connector (Week 4)

**Goal**: Users can index CVEs and cross-reference with ATT&CK and Sigma.

Tasks:
- [ ] Build NVD API fetcher (with date range/keyword/product filters)
- [ ] Build CVE JSON parser (extract descriptions, CVSS, CPEs, references)
- [ ] Handle rate limiting (queue with delays)
- [ ] Add "Index NVD" button with filter options to landing page
- [ ] Add vulnerability analysis system prompt
- [ ] Implement CVE→ATT&CK mapping for cross-domain expansion
- [ ] Test with sample CVE queries

### Phase 5: Compliance + Upload (Week 5)

**Goal**: Full platform with all connectors operational.

Tasks:
- [ ] Build NIST 800-53 OSCAL fetcher and parser
- [ ] Add "Index NIST 800-53" button to landing page
- [ ] Build custom upload handler (PDF, MD, TXT, JSON, YAML)
- [ ] Add PDF text extraction (pdf.js)
- [ ] Add compliance analysis system prompt
- [ ] Add cross-domain mode as default prompt
- [ ] Implement file drag-and-drop UI

### Phase 6: Polish & Ship (Week 6)

**Goal**: Production-ready, documented, deployed.

Tasks:
- [ ] Landing page with "How it Works" animated pipeline diagram
- [ ] Example queries section with pre-built demos
- [ ] Source status indicators (indexed/not indexed with chunk counts)
- [ ] Performance optimization (lazy loading connectors, batch embedding)
- [ ] Mobile responsive layout
- [ ] README with screenshots, architecture diagram, quick start
- [ ] Deploy to Vercel
- [ ] Metrics / ablation page (like GitAsk has)

---

## 8. Claude CLI Prompt Reference

When handing this to Claude CLI for implementation, use this as the system context. Copy the relevant section for each task.

### For Theme Implementation

```
I'm building SecAsk, a security knowledge RAG platform forked from GitAsk 
(https://github.com/FloareDor/gitask). The tech stack is Next.js 16, React 19, 
TypeScript, Tailwind CSS, Framer Motion.

I need to implement the "Papercut Layers" design system. Here are the specs:

THEME: Neo-brutalism + papercut/stacked paper aesthetic
- Background: Warm cream (#F5F0E8)
- Cards: Near-white (#FFFDF7) with 2.5px black borders and hard-offset shadows (3px 3px 0px #1A1A1A)
- Stacked card effect: ::before pseudo-element creates a second paper layer visible behind
- Buttons: Black fill or white fill, thick borders, hard shadows, press-flat on :active
- Typography: Archivo Black for headlines, DM Sans for body, JetBrains Mono for code/data
- Border radius: 2px maximum everywhere (paper has sharp edges)
- Hover: Cards lift (translate -1px -1px) and shadow grows
- Severity colors: Red (#D94F3B), Amber (#E8943A), Gold (#D4A843), Sage (#6B8F71), Slate (#5B7FA5)
- Domain tags: Color-coded backgrounds with black borders (ATT&CK=orange, Sigma=green, NVD=red, Compliance=blue)
- Paper texture: Subtle noise overlay at 4% opacity on body

[Then paste the specific CSS from Section 3 of this document]
```

### For Connector Implementation

```
I'm building a data connector for [ATT&CK / Sigma / NVD / NIST] in SecAsk.

The existing GitAsk codebase uses:
- @babycommando/entity-db on IndexedDB for vector storage
- @huggingface/transformers with all-MiniLM-L12-v2 for embeddings
- Binary quantization with Uint32Array packing

I need to:
1. Fetch data from [source URL]
2. Parse [format] into chunks with metadata
3. Embed each chunk using the existing embedding pipeline
4. Store in entity-db with domain tag "[tag]"
5. Build relationship graph entries for cross-domain expansion

[Then paste the specific connector spec from Section 5 of this document]
```

---

## Appendix: Key URLs

| Resource | URL |
|----------|-----|
| GitAsk repo (fork source) | https://github.com/FloareDor/gitask |
| MITRE ATT&CK STIX data | https://github.com/mitre/cti |
| SigmaHQ rules | https://github.com/SigmaHQ/sigma |
| NVD API v2.0 | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| NIST OSCAL content | https://github.com/usnistgov/oscal-content |
| OSV vulnerability database | https://osv.dev/docs/ |
| CISA KEV (Known Exploited Vulns) | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Archivo Black font | https://fonts.google.com/specimen/Archivo+Black |
| DM Sans font | https://fonts.google.com/specimen/DM+Sans |
| JetBrains Mono font | https://fonts.google.com/specimen/JetBrains+Mono |

---

*SecAsk: Ask your security stack anything. Browser-native. No server. Keys stay local.*

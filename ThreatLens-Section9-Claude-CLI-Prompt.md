# ThreatLens — Section 9: Hybrid Agentic Security Pipeline

## Context

ThreatLens currently uses pure RAG for all analysis, including code security. The problem: code analysis via RAG is inconsistent because random chunks get retrieved each time, and the LLM only sees fragments through a keyhole. The same query on the same repo produces different results.

The fix: Replace the RAG approach for code analysis with a structured agentic pipeline. Keep RAG for knowledge bases (ATT&CK, Sigma, NVD, NIST) where retrieval makes sense. Use Groq/Gemini (BYOK) for all LLM calls — no local WebLLM needed.

## Architecture Change

### Before (Pure RAG)
```
Every query → retrieve random chunks → send to LLM → inconsistent output
```

### After (Hybrid)
```
Knowledge queries (ATT&CK, Sigma, NVD, NIST) → RAG (existing pipeline, keep as is)
Code security scans → 6-step agentic pipeline (new, described below)
Mixed queries → agentic pipeline results + RAG cross-reference
```

The existing RAG pipeline for knowledge bases stays UNTOUCHED. Only code analysis gets the new pipeline.

## The 6-Step Agentic Pipeline

This pipeline runs when:
- User clicks any quick action button (Scan Vulnerabilities, Check Dependencies, Find Secrets, Map Attack Surface, Security Improvements)
- User asks a code security question and a repo is indexed
- Mode detection returns "code-security"

### Step 1: INVENTORY (Deterministic — No LLM)

Parse the indexed repo to build a structured map of the codebase. This uses the chunks already stored in entity-db from the repo connector.

```javascript
async function buildInventory(repoChunks) {
  const inventory = {
    totalFiles: 0,
    languages: {},
    entryPoints: [],
    packageFiles: [],
    configFiles: [],
    authFiles: [],
    apiFiles: [],
    allFiles: [],
  };

  const fileMap = new Map(); // filename → chunk contents combined

  for (const chunk of repoChunks) {
    const filename = chunk.metadata?.filename || '';
    const content = chunk.content || '';

    // Combine chunks from the same file
    if (!fileMap.has(filename)) {
      fileMap.set(filename, { filename, content: '', language: chunk.metadata?.language || 'unknown' });
    }
    fileMap.get(filename).content += '\n' + content;
  }

  for (const [filename, file] of fileMap) {
    inventory.totalFiles++;
    inventory.allFiles.push({ filename, language: file.language, size: file.content.length });

    // Count languages
    const lang = file.language;
    inventory.languages[lang] = (inventory.languages[lang] || 0) + 1;

    const lower = filename.toLowerCase();

    // Identify package/dependency files
    if (['package.json', 'requirements.txt', 'go.mod', 'cargo.toml', 'gemfile',
         'podfile', 'build.gradle', 'pom.xml', 'composer.json', 'package.swift',
         'pubspec.yaml', 'mix.exs'].some(pkg => lower.endsWith(pkg))) {
      inventory.packageFiles.push(filename);
    }

    // Identify config files
    if (lower.includes('config') || lower.includes('.env') || lower.includes('settings') ||
        lower.includes('docker') || lower.includes('nginx') || lower.includes('.yml') ||
        lower.includes('.yaml') || lower.includes('.toml') || lower.includes('.ini')) {
      inventory.configFiles.push(filename);
    }

    // Identify auth-related files
    if (lower.includes('auth') || lower.includes('login') || lower.includes('session') ||
        lower.includes('token') || lower.includes('oauth') || lower.includes('jwt') ||
        lower.includes('password') || lower.includes('credential') || lower.includes('permission')) {
      inventory.authFiles.push(filename);
    }

    // Identify API/route files
    if (lower.includes('route') || lower.includes('api') || lower.includes('endpoint') ||
        lower.includes('controller') || lower.includes('handler') || lower.includes('view') ||
        lower.includes('servlet') || lower.includes('resolver')) {
      inventory.apiFiles.push(filename);
    }

    // Identify entry points
    if (lower.includes('main') || lower.includes('index') || lower.includes('app') ||
        lower.includes('server') || lower.includes('startup') || lower === 'manage.py') {
      inventory.entryPoints.push(filename);
    }
  }

  return { inventory, fileMap };
}
```

This is fully deterministic. Same repo = same inventory every time.

### Step 2: DEPENDENCY AUDIT (Deterministic + NVD Cross-Reference)

Parse package files and check for known vulnerable dependencies.

```javascript
async function auditDependencies(fileMap, nvdIndexed) {
  const findings = [];

  // Find and parse package files
  for (const [filename, file] of fileMap) {
    const lower = filename.toLowerCase();

    // package.json (JavaScript/TypeScript)
    if (lower.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };
        for (const [name, version] of Object.entries(allDeps)) {
          findings.push({
            type: 'dependency',
            package: name,
            version: version,
            file: filename,
            ecosystem: 'npm',
          });
        }
      } catch (e) { /* malformed JSON, skip */ }
    }

    // requirements.txt (Python)
    if (lower.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*([=<>!~]+.+)?/);
        if (match) {
          findings.push({
            type: 'dependency',
            package: match[1],
            version: match[2] || 'unspecified',
            file: filename,
            ecosystem: 'pip',
          });
        }
      }
    }

    // go.mod (Go)
    if (lower.endsWith('go.mod')) {
      const requireRegex = /require\s+\(\s*([\s\S]*?)\)/g;
      const match = requireRegex.exec(file.content);
      if (match) {
        const lines = match[1].split('\n');
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 2) {
            findings.push({
              type: 'dependency',
              package: parts[0],
              version: parts[1],
              file: filename,
              ecosystem: 'go',
            });
          }
        }
      }
    }

    // Add more parsers for Cargo.toml, Gemfile, Podfile, etc. as needed
  }

  // Cross-reference with NVD if indexed
  if (nvdIndexed) {
    const nvdChunks = await getChunksByTag('nvd');
    for (const dep of findings) {
      // Search NVD chunks for matching package name
      const matchingCVEs = nvdChunks.filter(cve => {
        const desc = (cve.metadata?.description || '').toLowerCase();
        const cpes = (cve.metadata?.cpe_affected || []).join(' ').toLowerCase();
        const pkgLower = dep.package.toLowerCase();
        return desc.includes(pkgLower) || cpes.includes(pkgLower);
      });

      if (matchingCVEs.length > 0) {
        dep.cves = matchingCVEs.map(c => ({
          id: c.metadata.cve_id,
          severity: c.metadata.cvss_severity,
          score: c.metadata.cvss_score,
          description: c.metadata.description?.substring(0, 200),
        }));
        dep.vulnerable = true;
      }
    }
  }

  return findings;
}
```

Deterministic. Same deps + same NVD index = same results.

### Step 3: PATTERN SCAN (Deterministic — Regex-Based)

Scan ALL code for known dangerous patterns. No LLM involved.

```javascript
function patternScan(fileMap) {
  const findings = [];

  const patterns = [
    // Hardcoded Secrets
    {
      name: 'Hardcoded API Key',
      severity: 'CRITICAL',
      category: 'secrets',
      regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,})['"`]/gi,
    },
    {
      name: 'Hardcoded Password',
      severity: 'CRITICAL',
      category: 'secrets',
      regex: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]/gi,
    },
    {
      name: 'Hardcoded Token/Secret',
      severity: 'CRITICAL',
      category: 'secrets',
      regex: /(?:secret|token|private[_-]?key|access[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-\/.+]{16,})['"`]/gi,
    },
    {
      name: 'AWS Access Key',
      severity: 'CRITICAL',
      category: 'secrets',
      regex: /AKIA[0-9A-Z]{16}/g,
    },
    {
      name: 'Private Key File',
      severity: 'CRITICAL',
      category: 'secrets',
      regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
    },

    // Injection
    {
      name: 'Potential SQL Injection',
      severity: 'HIGH',
      category: 'injection',
      regex: /(?:execute|query|raw|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[\s\S]*?\$\{|(?:execute|query|raw|exec)\s*\(\s*(?:["']?\s*\+|f['"])/gi,
    },
    {
      name: 'SQL String Concatenation',
      severity: 'HIGH',
      category: 'injection',
      regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    },
    {
      name: 'Command Injection Risk',
      severity: 'HIGH',
      category: 'injection',
      regex: /(?:exec|spawn|system|popen|subprocess\.call|subprocess\.run|os\.system|Process\.run|child_process)\s*\(/gi,
    },
    {
      name: 'eval() Usage',
      severity: 'HIGH',
      category: 'injection',
      regex: /\beval\s*\(/g,
    },

    // Authentication
    {
      name: 'Default Credentials',
      severity: 'HIGH',
      category: 'auth',
      regex: /(?:admin[/:]\s*admin|root[/:]\s*root|test[/:]\s*test|user[/:]\s*(?:pass|password)|default[_-]?(?:password|pass|user))/gi,
    },
    {
      name: 'Weak Hash Algorithm',
      severity: 'MEDIUM',
      category: 'crypto',
      regex: /(?:md5|sha1)\s*\(|(?:hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"])/gi,
    },
    {
      name: 'JWT Without Verification',
      severity: 'HIGH',
      category: 'auth',
      regex: /jwt\.decode\s*\([^)]*verify\s*[:=]\s*(?:false|False)|algorithms\s*[:=]\s*\[?\s*['"]none['"]/gi,
    },

    // Network/Transport
    {
      name: 'Insecure HTTP URL',
      severity: 'MEDIUM',
      category: 'transport',
      regex: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"`\s]+['"`]/gi,
    },
    {
      name: 'SSL Verification Disabled',
      severity: 'HIGH',
      category: 'transport',
      regex: /verify\s*[:=]\s*(?:false|False)|CERT_NONE|InsecureRequestWarning|rejectUnauthorized\s*[:=]\s*false/gi,
    },
    {
      name: 'CORS Wildcard',
      severity: 'MEDIUM',
      category: 'transport',
      regex: /(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*['"`]\*['"`]|origin\s*:\s*true/gi,
    },

    // Data Handling
    {
      name: 'Insecure Deserialization',
      severity: 'HIGH',
      category: 'data',
      regex: /(?:pickle\.loads|yaml\.load\s*\([^)]*\)|unserialize|ObjectInputStream|JSON\.parse\s*\(\s*(?:req\.|request\.))/gi,
    },
    {
      name: 'Path Traversal Risk',
      severity: 'HIGH',
      category: 'data',
      regex: /(?:readFile|readFileSync|open|fopen)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi,
    },
    {
      name: 'Sensitive Data in Logs',
      severity: 'MEDIUM',
      category: 'data',
      regex: /(?:console\.log|logger?\.\w+|print|println)\s*\([^)]*(?:password|token|secret|key|credential|ssn|credit.?card)/gi,
    },

    // Configuration
    {
      name: 'Debug Mode Enabled',
      severity: 'MEDIUM',
      category: 'config',
      regex: /(?:DEBUG\s*[:=]\s*(?:true|True|1|['"]true['"])|debug\s*[:=]\s*true|app\.debug\s*=\s*True)/gi,
    },
    {
      name: 'CSRF Protection Disabled',
      severity: 'HIGH',
      category: 'config',
      regex: /(?:csrf\s*[:=]\s*false|disable.*csrf|@csrf_exempt|CSRFProtect.*disable)/gi,
    },
  ];

  for (const [filename, file] of fileMap) {
    // Skip non-code files, binary files, node_modules, etc.
    const lower = filename.toLowerCase();
    if (lower.includes('node_modules') || lower.includes('.min.') ||
        lower.includes('vendor/') || lower.includes('dist/') ||
        lower.endsWith('.md') || lower.endsWith('.txt') ||
        lower.endsWith('.json') && !lower.includes('config')) continue;

    const lines = file.content.split('\n');

    for (const pattern of patterns) {
      let match;
      // Reset regex
      pattern.regex.lastIndex = 0;

      while ((match = pattern.regex.exec(file.content)) !== null) {
        // Find line number
        const beforeMatch = file.content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;

        // Get surrounding context (3 lines before and after)
        const startLine = Math.max(0, lineNumber - 4);
        const endLine = Math.min(lines.length, lineNumber + 3);
        const context = lines.slice(startLine, endLine).join('\n');

        findings.push({
          type: 'pattern',
          name: pattern.name,
          severity: pattern.severity,
          category: pattern.category,
          file: filename,
          line: lineNumber,
          match: match[0].substring(0, 100), // Truncate long matches
          context: context,
          // Unique ID for deduplication
          id: `${pattern.name}:${filename}:${lineNumber}`,
        });
      }
    }
  }

  // Deduplicate (same pattern at same location)
  const seen = new Set();
  const deduped = findings.filter(f => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });

  return deduped;
}
```

Fully deterministic. Same code = same findings every time.

### Step 4: LLM DEEP ANALYSIS (Groq/Gemini via BYOK)

Take the deterministic findings from Steps 1-3 and send TARGETED code sections to the LLM for deeper analysis. The LLM confirms/denies findings, assesses exploitability, and adds context.

```javascript
async function deepAnalysis(inventory, patternFindings, depFindings, fileMap, llmClient) {
  const analysisResults = [];

  // 4a: Analyze each pattern finding with surrounding code context
  for (const finding of patternFindings) {
    const file = fileMap.get(finding.file);
    if (!file) continue;

    // Get a generous context window around the finding (30 lines before/after)
    const lines = file.content.split('\n');
    const startLine = Math.max(0, finding.line - 31);
    const endLine = Math.min(lines.length, finding.line + 30);
    const codeContext = lines.slice(startLine, endLine)
      .map((line, i) => `${startLine + i + 1}: ${line}`)
      .join('\n');

    const prompt = `You are a security code reviewer. Analyze this specific finding.

FINDING: ${finding.name}
SEVERITY: ${finding.severity}
FILE: ${finding.file}
LINE: ${finding.line}
MATCHED PATTERN: ${finding.match}

CODE CONTEXT:
\`\`\`
${codeContext}
\`\`\`

Analyze:
1. Is this a TRUE POSITIVE or FALSE POSITIVE? Explain why.
2. If true positive: How exploitable is it? What is the attack vector?
3. What is the actual severity? (CRITICAL / HIGH / MEDIUM / LOW)
4. Provide a specific remediation with code example.
5. What CWE ID does this map to?

Respond in this exact JSON format:
{
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "exploitability": "description of how this could be exploited",
  "actual_severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
  "cwe_id": "CWE-XXX",
  "remediation": "specific fix with code",
  "explanation": "brief explanation"
}`;

    try {
      const response = await llmClient.chat(prompt);
      const analysis = JSON.parse(cleanJsonResponse(response));
      analysisResults.push({
        ...finding,
        analysis,
      });
    } catch (e) {
      // If LLM fails, keep the original finding without deep analysis
      analysisResults.push({
        ...finding,
        analysis: { verdict: 'UNANALYZED', explanation: 'LLM analysis failed' },
      });
    }
  }

  // 4b: Analyze auth and API files for logic flaws
  // These aren't caught by regex — need LLM semantic understanding
  const criticalFiles = [
    ...inventory.authFiles,
    ...inventory.apiFiles,
  ];

  for (const filename of criticalFiles.slice(0, 10)) { // Limit to 10 files
    const file = fileMap.get(filename);
    if (!file || file.content.length < 50) continue;

    // Truncate if too long (keep first 3000 chars for context window limits)
    const truncatedContent = file.content.substring(0, 3000);

    const prompt = `You are a security code reviewer. Analyze this file for security vulnerabilities that regex cannot catch — logic flaws, broken access control, insecure design patterns.

FILE: ${filename}

\`\`\`
${truncatedContent}
\`\`\`

Look specifically for:
- Authentication bypass opportunities
- Authorization / access control flaws (IDOR, privilege escalation)
- Race conditions
- Insecure session management
- Business logic flaws
- Missing input validation on critical operations
- Insecure direct object references

For each finding respond in JSON array format:
[
  {
    "name": "vulnerability name",
    "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
    "line": approximate_line_number,
    "cwe_id": "CWE-XXX",
    "explanation": "what the vulnerability is",
    "exploitability": "how to exploit it",
    "remediation": "how to fix it"
  }
]

If no vulnerabilities found, respond with: []`;

    try {
      const response = await llmClient.chat(prompt);
      const logicFindings = JSON.parse(cleanJsonResponse(response));
      for (const lf of logicFindings) {
        analysisResults.push({
          type: 'logic',
          name: lf.name,
          severity: lf.severity,
          category: 'logic',
          file: filename,
          line: lf.line,
          analysis: {
            verdict: 'TRUE_POSITIVE',
            confidence: 'MEDIUM', // Logic flaws are inherently less certain
            cwe_id: lf.cwe_id,
            exploitability: lf.exploitability,
            actual_severity: lf.severity,
            remediation: lf.remediation,
            explanation: lf.explanation,
          },
        });
      }
    } catch (e) {
      // Skip if LLM fails on this file
    }
  }

  return analysisResults;
}

// Helper to clean LLM response before JSON parsing
function cleanJsonResponse(response) {
  // Strip markdown code fences if present
  let cleaned = response.trim();
  cleaned = cleaned.replace(/^```json?\s*\n?/i, '');
  cleaned = cleaned.replace(/\n?```\s*$/i, '');
  return cleaned.trim();
}
```

### Step 5: CROSS-REFERENCE (RAG on Knowledge Bases)

Take findings from Step 4 and enrich with ATT&CK, Sigma, NIST via the existing RAG pipeline.

```javascript
async function crossReference(analysisResults, indexedSources) {
  const enriched = [];

  for (const finding of analysisResults) {
    const enrichment = {};

    // Skip false positives
    if (finding.analysis?.verdict === 'FALSE_POSITIVE') {
      enriched.push({ ...finding, enrichment: { skipped: 'False positive' } });
      continue;
    }

    // Map to ATT&CK techniques via RAG
    if (indexedSources.includes('attack')) {
      const attackQuery = `${finding.name} ${finding.analysis?.cwe_id || ''} ${finding.category} vulnerability technique`;
      const attackResults = await ragSearch(attackQuery, 'attack', 3);
      enrichment.attack = attackResults.map(r => ({
        technique_id: r.metadata.attack_id,
        name: r.metadata.name,
        tactics: r.metadata.tactics,
      }));
    }

    // Find Sigma detection rules
    if (indexedSources.includes('sigma')) {
      const sigmaQuery = `detect ${finding.name} ${finding.category}`;
      const sigmaResults = await ragSearch(sigmaQuery, 'sigma', 3);
      enrichment.sigma = sigmaResults.map(r => ({
        title: r.metadata.title,
        level: r.metadata.level,
        rule_id: r.metadata.rule_id,
      }));
    }

    // Find NIST compliance controls
    if (indexedSources.includes('compliance')) {
      const complianceMap = {
        'secrets': 'access control credential management',
        'injection': 'input validation system integrity',
        'auth': 'identification authentication access control',
        'crypto': 'cryptographic protection',
        'transport': 'transmission confidentiality integrity',
        'data': 'information handling protection',
        'config': 'configuration management security settings',
        'logic': 'access control authorization',
      };
      const nistQuery = complianceMap[finding.category] || `security control ${finding.name}`;
      const nistResults = await ragSearch(nistQuery, 'compliance', 3);
      enrichment.compliance = nistResults.map(r => ({
        control_id: r.metadata.control_id,
        title: r.metadata.title,
        family: r.metadata.family_title,
      }));
    }

    enriched.push({ ...finding, enrichment });
  }

  return enriched;
}
```

### Step 6: REPORT COMPILATION (Deterministic Template)

Compile everything into the final structured output.

```javascript
function compileReport(inventory, depFindings, enrichedResults) {
  // Filter out false positives
  const confirmed = enrichedResults.filter(
    f => f.analysis?.verdict !== 'FALSE_POSITIVE'
  );

  // Sort by severity
  const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
  confirmed.sort((a, b) => {
    const sevA = severityOrder[a.analysis?.actual_severity || a.severity] ?? 4;
    const sevB = severityOrder[b.analysis?.actual_severity || b.severity] ?? 4;
    return sevA - sevB;
  });

  // Count by severity
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of confirmed) {
    const sev = f.analysis?.actual_severity || f.severity;
    counts[sev] = (counts[sev] || 0) + 1;
  }

  // Vulnerable dependencies
  const vulnDeps = depFindings.filter(d => d.vulnerable);

  return {
    summary: {
      totalFindings: confirmed.length,
      counts,
      vulnerableDependencies: vulnDeps.length,
      filesScanned: inventory.totalFiles,
      languages: Object.keys(inventory.languages),
    },
    findings: confirmed.map(f => ({
      name: f.name,
      severity: f.analysis?.actual_severity || f.severity,
      category: f.category,
      file: f.file,
      line: f.line,
      verdict: f.analysis?.verdict,
      confidence: f.analysis?.confidence,
      cwe: f.analysis?.cwe_id,
      explanation: f.analysis?.explanation,
      exploitability: f.analysis?.exploitability,
      remediation: f.analysis?.remediation,
      context: f.context,
      attack_techniques: f.enrichment?.attack || [],
      sigma_rules: f.enrichment?.sigma || [],
      compliance_controls: f.enrichment?.compliance || [],
    })),
    dependencies: depFindings,
    inventory,
  };
}
```

---

## Integration: The Scan Orchestrator

Wire all 6 steps together into one function that the quick action buttons call.

```javascript
async function runSecurityScan(repoChunks, indexedSources, llmClient, progressCallback) {

  // Step 1: Inventory
  progressCallback({ step: 1, label: 'Building inventory', status: 'running' });
  const { inventory, fileMap } = await buildInventory(repoChunks);
  progressCallback({
    step: 1,
    label: 'Inventory complete',
    status: 'done',
    detail: `${inventory.totalFiles} files, ${Object.keys(inventory.languages).join(', ')}`,
  });

  // Step 2: Dependency Audit
  progressCallback({ step: 2, label: 'Auditing dependencies', status: 'running' });
  const depFindings = await auditDependencies(fileMap, indexedSources.includes('nvd'));
  const vulnDeps = depFindings.filter(d => d.vulnerable);
  progressCallback({
    step: 2,
    label: 'Dependencies checked',
    status: 'done',
    detail: `${depFindings.length} packages, ${vulnDeps.length} vulnerable`,
  });

  // Step 3: Pattern Scan
  progressCallback({ step: 3, label: 'Scanning for patterns', status: 'running' });
  const patternFindings = patternScan(fileMap);
  progressCallback({
    step: 3,
    label: 'Pattern scan complete',
    status: 'done',
    detail: `${patternFindings.length} suspicious patterns found`,
  });

  // Step 4: Deep Analysis (LLM)
  progressCallback({ step: 4, label: 'Deep analysis', status: 'running' });
  const analysisResults = await deepAnalysis(inventory, patternFindings, depFindings, fileMap, llmClient);
  const truePositives = analysisResults.filter(r => r.analysis?.verdict === 'TRUE_POSITIVE');
  progressCallback({
    step: 4,
    label: 'Deep analysis complete',
    status: 'done',
    detail: `${truePositives.length} confirmed, ${analysisResults.length - truePositives.length} filtered`,
  });

  // Step 5: Cross-Reference
  progressCallback({ step: 5, label: 'Cross-referencing', status: 'running' });
  const enrichedResults = await crossReference(analysisResults, indexedSources);
  progressCallback({
    step: 5,
    label: 'Cross-reference complete',
    status: 'done',
    detail: `Mapped to ATT&CK, Sigma, NIST`,
  });

  // Step 6: Compile Report
  progressCallback({ step: 6, label: 'Compiling report', status: 'running' });
  const report = compileReport(inventory, depFindings, enrichedResults);
  progressCallback({
    step: 6,
    label: 'Report ready',
    status: 'done',
    detail: `${report.summary.totalFindings} findings`,
  });

  return report;
}
```

---

## Scan Progress UI

When the scan runs, show a step-by-step progress card in the chat area:

```
┌─────────────────────────────────────────┐
│  SECURITY SCAN: OffensiveSage/SimplySecure │
│                                         │
│  ✅ Step 1: Inventory                   │
│     12 files, Swift, macOS              │
│                                         │
│  ✅ Step 2: Dependencies                │
│     8 packages, 2 vulnerable            │
│                                         │
│  ✅ Step 3: Pattern Scan                │
│     7 suspicious patterns found         │
│                                         │
│  🔄 Step 4: Deep Analysis (Groq)       │
│     Analyzing finding 3/7...            │
│                                         │
│  ⏳ Step 5: Cross-referencing           │
│  ⏳ Step 6: Compiling report            │
│                                         │
│  [Cancel Scan]                          │
└─────────────────────────────────────────┘
```

Style this as a paper-card with dark charcoal theme:
- Card bg: #1A1A1A, border: 2.5px solid #333, shadow: black offset
- Done steps: #66BB6A green checkmark
- Running step: #F5A623 amber spinner
- Pending steps: #666666 gray clock
- Detail text: #A0A0A0, JetBrains Mono, var(--text-xs)

---

## Scan Results Display

After the scan completes, render the report in the chat as a structured card (NOT as a wall of text from the LLM):

```
┌─────────────────────────────────────────┐
│  SCAN RESULTS                           │
│                                         │
│  ┌────┐ ┌────┐ ┌────┐ ┌────┐          │
│  │ 2  │ │ 3  │ │ 4  │ │ 1  │          │
│  │CRIT│ │HIGH│ │MED │ │LOW │          │
│  └────┘ └────┘ └────┘ └────┘          │
│                                         │
│  ── CRITICAL ──                         │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ 🔴 Hardcoded API Key           │   │
│  │ File: config/settings.py:23    │   │
│  │ CWE-798 | Confidence: HIGH     │   │
│  │                                 │   │
│  │ Explanation: API key for AWS... │   │
│  │ Remediation: Use env variables..│   │
│  │                                 │   │
│  │ ATT&CK: T1552.001             │   │
│  │ Sigma: aws_credential_access    │   │
│  │ NIST: IA-5, SC-12              │   │
│  │                                 │   │
│  │ [View Code] [Expand]            │   │
│  └─────────────────────────────────┘   │
│                                         │
│  [Export PDF] [Export MD] [Re-scan]     │
└─────────────────────────────────────────┘
```

### Finding Card Component

Each finding is its own paper-card:
- Left border colored by severity (4px solid severity color)
- Severity badge (top right)
- File + line as clickable link (opens source detail)
- CWE ID as a tag
- Confidence badge (HIGH/MEDIUM/LOW)
- Collapsible explanation, exploitability, remediation sections
- Cross-domain tags: ATT&CK technique IDs, Sigma rule names, NIST control IDs as clickable chips
- "View Code" button shows the code context with the vulnerable line highlighted

---

## Quick Action Button Mapping

Update the quick action buttons to use the agentic pipeline:

- **Scan Vulnerabilities** → `runSecurityScan(repoChunks, indexedSources, llmClient, callback)` — full 6-step pipeline
- **Check Dependencies** → run only Steps 1-2 (inventory + dependency audit) — fast, no LLM needed
- **Find Secrets** → run only Step 3 filtered to `category: 'secrets'` — fast, deterministic
- **Map Attack Surface** → run Step 1 (inventory) then send entry points + API files to LLM for surface mapping
- **Security Improvements** → run full pipeline, then ask LLM to prioritize top 10 improvements from results

---

## LLM Client Abstraction

Create a simple LLM client that works with the BYOK keys:

```javascript
class LLMClient {
  constructor(provider, apiKey) {
    this.provider = provider; // 'groq' or 'gemini'
    this.apiKey = apiKey;
  }

  async chat(prompt, options = {}) {
    if (this.provider === 'groq') {
      return this.callGroq(prompt, options);
    } else if (this.provider === 'gemini') {
      return this.callGemini(prompt, options);
    }
    throw new Error(`Unknown provider: ${this.provider}`);
  }

  async callGroq(prompt, options) {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: options.model || 'llama-3.1-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a security code reviewer. Respond only in the requested format. No preamble.' },
          { role: 'user', content: prompt },
        ],
        temperature: 0.1, // Low temperature for consistency
        max_tokens: options.maxTokens || 2000,
      }),
    });
    const data = await response.json();
    return data.choices?.[0]?.message?.content || '';
  }

  async callGemini(prompt, options) {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.1, // Low temperature for consistency
            maxOutputTokens: options.maxTokens || 2000,
          },
        }),
      }
    );
    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }
}
```

Key: **temperature: 0.1** for both providers. This drastically reduces randomness in outputs. Combined with the deterministic pre-scan, results will be much more consistent.

---

## What Changes in Existing Code

1. **Mode detection**: When `detectMode` returns "code-security" AND a quick action is clicked, route to `runSecurityScan` instead of the RAG chat pipeline
2. **Chat display**: When scan results come back, render the structured finding cards instead of plain LLM text
3. **Quick action buttons**: Wire to the scan orchestrator instead of sending pre-built prompts to chat
4. **Regular chat still works**: If user types a free-form question about the code (not a quick action), use the existing RAG pipeline. The agentic pipeline is only for structured scans.
5. **Report generation**: Update the PDF/MD export to use the structured scan report instead of parsing chat messages

---

## API Key Requirement

The agentic pipeline requires a BYOK API key (Groq or Gemini). If no key is set:
- Steps 1, 2, 3 still work (deterministic, no LLM needed)
- Step 4 is skipped — show message: "Add a Groq or Gemini API key for deep analysis. Pattern scan results shown below."
- Steps 5, 6 work with pattern scan results only (less detailed but still useful)

This means ThreatLens provides value even without an API key (deterministic pattern scanning), and becomes much more powerful with one.

---

## Checklist

- [ ] buildInventory parses all repo chunks into structured file map
- [ ] auditDependencies parses package.json, requirements.txt, go.mod
- [ ] Dependency cross-reference with NVD works when NVD is indexed
- [ ] patternScan finds hardcoded secrets, injection, auth issues, etc.
- [ ] Pattern scan is deterministic — same repo = same results
- [ ] LLM deep analysis sends targeted code to Groq/Gemini
- [ ] LLM responses are parsed as JSON correctly
- [ ] Temperature is set to 0.1 for consistency
- [ ] Cross-reference maps findings to ATT&CK, Sigma, NIST via RAG
- [ ] Report compilation sorts by severity and deduplicates
- [ ] Scan progress UI shows step-by-step with live updates
- [ ] Scan results render as structured finding cards, not LLM text
- [ ] Each finding card shows severity, CWE, file, line, cross-domain tags
- [ ] Export PDF works with structured scan data
- [ ] Export MD works with structured scan data
- [ ] Quick action buttons route to agentic pipeline
- [ ] Regular chat questions still use existing RAG pipeline
- [ ] Works without API key (Steps 1-3 only, with message to add key)
- [ ] Works with Groq API key
- [ ] Works with Gemini API key

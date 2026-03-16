# ThreatLens — Section 8: Reports & Visualizations

## Context

I'm building ThreatLens, a security knowledge RAG platform forked from GitAsk. The dark charcoal Papercut Layers theme is applied. All core functionality is complete — 6 data connectors (ATT&CK, Sigma, NVD, NIST, GitHub repos, custom upload), smart retrieval with cross-domain graph expansion, mode-specific prompts, citation chips, quick action buttons, and dynamic example queries.

Now I need to add reporting and visualization features. These should use data already stored in entity-db from the indexed sources. No new data fetching needed — just read what's already indexed and visualize it.

Use Recharts for charts (already available in the project or install it: `npm install recharts`). For the relationship graph, use d3-force or a simple custom SVG/canvas implementation. For PDF export, use browser print-to-PDF or a library like `jspdf` (`npm install jspdf jspdf-autotable`).

All visuals must follow the dark charcoal Papercut Layers theme:
- Background: #0F0F0F / #1A1A1A
- Text: #F5F5F5 / #A0A0A0
- Accent: #F5A623 (amber)
- Borders: #333333 (2.5px)
- Shadows: black hard-offset
- Severity colors: Critical #FF4444, High #F5A623, Medium #FFD966, Low #66BB6A, Info #64B5F6
- Charts should use these severity colors consistently
- All chart containers should be paper-card style (dark charcoal bg, thick border, hard shadow)

---

## Part 1: ATT&CK Coverage Heatmap

### What It Shows
A visual matrix of MITRE ATT&CK techniques organized by tactic (columns) and technique (rows). Each cell is color-coded based on whether a Sigma detection rule exists for that technique.

### Requirements

- Only show this when BOTH ATT&CK and Sigma are indexed
- Read all ATT&CK technique chunks (tag: "attack", metadata.type: "technique") from entity-db
- Read all Sigma rule chunks (tag: "sigma") and extract their attack_tags arrays
- Build a mapping: technique_id → number of Sigma rules that cover it

### Layout

```
┌──────────────────────────────────────────────────────────────┐
│  ATT&CK DETECTION COVERAGE                          [Export] │
│──────────────────────────────────────────────────────────────│
│                                                              │
│  Tactics →                                                   │
│  ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┐        │
│  │Recon │Init  │Exec  │Persis│Priv  │Def   │Cred  │ ...    │
│  │      │Access│      │tence │Escal │Evasn │Access│        │
│  ├──────┼──────┼──────┼──────┼──────┼──────┼──────┤        │
│  │      │ T1190│T1059 │T1053 │T1068 │T1070 │T1003 │        │
│  │      │  ██  │  ██  │  ██  │  ░░  │  ██  │  ██  │        │
│  │      │ T1133│T1059 │T1547 │T1548 │T1055 │T1110 │        │
│  │      │  ░░  │ .001 │  ██  │  ░░  │  ██  │  ░░  │        │
│  │      │      │  ██  │      │      │      │      │        │
│  └──────┴──────┴──────┴──────┴──────┴──────┴──────┘        │
│                                                              │
│  Legend:                                                     │
│  ██ Covered (3+ rules)  ▓▓ Partial (1-2 rules)  ░░ No rule │
│                                                              │
│  Coverage: 234/456 techniques (51%)                          │
│  Critical gaps: [list of high-priority uncovered techniques] │
└──────────────────────────────────────────────────────────────┘
```

### Color Coding

- **Covered (3+ Sigma rules)**: #66BB6A (sage green) — good coverage
- **Partial (1-2 Sigma rules)**: #F5A623 (amber) — some coverage
- **No coverage (0 rules)**: #FF4444 with low opacity (dark red) — gap
- **Not applicable / deprecated**: #333333 (dark gray)

### Implementation

```jsx
// Pseudocode for the heatmap component
function ATTACKHeatmap() {
  const [techniques, setTechniques] = useState([]);
  const [sigmaMapping, setSigmaMapping] = useState({});
  
  useEffect(() => {
    // 1. Load all ATT&CK techniques from entity-db
    const attackChunks = await getChunksByTag('attack');
    const techs = attackChunks.filter(c => c.metadata.type === 'technique');
    
    // 2. Load all Sigma rules and build technique → rule count map
    const sigmaChunks = await getChunksByTag('sigma');
    const mapping = {};
    for (const rule of sigmaChunks) {
      for (const tag of (rule.metadata.attack_tags || [])) {
        mapping[tag] = (mapping[tag] || 0) + 1;
      }
    }
    
    setTechniques(techs);
    setSigmaMapping(mapping);
  }, []);
  
  // 3. Group techniques by tactic
  const tactics = groupByTactic(techniques);
  
  // 4. Render grid
  return (
    <div className="paper-card">
      <h2>ATT&CK Detection Coverage</h2>
      <div className="heatmap-grid">
        {Object.entries(tactics).map(([tactic, techs]) => (
          <div className="tactic-column" key={tactic}>
            <div className="tactic-header">{tactic}</div>
            {techs.map(tech => (
              <div 
                key={tech.metadata.attack_id}
                className="technique-cell"
                style={{ backgroundColor: getCoverageColor(sigmaMapping[tech.metadata.attack_id] || 0) }}
                title={`${tech.metadata.attack_id}: ${tech.metadata.name}\nSigma rules: ${sigmaMapping[tech.metadata.attack_id] || 0}`}
              >
                {tech.metadata.attack_id}
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="coverage-stats">
        Coverage: {coveredCount}/{totalCount} techniques ({percentage}%)
      </div>
    </div>
  );
}
```

### Interactivity

- Hover over a cell → tooltip shows technique name, ID, and number of Sigma rules
- Click a cell → opens a detail panel showing the technique description AND the Sigma rules that cover it
- The heatmap should be horizontally scrollable if tactics overflow

### Tactic Order (ATT&CK Enterprise)

Display tactics in kill chain order (left to right):
Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact

---

## Part 2: Severity Distribution Charts

### What It Shows

Charts showing the breakdown of indexed data by severity, type, or category. Multiple chart types based on what's indexed.

### Chart 1: CVE Severity Distribution (when NVD is indexed)

Horizontal bar chart showing count of CVEs by severity level.

```
CRITICAL  ████████████████  142
HIGH      ██████████████████████████  267
MEDIUM    ████████████████████████████████  398
LOW       ████████  76
```

- Use severity colors: Critical #FF4444, High #F5A623, Medium #FFD966, Low #66BB6A
- Show total CVE count
- Click a bar → filters chat to show CVEs of that severity

### Chart 2: Sigma Rule Level Distribution (when Sigma is indexed)

Donut/ring chart showing Sigma rules by level.

- Critical: #FF4444
- High: #F5A623
- Medium: #FFD966
- Low: #66BB6A
- Informational: #64B5F6

Center of donut shows total rule count.

### Chart 3: ATT&CK Technique Distribution by Tactic (when ATT&CK is indexed)

Horizontal bar chart showing how many techniques exist per tactic.

- All bars in amber (#F5A623)
- Sorted by count descending

### Chart 4: NIST Control Family Distribution (when NIST is indexed)

Horizontal bar chart showing controls per family (AC, AU, AT, CM, etc.)

- All bars in #64B5F6 (info blue)
- Show family full name on hover

### Implementation

Use Recharts for all charts:

```jsx
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

function SeverityChart({ cveChunks }) {
  const data = [
    { name: 'CRITICAL', count: cveChunks.filter(c => c.metadata.cvss_severity === 'CRITICAL').length, color: '#FF4444' },
    { name: 'HIGH', count: cveChunks.filter(c => c.metadata.cvss_severity === 'HIGH').length, color: '#F5A623' },
    { name: 'MEDIUM', count: cveChunks.filter(c => c.metadata.cvss_severity === 'MEDIUM').length, color: '#FFD966' },
    { name: 'LOW', count: cveChunks.filter(c => c.metadata.cvss_severity === 'LOW').length, color: '#66BB6A' },
  ];

  return (
    <div className="paper-card">
      <h3>CVE Severity Distribution</h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical">
          <XAxis type="number" stroke="#A0A0A0" />
          <YAxis dataKey="name" type="category" stroke="#A0A0A0" width={80} />
          <Tooltip 
            contentStyle={{ background: '#1A1A1A', border: '2px solid #333', color: '#F5F5F5' }}
          />
          <Bar dataKey="count">
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <p className="text-secondary">Total: {cveChunks.length} CVEs indexed</p>
    </div>
  );
}
```

### Chart Styling (Dark Theme)

All Recharts components need dark theme overrides:
- Chart background: transparent (paper-card provides the bg)
- Axis lines and ticks: #A0A0A0
- Grid lines: #333333
- Tooltip: bg #1A1A1A, border 2px solid #333, text #F5F5F5
- Labels: #A0A0A0, font-family DM Sans

---

## Part 3: Cross-Domain Relationship Graph

### What It Shows

An interactive force-directed graph showing how indexed security objects connect across domains. Nodes are techniques, CVEs, Sigma rules, controls. Edges are relationships (detects, mitigates, exploits, related-to).

### When to Show

Show this when 2+ sources are indexed. The more sources, the richer the graph.

### Node Types & Styling

| Node Type | Color | Shape | Size |
|-----------|-------|-------|------|
| ATT&CK Technique | #F5A623 (amber) | Circle | Medium |
| ATT&CK Group | #FF8A65 (orange) | Diamond | Large |
| Sigma Rule | #66BB6A (green) | Square | Small |
| CVE | #FF4444 (red) | Circle | Size by CVSS score |
| NIST Control | #64B5F6 (blue) | Hexagon | Medium |
| Code File | #CE93D8 (purple) | Rectangle | Small |

### Edge Types

- Sigma → ATT&CK technique: "detects" (green dashed line)
- ATT&CK group → technique: "uses" (amber solid line)
- CVE → ATT&CK technique: "exploits" (red solid line)
- Mitigation → technique: "mitigates" (blue solid line)
- NIST control → NIST control: "related" (blue dashed line)

### Implementation

Use d3-force for the force-directed layout. Render with SVG or Canvas.

```jsx
import * as d3 from 'd3';

function CrossDomainGraph({ indexedSources }) {
  const svgRef = useRef(null);
  
  useEffect(() => {
    // 1. Build nodes from indexed chunks
    const nodes = [];
    const links = [];
    
    // Add ATT&CK techniques as nodes
    const attackChunks = await getChunksByTag('attack');
    for (const chunk of attackChunks) {
      if (chunk.metadata.type === 'technique') {
        nodes.push({
          id: chunk.metadata.attack_id,
          label: chunk.metadata.name,
          type: 'technique',
          domain: 'attack',
          color: '#F5A623',
        });
      }
      if (chunk.metadata.type === 'group') {
        nodes.push({
          id: chunk.metadata.attack_id,
          label: chunk.metadata.name,
          type: 'group',
          domain: 'attack',
          color: '#FF8A65',
        });
      }
    }
    
    // Add Sigma rules as nodes and link to techniques
    const sigmaChunks = await getChunksByTag('sigma');
    for (const chunk of sigmaChunks) {
      const nodeId = `sigma-${chunk.metadata.rule_id}`;
      nodes.push({
        id: nodeId,
        label: chunk.metadata.title,
        type: 'sigma',
        domain: 'sigma',
        color: '#66BB6A',
      });
      // Create edges to ATT&CK techniques
      for (const tag of (chunk.metadata.attack_tags || [])) {
        links.push({
          source: nodeId,
          target: tag,
          type: 'detects',
          color: '#66BB6A',
        });
      }
    }
    
    // Add CVEs as nodes
    const nvdChunks = await getChunksByTag('nvd');
    for (const chunk of nvdChunks) {
      nodes.push({
        id: chunk.metadata.cve_id,
        label: chunk.metadata.cve_id,
        type: 'cve',
        domain: 'nvd',
        color: '#FF4444',
        size: (chunk.metadata.cvss_score || 5) * 2, // Size by severity
      });
    }
    
    // Add NIST controls as nodes
    const nistChunks = await getChunksByTag('compliance');
    for (const chunk of nistChunks) {
      nodes.push({
        id: chunk.metadata.control_id,
        label: `${chunk.metadata.control_id}: ${chunk.metadata.title}`,
        type: 'control',
        domain: 'compliance',
        color: '#64B5F6',
      });
      // Link related controls
      for (const relId of (chunk.metadata.related_controls || [])) {
        links.push({
          source: chunk.metadata.control_id,
          target: relId,
          type: 'related',
          color: '#64B5F6',
        });
      }
    }
    
    // 2. Filter to only show nodes that have connections (avoid floating orphans)
    const connectedIds = new Set();
    links.forEach(l => { connectedIds.add(l.source); connectedIds.add(l.target); });
    const filteredNodes = nodes.filter(n => connectedIds.has(n.id));
    // Also keep links that reference existing nodes
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target));
    
    // 3. LIMIT nodes to avoid performance issues
    // If more than 200 nodes, show only the most connected ones
    // Calculate node degree and keep top 200
    
    // 4. Run d3-force simulation
    const simulation = d3.forceSimulation(filteredNodes)
      .force('link', d3.forceLink(filteredLinks).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(20));
    
    // 5. Render SVG
    const svg = d3.select(svgRef.current);
    
    // Draw edges
    const link = svg.selectAll('.link')
      .data(filteredLinks)
      .join('line')
      .attr('class', 'link')
      .attr('stroke', d => d.color)
      .attr('stroke-opacity', 0.4)
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', d => d.type === 'detects' || d.type === 'related' ? '4,4' : 'none');
    
    // Draw nodes
    const node = svg.selectAll('.node')
      .data(filteredNodes)
      .join('circle')
      .attr('class', 'node')
      .attr('r', d => d.size || 8)
      .attr('fill', d => d.color)
      .attr('stroke', '#333')
      .attr('stroke-width', 2)
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));
    
    // Labels
    const labels = svg.selectAll('.label')
      .data(filteredNodes)
      .join('text')
      .attr('class', 'label')
      .attr('fill', '#A0A0A0')
      .attr('font-size', '10px')
      .attr('font-family', 'JetBrains Mono')
      .text(d => d.id);
    
    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      labels.attr('x', d => d.x + 12).attr('y', d => d.y + 4);
    });
    
  }, [indexedSources]);
  
  return (
    <div className="paper-card" style={{ overflow: 'hidden' }}>
      <h2>Cross-Domain Threat Map</h2>
      <div className="graph-legend">
        <span style={{ color: '#F5A623' }}>● ATT&CK Technique</span>
        <span style={{ color: '#FF8A65' }}>● Threat Group</span>
        <span style={{ color: '#66BB6A' }}>■ Sigma Rule</span>
        <span style={{ color: '#FF4444' }}>● CVE</span>
        <span style={{ color: '#64B5F6' }}>● NIST Control</span>
      </div>
      <svg ref={svgRef} width="100%" height={500} style={{ background: '#0F0F0F' }} />
      <div className="graph-controls">
        <button className="btn-secondary">Zoom In</button>
        <button className="btn-secondary">Zoom Out</button>
        <button className="btn-secondary">Reset</button>
      </div>
    </div>
  );
}
```

### Interactivity

- **Hover** a node → highlight it and all connected edges, dim everything else. Show tooltip with full name and details.
- **Click** a node → open the source detail panel with the full chunk content
- **Drag** nodes to rearrange
- **Zoom** and **pan** the graph (d3-zoom)
- **Filter** by domain — toggle buttons to show/hide ATT&CK, Sigma, NVD, NIST nodes
- **Search** — text input to find and highlight a specific node by ID or name

### Performance

- Limit to 200 most-connected nodes by default
- Show a "Show all X nodes" button if there are more
- Use requestAnimationFrame for smooth simulation
- Canvas rendering (instead of SVG) if nodes > 500

---

## Part 4: Security Report Generation

### What It Does

After a chat session or quick action scan, the user can click "Generate Report" to export a structured security report as a downloadable PDF or Markdown file.

### Report Trigger

Add a "Generate Report" button in two places:
1. Below any assistant chat response — small button: "Export as Report"
2. In the sidebar or header — "Generate Full Report" button that compiles all findings from the current chat session

### Report Structure

```
┌──────────────────────────────────────────────────┐
│  THREATLENS SECURITY REPORT                      │
│  Generated: March 11, 2026                       │
│  Target: OffensiveSage/SimplySecure              │
│  Sources: ATT&CK, Sigma, NVD, Code Repo         │
├──────────────────────────────────────────────────┤
│                                                  │
│  EXECUTIVE SUMMARY                               │
│  [2-3 sentence summary of key findings]          │
│                                                  │
│  FINDINGS BY SEVERITY                            │
│                                                  │
│  ● CRITICAL (2)                                  │
│    1. Default credentials in README.md           │
│       Evidence: lines 1-2                        │
│       Remediation: Remove defaults, enforce...   │
│    2. SQL Injection via Process API              │
│       Evidence: SECURITY_TASKS_README.md:34-36   │
│       Remediation: Use parameterized queries...  │
│                                                  │
│  ● HIGH (3)                                      │
│    3. XSS via UserDefaults                       │
│    4. ...                                        │
│                                                  │
│  ● MEDIUM (4)                                    │
│    ...                                           │
│                                                  │
│  DETECTION COVERAGE                              │
│  [If Sigma indexed: which findings have rules]   │
│                                                  │
│  ATT&CK MAPPING                                  │
│  [If ATT&CK indexed: techniques for each finding]│
│                                                  │
│  COMPLIANCE IMPACT                               │
│  [If NIST indexed: which controls are affected]  │
│                                                  │
│  RECOMMENDATIONS                                 │
│  [Prioritized list of remediation steps]         │
│                                                  │
│  APPENDIX                                        │
│  - Sources consulted                             │
│  - Indexed data statistics                       │
│  - Tool version and methodology                  │
│                                                  │
│  Generated by ThreatLens                         │
│  https://github.com/OffensiveSage/ThreatLens    │
└──────────────────────────────────────────────────┘
```

### Implementation — PDF Export

Use jspdf + jspdf-autotable for PDF generation:

```bash
npm install jspdf jspdf-autotable
```

```javascript
import jsPDF from 'jspdf';
import 'jspdf-autotable';

function generateSecurityReport(chatMessages, indexedSources, metadata) {
  const doc = new jsPDF();
  
  // Title page
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('THREATLENS', 20, 30);
  doc.setFontSize(16);
  doc.text('SECURITY REPORT', 20, 42);
  
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Generated: ${new Date().toLocaleDateString()}`, 20, 60);
  doc.text(`Target: ${metadata.repoName || 'Multiple Sources'}`, 20, 68);
  doc.text(`Sources: ${indexedSources.join(', ')}`, 20, 76);
  
  // Extract findings from chat messages
  const assistantMessages = chatMessages.filter(m => m.role === 'assistant');
  const findings = extractFindings(assistantMessages);
  
  // Executive Summary
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('EXECUTIVE SUMMARY', 20, 96);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const summary = generateSummary(findings);
  doc.text(doc.splitTextToSize(summary, 170), 20, 106);
  
  // Findings table
  let yPos = 130;
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('FINDINGS', 20, yPos);
  yPos += 10;
  
  // Group findings by severity
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const severityColors = {
    'CRITICAL': [255, 68, 68],
    'HIGH': [245, 166, 35],
    'MEDIUM': [255, 217, 102],
    'LOW': [102, 187, 106],
    'INFO': [100, 181, 246]
  };
  
  for (const severity of severityOrder) {
    const sevFindings = findings.filter(f => f.severity === severity);
    if (sevFindings.length === 0) continue;
    
    // Add findings table using autotable
    doc.autoTable({
      startY: yPos,
      head: [[`${severity} (${sevFindings.length})`,'Details','Evidence']],
      body: sevFindings.map(f => [f.title, f.description, f.evidence]),
      headStyles: { fillColor: severityColors[severity], textColor: [0,0,0] },
      styles: { fontSize: 8, cellPadding: 4 },
      theme: 'grid',
    });
    
    yPos = doc.lastAutoTable.finalY + 10;
    
    // Add new page if needed
    if (yPos > 260) {
      doc.addPage();
      yPos = 20;
    }
  }
  
  // Footer on each page
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text('Generated by ThreatLens | github.com/OffensiveSage/ThreatLens', 20, 288);
    doc.text(`Page ${i} of ${pageCount}`, 180, 288);
  }
  
  // Save
  doc.save(`ThreatLens-Report-${new Date().toISOString().split('T')[0]}.pdf`);
}

// Extract structured findings from chat messages
function extractFindings(messages) {
  const findings = [];
  
  for (const msg of messages) {
    // Parse numbered findings from assistant responses
    // Look for patterns like:
    // "1. **Finding Title**: Description (File.ext, lines X-Y)"
    // "CONFIRMED: ..." or "INFERRED: ..."
    const findingRegex = /\d+\.\s+\*\*([^*]+)\*\*[:\s]*(.+?)(?:\(([^)]+)\))?(?:\n|$)/g;
    let match;
    while ((match = findingRegex.exec(msg.content)) !== null) {
      const title = match[1].trim();
      const description = match[2].trim();
      const evidence = match[3]?.trim() || 'Unknown';
      
      // Infer severity from keywords
      let severity = 'MEDIUM';
      const lower = (title + description).toLowerCase();
      if (lower.includes('critical') || lower.includes('rce') || lower.includes('remote code')) severity = 'CRITICAL';
      else if (lower.includes('sql injection') || lower.includes('authentication') || lower.includes('credential')) severity = 'HIGH';
      else if (lower.includes('xss') || lower.includes('insecure') || lower.includes('missing')) severity = 'MEDIUM';
      else if (lower.includes('info') || lower.includes('best practice')) severity = 'LOW';
      
      findings.push({ title, description, evidence, severity });
    }
  }
  
  return findings;
}
```

### Markdown Export Alternative

Also offer a Markdown export option (simpler, can be pasted into docs/tickets):

```javascript
function generateMarkdownReport(chatMessages, indexedSources, metadata) {
  let md = `# ThreatLens Security Report\n\n`;
  md += `**Generated:** ${new Date().toLocaleDateString()}\n`;
  md += `**Target:** ${metadata.repoName || 'Multiple Sources'}\n`;
  md += `**Sources:** ${indexedSources.join(', ')}\n\n`;
  md += `---\n\n`;
  
  // Include all assistant messages as findings
  const assistantMessages = chatMessages.filter(m => m.role === 'assistant');
  
  md += `## Findings\n\n`;
  for (const msg of assistantMessages) {
    md += msg.content + '\n\n';
  }
  
  md += `---\n\n`;
  md += `*Generated by [ThreatLens](https://github.com/OffensiveSage/ThreatLens)*\n`;
  
  // Download as .md file
  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ThreatLens-Report-${new Date().toISOString().split('T')[0]}.md`;
  a.click();
  URL.revokeObjectURL(url);
}
```

### Report UI Buttons

```jsx
// Below each assistant message
<div className="report-actions">
  <button className="btn-secondary btn-small" onClick={() => generateSecurityReport(...)}>
    <FileText size={14} /> Export PDF
  </button>
  <button className="btn-secondary btn-small" onClick={() => generateMarkdownReport(...)}>
    <FileCode size={14} /> Export MD
  </button>
</div>

// In the chat header or sidebar
<button className="btn-primary" onClick={() => generateFullReport(...)}>
  <ClipboardList size={16} /> Generate Full Report
</button>
```

Style the buttons with dark charcoal Papercut Layers: #1A1A1A bg, #333 border, amber text, hard shadow. Small size variant for inline buttons.

---

## Part 5: Visualization Dashboard Page

### New Route: /dashboard

Create a new page at `/dashboard` (or `/threatlens/dashboard`) that shows all visualizations together. This is a read-only overview of everything that's indexed.

### Layout

```
┌──────────────────────────────────────────────────────────────┐
│  THREATLENS  |  Dashboard  |  Chat  |  Sources               │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────┐  ┌─────────────────────┐           │
│  │ INDEXED SOURCES     │  │ TOTAL CHUNKS         │           │
│  │ 4 / 6 active        │  │ 6,247                │           │
│  └─────────────────────┘  └─────────────────────┘           │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ATT&CK DETECTION COVERAGE HEATMAP                    │   │
│  │ [Full heatmap from Part 1]                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌────────────────────┐  ┌────────────────────┐             │
│  │ CVE SEVERITY       │  │ SIGMA RULE LEVELS  │             │
│  │ [Bar chart]        │  │ [Donut chart]      │             │
│  └────────────────────┘  └────────────────────┘             │
│                                                              │
│  ┌────────────────────┐  ┌────────────────────┐             │
│  │ ATT&CK BY TACTIC   │  │ NIST BY FAMILY     │             │
│  │ [Bar chart]        │  │ [Bar chart]        │             │
│  └────────────────────┘  └────────────────────┘             │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ CROSS-DOMAIN THREAT MAP                               │   │
│  │ [Interactive graph from Part 3]                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Top Stats Bar

Four paper-card stat boxes in a row:
- Sources Indexed: X / 6
- Total Chunks: X,XXX
- Detection Coverage: XX% (techniques with Sigma rules / total techniques)
- Critical Findings: X (if a scan has been run)

Each stat box: dark charcoal bg, amber number text (large, Archivo Black), label below in #A0A0A0.

### Navigation

Add "Dashboard" as a nav item in the header, alongside the existing chat/sources navigation. Only show Dashboard link if at least 1 source is indexed.

### Responsive

- Desktop: 2-column grid for charts, full-width for heatmap and graph
- Tablet: single column
- Mobile: single column, charts scale down

---

## Dependencies

Run before starting:
```bash
npm install recharts jspdf jspdf-autotable
```

If d3 is already in the project (check package.json), no need to install. Otherwise: `npm install d3`

---

## Integration Checklist

- [ ] ATT&CK heatmap renders when ATT&CK + Sigma are both indexed
- [ ] Heatmap cells are interactive (hover tooltip, click to detail)
- [ ] Coverage percentage is calculated correctly
- [ ] CVE severity chart renders when NVD is indexed
- [ ] Sigma level donut chart renders when Sigma is indexed
- [ ] ATT&CK tactic bar chart renders when ATT&CK is indexed
- [ ] NIST family bar chart renders when NIST is indexed
- [ ] Charts only appear for their respective indexed sources
- [ ] Cross-domain graph renders with 2+ sources indexed
- [ ] Graph nodes are draggable, clickable, hoverable
- [ ] Graph has zoom/pan controls
- [ ] Graph limits to 200 nodes for performance
- [ ] "Export PDF" button generates a downloadable PDF report
- [ ] "Export MD" button generates a downloadable Markdown report
- [ ] Report includes findings, severity, evidence, recommendations
- [ ] Dashboard page shows all visualizations together
- [ ] Dashboard responsive on mobile
- [ ] All charts follow dark charcoal Papercut Layers theme
- [ ] All chart tooltips are styled with dark theme

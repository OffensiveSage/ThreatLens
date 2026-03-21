# ThreatLens — Governance Dashboard (Repo-Driven)

## Context

ThreatLens already has a 6-step agentic security scanning pipeline that scans GitHub repos and produces structured findings. Each finding has: name, severity, category, file, line, CWE ID, explanation, remediation, and cross-domain enrichment (ATT&CK, Sigma, NIST).

Now I need a Governance Dashboard at `/dashboard/governance` that takes the scan results from ANY scanned repo and automatically maps them to compliance frameworks (NIST 800-53, NIST CSF, NIS2) using the finding's CWE ID as the bridge. The dashboard shows the organization's security posture based on REAL scan data, not mock data.

The key insight: CWE IDs bridge code findings to compliance frameworks.

```
Code Finding → CWE ID → NIST 800-53 Controls → NIST CSF Functions → NIS2 Articles
```

Use the existing dark charcoal Papercut Layers theme for everything.

---

## Part 1: CWE-to-Compliance Mapping Table

Create this as a static mapping file at `src/data/cweComplianceMap.json`. This is well-established industry mapping, not made up.

```json
{
  "CWE-78": {
    "name": "OS Command Injection",
    "nist_800_53": ["SI-10", "SA-11", "SC-39"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-79": {
    "name": "Cross-site Scripting (XSS)",
    "nist_800_53": ["SI-10", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-89": {
    "name": "SQL Injection",
    "nist_800_53": ["SI-10", "SA-11", "SA-15"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-200": {
    "name": "Information Exposure",
    "nist_800_53": ["AC-4", "SC-8", "SI-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-2" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-209": {
    "name": "Information Exposure Through Error Message",
    "nist_800_53": ["SI-11", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-20": {
    "name": "Improper Input Validation",
    "nist_800_53": ["SI-10", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-22": {
    "name": "Path Traversal",
    "nist_800_53": ["AC-6", "SI-10", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-250": {
    "name": "Execution with Unnecessary Privileges",
    "nist_800_53": ["AC-6", "CM-7"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(i) - Human resources security, access control policies"]
  },
  "CWE-259": {
    "name": "Use of Hard-coded Password",
    "nist_800_53": ["IA-5", "SC-12", "SC-13"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security", "Article 21(2)(j) - Multi-factor authentication"]
  },
  "CWE-261": {
    "name": "Weak Encoding for Password",
    "nist_800_53": ["IA-5", "SC-13"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-284": {
    "name": "Improper Access Control",
    "nist_800_53": ["AC-3", "AC-6"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(i) - Human resources security, access control policies"]
  },
  "CWE-287": {
    "name": "Improper Authentication",
    "nist_800_53": ["IA-2", "IA-5", "IA-8"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-7" },
    "nis2_articles": ["Article 21(2)(j) - Multi-factor authentication"]
  },
  "CWE-306": {
    "name": "Missing Authentication for Critical Function",
    "nist_800_53": ["IA-2", "AC-3"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-7" },
    "nis2_articles": ["Article 21(2)(j) - Multi-factor authentication"]
  },
  "CWE-311": {
    "name": "Missing Encryption of Sensitive Data",
    "nist_800_53": ["SC-8", "SC-12", "SC-13", "SC-28"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-319": {
    "name": "Cleartext Transmission of Sensitive Info",
    "nist_800_53": ["SC-8", "SC-23"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-2" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-326": {
    "name": "Inadequate Encryption Strength",
    "nist_800_53": ["SC-12", "SC-13"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-327": {
    "name": "Use of Broken Crypto Algorithm",
    "nist_800_53": ["SC-13"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security"]
  },
  "CWE-352": {
    "name": "Cross-Site Request Forgery (CSRF)",
    "nist_800_53": ["SI-10", "SC-23"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-434": {
    "name": "Unrestricted Upload of Dangerous File Type",
    "nist_800_53": ["SI-10", "CM-7"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-502": {
    "name": "Deserialization of Untrusted Data",
    "nist_800_53": ["SI-10", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-522": {
    "name": "Insufficiently Protected Credentials",
    "nist_800_53": ["IA-5", "SC-28"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-1" },
    "nis2_articles": ["Article 21(2)(j) - Multi-factor authentication"]
  },
  "CWE-532": {
    "name": "Information Exposure Through Log Files",
    "nist_800_53": ["AU-9", "SI-11"],
    "nist_csf": { "function": "Detect", "category": "DE.AE", "subcategory": "DE.AE-3" },
    "nis2_articles": ["Article 21(2)(g) - Basic cyber hygiene practices"]
  },
  "CWE-611": {
    "name": "Improper Restriction of XML External Entity Reference",
    "nist_800_53": ["SI-10", "SA-11"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-639": {
    "name": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "nist_800_53": ["AC-3", "AC-6"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(i) - Human resources security, access control policies"]
  },
  "CWE-732": {
    "name": "Incorrect Permission Assignment",
    "nist_800_53": ["AC-3", "AC-6"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(i) - Human resources security, access control policies"]
  },
  "CWE-778": {
    "name": "Insufficient Logging",
    "nist_800_53": ["AU-2", "AU-3", "AU-12"],
    "nist_csf": { "function": "Detect", "category": "DE.AE", "subcategory": "DE.AE-3" },
    "nis2_articles": ["Article 21(2)(g) - Basic cyber hygiene practices"]
  },
  "CWE-798": {
    "name": "Use of Hard-coded Credentials",
    "nist_800_53": ["IA-5", "SC-12"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-1" },
    "nis2_articles": ["Article 21(2)(d) - Supply chain security", "Article 21(2)(j) - Multi-factor authentication"]
  },
  "CWE-862": {
    "name": "Missing Authorization",
    "nist_800_53": ["AC-3", "AC-6"],
    "nist_csf": { "function": "Protect", "category": "PR.AC", "subcategory": "PR.AC-4" },
    "nis2_articles": ["Article 21(2)(i) - Human resources security, access control policies"]
  },
  "CWE-918": {
    "name": "Server-Side Request Forgery (SSRF)",
    "nist_800_53": ["SI-10", "SC-7"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-5" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  },
  "CWE-1004": {
    "name": "Sensitive Cookie Without HttpOnly Flag",
    "nist_800_53": ["SC-23"],
    "nist_csf": { "function": "Protect", "category": "PR.DS", "subcategory": "PR.DS-2" },
    "nis2_articles": ["Article 21(2)(e) - Network and information systems security"]
  }
}
```

Also create a NIST CSF structure reference and NIS2 articles reference:

### src/data/nistCSFStructure.json

```json
{
  "functions": [
    {
      "id": "ID",
      "name": "Identify",
      "color": "#64B5F6",
      "categories": [
        { "id": "ID.AM", "name": "Asset Management" },
        { "id": "ID.BE", "name": "Business Environment" },
        { "id": "ID.GV", "name": "Governance" },
        { "id": "ID.RA", "name": "Risk Assessment" },
        { "id": "ID.RM", "name": "Risk Management Strategy" },
        { "id": "ID.SC", "name": "Supply Chain Risk Management" }
      ]
    },
    {
      "id": "PR",
      "name": "Protect",
      "color": "#F5A623",
      "categories": [
        { "id": "PR.AC", "name": "Identity Management & Access Control" },
        { "id": "PR.AT", "name": "Awareness and Training" },
        { "id": "PR.DS", "name": "Data Security" },
        { "id": "PR.IP", "name": "Information Protection Processes" },
        { "id": "PR.MA", "name": "Maintenance" },
        { "id": "PR.PT", "name": "Protective Technology" }
      ]
    },
    {
      "id": "DE",
      "name": "Detect",
      "color": "#66BB6A",
      "categories": [
        { "id": "DE.AE", "name": "Anomalies and Events" },
        { "id": "DE.CM", "name": "Security Continuous Monitoring" },
        { "id": "DE.DP", "name": "Detection Processes" }
      ]
    },
    {
      "id": "RS",
      "name": "Respond",
      "color": "#FF8A65",
      "categories": [
        { "id": "RS.RP", "name": "Response Planning" },
        { "id": "RS.CO", "name": "Communications" },
        { "id": "RS.AN", "name": "Analysis" },
        { "id": "RS.MI", "name": "Mitigation" },
        { "id": "RS.IM", "name": "Improvements" }
      ]
    },
    {
      "id": "RC",
      "name": "Recover",
      "color": "#CE93D8",
      "categories": [
        { "id": "RC.RP", "name": "Recovery Planning" },
        { "id": "RC.IM", "name": "Improvements" },
        { "id": "RC.CO", "name": "Communications" }
      ]
    }
  ]
}
```

### src/data/nis2Articles.json

```json
{
  "articles": [
    {
      "id": "Art21-2a",
      "article": "Article 21(2)(a)",
      "title": "Policies on risk analysis and information system security",
      "description": "Establish and maintain policies for risk analysis and information system security",
      "assessable_from_code": false,
      "fallback_status": "Not Assessed - Requires policy review"
    },
    {
      "id": "Art21-2b",
      "article": "Article 21(2)(b)",
      "title": "Incident handling",
      "description": "Procedures for handling security incidents including detection, response, and reporting",
      "assessable_from_code": false,
      "fallback_status": "Not Assessed - Requires IR plan review"
    },
    {
      "id": "Art21-2c",
      "article": "Article 21(2)(c)",
      "title": "Business continuity and crisis management",
      "description": "Business continuity including backup management, disaster recovery, and crisis management",
      "assessable_from_code": false,
      "fallback_status": "Not Assessed - Requires BCP review"
    },
    {
      "id": "Art21-2d",
      "article": "Article 21(2)(d)",
      "title": "Supply chain security",
      "description": "Security in network and information systems acquisition, development, and maintenance including vulnerability handling and disclosure",
      "assessable_from_code": true,
      "code_indicators": ["CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-259", "CWE-798", "CWE-200"]
    },
    {
      "id": "Art21-2e",
      "article": "Article 21(2)(e)",
      "title": "Network and information systems security",
      "description": "Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure",
      "assessable_from_code": true,
      "code_indicators": ["CWE-79", "CWE-89", "CWE-78", "CWE-20", "CWE-352", "CWE-434", "CWE-502", "CWE-611", "CWE-918", "CWE-22", "CWE-209"]
    },
    {
      "id": "Art21-2f",
      "article": "Article 21(2)(f)",
      "title": "Vulnerability assessment and handling",
      "description": "Policies and procedures for assessing the effectiveness of cybersecurity risk management measures",
      "assessable_from_code": false,
      "fallback_status": "Not Assessed - Requires vulnerability management process review"
    },
    {
      "id": "Art21-2g",
      "article": "Article 21(2)(g)",
      "title": "Basic cyber hygiene and security training",
      "description": "Basic cyber hygiene practices and cybersecurity training",
      "assessable_from_code": true,
      "code_indicators": ["CWE-778", "CWE-532"]
    },
    {
      "id": "Art21-2h",
      "article": "Article 21(2)(h)",
      "title": "Cryptography and encryption",
      "description": "Policies and procedures regarding the use of cryptography and where appropriate, encryption",
      "assessable_from_code": true,
      "code_indicators": ["CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-261"]
    },
    {
      "id": "Art21-2i",
      "article": "Article 21(2)(i)",
      "title": "Human resources security and access control",
      "description": "Human resources security, access control policies and asset management",
      "assessable_from_code": true,
      "code_indicators": ["CWE-284", "CWE-287", "CWE-306", "CWE-639", "CWE-732", "CWE-862", "CWE-250"]
    },
    {
      "id": "Art21-2j",
      "article": "Article 21(2)(j)",
      "title": "Multi-factor authentication and secure communications",
      "description": "Use of multi-factor authentication or continuous authentication solutions, secured voice, video, text communications and secured emergency communication systems",
      "assessable_from_code": true,
      "code_indicators": ["CWE-287", "CWE-306", "CWE-522", "CWE-259", "CWE-798"]
    },
    {
      "id": "Art23",
      "article": "Article 23",
      "title": "Incident reporting obligations",
      "description": "Obligation to report significant incidents to competent authorities within 24/72 hours",
      "assessable_from_code": false,
      "fallback_status": "Not Assessed - Requires incident reporting process review"
    }
  ]
}
```

---

## Part 2: Compliance Mapping Engine

Create `src/lib/complianceMapper.ts`. This takes scan results and maps them to frameworks.

```typescript
import cweMap from '../data/cweComplianceMap.json';
import csfStructure from '../data/nistCSFStructure.json';
import nis2Articles from '../data/nis2Articles.json';

interface ScanFinding {
  name: string;
  severity: string;
  category: string;
  file: string;
  line: number;
  analysis: {
    verdict: string;
    cwe_id: string;
    actual_severity: string;
    explanation: string;
    remediation: string;
  };
}

interface ComplianceResult {
  riskScore: number;
  nist80053: NIST80053Result;
  nistCSF: NISTCSFResult;
  nis2: NIS2Result;
}

// Main mapping function — takes scan findings, returns full compliance picture
export function mapToCompliance(findings: ScanFinding[]): ComplianceResult {
  // Filter to confirmed findings only
  const confirmed = findings.filter(f => f.analysis?.verdict !== 'FALSE_POSITIVE');
  
  // 1. Map each finding to compliance frameworks via CWE
  const mappedFindings = confirmed.map(f => {
    const cwe = f.analysis?.cwe_id || '';
    const cweData = cweMap[cwe] || null;
    return {
      ...f,
      compliance: {
        nist_800_53: cweData?.nist_800_53 || [],
        nist_csf: cweData?.nist_csf || null,
        nis2_articles: cweData?.nis2_articles || [],
      }
    };
  });
  
  // 2. Calculate NIST 800-53 control status
  const nist80053 = calculateNIST80053(mappedFindings);
  
  // 3. Calculate NIST CSF function scores
  const nistCSF = calculateNISTCSF(mappedFindings);
  
  // 4. Calculate NIS2 compliance
  const nis2 = calculateNIS2(mappedFindings);
  
  // 5. Calculate overall risk score
  const riskScore = calculateRiskScore(confirmed, nist80053, nistCSF);
  
  return { riskScore, nist80053, nistCSF, nis2 };
}

function calculateNIST80053(mappedFindings) {
  // Collect all violated controls
  const violatedControls = new Map(); // controlId → array of findings
  
  for (const f of mappedFindings) {
    for (const controlId of f.compliance.nist_800_53) {
      if (!violatedControls.has(controlId)) {
        violatedControls.set(controlId, []);
      }
      violatedControls.get(controlId).push({
        finding: f.name,
        severity: f.analysis?.actual_severity || f.severity,
        file: f.file,
        line: f.line,
        cwe: f.analysis?.cwe_id,
      });
    }
  }
  
  // Build control families summary
  const families = {};
  for (const [controlId, findings] of violatedControls) {
    const family = controlId.split('-')[0]; // "SI-10" → "SI"
    if (!families[family]) {
      families[family] = { total_violated: 0, controls: [], max_severity: 'LOW' };
    }
    families[family].total_violated++;
    families[family].controls.push({ controlId, findings });
    
    // Track max severity per family
    const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    for (const f of findings) {
      if ((severityRank[f.severity] || 0) > (severityRank[families[family].max_severity] || 0)) {
        families[family].max_severity = f.severity;
      }
    }
  }
  
  return {
    totalViolatedControls: violatedControls.size,
    violatedControls: Object.fromEntries(violatedControls),
    families,
  };
}

function calculateNISTCSF(mappedFindings) {
  // Count findings per CSF function
  const functionFindings = { Identify: [], Protect: [], Detect: [], Respond: [], Recover: [] };
  const categoryFindings = {}; // "PR.AC" → findings[]
  
  for (const f of mappedFindings) {
    if (f.compliance.nist_csf) {
      const func = f.compliance.nist_csf.function;
      const cat = f.compliance.nist_csf.category;
      
      if (functionFindings[func]) {
        functionFindings[func].push(f);
      }
      
      if (!categoryFindings[cat]) categoryFindings[cat] = [];
      categoryFindings[cat].push(f);
    }
  }
  
  // Calculate score per function (100 = no findings, subtract per finding)
  // This is a simplified scoring — more findings = lower score
  const scores = {};
  for (const [func, findings] of Object.entries(functionFindings)) {
    let score = 100;
    for (const f of findings) {
      const penalty = { CRITICAL: 15, HIGH: 10, MEDIUM: 5, LOW: 2 };
      score -= penalty[f.analysis?.actual_severity || f.severity] || 3;
    }
    scores[func] = Math.max(0, Math.min(100, score));
  }
  
  // Functions not assessable from code get "N/A" unless findings exist
  // Identify, Respond, Recover typically can't be assessed from code alone
  const assessableFromCode = {
    Identify: false,
    Protect: true,
    Detect: true,
    Respond: false,
    Recover: false,
  };
  
  return {
    scores,
    assessableFromCode,
    functionFindings,
    categoryFindings,
  };
}

function calculateNIS2(mappedFindings) {
  const articleStatus = {};
  
  for (const article of nis2Articles.articles) {
    if (article.assessable_from_code) {
      // Check if any findings map to this article's CWE indicators
      const relatedFindings = mappedFindings.filter(f =>
        f.compliance.nis2_articles.some(a => a.includes(article.article))
      );
      
      if (relatedFindings.length === 0) {
        articleStatus[article.id] = {
          ...article,
          status: 'Pass',
          findings: [],
          finding_count: 0,
        };
      } else {
        const hasCritical = relatedFindings.some(f => 
          (f.analysis?.actual_severity || f.severity) === 'CRITICAL'
        );
        const hasHigh = relatedFindings.some(f => 
          (f.analysis?.actual_severity || f.severity) === 'HIGH'
        );
        
        articleStatus[article.id] = {
          ...article,
          status: hasCritical ? 'Non-Compliant' : hasHigh ? 'Partial' : 'Needs Improvement',
          findings: relatedFindings.map(f => ({
            name: f.name,
            severity: f.analysis?.actual_severity || f.severity,
            cwe: f.analysis?.cwe_id,
            file: f.file,
          })),
          finding_count: relatedFindings.length,
        };
      }
    } else {
      articleStatus[article.id] = {
        ...article,
        status: 'Not Assessed',
        statusNote: article.fallback_status,
        findings: [],
        finding_count: 0,
      };
    }
  }
  
  // Calculate overall NIS2 readiness
  const assessed = Object.values(articleStatus).filter(a => a.assessable_from_code);
  const passing = assessed.filter(a => a.status === 'Pass');
  const readinessPercent = assessed.length > 0 
    ? Math.round((passing.length / assessed.length) * 100) 
    : 0;
  
  return {
    articles: articleStatus,
    readinessPercent,
    totalArticles: nis2Articles.articles.length,
    assessedFromCode: assessed.length,
    notAssessed: nis2Articles.articles.length - assessed.length,
  };
}

function calculateRiskScore(findings, nist80053, nistCSF) {
  let score = 100;
  
  // Penalize by finding severity
  for (const f of findings) {
    const severity = f.analysis?.actual_severity || f.severity;
    const penalty = { CRITICAL: 8, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
    score -= penalty[severity] || 1;
  }
  
  // Penalize by violated control count
  score -= nist80053.totalViolatedControls * 1.5;
  
  // Bonus for good CSF scores
  const csfAvg = Object.values(nistCSF.scores)
    .filter(s => typeof s === 'number')
    .reduce((a, b) => a + b, 0) / 5;
  score += csfAvg * 0.1;
  
  return Math.max(0, Math.min(100, Math.round(score)));
}
```

---

## Part 3: Dashboard Page UI

Create the governance dashboard page at `/dashboard/governance`. This page reads scan results from the most recent scan (stored in state or IndexedDB) and runs them through the compliance mapper.

### Page Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  THREATLENS  |  Scan  |  Dashboard  |  Governance                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Repo: OffensiveSage/SimplySecure  |  Last scan: 5 mins ago     │
│  [Re-scan]  [Generate PDF Report]                                │
│                                                                  │
│  ── EXECUTIVE SUMMARY ──                                         │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐│
│  │   72     │ │    10    │ │   68%    │ │   45%    │ │   7    ││
│  │ RISK     │ │ FINDINGS │ │ CSF      │ │ NIS2     │ │CONTROLS││
│  │ SCORE    │ │ CONFIRMED│ │ SCORE    │ │ READY    │ │VIOLATED││
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └────────┘│
│                                                                  │
│  ── NIST CSF MATURITY ──                                         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Identify   Protect    Detect    Respond    Recover      │   │
│  │    N/A       62%        45%       N/A        N/A         │   │
│  │    ░░░       ████       ███       ░░░        ░░░         │   │
│  │                                                          │   │
│  │  [Categories breakdown below each function]              │   │
│  │  PR.AC: 3 findings  PR.DS: 5 findings  DE.AE: 2 findings│   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── NIST 800-53 VIOLATED CONTROLS ──                             │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Family  │ Controls Violated │ Max Severity │ Findings   │   │
│  │──────────┼───────────────────┼──────────────┼────────────│   │
│  │  SI      │ SI-10, SI-11      │ HIGH         │ 5          │   │
│  │  IA      │ IA-2, IA-5        │ CRITICAL     │ 3          │   │
│  │  SC      │ SC-8, SC-12, SC-13│ HIGH         │ 4          │   │
│  │  AC      │ AC-3, AC-6        │ MEDIUM       │ 2          │   │
│  │  AU      │ AU-2, AU-3        │ MEDIUM       │ 1          │   │
│  │  SA      │ SA-11             │ HIGH         │ 3          │   │
│  │                                                          │   │
│  │  Click any row to see the specific findings              │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── NIS2 COMPLIANCE TRACKER ──                                   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Overall Readiness: 45%  ████████░░░░░░░░░░              │   │
│  │                                                          │   │
│  │  ✅ Art 21(2)(a) Risk analysis policies    NOT ASSESSED  │   │
│  │  ✅ Art 21(2)(b) Incident handling         NOT ASSESSED  │   │
│  │  ✅ Art 21(2)(c) Business continuity       NOT ASSESSED  │   │
│  │  🔴 Art 21(2)(d) Supply chain security     NON-COMPLIANT │   │
│  │     → 3 findings: hardcoded creds, weak crypto, no HTTPS│   │
│  │  🔴 Art 21(2)(e) Network/info security     NON-COMPLIANT │   │
│  │     → 5 findings: SQLi, XSS, command injection          │   │
│  │  ✅ Art 21(2)(f) Vulnerability assessment  NOT ASSESSED  │   │
│  │  🟡 Art 21(2)(g) Cyber hygiene            NEEDS IMPROVE  │   │
│  │     → 1 finding: insufficient logging                    │   │
│  │  🔴 Art 21(2)(h) Cryptography             NON-COMPLIANT │   │
│  │     → 2 findings: weak hash, cleartext transmission      │   │
│  │  🟡 Art 21(2)(i) Access control           PARTIAL        │   │
│  │     → 2 findings: improper access control, missing authz │   │
│  │  🔴 Art 21(2)(j) Multi-factor auth        NON-COMPLIANT │   │
│  │     → 2 findings: hardcoded creds, missing auth          │   │
│  │  ✅ Art 23 Incident reporting              NOT ASSESSED  │   │
│  │                                                          │   │
│  │  Legend:                                                 │   │
│  │  ✅ Pass / Not Assessed  🟡 Partial  🔴 Non-Compliant   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ── FINDINGS BY SEVERITY ──                                      │
│                                                                  │
│  ┌──────────────────────────┐  ┌────────────────────────────┐   │
│  │ [Severity bar chart]     │  │ [Top findings table]       │   │
│  │ CRITICAL ████ 2          │  │ 1. Hardcoded API key  CRIT │   │
│  │ HIGH     ██████ 3        │  │ 2. SQL Injection      HIGH │   │
│  │ MEDIUM   ████████ 4      │  │ 3. Missing auth       HIGH │   │
│  │ LOW      ██ 1            │  │ 4. No HTTPS           MED  │   │
│  └──────────────────────────┘  └────────────────────────────┘   │
│                                                                  │
│  ── FINDINGS DETAIL TABLE ──                                     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Sev  │ Finding        │ CWE    │ File     │ NIST  │ NIS2 │   │
│  │──────┼────────────────┼────────┼──────────┼───────┼──────│   │
│  │ CRIT │ Hardcoded key  │CWE-798 │config.py │IA-5   │Art21d│   │
│  │ HIGH │ SQL Injection  │CWE-89  │auth.py   │SI-10  │Art21e│   │
│  │ HIGH │ Missing auth   │CWE-306 │api.py    │IA-2   │Art21j│   │
│  │ MED  │ No HTTPS       │CWE-319 │utils.py  │SC-8   │Art21d│   │
│  │ ...                                                      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### No Scan Data State

If no repo has been scanned yet, show:

```
┌─────────────────────────────────────────┐
│                                         │
│  No scan data available.                │
│                                         │
│  Scan a GitHub repository first to      │
│  generate your governance dashboard.    │
│                                         │
│  [Go to Scanner]                        │
│                                         │
└─────────────────────────────────────────┘
```

---

## Part 4: PDF Executive Report

When "Generate PDF Report" is clicked, produce a professional PDF using jspdf.

### PDF Structure

**Page 1: Title Page**
- "THREATLENS" logo text
- "Security Posture & Compliance Report"
- Repository name
- Date generated
- Risk score prominently displayed

**Page 2: Executive Summary**
- Risk Score: X/100 with color indicator
- Total Findings: X (breakdown by severity)
- NIST CSF Average Score: X%
- NIS2 Readiness: X%
- Violated NIST 800-53 Controls: X
- Key insight: 1-2 sentence summary of the worst issues

**Page 3: NIST CSF Maturity**
- Table showing each function's score
- Categories breakdown
- "Assessed from code" vs "Requires additional review" distinction

**Page 4: NIS2 Compliance Status**
- Table: Article | Status | Finding Count | Key Issues
- Overall readiness bar
- Note which articles need policy/process review

**Page 5: NIST 800-53 Violated Controls**
- Table: Control | Family | Findings | Max Severity | Remediation Priority

**Page 6-7: Detailed Findings**
- Each finding: Severity, Name, CWE, File:Line, Explanation, Remediation
- Sorted by severity

**Page 8: Recommendations**
- Top 5 prioritized recommendations derived from findings
- Each recommendation: Priority (1-5), Action, Affected Controls, Estimated Impact

**Footer on every page:**
- "Generated by ThreatLens | Confidential | [Date]"
- Page X of Y

### Generating Recommendations

Derive recommendations automatically from the findings:

```typescript
function generateRecommendations(complianceResult) {
  const recs = [];
  
  // Group findings by category and count
  const categories = {};
  for (const f of complianceResult.findings) {
    const cat = f.category;
    if (!categories[cat]) categories[cat] = { count: 0, maxSeverity: 'LOW', findings: [] };
    categories[cat].count++;
    categories[cat].findings.push(f);
  }
  
  // Generate recommendation per category, sorted by impact
  const recTemplates = {
    secrets: {
      action: "Implement secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager). Remove all hardcoded credentials and rotate compromised keys immediately.",
      controls: ["IA-5", "SC-12"],
    },
    injection: {
      action: "Implement parameterized queries and input validation across all data entry points. Conduct developer training on secure coding practices.",
      controls: ["SI-10", "SA-11"],
    },
    auth: {
      action: "Implement proper authentication and authorization framework. Add multi-factor authentication for privileged operations. Review access control model.",
      controls: ["IA-2", "AC-3", "AC-6"],
    },
    crypto: {
      action: "Upgrade all cryptographic implementations to current standards (AES-256, SHA-256+). Replace weak hash algorithms. Enforce TLS 1.2+ for all communications.",
      controls: ["SC-12", "SC-13"],
    },
    transport: {
      action: "Enforce HTTPS/TLS for all network communications. Implement HSTS headers. Remove all plaintext HTTP endpoints.",
      controls: ["SC-8", "SC-23"],
    },
    data: {
      action: "Implement data classification and handling procedures. Add input validation for all deserialization and file handling operations.",
      controls: ["SI-10", "MP-4"],
    },
    config: {
      action: "Disable debug mode in production. Implement security configuration baseline. Add automated configuration compliance checking.",
      controls: ["CM-6", "CM-7"],
    },
    logic: {
      action: "Conduct thorough security design review of authentication and authorization flows. Implement automated security testing in CI/CD pipeline.",
      controls: ["SA-11", "SA-15"],
    },
  };
  
  for (const [cat, data] of Object.entries(categories).sort((a, b) => b[1].count - a[1].count)) {
    const template = recTemplates[cat];
    if (template) {
      recs.push({
        priority: recs.length + 1,
        category: cat,
        action: template.action,
        affectedControls: template.controls,
        findingCount: data.count,
        impact: data.count >= 3 ? 'High' : data.count >= 2 ? 'Medium' : 'Low',
      });
    }
  }
  
  return recs.slice(0, 5); // Top 5
}
```

---

## Part 5: Navigation Integration

Add "Governance" to the ThreatLens navigation:

- In the main header/nav bar, add: **Scan | Dashboard | Governance**
- "Governance" links to `/dashboard/governance`
- Show a badge on the Governance nav item if scan data exists: "Ready" in amber
- If no scan data, the badge says "No data" in gray

After a scan completes (from the quick action buttons or agentic pipeline), show a toast/banner:

"Scan complete. View your Governance Dashboard →"

with a link to `/dashboard/governance`.

---

## Checklist

- [ ] CWE-to-compliance mapping table created with 30+ CWE entries
- [ ] NIST CSF structure reference file created
- [ ] NIS2 articles reference file created with assessable_from_code flags
- [ ] complianceMapper.ts maps findings → NIST 800-53, CSF, NIS2 correctly
- [ ] Risk score calculation works (0-100 scale)
- [ ] Governance dashboard page renders at /dashboard/governance
- [ ] Executive summary stat cards show risk score, findings count, CSF score, NIS2 readiness, violated controls
- [ ] NIST CSF section shows function scores with "N/A" for non-code-assessable functions
- [ ] NIST 800-53 table shows violated control families with finding counts
- [ ] NIS2 tracker shows each article's status (Pass/Partial/Non-Compliant/Not Assessed)
- [ ] "Not Assessed" articles clearly state they need policy review
- [ ] Findings severity chart renders
- [ ] Findings detail table is sortable and shows CWE, NIST, NIS2 mappings
- [ ] PDF report generates with all sections
- [ ] PDF looks professional enough for a governance board
- [ ] Empty state shown when no scan data exists
- [ ] Navigation includes Governance link
- [ ] Post-scan toast directs users to governance dashboard
- [ ] Everything follows dark charcoal Papercut Layers theme

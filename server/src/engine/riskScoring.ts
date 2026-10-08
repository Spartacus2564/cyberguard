import { Finding, Severity } from '../types';

const SEVERITY_BASE: Record<Severity, number> = {
  [Severity.CRITICAL]: 10,
  [Severity.HIGH]: 7,
  [Severity.MEDIUM]: 4,
  [Severity.LOW]: 2,
  [Severity.INFO]: 0,
};

const SEVERITY_PENALTY: Record<Severity, number> = {
  [Severity.CRITICAL]: 8,
  [Severity.HIGH]: 4,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 0.5,
  [Severity.INFO]: 0,
};

const MAX_FINDINGS_PER_SEVERITY: Record<Severity, number> = {
  [Severity.CRITICAL]: 3,
  [Severity.HIGH]: 5,
  [Severity.MEDIUM]: 10,
  [Severity.LOW]: 15,
  [Severity.INFO]: Infinity,
};

const CATEGORY_WEIGHTS: Record<string, number> = {
  'TLS/HTTPS': 1.4,
  'TLS/SSL Deep': 1.4,
  'Security Headers': 1.2,
  'DNS Security': 1.1,
  'DNS Deep': 1.1,
  'Email Security': 1.15,
  'Port Scan': 1.0,
  'Web Configuration': 1.0,
  'Technology Detection': 0.8,
  'Subdomain Discovery': 0.9,
  'Subdomain Takeover': 1.3,
  'Active Vulnerability': 1.5,
  'CVE Correlation': 1.3,
  'OS Fingerprinting': 0.9,
  'Site Crawl': 1.0,
  'SQL Injection': 1.5,
  'Cross-Site Scripting': 1.2,
  'Open Redirect': 1.0,
  'Path Traversal': 1.4,
  'Header Injection': 1.1,
  'CSRF': 1.2,
  'Information Disclosure': 0.8,
  'Service Detection': 0.7,
  'Certificate Transparency': 1.1,
  'Authentication': 1.5,
  'Service Exposure': 1.3,
  'Transport Layer Security': 1.4,
  'HTTP Method Security': 1.1,
  'API Security': 1.4,
  'Supply Chain Security': 1.2,
  'Cloud Security': 1.3,
  'Client-Side Security': 1.2,
  'Race Condition': 1.2,
  'Second-Order Injection': 1.4,
  'Authenticated Scanning': 1.5,
};

const CATEGORY_DESCRIPTIONS: Record<string, string> = {
  'TLS/HTTPS': 'Encryption and transport security',
  'TLS/SSL Deep': 'Advanced TLS cipher and protocol analysis',
  'Security Headers': 'HTTP security header configuration',
  'DNS Security': 'DNS configuration and security extensions',
  'DNS Deep': 'Advanced DNS security analysis',
  'Email Security': 'Email authentication (SPF/DKIM/DMARC)',
  'Port Scan': 'Network exposure and open ports',
  'Web Configuration': 'Web server configuration and information disclosure',
  'Technology Detection': 'Technology stack identification',
  'Subdomain Discovery': 'Attack surface enumeration',
  'Subdomain Takeover': 'Subdomain takeover vulnerabilities',
  'Active Vulnerability': 'Active vulnerability testing (SQLi, XSS, etc.)',
  'CVE Correlation': 'Known vulnerability correlation',
  'OS Fingerprinting': 'Operating system and service detection',
  'Site Crawl': 'Web application crawling and analysis',
  'SQL Injection': 'SQL injection vulnerabilities',
  'Cross-Site Scripting': 'Cross-site scripting vulnerabilities',
  'Open Redirect': 'Open redirect vulnerabilities',
  'Path Traversal': 'Path traversal / directory traversal',
  'Header Injection': 'HTTP header injection / CRLF injection',
  'CSRF': 'Cross-site request forgery',
  'Information Disclosure': 'Sensitive information exposure',
  'Service Detection': 'Network service identification',
  'Certificate Transparency': 'Certificate transparency compliance',
  'Authentication': 'Authentication and session security',
  'Service Exposure': 'Publicly accessible infrastructure services',
  'Transport Layer Security': 'Transport and credential transmission security',
  'HTTP Method Security': 'HTTP method configuration and verb tampering',
  'API Security': 'API authentication, authorization, and rate limiting',
  'Supply Chain Security': 'Third-party dependencies and build pipeline security',
  'Cloud Security': 'Cloud infrastructure and metadata security',
  'Client-Side Security': 'Browser-side security controls and DOM safety',
  'Race Condition': 'Concurrency and time-of-check-time-of-use vulnerabilities',
  'Second-Order Injection': 'Stored and delayed injection attacks',
  'Authenticated Scanning': 'Post-authentication vulnerability testing',
};

const COMPLIANCE_FRAMEWORKS: Record<string, Record<string, string[]>> = {
  'OWASP Top 10 2021': {
    'A01 - Broken Access Control': ['CSRF', 'Path Traversal', 'Open Redirect', 'Subdomain Takeover', 'Authentication', 'HTTP Method Security', 'Authenticated Scanning'],
    'A02 - Cryptographic Failures': ['TLS/HTTPS', 'TLS/SSL Deep', 'Certificate Transparency'],
    'A03 - Injection': ['SQL Injection', 'Cross-Site Scripting', 'Active Vulnerability', 'Header Injection', 'Second-Order Injection'],
    'A04 - Insecure Design': ['Web Configuration', 'Site Crawl', 'Race Condition'],
    'A05 - Security Misconfiguration': ['Security Headers', 'DNS Security', 'DNS Deep', 'Email Security', 'Port Scan', 'Web Configuration', 'Service Exposure', 'HTTP Method Security', 'Cloud Security'],
    'A06 - Vulnerable Components': ['CVE Correlation', 'Technology Detection', 'Supply Chain Security'],
    'A07 - Auth Failures': ['Active Vulnerability', 'Site Crawl', 'Authentication', 'Authenticated Scanning', 'Client-Side Security'],
    'A08 - Data Integrity': ['Technology Detection', 'Site Crawl', 'Supply Chain Security'],
    'A09 - Logging': ['Information Disclosure', 'OS Fingerprinting'],
    'A10 - SSRF': ['Subdomain Discovery', 'Subdomain Takeover', 'Cloud Security'],
  },
  'NIST CSF 2.0': {
    'PR.DS - Data Security': ['TLS/HTTPS', 'TLS/SSL Deep', 'Certificate Transparency'],
    'PR.AC - Access Control': ['CSRF', 'Path Traversal', 'Security Headers'],
    'PR.IP - Info Protection': ['Information Disclosure', 'Web Configuration'],
    'DE.CM - Continuous Monitoring': ['Port Scan', 'DNS Security', 'DNS Deep'],
    'DE.AE - Anomaly Detection': ['Active Vulnerability', 'Site Crawl'],
    'RS.RP - Response Planning': ['Email Security', 'OS Fingerprinting'],
    'RC.CO - Communications': ['Technology Detection', 'CVE Correlation'],
  },
  'PCI DSS 4.0': {
    'Req 1 - Network Controls': ['Port Scan', 'OS Fingerprinting'],
    'Req 2 - Secure Config': ['Security Headers', 'Web Configuration', 'DNS Security'],
    'Req 3 - Protect Data': ['TLS/HTTPS', 'TLS/SSL Deep'],
    'Req 4 - Encrypt Trans': ['TLS/HTTPS', 'TLS/SSL Deep'],
    'Req 6 - Secure Systems': ['CVE Correlation', 'Active Vulnerability', 'Technology Detection'],
    'Req 8 - Identify Users': ['CSRF', 'Site Crawl'],
    'Req 10 - Log Access': ['Information Disclosure'],
    'Req 11 - Test Security': ['Subdomain Discovery', 'Subdomain Takeover'],
  },
};

interface SecurityScoreResult {
  score: number;
  grade: string;
  gradeLabel: string;
  riskLevel: string;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  categoryScores: Record<string, { score: number; weight: number; findings: number }>;
  complianceMapping: Record<string, { passed: number; failed: number; total: number; percentage: number }>;
  complianceFrameworkResults: Record<string, Record<string, { passed: boolean; findings: Finding[] }>>;
  scoringBreakdown: ScoringBreakdown[];
}

interface ScoringBreakdown {
  findingId: string;
  title: string;
  severity: Severity;
  category: string;
  baseDeduction: number;
  adjustedDeduction: number;
  cumulativeScore: number;
}

function calculateSecurityScore(findings: Finding[]): SecurityScoreResult {
  let score = 100;

  const severityCounts: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const categoryFindings: Record<string, number> = {};
  const categoryPenalties: Record<string, number> = {};

  for (const finding of findings) {
    severityCounts[finding.severity]++;

    const weight = CATEGORY_WEIGHTS[finding.category] ?? 1.0;
    const basePenalty = SEVERITY_PENALTY[finding.severity];
    const count = severityCounts[finding.severity];
    const maxForSeverity = MAX_FINDINGS_PER_SEVERITY[finding.severity];

    let penalty: number;
    if (count <= maxForSeverity) {
      penalty = basePenalty * weight;
    } else {
      const diminishingFactor = maxForSeverity / count;
      penalty = basePenalty * weight * diminishingFactor;
    }

    score -= penalty;

    if (!categoryFindings[finding.category]) {
      categoryFindings[finding.category] = 0;
      categoryPenalties[finding.category] = 0;
    }
    categoryFindings[finding.category]++;
    categoryPenalties[finding.category] += penalty;
  }

  score = Math.max(0, Math.min(100, score));

  const categoryScores: Record<string, { score: number; weight: number; findings: number }> = {};
  for (const [category, findingsCount] of Object.entries(categoryFindings)) {
    const penalty = categoryPenalties[category] || 0;
    const catScore = Math.max(0, 100 - penalty * 5);
    categoryScores[category] = {
      score: Math.round(catScore),
      weight: CATEGORY_WEIGHTS[category] ?? 1.0,
      findings: findingsCount,
    };
  }

  const complianceMapping = buildComplianceMapping(findings);
  const complianceFrameworkResults = buildComplianceFrameworkResults(findings);
  const scoringBreakdown = generateScoringBreakdown(findings);

  return {
    score: Math.round(score * 10) / 10,
    grade: getGrade(score),
    gradeLabel: getGradeLabel(score),
    riskLevel: getRiskLevel(score),
    breakdown: {
      critical: severityCounts[Severity.CRITICAL],
      high: severityCounts[Severity.HIGH],
      medium: severityCounts[Severity.MEDIUM],
      low: severityCounts[Severity.LOW],
      info: severityCounts[Severity.INFO],
    },
    categoryScores,
    complianceMapping,
    complianceFrameworkResults,
    scoringBreakdown,
  };
}

function buildComplianceMapping(findings: Finding[]): Record<string, { passed: number; failed: number; total: number; percentage: number }> {
  const categoriesWithChecks = Object.keys(CATEGORY_WEIGHTS);
  const mapping: Record<string, { passed: number; failed: number; total: number; percentage: number }> = {};

  for (const category of categoriesWithChecks) {
    const catFindings = findings.filter(f => f.category === category);
    const nonInfoFindings = catFindings.filter(f => f.severity !== Severity.INFO);
    const failed = nonInfoFindings.length;
    const passed = Math.max(0, 10 - failed);
    const total = passed + failed;
    mapping[category] = {
      passed,
      failed,
      total,
      percentage: total > 0 ? Math.round((passed / total) * 100) : 100,
    };
  }

  return mapping;
}

function buildComplianceFrameworkResults(findings: Finding[]): Record<string, Record<string, { passed: boolean; findings: Finding[] }>> {
  const results: Record<string, Record<string, { passed: boolean; findings: Finding[] }>> = {};

  for (const [framework, controls] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
    results[framework] = {};
    for (const [control, categories] of Object.entries(controls)) {
      const controlFindings = findings.filter(f =>
        categories.includes(f.category) && f.severity !== Severity.INFO
      );
      results[framework][control] = {
        passed: controlFindings.length === 0,
        findings: controlFindings,
      };
    }
  }

  return results;
}

function getGrade(score: number): string {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 85) return 'A-';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'B-';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 55) return 'C-';
  if (score >= 50) return 'D+';
  if (score >= 40) return 'D';
  if (score >= 30) return 'D-';
  return 'F';
}

function getGradeLabel(score: number): string {
  if (score >= 95) return 'Excellent';
  if (score >= 90) return 'Very Good';
  if (score >= 80) return 'Good';
  if (score >= 70) return 'Above Average';
  if (score >= 60) return 'Average';
  if (score >= 50) return 'Below Average';
  if (score >= 40) return 'Poor';
  return 'Critical';
}

function getRiskLevel(score: number): string {
  if (score >= 90) return 'Minimal Risk';
  if (score >= 80) return 'Low Risk';
  if (score >= 70) return 'Moderate Risk';
  if (score >= 60) return 'Elevated Risk';
  if (score >= 50) return 'High Risk';
  if (score >= 30) return 'Severe Risk';
  return 'Critical Risk';
}

function generateScoringBreakdown(findings: Finding[]): ScoringBreakdown[] {
  const breakdown: ScoringBreakdown[] = [];
  let currentScore = 100;

  const severityCounts: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const sortedFindings = [...findings].sort((a, b) => {
    const order: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 1,
      [Severity.MEDIUM]: 2,
      [Severity.LOW]: 3,
      [Severity.INFO]: 4,
    };
    return order[a.severity] - order[b.severity];
  });

  for (const finding of sortedFindings) {
    severityCounts[finding.severity]++;

    const weight = CATEGORY_WEIGHTS[finding.category] ?? 1.0;
    const basePenalty = SEVERITY_PENALTY[finding.severity];
    const baseDeduction = basePenalty * weight;

    const count = severityCounts[finding.severity];
    const maxForSeverity = MAX_FINDINGS_PER_SEVERITY[finding.severity];

    let adjustedDeduction: number;
    if (count <= maxForSeverity) {
      adjustedDeduction = baseDeduction;
    } else {
      const diminishingFactor = maxForSeverity / count;
      adjustedDeduction = baseDeduction * diminishingFactor;
    }

    currentScore = Math.max(0, currentScore - adjustedDeduction);

    breakdown.push({
      findingId: finding.id,
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      baseDeduction: Math.round(baseDeduction * 10) / 10,
      adjustedDeduction: Math.round(adjustedDeduction * 10) / 10,
      cumulativeScore: Math.round(currentScore * 10) / 10,
    });
  }

  return breakdown;
}

function calculateCvssLikeScore(severity: Severity, category: string): number {
  const weight = CATEGORY_WEIGHTS[category] ?? 1.0;
  const normalizedWeight = 0.7 + (weight - 1.0) * 0.3;

  const ranges: Record<Severity, [number, number]> = {
    [Severity.CRITICAL]: [9.0, 10.0],
    [Severity.HIGH]: [7.0, 8.9],
    [Severity.MEDIUM]: [4.0, 6.9],
    [Severity.LOW]: [0.1, 3.9],
    [Severity.INFO]: [0.0, 0.0],
  };

  const [min, max] = ranges[severity];
  if (severity === Severity.INFO) return 0.0;

  const seed = hashString(severity + category);
  const baseScore = min + (seed % 100) / 100 * (max - min);
  const adjustedScore = baseScore * normalizedWeight;

  return Math.round(Math.min(max, Math.max(min, adjustedScore)) * 10) / 10;
}

function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash) % 100;
}

function calculateFindingScore(finding: Finding): number {
  const base = SEVERITY_BASE[finding.severity];
  const weight = CATEGORY_WEIGHTS[finding.category] ?? 1.0;
  return base * weight;
}

export {
  calculateFindingScore,
  calculateSecurityScore,
  getGrade,
  getGradeLabel,
  getRiskLevel,
  generateScoringBreakdown,
  calculateCvssLikeScore,
  buildComplianceMapping,
  buildComplianceFrameworkResults,
  SecurityScoreResult,
  ScoringBreakdown,
  SEVERITY_BASE,
  SEVERITY_PENALTY,
  MAX_FINDINGS_PER_SEVERITY,
  CATEGORY_WEIGHTS,
  CATEGORY_DESCRIPTIONS,
  COMPLIANCE_FRAMEWORKS,
};

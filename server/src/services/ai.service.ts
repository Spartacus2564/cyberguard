import { Finding, Severity, ScanModule, ScanResult } from '../types';
import { config } from '../config';
import logger from '../utils/logger';
import { MidScanInsight } from '../engine';
import { 
  AttackGraphContext, AttackGraph, AttackGraphNode, AttackGraphEdge, AttackGraphPath, MitreCoverage,
  ReasoningContext, ReasoningResult, ReasoningAction, Hypothesis, PivotOpportunity,
  PivotContext, PivotChain, PivotStep,
  ValidationContext, ValidationResult, RetestPlan,
  ChecklistContext, PreExploitChecklist, ChecklistPhase, ChecklistItem,
  AttackSurfaceTarget, AttackVector, PriorityVector, AttackSurfaceMap,
  DetectedService, Credential, NetworkSegment, HostInfo,
  TargetType
} from './reasoningTypes';

// Re-export types from reasoningTypes for backward compatibility
export type { 
  AttackGraphContext, AttackGraph, AttackGraphNode, AttackGraphEdge, AttackGraphPath, MitreCoverage,
  ReasoningContext, ReasoningResult, ReasoningAction, Hypothesis, PivotOpportunity,
  PivotContext, PivotChain, PivotStep,
  ValidationContext, ValidationResult, RetestPlan, RetestResult, RetestSummary,
  ChecklistContext, PreExploitChecklist, ChecklistPhase, ChecklistItem,
  AttackSurfaceTarget, AttackVector, PriorityVector, AttackSurfaceMap,
  DetectedService, Credential, NetworkSegment, HostInfo,
  CredentialType, CredentialAccessLevel, TargetType,
  AttackNode, AttackEdge, AttackPath
} from './reasoningTypes';

// ─── Types ───

export interface AIProvider {
  summarize(text: string): Promise<string>;
  explainFinding(finding: Finding): Promise<{
    executiveSummary: string;
    businessImpact: string;
    remediation: string;
  }>;
  generateExecutiveSummary(findings: Finding[], domain: string): Promise<string>;
  prioritizeRemediation(findings: Finding[]): Promise<string[]>;
  analyzeVulnerabilityChains(findings: Finding[], domain: string): Promise<VulnerabilityChain[]>;
  generateAttackNarrative(findings: Finding[], domain: string): Promise<string>;
  classifyExploitability(finding: Finding): Promise<ExploitabilityInfo>;
  generateRemediationPlan(findings: Finding[], domain: string): Promise<RemediationPhase[]>;
  deduplicateFindings(findings: Finding[]): Promise<Finding[]>;
  adjustSeverityWithContext(findings: Finding[], context: string): Promise<Finding[]>;
  generateContextualPayloads(context: string, attackType: string): Promise<string[]>;
  enrichFindingEvidence(finding: Finding, context: string): Promise<Finding>;
  generateServiceAuditPayloads(service: string, version: string): Promise<string[]>;
  chat(messages: { role: string; content: string }[]): Promise<string>;
  generateNovelPayloads(techStack: string[], version: string, attackType: string): Promise<string[]>;
  reasonAboutVulnerabilities(techStack: string[], findings: Finding[]): Promise<VulnerabilityReasoning>;
  // ─── NEW: Scan-time AI orchestration ───────────────────────────────────
  assessReconForAttacks(reconSummary: ReconSummary): Promise<AttackRecommendations>;
  triageAndEnrichFindings(findings: Finding[], domain: string, reconContext: string): Promise<{ findings: Finding[]; chains: VulnerabilityChain[]; attackNarrative: string; remediationPlan: RemediationPhase[] }>;
  scoreFindingCvss(finding: Finding): Promise<number>;
  reasonMidScan(findings: Finding[], domain: string): Promise<MidScanInsight[]>;
  // ─── NEW: Module-specific AI analysis ──────────────────────────────────
  filterFalsePositives(findings: Finding[], domain: string): Promise<Finding[]>;
  analyzeRedirect(url: string, redirectChain: { url: string; statusCode: number; location: string }[], finalUrl: string, domain: string): Promise<{ isMalicious: boolean; explanation: string; confidence: number }>;
  analyzeHeaders(headers: Record<string, string>, domain: string, body: string): Promise<{ findings: Partial<Finding>[] }>;
  analyzeTls(certInfo: { subject: string; issuer: string; validFrom: string; validTo: string; sans: string[]; protocol: string; cipher: string }, domain: string): Promise<{ findings: Partial<Finding>[] }>;
  analyzeSiteCrawl(urls: { url: string; status: number; contentLength: number; isSpa: boolean }[], domain: string, techStack: string[]): Promise<{ findings: Partial<Finding>[] }>;
  analyzeWebConfig(configs: { path: string; status: number; contentType: string; snippet: string }[], domain: string): Promise<{ findings: Partial<Finding>[] }>;
  analyzeSmarterRecon(hypotheses: { title: string; confidence: number; status: string; evidence: string }[], domain: string, techStack: string[]): Promise<{ validated: { title: string; confidence: number; reasoning: string }[] }>;
  analyzeDeepDiscovery(discoveries: { url: string; status: number; size: number; type: string }[], domain: string): Promise<{ findings: Partial<Finding>[] }>;
  // ─── NEW: Reasoning Engine & Universal Attack Surface ───────────────────
  buildAttackGraph(context: AttackGraphContext): Promise<AttackGraph>;
  reasonNextSteps(context: ReasoningContext): Promise<ReasoningResult>;
  enumerateAttackSurface(target: AttackSurfaceTarget): Promise<AttackSurfaceMap>;
  detectPivotChains(context: PivotContext): Promise<PivotChain[]>;
  validateFinding(finding: Finding, context: ValidationContext): Promise<ValidationResult>;
  generatePreExploitChecklist(targetType: string, context: ChecklistContext): Promise<PreExploitChecklist>;
}

export interface DeduplicationResult {
  kept: Finding[];
  merged: { into: string; from: string[] }[];
}

export interface SeverityAdjustment {
  findingTitle: string;
  originalSeverity: string;
  adjustedSeverity: string;
  rationale: string;
}

export interface ReconSummary {
  domain: string;
  techStack: string[];
  openPorts: number[];
  headers: string;
  tlsInfo: string;
  dnsInfo: string;
  subdomains: string[];
}

export interface AttackRecommendations {
  priorityAttacks: string[];
  focusParams: string[];
  likelyVulnTypes: string[];
  wafLikely: boolean;
  authRequired: boolean;
  apiDetected: boolean;
  frameworkSpecificTests: string[];
  rationale: string;
}

export interface VulnerabilityChain {
  title: string;
  description: string;
  severity: Severity;
  findings: string[];
  attackPath: string[];
  impact: string;
  severityRationale?: string;
}

export interface ExploitabilityInfo {
  score: number;
  vector: string;
  complexity: string;
  requiresAuth: boolean;
  userInteraction: boolean;
  privilegesRequired: string;
  lateralMovement: boolean;
}

export interface VulnerabilityReasoning {
  novelAttackVectors: string[];
  versionSpecificRisks: string[];
  bypassTechniques: string[];
  chainingOpportunities: string[];
  zeroDayIndicators: string[];
}

export interface RemediationPhase {
  phase: string;
  timeframe: string;
  findings: string[];
  actions: string[];
  riskReduction: string;
}

export interface TriageResult {
  findings: Finding[];
  chains: VulnerabilityChain[];
  attackNarrative: string;
  remediationPlan: RemediationPhase[];
}

// ─── NEW: Reasoning Engine Types ───────────────────────────────────────────

// ─── Types imported from reasoningTypes ───
// TargetType, AttackGraphContext, DetectedService, Credential, NetworkSegment, HostInfo,
// AttackGraphContext, AttackGraph, AttackGraphNode, AttackGraphEdge, AttackGraphPath, MitreCoverage,
// ReasoningContext, ReasoningResult, ReasoningAction, Hypothesis, PivotOpportunity,
// PivotContext, PivotChain, PivotStep, ValidationContext, ValidationResult, RetestPlan,
// ChecklistContext, PreExploitChecklist, ChecklistPhase, ChecklistItem,
// AttackSurfaceTarget, AttackVector, PriorityVector, AttackSurfaceMap,
// DetectedService, Credential, NetworkSegment, HostInfo, TargetType
// are all imported from './reasoningTypes'
// ─── Types imported from reasoningTypes ───
// AttackGraph, AttackNode, AttackEdge, AttackPath, MitreCoverage,
// AttackGraphContext, AttackNode, AttackEdge, AttackPath, MitreCoverage,
// ReasoningContext, ReasoningResult, ReasoningAction, Hypothesis,
// PivotOpportunity, PivotContext, PivotChain, PivotStep,
// ValidationContext, ValidationResult, RetestPlan,
// ChecklistContext, PreExploitChecklist, ChecklistPhase, ChecklistItem,
// AttackSurfaceTarget, AttackVector, PriorityVector, AttackSurfaceMap,
// TargetType, DetectedService, Credential, NetworkSegment, HostInfo, MitreCoverage
// are all imported from './reasoningTypes'

const SEVERITY_BUSINESS_LANGUAGE: Record<Severity, string> = {
  [Severity.CRITICAL]: 'poses an immediate and severe risk',
  [Severity.HIGH]: 'presents a significant security risk',
  [Severity.MEDIUM]: 'represents a moderate security concern',
  [Severity.LOW]: 'presents a minor security concern',
  [Severity.INFO]: 'is an informational observation',
};

const SEVERITY_URGENCY: Record<Severity, string> = {
  [Severity.CRITICAL]: 'requires immediate remediation',
  [Severity.HIGH]: 'should be addressed urgently',
  [Severity.MEDIUM]: 'should be addressed in a timely manner',
  [Severity.LOW]: 'can be addressed during routine maintenance',
  [Severity.INFO]: 'is noted for awareness',
};

class TemplateProvider implements AIProvider {
  async summarize(text: string): Promise<string> {
    const sentences = text.split(/[.!?]+/).filter((s) => s.trim().length > 0);
    const summary = sentences.slice(0, 3).join('. ').trim();
    return summary + (summary.endsWith('.') ? '' : '.');
  }

  async explainFinding(finding: Finding): Promise<{
    executiveSummary: string;
    businessImpact: string;
    remediation: string;
  }> {
    const businessLang = SEVERITY_BUSINESS_LANGUAGE[finding.severity];
    const urgency = SEVERITY_URGENCY[finding.severity];
    return {
      executiveSummary: `The ${finding.category.toLowerCase()} finding "${finding.title}" ${businessLang} to the target environment. ${finding.description}`,
      businessImpact: `This issue ${businessLang}. ${finding.impact} If left unaddressed, it could lead to unauthorized access, data compromise, or service disruption.`,
      remediation: `${finding.remediation} ${urgency.charAt(0).toUpperCase() + urgency.slice(1)}.`,
    };
  }

  async generateExecutiveSummary(findings: Finding[], domain: string): Promise<string> {
    const total = findings.length;
    const critical = findings.filter(f => f.severity === Severity.CRITICAL).length;
    const high = findings.filter(f => f.severity === Severity.HIGH).length;
    const medium = findings.filter(f => f.severity === Severity.MEDIUM).length;
    const low = findings.filter(f => f.severity === Severity.LOW).length;
    const info = findings.filter(f => f.severity === Severity.INFO).length;

    const parts: string[] = [];
    parts.push(`The security assessment of ${domain} identified ${total} finding(s) across multiple security domains.`);
    if (critical > 0) parts.push(`${critical} critical finding(s) require immediate attention as they pose severe risks to confidentiality, integrity, or availability.`);
    if (high > 0) parts.push(`${high} high-severity finding(s) present significant risks that should be addressed promptly.`);
    if (medium > 0) parts.push(`${medium} medium-severity finding(s) represent moderate security concerns.`);
    if (low > 0) parts.push(`${low} low-severity finding(s) are minor issues.`);
    if (info > 0) parts.push(`${info} informational finding(s) are noted for awareness.`);

    const categories = [...new Set(findings.map(f => f.category))];
    if (categories.length > 0) parts.push(`Findings span: ${categories.join(', ')}.`);
    return parts.join(' ');
  }

  async prioritizeRemediation(findings: Finding[]): Promise<string[]> {
    const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return [...findings]
      .sort((a, b) => order[a.severity] - order[b.severity])
      .map(f => `[${f.severity}] ${f.title} - ${SEVERITY_URGENCY[f.severity]}`);
  }

  async analyzeVulnerabilityChains(findings: Finding[], domain: string): Promise<VulnerabilityChain[]> {
    return [];
  }

  async generateAttackNarrative(findings: Finding[], domain: string): Promise<string> {
    return `Analysis of ${domain} identified ${findings.length} security findings that could be chained together by an attacker.`;
  }

  async classifyExploitability(finding: Finding): Promise<ExploitabilityInfo> {
    return { score: 5, vector: 'NETWORK', complexity: 'MEDIUM', requiresAuth: false, userInteraction: false, privilegesRequired: 'NONE', lateralMovement: false };
  }

  async generateRemediationPlan(findings: Finding[], domain: string): Promise<RemediationPhase[]> {
    const critical = findings.filter(f => f.severity === Severity.CRITICAL);
    const high = findings.filter(f => f.severity === Severity.HIGH);
    const medium = findings.filter(f => f.severity === Severity.MEDIUM);
    const low = findings.filter(f => f.severity === Severity.LOW || f.severity === Severity.INFO);

    const phases: RemediationPhase[] = [];
    if (critical.length) phases.push({ phase: 'Phase 1 - Immediate', timeframe: '0-24 hours', findings: critical.map(f => f.title), actions: ['Block public access if needed', 'Apply emergency patches', 'Implement WAF rules'], riskReduction: 'Critical' });
    if (high.length) phases.push({ phase: 'Phase 2 - Urgent', timeframe: '1-7 days', findings: high.map(f => f.title), actions: ['Implement security headers', 'Fix authentication flaws', 'Patch injection vulnerabilities'], riskReduction: 'High' });
    if (medium.length) phases.push({ phase: 'Phase 3 - Scheduled', timeframe: '1-4 weeks', findings: medium.map(f => f.title), actions: ['Implement CSP', 'Fix cookie flags', 'Add rate limiting'], riskReduction: 'Medium' });
    if (low.length) phases.push({ phase: 'Phase 4 - Backlog', timeframe: '1-3 months', findings: low.map(f => f.title), actions: ['Remove information disclosure', 'Harden configurations', 'Update dependencies'], riskReduction: 'Low' });
    return phases;
  }

  async deduplicateFindings(findings: Finding[]): Promise<Finding[]> {
    // Simple dedup by title similarity
    const seen = new Map<string, Finding>();
    for (const f of findings) {
      const key = f.title.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!seen.has(key)) seen.set(key, f);
    }
    return Array.from(seen.values());
  }

  async adjustSeverityWithContext(findings: Finding[], _context: string): Promise<Finding[]> {
    return findings;
  }

  async generateContextualPayloads(_context: string, _attackType: string): Promise<string[]> {
    return [];
  }

  async enrichFindingEvidence(finding: Finding, _context: string): Promise<Finding> {
    return finding;
  }

  async generateServiceAuditPayloads(_service: string, _version: string): Promise<string[]> {
    return [];
  }

  async generateNovelPayloads(techStack: string[], version: string, attackType: string): Promise<string[]> {
    const stack = techStack.join(', ');
    return [
      `<script>alert(1)</script>`,
      `{{7*7}}`,
      `${"' OR 1=1 --"}`,
      `../../etc/passwd`,
      `; ls -la`,
    ];
  }

  async reasonAboutVulnerabilities(_techStack: string[], _findings: Finding[]): Promise<VulnerabilityReasoning> {
    return {
      novelAttackVectors: [],
      versionSpecificRisks: [],
      bypassTechniques: [],
      chainingOpportunities: [],
      zeroDayIndicators: [],
    };
  }

  async assessReconForAttacks(_reconSummary: ReconSummary): Promise<AttackRecommendations> {
    return {
      priorityAttacks: ['activeVuln', 'brokenAuth', 'advancedAttacks', 'apiSecurity', 'httpMethods', 'serviceAudit', 'siteCrawl', 'subdomainTakeover'],
      focusParams: ['id', 'user', 'token', 'redirect', 'file'],
      likelyVulnTypes: ['SQLi', 'XSS', 'SSRF'],
      wafLikely: false,
      authRequired: false,
      apiDetected: false,
      frameworkSpecificTests: [],
      rationale: 'Default prioritization (template provider)',
    };
  }

  async triageAndEnrichFindings(
    findings: Finding[],
    domain: string,
    _reconContext: string,
  ): Promise<{ findings: Finding[]; chains: VulnerabilityChain[]; attackNarrative: string; remediationPlan: RemediationPhase[] }> {
    const deduped = await this.deduplicateFindings(findings);
    const chains = await this.analyzeVulnerabilityChains(deduped, domain);
    const narrative = await this.generateAttackNarrative(deduped, domain);
    const remPlan = await this.generateRemediationPlan(deduped, domain);
    return { findings: deduped, chains, attackNarrative: narrative, remediationPlan: remPlan };
  }

  async chat(messages: { role: string; content: string }[]): Promise<string> {
    const last = messages[messages.length - 1];
    return `I received your message: "${last.content}". AI chat requires Ollama to be running. Please ensure Ollama is started and the model is available.`;
  }

  async scoreFindingCvss(finding: Finding): Promise<number> {
    const fallback: Record<string, number> = { CRITICAL: 9.0, HIGH: 7.5, MEDIUM: 5.0, LOW: 2.5, INFO: 0.0 };
    return fallback[finding.severity] ?? 5.0;
  }

  async reasonMidScan(findings: Finding[], domain: string): Promise<MidScanInsight[]> {
    const insights: MidScanInsight[] = [];

    const criticalCount = findings.filter(f => f.severity === Severity.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === Severity.HIGH).length;

    if (criticalCount > 0) {
      insights.push({
        type: 'risk_update',
        title: 'Critical vulnerabilities detected',
        description: `${criticalCount} critical finding(s) detected. These require immediate attention and could lead to full system compromise.`,
        severity: 'CRITICAL',
        confidence: 0.9,
      });
    } else if (highCount > 0) {
      insights.push({
        type: 'risk_update',
        title: 'High-severity vulnerabilities detected',
        description: `${highCount} high-severity finding(s) detected. These present significant risk and should be prioritized.`,
        severity: 'HIGH',
        confidence: 0.85,
      });
    }

    const categories = [...new Set(findings.map(f => f.category))];
    if (categories.includes('Authentication') && categories.includes('Information Disclosure')) {
      insights.push({
        type: 'chain_detected',
        title: 'Potential attack chain: Info Disclosure + Auth Weakness',
        description: 'Information disclosure combined with authentication weaknesses may allow credential harvesting and unauthorized access.',
        confidence: 0.75,
        relatedModules: ['brokenAuth', 'activeVuln'],
      });
    }

    const techFindings = findings.filter(f => f.category === 'Technology Detection');
    if (techFindings.length > 0) {
      const techs = techFindings.map(f => f.title).join(', ');
      insights.push({
        type: 'recommendation',
        title: 'Technology stack identified',
        description: `Detected: ${techs}. Focusing subsequent modules on technology-specific attack vectors.`,
        confidence: 0.85,
      });
    }

    return insights;
  }

  // Stub implementations for new interface methods
  async filterFalsePositives(findings: Finding[]): Promise<Finding[]> { return findings; }
  async analyzeRedirect() { return { isMalicious: false, explanation: 'stub', confidence: 0 }; }
  async analyzeHeaders() { return { findings: [] }; }
  async analyzeTls() { return { findings: [] }; }
  async analyzeSiteCrawl() { return { findings: [] }; }
  async analyzeWebConfig() { return { findings: [] }; }
  async analyzeSmarterRecon() { return { validated: [] }; }
  async analyzeDeepDiscovery() { return { findings: [] }; }
  // ─── NEW: Reasoning Engine Stubs ─────────────────────────────────────────
  async buildAttackGraph() { return { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } }; }
  async reasonNextSteps() { return { nextActions: [], updatedHypotheses: [], pivotOpportunities: [], riskAssessment: '', confidence: 0 }; }
  async enumerateAttackSurface() { return { vectors: [], coverage: { tested: [], untested: [], coveragePercent: 0 }, priorities: [] }; }
  async detectPivotChains() { return []; }
  async validateFinding() { return { validated: false, confidence: 0, additionalEvidence: [], falsePositiveIndicators: [], recommendedRetest: [] }; }
  async generatePreExploitChecklist(targetType: TargetType, context: ChecklistContext): Promise<PreExploitChecklist> { 
  return { targetType, phases: [], totalChecks: 0, completed: 0 }; 
}
}

// ─── OpenAI-Compatible Fallback Provider ───
// Works with any OpenAI-compatible API: OpenRouter, LM Studio, vLLM, Together AI, Groq, etc.

class OpenAICompatibleProvider implements AIProvider {
  private baseUrl: string;
  private apiKey: string;
  private model: string;
  private timeout: number;
  private fallback: TemplateProvider;
  private available: boolean | null = null;
  private availableUntil = 0;

  constructor() {
    this.baseUrl = config.aiBaseUrl || 'https://openrouter.ai/api/v1';
    this.apiKey = config.aiApiKey;
    this.model = config.aiModel || 'meta-llama/llama-3-8b-instruct';
    this.timeout = config.ollamaTimeout;
    this.fallback = new TemplateProvider();
    logger.info(`[AI] OpenAI-compatible provider initialized: ${this.baseUrl} (model: ${this.model})`);
  }

  async isAvailable(): Promise<boolean> {
    if (this.available !== null && Date.now() < this.availableUntil) return this.available;
    if (!this.apiKey) {
      this.available = false;
      this.availableUntil = Date.now() + 5000;
      return false;
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`${this.baseUrl}/models`, {
        headers: { 'Authorization': `Bearer ${this.apiKey}` },
        signal: controller.signal,
      });
      clearTimeout(timer);
      this.available = res.ok;
      this.availableUntil = Date.now() + (res.ok ? 60000 : 5000);
      if (this.available) logger.info(`[AI] OpenAI-compatible endpoint available at ${this.baseUrl}`);
      else logger.info(`[AI] OpenAI-compatible endpoint returned ${res.status}`);
    } catch {
      this.available = false;
      this.availableUntil = Date.now() + 5000;
      logger.info('[AI] OpenAI-compatible endpoint not reachable');
    }
    return this.available;
  }

  private async chatCompletion(messages: { role: string; content: string }[], model?: string): Promise<string> {
    if (!(await this.isAvailable())) return '';
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      const res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: model || this.model,
          messages,
          temperature: 0.3,
          max_tokens: 2000,
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) return '';
      const data = await res.json() as any;
      return data.choices?.[0]?.message?.content || '';
    } catch {
      return '';
    }
  }

  async completePrompt(prompt: string): Promise<string> {
    return this.chatCompletion([{ role: 'user', content: prompt }]);
  }

  async summarize(text: string): Promise<string> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a cybersecurity analyst. Summarize the following concisely.' },
      { role: 'user', content: text },
    ]);
    return result || this.fallback.summarize(text);
  }

  async explainFinding(finding: Finding): Promise<{ executiveSummary: string; businessImpact: string; remediation: string; }> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a cybersecurity expert. Analyze the finding and provide: 1) executive summary (2-3 sentences), 2) business impact (2-3 sentences), 3) remediation steps. Return JSON with keys: executiveSummary, businessImpact, remediation.' },
      { role: 'user', content: JSON.stringify({ title: finding.title, description: finding.description, severity: finding.severity, category: finding.category, evidence: finding.evidence, impact: finding.impact, remediation: finding.remediation }) },
    ]);
    try {
      const parsed = JSON.parse(result);
      return { executiveSummary: parsed.executiveSummary, businessImpact: parsed.businessImpact, remediation: parsed.remediation };
    } catch {
      return this.fallback.explainFinding(finding);
    }
  }

  async generateExecutiveSummary(findings: Finding[], domain: string): Promise<string> {
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => (severityCounts as any)[f.severity]++);
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a CISO writing a board-ready executive summary. Be concise, authoritative, business-focused.' },
      { role: 'user', content: `Write a 3-4 sentence executive summary for a security assessment of ${domain}. Findings: ${JSON.stringify(severityCounts)} total=${findings.length}. Categories: ${[...new Set(findings.map(f => f.category))].join(', ')}. Top findings: ${findings.slice(0, 5).map(f => `[${f.severity}] ${f.title}`).join('; ')}` },
    ]);
    return result || this.fallback.generateExecutiveSummary(findings, domain);
  }

  async prioritizeRemediation(findings: Finding[]): Promise<string[]> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a vulnerability management expert. Prioritize findings by risk. Return a JSON array of strings, each formatted as "[SEVERITY] Title - Action needed". Most critical first.' },
      { role: 'user', content: JSON.stringify(findings.map(f => ({ title: f.title, severity: f.severity, category: f.category }))) },
    ]);
    try {
      const parsed = JSON.parse(result);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      logger.warn('[AI] Failed to parse remediation priority response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.prioritizeRemediation(findings);
  }

  async analyzeVulnerabilityChains(findings: Finding[], domain: string): Promise<VulnerabilityChain[]> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a penetration tester. Identify attack chains where one vulnerability enables another. Return JSON array of chains with: title, description, severity (CRITICAL/HIGH/MEDIUM/LOW), findings (array of finding titles), attackPath (array of steps), impact.' },
      { role: 'user', content: `Domain: ${domain}\nFindings:\n${findings.map(f => `[${f.severity}] ${f.title} (${f.category}): ${f.description?.substring(0, 100)}`).join('\n')}` },
    ]);
    try {
      const parsed = JSON.parse(result);
      if (Array.isArray(parsed)) return parsed.map((c: any) => ({
        title: c.title || 'Attack Chain',
        description: c.description || '',
        severity: c.severity || 'HIGH',
        findings: c.findings || [],
        attackPath: c.attackPath || [],
        impact: c.impact || '',
      }));
    } catch (e) {
      logger.warn('[AI] Failed to parse vulnerability chain response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.analyzeVulnerabilityChains(findings, domain);
  }

  async generateAttackNarrative(findings: Finding[], domain: string): Promise<string> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a threat intelligence analyst. Write a 2-3 paragraph attack narrative describing how an adversary would chain these findings to compromise the target.' },
      { role: 'user', content: `Target: ${domain}\nFindings: ${findings.map(f => `[${f.severity}] ${f.title}`).join(', ')}` },
    ]);
    return result || this.fallback.generateAttackNarrative(findings, domain);
  }

  async classifyExploitability(finding: Finding): Promise<ExploitabilityInfo> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'Classify exploitability. Return JSON: {score: 0-10, vector: NETWORK/LOCAL/ADJACENT/PHYSICAL, complexity: LOW/MEDIUM/HIGH, requiresAuth: bool, userInteraction: bool, privilegesRequired: NONE/LOW/HIGH, lateralMovement: bool}' },
      { role: 'user', content: JSON.stringify({ title: finding.title, description: finding.description, severity: finding.severity, category: finding.category }) },
    ]);
    try {
      const parsed = JSON.parse(result);
      return { score: parsed.score ?? 5, vector: parsed.vector ?? 'NETWORK', complexity: parsed.complexity ?? 'MEDIUM', requiresAuth: parsed.requiresAuth ?? false, userInteraction: parsed.userInteraction ?? false, privilegesRequired: parsed.privilegesRequired ?? 'NONE', lateralMovement: parsed.lateralMovement ?? false };
    } catch (e) {
      logger.warn('[AI] Failed to parse exploitability response: ' + (e instanceof Error ? e.message : String(e)));
      return this.fallback.classifyExploitability(finding);
    }
  }

  async generateRemediationPlan(findings: Finding[], domain: string): Promise<RemediationPhase[]> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'Create a phased remediation plan. Return JSON array of phases with: phase, timeframe, findings (titles), actions (array), riskReduction.' },
      { role: 'user', content: JSON.stringify(findings.map(f => ({ title: f.title, severity: f.severity }))) },
    ]);
    try {
      const parsed = JSON.parse(result);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      logger.warn('[AI] Failed to parse remediation plan response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.generateRemediationPlan(findings, domain);
  }

  async deduplicateFindings(findings: Finding[]): Promise<Finding[]> {
    return findings;
  }

  async adjustSeverityWithContext(findings: Finding[], context: string): Promise<Finding[]> {
    return findings;
  }

  async generateContextualPayloads(context: string, attackType: string): Promise<string[]> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'Generate 5 security testing payloads for the given context. Return JSON array of payload strings.' },
      { role: 'user', content: `Context: ${context}, Attack type: ${attackType}` },
    ]);
    try {
      const parsed = JSON.parse(result);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      logger.warn('[AI] Failed to parse contextual payloads response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.generateContextualPayloads(context, attackType);
  }

  async enrichFindingEvidence(finding: Finding, context: string): Promise<Finding> {
    return finding;
  }

  async generateServiceAuditPayloads(service: string, version: string): Promise<string[]> {
    return this.fallback.generateServiceAuditPayloads(service, version);
  }

  async chat(messages: { role: string; content: string }[]): Promise<string> {
    const result = await this.chatCompletion(messages);
    return result || this.fallback.chat(messages);
  }

  async generateNovelPayloads(techStack: string[], version: string, attackType: string): Promise<string[]> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are an expert penetration tester. Generate 5 novel, context-specific payloads. Return JSON array of payload strings.' },
      { role: 'user', content: `Tech stack: ${techStack.join(', ')}, version: ${version}, attack type: ${attackType}. Generate 5 novel payloads that work against this specific combination. Consider framework-specific quirks, version-specific bugs, and bypass techniques.` },
    ]);
    try {
      const parsed = JSON.parse(result);
      if (Array.isArray(parsed)) return parsed;
    } catch (e) {
      logger.warn('[AI] Failed to parse novel payloads response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.generateNovelPayloads(techStack, version, attackType);
  }

  async reasonAboutVulnerabilities(techStack: string[], findings: Finding[]): Promise<VulnerabilityReasoning> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'You are a zero-day researcher. Analyze the tech stack and existing findings. Return JSON with keys: novelAttackVectors, versionSpecificRisks, bypassTechniques, chainingOpportunities, zeroDayIndicators.' },
      { role: 'user', content: `Tech stack: ${techStack.join(', ')}\nFindings: ${findings.map(f => `[${f.severity}] ${f.title}: ${f.description.substring(0, 100)}`).join('\n')}` },
    ]);
    try {
      const parsed = JSON.parse(result);
      return {
        novelAttackVectors: parsed.novelAttackVectors || [],
        versionSpecificRisks: parsed.versionSpecificRisks || [],
        bypassTechniques: parsed.bypassTechniques || [],
        chainingOpportunities: parsed.chainingOpportunities || [],
        zeroDayIndicators: parsed.zeroDayIndicators || [],
      };
    } catch (e) {
      logger.warn('[AI] Failed to parse vulnerability reasoning response: ' + (e instanceof Error ? e.message : String(e)));
    }
    return this.fallback.reasonAboutVulnerabilities(techStack, findings);
  }

  async assessReconForAttacks(reconSummary: ReconSummary): Promise<AttackRecommendations> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'Analyze reconnaissance data and recommend attack priorities. Return JSON: {priorityAttacks: string[], focusParams: string[], likelyVulnTypes: string[], wafLikely: bool, authRequired: bool, apiDetected: bool, frameworkSpecificTests: string[], rationale: string}' },
      { role: 'user', content: JSON.stringify(reconSummary) },
    ]);
    try {
      const parsed = JSON.parse(result);
      return { priorityAttacks: parsed.priorityAttacks || [], focusParams: parsed.focusParams || [], likelyVulnTypes: parsed.likelyVulnTypes || [], wafLikely: parsed.wafLikely ?? false, authRequired: parsed.authRequired ?? false, apiDetected: parsed.apiDetected ?? false, frameworkSpecificTests: parsed.frameworkSpecificTests || [], rationale: parsed.rationale || '' };
    } catch {
      return this.fallback.assessReconForAttacks(reconSummary);
    }
  }

  async triageAndEnrichFindings(findings: Finding[], domain: string, reconContext: string): Promise<{ findings: Finding[]; chains: VulnerabilityChain[]; attackNarrative: string; remediationPlan: RemediationPhase[] }> {
    return this.fallback.triageAndEnrichFindings(findings, domain, reconContext);
  }

  async scoreFindingCvss(finding: Finding): Promise<number> {
    const result = await this.chatCompletion([
      { role: 'system', content: 'Score CVSS v3.1. Return only the numeric score (0-10).' },
      { role: 'user', content: JSON.stringify({ title: finding.title, description: finding.description, severity: finding.severity, category: finding.category }) },
    ]);
    const score = parseFloat(result);
    if (!isNaN(score) && score >= 0 && score <= 10) return score;
    return this.fallback.scoreFindingCvss(finding);
  }

  async reasonMidScan(findings: Finding[], domain: string): Promise<MidScanInsight[]> {
    const findingSummary = findings.slice(0, 10).map(f => `[${f.severity}] ${f.title}: ${f.description?.slice(0, 100)}`).join('\n');
    const prompt = `You are a security analyst monitoring a live scan of ${domain}. Analyze these findings and provide real-time insights:\n\n${findingSummary}\n\nReturn a JSON array of insights (max 3). Each insight has: type ("pattern"|"recommendation"|"risk_update"|"chain_detected"), title, description, severity (optional), confidence (0-1), relatedModules (optional string array).\n\nReturn ONLY valid JSON, no markdown.`;

    try {
      const response = await this.chatCompletion([
        { role: 'system', content: 'You are a security analyst. Return ONLY valid JSON array.' },
        { role: 'user', content: prompt },
      ]);
      const parsed = JSON.parse(response);
      return Array.isArray(parsed) ? parsed.slice(0, 3).map((i: Record<string, unknown>) => ({
        type: (['pattern', 'recommendation', 'risk_update', 'chain_detected'].includes(i.type as string) ? i.type : 'pattern') as MidScanInsight['type'],
        title: (i.title as string) || 'Analysis',
        description: (i.description as string) || '',
        severity: i.severity as string | undefined,
        confidence: (i.confidence as number) || 0.7,
        relatedModules: i.relatedModules as string[] | undefined,
      })) : [];
    } catch {
      return [];
    }
  }

  // Stub implementations for new interface methods
  async filterFalsePositives(findings: Finding[]): Promise<Finding[]> { return findings; }
  async analyzeRedirect() { return { isMalicious: false, explanation: 'stub', confidence: 0 }; }
  async analyzeHeaders() { return { findings: [] }; }
  async analyzeTls() { return { findings: [] }; }
  async analyzeSiteCrawl() { return { findings: [] }; }
  async analyzeWebConfig() { return { findings: [] }; }
  async analyzeSmarterRecon() { return { validated: [] }; }
  async analyzeDeepDiscovery() { return { findings: [] }; }
  async buildAttackGraph() { return { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } }; }
  async reasonNextSteps() { return { nextActions: [], updatedHypotheses: [], pivotOpportunities: [], riskAssessment: '', confidence: 0 }; }
  async enumerateAttackSurface() { return { vectors: [], coverage: { tested: [], untested: [], coveragePercent: 0 }, priorities: [] }; }
  async detectPivotChains() { return []; }
  async validateFinding() { return { validated: false, confidence: 0, additionalEvidence: [], falsePositiveIndicators: [], recommendedRetest: [] }; }
  async generatePreExploitChecklist() { return { targetType: 'network' as any, phases: [], totalChecks: 0, completed: 0 }; }
}

// ─── Ollama Provider ───

class OllamaProvider implements AIProvider {
  private baseUrl: string;
  private model: string;              // general model (dolphin3:8b)
  private securityModel: string;      // security model (Cybersecurity-BaronLLM)
  private generalModel: string;       // alias for model
  private reasoningModel: string;     // dedicated reasoning model (Cybersecurity-BaronLLM)
  private timeout: number;
  private fallback: TemplateProvider;
  private openaiFallback: OpenAICompatibleProvider | null = null;
  private available: boolean | null = null;
  private securityModelAvailable: boolean | null = null;
  private generalModelAvailable: boolean | null = null;
  private reasoningModelAvailable: boolean | null = null;
  private availableUntil = 0;
  private modelAvailabilityUntil = 0;
  // AI Response Cache with TTL
  private responseCache: Map<string, { data: unknown; expires: number }> = new Map();
  private readonly CACHE_TTL = 30 * 60 * 1000; // 30 minutes
  private readonly MAX_CACHE_SIZE = 500;

  constructor() {
    this.baseUrl = config.ollamaBaseUrl;
    this.model = config.generalModel || config.aiModel || 'dolphin3:8b';
    this.generalModel = this.model;
    this.securityModel = config.securityModel || 'AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF';
    this.reasoningModel = config.reasoningModel || 'AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF';
    this.timeout = 300000; // 5 minutes per call
    this.fallback = new TemplateProvider();
    // Prepare OpenAI-compatible fallback if API key is configured
    if (config.aiApiKey) {
      this.openaiFallback = new OpenAICompatibleProvider();
    }
    // Start cache cleanup interval
    setInterval(() => this.cleanupCache(), 5 * 60 * 1000);
  }

  private getCacheKey(prompt: string, options: Record<string, unknown> = {}): string {
    const opts = JSON.stringify(options);
    const hash = require('crypto').createHash('sha256').update(prompt + opts).digest('hex').substring(0, 16);
    return hash;
  }

  private getCached<T>(key: string): T | null {
    const entry = this.responseCache.get(key);
    if (entry && entry.expires > Date.now()) {
      logger.debug(`[AI] Cache hit for key: ${key}`);
      return entry.data as T;
    }
    if (entry) {
      this.responseCache.delete(key);
    }
    return null;
  }

  private setCache(key: string, data: unknown): void {
    if (this.responseCache.size >= this.MAX_CACHE_SIZE) {
      // Remove oldest entry
      const firstKey = this.responseCache.keys().next().value;
      if (firstKey) this.responseCache.delete(firstKey);
    }
    this.responseCache.set(key, { data, expires: Date.now() + this.CACHE_TTL });
  }

  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.responseCache.entries()) {
      if (entry.expires <= now) {
        this.responseCache.delete(key);
      }
    }
  }

  private async isAvailable(): Promise<boolean> {
    if (this.available !== null && Date.now() < this.availableUntil) return this.available;
    try {
      const res = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(5000) });
      this.available = res.ok;
      this.availableUntil = Date.now() + (res.ok ? 30000 : 5000);
      if (this.available) {
        logger.info(`[AI] Ollama connected, generalModel: ${this.generalModel}, securityModel: ${this.securityModel}`);
      } else {
        logger.info('[AI] Ollama not available, falling back to AI provider');
      }
      return this.available;
    } catch {
      this.available = false;
      this.availableUntil = Date.now() + 5000;
      logger.info('[AI] Ollama not reachable, falling back to AI provider');
      return false;
    }
  }

  private async isSecurityModelAvailable(): Promise<boolean> {
    if (this.securityModelAvailable !== null && Date.now() < this.modelAvailabilityUntil) return this.securityModelAvailable;
    try {
      const res = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) { this.securityModelAvailable = false; this.modelAvailabilityUntil = Date.now() + 30000; return false; }
      const data = await res.json() as { models?: Array<{ name: string }> };
      const models = (data.models || []).map(m => m.name);
      this.securityModelAvailable = models.some(m =>
        m === this.securityModel || m.startsWith(this.securityModel + ':')
      );
      this.modelAvailabilityUntil = Date.now() + 30000;
      if (this.securityModelAvailable) logger.info(`[AI] Security model available: ${this.securityModel}`);
      else logger.info(`[AI] Security model ${this.securityModel} not found, using general model for security analysis`);
      return this.securityModelAvailable;
    } catch {
      this.securityModelAvailable = false;
      this.modelAvailabilityUntil = Date.now() + 30000;
      return false;
    }
  }

  private async isGeneralModelAvailable(): Promise<boolean> {
    if (this.generalModelAvailable !== null && Date.now() < this.modelAvailabilityUntil) return this.generalModelAvailable;
    try {
      const res = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) { this.generalModelAvailable = false; this.modelAvailabilityUntil = Date.now() + 30000; return false; }
      const data = await res.json() as { models?: Array<{ name: string }> };
      const models = (data.models || []).map(m => m.name);
      this.generalModelAvailable = models.some(m =>
        m === this.generalModel || m.startsWith(this.generalModel + ':')
      );
      this.modelAvailabilityUntil = Date.now() + 30000;
      if (this.generalModelAvailable) logger.info(`[AI] General model available: ${this.generalModel}`);
      return this.generalModelAvailable;
    } catch {
      this.generalModelAvailable = false;
      this.modelAvailabilityUntil = Date.now() + 30000;
      return false;
    }
  }

  private async isReasoningModelAvailable(): Promise<boolean> {
    if (this.reasoningModelAvailable !== null && Date.now() < this.modelAvailabilityUntil) return this.reasoningModelAvailable;
    try {
      const res = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) { this.reasoningModelAvailable = false; this.modelAvailabilityUntil = Date.now() + 30000; return false; }
      const data = await res.json() as { models?: Array<{ name: string }> };
      const models = (data.models || []).map(m => m.name);
      this.reasoningModelAvailable = models.some(m =>
        m === this.reasoningModel || m.startsWith(this.reasoningModel + ':')
      );
      this.modelAvailabilityUntil = Date.now() + 30000;
      if (this.reasoningModelAvailable) logger.info(`[AI] Reasoning model available: ${this.reasoningModel}`);
      else logger.info(`[AI] Reasoning model ${this.reasoningModel} not found, using security model for reasoning`);
      return this.reasoningModelAvailable;
    } catch {
      this.reasoningModelAvailable = false;
      this.modelAvailabilityUntil = Date.now() + 30000;
      return false;
    }
  }

  private async generate(prompt: string, options: { temperature?: number; maxTokens?: number; format?: string; retries?: number; useSecurityModel?: boolean; useGeneralModel?: boolean; useReasoningModel?: boolean; useCache?: boolean } = {}): Promise<string> {
    if (!(await this.isAvailable())) {
      return this.openaiFallback ? this.openaiFallback.completePrompt(prompt) : '';
    }

    // Model routing: reasoning model for attack chains/planning, security model for vuln analysis, general for summaries
    let modelToUse: string;
    if (options.useReasoningModel && (await this.isReasoningModelAvailable())) {
      modelToUse = this.reasoningModel;
    } else if (options.useSecurityModel && (await this.isSecurityModelAvailable())) {
      modelToUse = this.securityModel;
    } else if (options.useGeneralModel && (await this.isGeneralModelAvailable())) {
      modelToUse = this.generalModel;
    } else if (options.useSecurityModel) {
      modelToUse = this.securityModel;
    } else if (options.useReasoningModel) {
      modelToUse = this.reasoningModel;
    } else {
      modelToUse = this.generalModel;
    }

    // Check cache first (only for non-streaming, deterministic calls)
    const useCache = options.useCache !== false && !options.format;
    if (useCache) {
      const cacheKey = this.getCacheKey(prompt, { model: modelToUse, temperature: options.temperature ?? 0.3, maxTokens: options.maxTokens });
      const cached = this.getCached<string>(cacheKey);
      if (cached) {
        logger.info(`[AI] Cache hit - returning cached response (${cached.length} chars)`);
        return cached;
      }
    }

    const maxRetries = options.retries ?? 2;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const body: Record<string, unknown> = {
          model: modelToUse,
          prompt,
          stream: false,
          options: {
            temperature: options.temperature ?? 0.3,
            num_predict: options.maxTokens ?? 1024,
            top_p: 0.9,
            top_k: 40,
            repeat_penalty: 1.15,
          },
        };
        if (options.format) body.format = options.format;

        const start = Date.now();
        const res = await fetch(`${this.baseUrl}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeout),
        });

        if (!res.ok) {
          logger.error(`[AI] Ollama HTTP ${res.status} (model: ${modelToUse})`);
          if (attempt < maxRetries) { await new Promise(r => setTimeout(r, 2000)); continue; }
          break;
        }

        const data = await res.json() as { response?: string };
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);
        const response = data.response || '';
        logger.info(`[AI] Generated ${response.length} chars in ${elapsed}s with ${modelToUse} (attempt ${attempt + 1})`);

        // Store in cache if enabled
        if (useCache) {
          const cacheKey = this.getCacheKey(prompt, { model: modelToUse, temperature: options.temperature ?? 0.3, maxTokens: options.maxTokens });
          this.setCache(cacheKey, response);
        }

        return response;
      } catch (error) {
        logger.error(`[AI] Ollama attempt ${attempt + 1} failed (${modelToUse}):`, { error: error instanceof Error ? error.message : String(error) });
        if (attempt < maxRetries) await new Promise(r => setTimeout(r, 2000));
      }
    }
    return this.openaiFallback ? this.openaiFallback.completePrompt(prompt) : '';
  }

  private async generateJSON<T>(prompt: string, options?: { maxTokens?: number; useSecurityModel?: boolean; useGeneralModel?: boolean; useReasoningModel?: boolean }): Promise<T | null> {
    const result = await this.generate(prompt, { temperature: 0.1, format: 'json', maxTokens: options?.maxTokens, useSecurityModel: options?.useSecurityModel, useGeneralModel: options?.useGeneralModel, useReasoningModel: options?.useReasoningModel });
    if (!result) return null;
    try {
      // Find JSON object in response (models sometimes add text before/after)
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (jsonMatch) return JSON.parse(jsonMatch[0]);
      return null;
    } catch {
      return null;
    }
  }

  private async generateJSONArray<T>(prompt: string, options?: { maxTokens?: number; useSecurityModel?: boolean; useGeneralModel?: boolean; useReasoningModel?: boolean }): Promise<T[] | null> {
    const result = await this.generate(prompt, { temperature: 0.1, format: 'json', maxTokens: options?.maxTokens, useSecurityModel: options?.useSecurityModel, useGeneralModel: options?.useGeneralModel, useReasoningModel: options?.useReasoningModel });
    if (!result) return null;
    try {
      const cleaned = this.stripMarkdown(result);
      const jsonMatch = cleaned.match(/\[[\s\S]*\]/);
      if (jsonMatch) return JSON.parse(jsonMatch[0]);
      return null;
    } catch {
      return null;
    }
  }

  private stripMarkdown(text: string): string {
    return text
      .replace(/\*\*([^*]+)\*\*/g, '$1')      // **bold**
      .replace(/\*([^*]+)\*/g, '$1')            // *italic*
      .replace(/^#{1,6}\s+/gm, '')              // # headers
      .replace(/`([^`]+)`/g, '$1')              // `code`
      .replace(/^\s*[-*]\s+/gm, '')             // - bullet points
      .replace(/^\s*\d+\.\s+/gm, '')            // 1. numbered lists
      .replace(/^>\s+/gm, '')                   // > blockquotes
      .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')  // [text](url) -> text
      .trim();
  }

  async summarize(text: string): Promise<string> {
    const result = await this.generate(
      `Summarize this security text in 2-3 sentences. No markdown, no bold, no headers. Plain text only.\n\n${text}`,
      { maxTokens: 256, useGeneralModel: true }
    );
    return result ? this.stripMarkdown(result) : this.fallback.summarize(text);
  }

  async explainFinding(finding: Finding): Promise<{
    executiveSummary: string;
    businessImpact: string;
    remediation: string;
  }> {
    const result = await this.generateJSON<{
      executiveSummary: string;
      businessImpact: string;
      remediation: string;
    }>(
      `You are a senior cybersecurity consultant. Analyze this security finding and provide a professional assessment.

FINDING:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Description: ${finding.description}
- Evidence: ${finding.evidence}
- Impact: ${finding.impact}
- Current Remediation: ${finding.remediation}

Provide:
1. executiveSummary: A 1-2 sentence executive summary of the finding's significance
2. businessImpact: Business impact in plain language (data loss, compliance, reputation, financial)
3. remediation: Specific, actionable remediation steps with implementation details

Respond in JSON format.`,
      { useSecurityModel: true }
    );
    return result || this.fallback.explainFinding(finding);
  }

  async generateExecutiveSummary(findings: Finding[], domain: string): Promise<string> {
    // Condense findings to summary stats + top findings only
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => sevCounts[f.severity as keyof typeof sevCounts]++);
    const topFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 10);
    const topList = topFindings.map(f => `- [${f.severity}] ${f.title}: ${f.description.substring(0, 80)}`).join('\n');
    const categories = [...new Set(findings.map(f => f.category))].join(', ');

    const result = await this.generate(
      `You are a senior security consultant writing an executive summary for a penetration test report for ${domain}.

Assessment Statistics:
- Total findings: ${findings.length}
- Critical: ${sevCounts.CRITICAL}, High: ${sevCounts.HIGH}, Medium: ${sevCounts.MEDIUM}, Low: ${sevCounts.LOW}, Informational: ${sevCounts.INFO}
- Categories tested: ${categories}

Critical and High severity findings:
${topList}

Write a professional executive summary (6-8 sentences) that a CISO could present to the board. Include:
1. Scope and methodology of the assessment
2. Overall risk posture (use terms like "significant", "moderate", "acceptable")
3. Key critical findings and their business implications
4. Estimated time to compromise for an attacker
5. Compliance impact (OWASP Top 10, PCI DSS, etc.)
6. Recommended immediate actions
7. Overall risk rating (Critical/High/Medium/Low)

Write as a professional security consultant. Use business language. PLAIN TEXT ONLY - no markdown, no bold, no headers, no bullet points.`,
      { maxTokens: 512, useGeneralModel: true }
    );
    return result ? this.stripMarkdown(result) : this.fallback.generateExecutiveSummary(findings, domain);
  }

  async prioritizeRemediation(findings: Finding[]): Promise<string[]> {
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => sevCounts[f.severity as keyof typeof sevCounts]++);
    const topFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 15);
    const topList = topFindings.map(f => `- [${f.severity}] ${f.title}: ${f.description.substring(0, 60)}`).join('\n');

    const result = await this.generate(
      `Prioritize these security findings for ${findings.length} total (${sevCounts.CRITICAL}C/${sevCounts.HIGH}H/${sevCounts.MEDIUM}M/${sevCounts.LOW}L):
${topList}

Return numbered list, most urgent first. Format: [SEV] Title - Why urgent`,
      { maxTokens: 512, useGeneralModel: true }
    );

    if (result) {
      const lines = this.stripMarkdown(result).split('\n').map(l => l.trim()).filter(l => l.length > 0 && l.includes('['));
      if (lines.length > 0) return lines;
    }
    return this.fallback.prioritizeRemediation(findings);
  }

  async analyzeVulnerabilityChains(findings: Finding[], domain: string): Promise<VulnerabilityChain[]> {
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
    findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++; });
    const criticalHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 12);
    const findingsList = criticalHigh.map(f => `- [${f.severity}] ${f.title} (${f.category}): ${f.description.substring(0, 80)}`).join('\n');

    // Build severity map from scanner findings
    const sevMap = new Map<string, string>();
    findings.forEach(f => sevMap.set(f.title.toLowerCase(), f.severity));
    const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    const result = await this.generateJSONArray<VulnerabilityChain>(
      `You are a senior penetration tester performing vulnerability chain analysis for ${domain}.

MITRE ATT&CK KILL CHAIN FRAMEWORK:
- Reconnaissance (TA0043): Information gathering about the target
- Resource Development (TA0042): Establishing infrastructure for attack
- Initial Access (TA0001): Gaining foothold (phishing, exploit public app, valid accounts)
- Execution (TA0002): Running malicious code (command injection, XSS, exploit)
- Persistence (TA0003): Maintaining access (backdoor, scheduled task)
- Privilege Escalation (TA0004): Gaining higher-level permissions
- Defense Evasion (TA0005): Avoiding detection
- Credential Access (TA0006): Stealing account credentials
- Discovery (TA0007): Mapping the environment
- Lateral Movement (TA0008): Moving through the network
- Collection (TA0009): Gathering target data
- Exfiltration (TA0010): Stealing data
- Impact (TA0040): Disrupting or destroying systems

Security findings identified during the assessment:
${findingsList}

Analyze how these vulnerabilities can be chained following the MITRE ATT&CK kill chain. A vulnerability chain occurs when multiple lower-severity issues are exploited together to achieve a higher-impact compromise.

For each chain, provide:
- title: A professional name for the attack chain (e.g., "Information Disclosure → Authentication Bypass → Data Exfiltration")
- description: A detailed explanation following the kill chain: "Step 1 (Reconnaissance): Exposed debug endpoint leaks server configuration. Step 2 (Initial Access): Leaked credentials enable authentication bypass. Step 3 (Execution): Authenticated access allows command injection..."
- severity: Classify based on the chain's overall impact (CRITICAL/HIGH/MEDIUM/LOW)
- findings: List the specific finding titles that form this chain
- attackPath: Write 4-6 detailed steps following the kill chain. Each step should reference a MITRE ATT&CK technique: "T1592 - Gather victim host information via exposed config files. T1078 - Valid accounts via leaked credentials. T1059 - Command and Scripting Interpreter via injection point..."
- impact: Describe the specific business impact including data breach, system compromise, lateral movement potential
- severityRationale: Explain why this chain deserves its severity rating based on the kill chain progression

Return JSON array (max 3 chains):
[{title:"Chain Name", description:"Kill chain explanation", severity:"CRITICAL", findings:["vuln1","vuln2"], attackPath:["T1xxx step1","T1xxx step2","T1xxx step3","T1xxx step4"], impact:"Business consequence", severityRationale:"Why this severity"}]

Focus on the most impactful chains. Be specific about exploitation techniques and MITRE ATT&CK techniques. PLAIN TEXT ONLY.`,
      { maxTokens: 1024, useSecurityModel: true }
    );

    if (!result) return this.fallback.analyzeVulnerabilityChains(findings, domain);

    // Smart severity merge: take the HIGHER of scanner and AI severity
    // Chains amplify risk, so a chain should be at least as severe as its worst component
    return result.map(chain => {
      // Find highest scanner severity among chain's findings
      let maxScannerSevIdx = sevOrder.length;
      for (const fTitle of (chain.findings || [])) {
        const scannerSev = sevMap.get(fTitle.toLowerCase());
        if (scannerSev) {
          const idx = sevOrder.indexOf(scannerSev);
          if (idx >= 0 && idx < maxScannerSevIdx) maxScannerSevIdx = idx;
        }
      }

      // Find AI's severity
      const aiSevIdx = sevOrder.indexOf(chain.severity);
      const effectiveIdx = aiSevIdx >= 0
        ? Math.min(maxScannerSevIdx, aiSevIdx) // take the MORE severe (lower index)
        : maxScannerSevIdx;

      chain.severity = (effectiveIdx < sevOrder.length ? sevOrder[effectiveIdx] : chain.severity) as Severity;
      return chain;
    });
  }

  async generateAttackNarrative(findings: Finding[], domain: string): Promise<string> {
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
    findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++; });
    const criticalHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 10);
    const findingsList = criticalHigh.map(f => `- [${f.severity}] ${f.title}: ${f.description.substring(0, 80)} | Evidence: ${f.evidence.substring(0, 120)}`).join('\n');

    const result = await this.generate(
      `You are a senior penetration tester writing a professional assessment report for ${domain}.

Vulnerability findings with evidence:
${findingsList}

Write a detailed penetration test narrative (minimum 4 paragraphs):

Paragraph 1: EXECUTIVE SUMMARY - scope of engagement, methodology used (passive reconnaissance, active scanning, vulnerability validation), overall risk posture summary with specific metrics (total findings, critical/high counts, estimated time to compromise).

Paragraph 2: ATTACK CHAIN ANALYSIS - how individual vulnerabilities connect into exploitation chains. Describe the specific sequence: for example, information disclosure leads to credential harvesting, which enables authentication bypass, which grants access to sensitive data. Reference specific findings by name and explain the lateral movement path.

Paragraph 3: EXPLOITATION PROOF - describe the exact HTTP requests, payloads, and server responses observed during testing. Include: HTTP method, full URL path, request headers, payload strings, response codes, response body snippets that confirm vulnerability. Be specific about what was tested and what was observed.

Paragraph 4: BUSINESS IMPACT - quantify the risk: what data could be exfiltrated, what systems could be compromised, what compliance frameworks are violated, estimated financial impact, reputational damage. Reference specific attack scenarios.

Write as a professional security consultant. Use technical language. Include specific HTTP details. PLAIN TEXT ONLY - no markdown, no bold, no headers, no bullet points.`,
      { maxTokens: 1024, useSecurityModel: true }
    );
    return result ? this.stripMarkdown(result) : this.fallback.generateAttackNarrative(findings, domain);
  }

  async classifyExploitability(finding: Finding): Promise<ExploitabilityInfo> {
    const result = await this.generateJSON<ExploitabilityInfo>(
      `Classify the exploitability of this security finding:

FINDING:
- Title: ${finding.title}
- Category: ${finding.category}
- Description: ${finding.description}
- Evidence: ${finding.evidence}

Provide:
- score: Exploitability score 1-10 (10 = trivially exploitable)
- vector: ATTACK_VECTOR (NETWORK/ADJACENT/LOCAL/PHYSICAL)
- complexity: ATTACK_COMPLEXITY (LOW/MEDIUM/HIGH)
- requiresAuth: Does exploitation require authentication? (true/false)
- userInteraction: Does exploitation require user interaction? (true/false)
- privilegesRequired: PRIVILEGES_REQUIRED (NONE/LOW/HIGH)
- lateralMovement: Can this finding enable lateral movement? (true/false)

Respond in JSON format.`,
      { useSecurityModel: true }
    );
    return result || this.fallback.classifyExploitability(finding);
  }

  async generateRemediationPlan(findings: Finding[], domain: string): Promise<RemediationPhase[]> {
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => sevCounts[f.severity as keyof typeof sevCounts]++);
    const criticalHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 10);
    const findingsList = criticalHigh.map(f => `- [${f.severity}] ${f.title} (${f.category}): ${f.description.substring(0, 60)}`).join('\n');

    const result = await this.generateJSONArray<RemediationPhase>(
      `You are a senior security consultant writing a remediation plan for ${domain}.

Security findings (${findings.length} total: ${sevCounts.CRITICAL} critical, ${sevCounts.HIGH} high, ${sevCounts.MEDIUM} medium, ${sevCounts.LOW} low):
${findingsList}

Create a prioritized remediation plan with 4 phases:

Phase 1 - IMMEDIATE (0-24 hours): Critical and actively exploitable issues that require emergency patching. Include specific actions like "Disable the exposed debug endpoint at /debug", "Rotate all potentially compromised credentials", "Apply WAF rules to block exploit patterns".

Phase 2 - URGENT (1-7 days): High-severity issues that need quick resolution. Include specific technical actions like "Implement Content-Security-Policy header with the following directives...", "Update TLS configuration to disable TLS 1.0/1.1".

Phase 3 - SCHEDULED (1-4 weeks): Medium-severity issues that should be addressed in the next development cycle. Include configuration changes and code fixes.

Phase 4 - BACKLOG (1-3 months): Low-severity hardening improvements. Include best practices and defense-in-depth measures.

For each phase, provide:
- phase: Phase name
- timeframe: When to complete
- findings: List of specific finding titles to address
- actions: List of specific, actionable remediation steps (not generic advice)
- riskReduction: Expected risk reduction (Critical/High/Medium/Low)

Return JSON array of 4 phases.`,
      { maxTokens: 1024, useGeneralModel: true }
    );

    if (!result) return this.fallback.generateRemediationPlan(findings, domain);
    // Strip markdown from actions
    return result.map(phase => ({
      ...phase,
      actions: (phase.actions || []).map(a => this.stripMarkdown(a)),
      findings: (phase.findings || []).map(f => this.stripMarkdown(f)),
    }));
  }

  // ─── AI DEDUPLICATION ────────────────────────────────────────────────────
  async deduplicateFindings(findings: Finding[]): Promise<Finding[]> {
    if (findings.length === 0) return findings;

    // Batch by category to avoid large prompts and improve accuracy
    const byCategory = new Map<string, Finding[]>();
    for (const f of findings) {
      const cat = f.category || 'General';
      if (!byCategory.has(cat)) byCategory.set(cat, []);
      byCategory.get(cat)!.push(f);
    }

    let allDeduplicated: Finding[] = [];
    for (const [category, catFindings] of byCategory.entries()) {
      if (catFindings.length === 1) {
        allDeduplicated.push(catFindings[0]);
        continue;
      }

      const findingsList = catFindings.map((f, i) => `${i}: [${f.severity}] ${f.title}: ${f.description.substring(0, 60)}`).join('\n');

      const result = await this.generateJSONArray<{ index: number; duplicateOf: number; reason: string }>(
        `You are a security finding deduplication engine. Analyze these ${category} findings and identify duplicates or near-duplicates.

Findings:
${findingsList}

Return JSON array of duplicates. Each entry: {index: N, duplicateOf: M, reason: "why N is a duplicate of M"}
Only include actual duplicates (same vulnerability, different detection method). Do NOT merge different vulnerabilities.
If no duplicates, return empty array [].`,
        { maxTokens: 1024, useGeneralModel: true }
      );

      if (!result || result.length === 0) {
        allDeduplicated.push(...catFindings);
        continue;
      }

      // Remove duplicates, keep the one with higher severity or more evidence
      const toRemove = new Set<number>();
      for (const dup of result) {
        if (dup.index >= 0 && dup.index < catFindings.length && dup.duplicateOf >= 0 && dup.duplicateOf < catFindings.length) {
          const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
          const keepIdx = sevOrder.indexOf(catFindings[dup.duplicateOf].severity) <= sevOrder.indexOf(catFindings[dup.index].severity)
            ? dup.duplicateOf : dup.index;
          const removeIdx = keepIdx === dup.duplicateOf ? dup.index : dup.duplicateOf;
          toRemove.add(removeIdx);
        }
      }

      const deduplicated = catFindings.filter((_, i) => !toRemove.has(i));
      allDeduplicated.push(...deduplicated);
    }

    logger.info(`[AI] Deduplication: ${findings.length} → ${allDeduplicated.length} findings (${findings.length - allDeduplicated.length} merged)`);
    return allDeduplicated;
  }

  // ─── AI FALSE-POSITIVE FILTER ─────────────────────────────────────────
  async filterFalsePositives(findings: Finding[], domain: string): Promise<Finding[]> {
    if (findings.length === 0) return findings;

    // Batch by category and severity for better accuracy
    const byCategory = new Map<string, Finding[]>();
    for (const f of findings) {
      const cat = f.category || 'General';
      if (!byCategory.has(cat)) byCategory.set(cat, []);
      byCategory.get(cat)!.push(f);
    }

    let allFiltered: Finding[] = [];
    for (const [category, catFindings] of byCategory.entries()) {
      // Process in chunks of 15 to avoid token limits
      const chunks: Finding[][] = [];
      for (let i = 0; i < catFindings.length; i += 15) {
        chunks.push(catFindings.slice(i, i + 15));
      }

      for (const chunk of chunks) {
        const findingsList = chunk.map((f, i) =>
          `${i}: [${f.severity}] ${f.title}\n   Asset: ${f.affectedAsset}\n   Evidence: ${(f.evidence || '').substring(0, 300)}\n   Confidence: ${f.confidence || 0.5}`
        ).join('\n\n');

        const result = await this.generateJSONArray<{ index: number; isFalsePositive: boolean; reason: string }>(
          `You are a security finding validator. Analyze these ${category} findings and determine if each is a REAL vulnerability or a FALSE POSITIVE.

A finding is a FALSE POSITIVE if:
- The evidence does NOT actually support the vulnerability claim (e.g., server returns same response for all payloads)
- The "vulnerability" is actually expected/normal behavior (e.g., login redirect after auth, CORS allowing same-origin)
- The detection was purely heuristic with no actual proof of exploitation
- The finding describes a theoretical risk with zero evidence of the issue existing
- HTTP response codes or body content contradict the finding's claim

A finding is REAL if:
- There is actual evidence of the vulnerability (server response changed with payload, error messages leak info, etc.)
- The proof shows the server accepted/processed a malicious payload
- The finding includes real HTTP request/response pairs demonstrating the issue

Target: ${domain}

Findings:
${findingsList}

Return JSON array. Each entry: {index: N, isFalsePositive: true/false, reason: "brief explanation"}
Only include findings that ARE false positives. If all findings are real, return empty array [].`,
          { maxTokens: 2048, useSecurityModel: true }
        );

        if (!result || result.length === 0) {
          allFiltered.push(...chunk);
          continue;
        }

        const falsePositives = new Set(result.filter(r => r.isFalsePositive).map(r => r.index));
        const filtered = chunk.filter((_, i) => !falsePositives.has(i));
        allFiltered.push(...filtered);

        for (const fp of result.filter(r => r.isFalsePositive)) {
          if (fp.index >= 0 && fp.index < chunk.length) {
            logger.info(`[AI] False positive removed: "${chunk[fp.index].title}" — ${fp.reason}`);
          }
        }
      }
    }

    logger.info(`[AI] False-positive filter: ${findings.length} → ${allFiltered.length} findings (${findings.length - allFiltered.length} false positives removed)`);
    return allFiltered;
  }

  // ─── AI REDIRECT ANALYSIS ─────────────────────────────────────────────
  async analyzeRedirect(
    url: string,
    redirectChain: { url: string; statusCode: number; location: string }[],
    finalUrl: string,
    domain: string,
  ): Promise<{ isMalicious: boolean; explanation: string; confidence: number }> {
    const chainStr = redirectChain.map((e, i) => `  ${i + 1}. ${e.url} → ${e.location} (${e.statusCode})`).join('\n');
    const result = await this.generateJSON<{ isMalicious: boolean; explanation: string; confidence: number }>(
      `You are a security analyst evaluating whether a URL redirect is malicious (open redirect vulnerability) or legitimate.

Original URL: ${url}
Redirect chain:
${chainStr}
Final URL: ${finalUrl}
Target domain: ${domain}

Determine:
1. Is the redirect legitimate (e.g., auth flow, www→non-www, HTTP→HTTPS, locale redirect) or malicious (open redirect)?
2. Legitimate redirects: same domain, auth-related paths, standard protocol upgrades, CDN redirects
3. Malicious redirects: external domain in redirect chain, user-controlled parameters leading to external URLs, bypass of same-origin policy

Return JSON: {isMalicious: bool, explanation: "brief reason", confidence: 0.0-1.0}`,
      { maxTokens: 512, useSecurityModel: true }
    );

    return result || { isMalicious: false, explanation: 'AI analysis unavailable', confidence: 0 };
  }

  // ─── AI HEADERS ANALYSIS ──────────────────────────────────────────────
  async analyzeHeaders(
    headers: Record<string, string | string[] | undefined>,
    domain: string,
    body: string,
  ): Promise<{ findings: Partial<Finding>[] }> {
    const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\n');
    const result = await this.generateJSONArray<{ title: string; severity: string; description: string; impact: string; remediation: string }>(
      `You are a web security header analyzer. Analyze these HTTP response headers for a security assessment of ${domain}.

Headers:
${headerStr}

Body snippet (first 500 chars): ${body.substring(0, 500)}

Identify ONLY real, exploitable security issues. Do NOT flag:
- Headers that are present and correctly configured
- Theoretical risks with no practical impact
- Missing headers that are not commonly expected

Focus on:
- CSP weaknesses (unsafe-inline, unsafe-eval, loose directives)
- HSTS misconfigurations (missing includeSubDomains, short max-age)
- X-Frame-Options missing when frameable content exists
- Security headers that actively weaken security
- Server information leakage (X-Powered-By, Server version)
- CORS misconfigurations (reflect Origin, wildcard with credentials)

Return JSON array of findings. Each: {title, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), description, impact, remediation}
If no issues found, return empty array [].`,
      { maxTokens: 2048, useSecurityModel: true }
    );

    return { findings: (result || []).map((f: any) => ({ ...f, severity: f.severity as Severity })) };
  }

  // ─── AI TLS ANALYSIS ──────────────────────────────────────────────────
  async analyzeTls(
    certInfo: { subject: string; issuer: string; validFrom: string; validTo: string; sans: string[]; protocol: string; cipher: string },
    domain: string,
  ): Promise<{ findings: Partial<Finding>[] }> {
    const certStr = `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nValid: ${certInfo.validFrom} to ${certInfo.validTo}\nSANs: ${certInfo.sans.join(', ')}\nProtocol: ${certInfo.protocol}\nCipher: ${certInfo.cipher}`;
    const result = await this.generateJSONArray<{ title: string; severity: string; description: string; impact: string; remediation: string }>(
      `You are a TLS/SSL security analyzer. Analyze this certificate configuration for ${domain}.

Certificate Info:
${certStr}

Identify real, exploitable TLS issues. Do NOT flag:
- Modern TLS configurations that are actually secure
- Certificate validity when it's currently valid
- Protocol/cipher choices that are actually fine

Focus on:
- Weak protocols (TLS 1.0, TLS 1.1, SSLv3)
- Weak ciphers (RC4, DES, 3DES, NULL, EXPORT)
- Self-signed or expired certificates
- Missing key algorithms (RSA < 2048, no ECDSA)
- HSTS missing with valid cert
- Certificate chain issues

Return JSON array. Each: {title, severity, description, impact, remediation}
If no issues, return empty array [].`,
      { maxTokens: 1024, useSecurityModel: true }
    );

    return { findings: (result || []).map((f: any) => ({ ...f, severity: f.severity as Severity })) };
  }

  // ─── AI SITE CRAWL ANALYSIS ───────────────────────────────────────────
  async analyzeSiteCrawl(
    urls: { url: string; status: number; contentLength: number; isSpa: boolean }[],
    domain: string,
    techStack: string[],
  ): Promise<{ findings: Partial<Finding>[] }> {
    const urlList = urls.slice(0, 50).map(u => `${u.status} ${u.url} (${u.contentLength}b) ${u.isSpa ? 'SPA' : ''}`).join('\n');
    const result = await this.generateJSONArray<{ title: string; severity: string; description: string; impact: string; remediation: string }>(
      `You are a web application security analyst. Analyze these discovered URLs and pages for ${domain}.

Tech stack: ${techStack.join(', ')}
URLs found:
${urlList}

Identify security issues from the URL patterns and page structure:
- Exposed admin panels or debug endpoints
- Sensitive files accessible without auth
- API endpoints that should be protected
- Information disclosure in URL patterns
- SPA-specific issues (client-side routing exposing hidden states)
- Framework-specific misconfigurations

Return JSON array. Each: {title, severity, description, impact, remediation}
If no issues, return empty array [].`,
      { maxTokens: 2048, useSecurityModel: true }
    );

    return { findings: (result || []).map((f: any) => ({ ...f, severity: f.severity as Severity })) };
  }

  // ─── AI WEB CONFIG ANALYSIS ───────────────────────────────────────────
  async analyzeWebConfig(
    configs: { path: string; status: number; contentType: string; snippet: string }[],
    domain: string,
  ): Promise<{ findings: Partial<Finding>[] }> {
    const configList = configs.map(c => `${c.path} (${c.status}) [${c.contentType}]\n  ${c.snippet.substring(0, 200)}`).join('\n');
    const result = await this.generateJSONArray<{ title: string; severity: string; description: string; impact: string; remediation: string }>(
      `You are a security analyst reviewing exposed configuration files for ${domain}.

Discovered files:
${configList}

Determine the real security impact of each file:
-暴露 credentials, API keys, tokens → CRITICAL
- Exposed .env, config.json, database credentials → HIGH
- Exposed backup files, source code → MEDIUM
- robots.txt, sitemap.xml, standard files → INFO (skip these)
- Version information, technology disclosure → LOW

Only report files that have REAL security impact. Skip standard files (robots.txt, favicon.ico, etc).

Return JSON array. Each: {title, severity, description, impact, remediation}
If no real issues, return empty array [].`,
      { maxTokens: 2048, useSecurityModel: true }
    );

    return { findings: (result || []).map((f: any) => ({ ...f, severity: f.severity as Severity })) };
  }

  // ─── AI SMARTER RECON ANALYSIS ────────────────────────────────────────
  async analyzeSmarterRecon(
    hypotheses: { title: string; confidence: number; status: string; evidence: string }[],
    domain: string,
    techStack: string[],
  ): Promise<{ validated: { title: string; confidence: number; reasoning: string }[] }> {
    const hypList = hypotheses.map(h => `[${h.status}] ${h.title} (confidence: ${h.confidence})\n  Evidence: ${h.evidence?.substring(0, 200) || 'none'}`).join('\n');
    const result = await this.generateJSONArray<{ title: string; confidence: number; reasoning: string }>(
      `You are a penetration testing hypothesis validator. These hypotheses were generated for ${domain} (tech: ${techStack.join(', ')}).

Hypotheses:
${hypList}

For each hypothesis, validate whether it's worth pursuing based on:
- Does the tech stack actually support this attack vector?
- Is the confidence score realistic given what we know?
- What specific tests should be run to validate?
- Adjust confidence up/down based on your analysis

Return JSON array with adjusted confidence and reasoning for each hypothesis.
Only include hypotheses where you have useful input (skip ones you can't evaluate).`,
      { maxTokens: 2048, useSecurityModel: true }
    );

    return { validated: result || [] };
  }

  // ─── AI DEEP DISCOVERY ANALYSIS ───────────────────────────────────────
  async analyzeDeepDiscovery(
    discoveries: { url: string; status: number; size: number; type: string }[],
    domain: string,
  ): Promise<{ findings: Partial<Finding>[] }> {
    const discList = discoveries.slice(0, 50).map(d => `${d.status} ${d.url} (${d.size}b, ${d.type})`).join('\n');
    const result = await this.generateJSONArray<{ title: string; severity: string; description: string; impact: string; remediation: string }>(
      `You are a security analyst reviewing deep content discovery results for ${domain}.

Discovered content:
${discList}

Identify security-significant discoveries:
- Backup files (.bak, .old, .swp) with sensitive data
- Source code or config files accidentally exposed
- Old versions of files with known vulnerabilities
- Internal API endpoints or admin interfaces
- Sensitive data in unexpected locations
- Files that should not be publicly accessible

Skip: static assets (JS/CSS/images), standard pages, 404s.

Return JSON array. Each: {title, severity, description, impact, remediation}
If no real issues, return empty array [].`,
      { maxTokens: 2048, useSecurityModel: true }
    );

    return { findings: (result || []).map((f: any) => ({ ...f, severity: f.severity as Severity })) };
  }

  // ─── AI CONTEXTUAL SEVERITY ADJUSTMENT ──────────────────────────────────
  async adjustSeverityWithContext(findings: Finding[], context: string): Promise<Finding[]> {
    if (findings.length === 0) return findings;

    const findingsList = findings.map(f =>
      `- [${f.severity}] ${f.title}: ${f.description.substring(0, 60)} | Asset: ${f.affectedAsset}`
    ).join('\n');

    const result = await this.generateJSONArray<SeverityAdjustment>(
      `You are a CVSS-like severity assessor. Analyze these security findings in the context of the target environment and adjust severities.

Target Context: ${context}

Findings:
${findingsList}

Rules for adjustment:
- If a vulnerability affects a login/auth endpoint, increase severity by one level
- If a vulnerability affects an admin panel, increase severity by one level
- If a WAF is detected and the finding is XSS/SQLi, decrease severity by one level (WAF provides mitigation)
- If a finding has a direct path to sensitive data (DB credentials, API keys), increase to CRITICAL
- If multiple findings chain together (e.g., open port + unauthenticated access), mark as CRITICAL
- If a finding is on an internal-only service not exposed to internet, decrease severity

Return JSON array:
[{findingTitle:"exact title", originalSeverity:"SEV", adjustedSeverity:"SEV", rationale:"brief reason"}]
Only include findings where severity should change. Empty array if no changes needed.`,
      { maxTokens: 1024 }
    );

    if (!result || result.length === 0) return findings;

    // Apply adjustments
    const adjustmentMap = new Map<string, string>();
    for (const adj of result) {
      if (adj.findingTitle && adj.adjustedSeverity) {
        adjustmentMap.set(adj.findingTitle.toLowerCase(), adj.adjustedSeverity);
      }
    }

    return findings.map(f => {
      const adjusted = adjustmentMap.get(f.title.toLowerCase());
      if (adjusted && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(adjusted)) {
        logger.info(`[AI] Severity adjusted: "${f.title}" ${f.severity} → ${adjusted}`);
        return { ...f, severity: adjusted as Severity };
      }
      return f;
    });
  }

  // ─── AI CONTEXTUAL PAYLOAD GENERATION ───────────────────────────────────
  async generateContextualPayloads(context: string, attackType: string): Promise<string[]> {
    const result = await this.generateJSONArray<string>(
      `You are a penetration testing payload generator. Given the target context, generate context-specific payloads for ${attackType} testing.

Target Context: ${context}

Generate 10-15 payloads that are tailored to the specific technology stack, framework, and configuration detected. Include:
- Framework-specific injection patterns
- Encoding bypass techniques if WAF detected
- Database-specific syntax if database type known
- Version-specific exploits if versions known

Return JSON array of payload strings. Each payload should be a single string.
Focus on payloads most likely to succeed given the specific context. No markdown.`,
      { maxTokens: 1024 }
    );

    return result || [];
  }

  // ─── AI EVIDENCE ENRICHMENT ─────────────────────────────────────────────
  async enrichFindingEvidence(finding: Finding, context: string): Promise<Finding> {
    const result = await this.generateJSON<{
      enrichedEvidence: string;
      exploitSteps: string[];
      verificationCommand: string;
      businessImpactDetail: string;
      proofOfConcept: string;
    }>(
      `You are a senior penetration tester writing a professional security assessment report. Generate detailed exploitation evidence for this finding.

FINDING:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Description: ${finding.description}
- Evidence: ${finding.evidence}
- Impact: ${finding.impact}
- Affected Asset: ${finding.affectedAsset}

TARGET CONTEXT: ${context}

Generate the following fields:

1. enrichedEvidence: Write a detailed technical description of the vulnerability. Include: what was tested, what was observed, what the server response indicated, why this confirms the vulnerability. Reference specific HTTP headers, status codes, and response patterns.

2. exploitSteps: Write 4-6 step-by-step exploitation instructions that a penetration tester would follow. Each step should be a specific action: "Navigate to...", "Intercept the request...", "Modify parameter X to...", "Observe response indicating...". Be specific about tools (Burp Suite, curl, browser dev tools) and techniques used.

3. verificationCommand: Write a complete, safe curl command that reproduces the finding. Include the full URL, headers, and any payloads. Example: curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin

4. businessImpactDetail: Write a specific business impact analysis. Include: what data could be accessed, what actions an attacker could take, which compliance frameworks are violated (OWASP, PCI DSS, HIPAA), estimated financial impact, reputational damage.

5. proofOfConcept: Write a complete proof-of-concept with ACTUAL HTTP request and response details. Format:
REQUEST: POST /vulnerable-endpoint HTTP/1.1 Host: target.com Content-Type: application/json {"payload": "..."}
RESPONSE: HTTP/1.1 200 OK [response body snippet showing vulnerability confirmation]
EXPLANATION: Why this confirms the vulnerability.

IMPORTANT: The proofOfConcept must contain realistic HTTP request/response pairs. Use the evidence field to understand what was already observed. Be specific about payloads, headers, and response patterns. PLAIN TEXT ONLY - no markdown, no bold, no headers.`,
      { useSecurityModel: true }
    );

    if (!result) return finding;

    const enrichedEvidence = result.enrichedEvidence || finding.evidence;
    const exploitSteps = result.exploitSteps || [];
    const verificationCmd = result.verificationCommand || '';
    const proofOfConcept = result.proofOfConcept || '';

    // Combine original evidence with enriched data
    let newEvidence = enrichedEvidence;
    if (exploitSteps.length > 0) {
      newEvidence += '\n\nExploitation Steps:\n' + exploitSteps.map((s, i) => `${i + 1}. ${s}`).join('\n');
    }
    if (verificationCmd) {
      newEvidence += `\n\nVerification Command: ${verificationCmd}`;
    }
    if (proofOfConcept) {
      newEvidence += `\n\nProof of Concept:\n${proofOfConcept}`;
    }

    return {
      ...finding,
      evidence: newEvidence,
      impact: result.businessImpactDetail || finding.impact,
    };
  }

  // ─── AI SERVICE AUDIT PAYLOADS ──────────────────────────────────────────
  async generateServiceAuditPayloads(service: string, version: string): Promise<string[]> {
    const result = await this.generateJSONArray<string>(
      `Generate service-specific security testing payloads for ${service} version ${version}.

Include:
- Unauthenticated access probes
- Default credential tests
- Known CVE exploitation attempts
- Configuration weakness checks
- Information disclosure probes

Return JSON array of payload strings. Each should be a complete, ready-to-use payload.`,
      { maxTokens: 512 }
    );

    return result || [];
  }

  // ─── AI NOVEL PAYLOAD GENERATION ───────────────────────────────────────
  async generateNovelPayloads(techStack: string[], version: string, attackType: string): Promise<string[]> {
    const result = await this.generateJSONArray<string>(
      `You are an expert penetration tester. Given the tech stack: ${techStack.join(', ')}, version: ${version}, and attack type: ${attackType}, generate 5 novel, context-specific payloads that would work against this specific combination. Consider framework-specific quirks, version-specific bugs, and bypass techniques. Return as JSON array of payload strings.`,
      { maxTokens: 1024 }
    );
    return result || this.fallback.generateNovelPayloads(techStack, version, attackType);
  }

  // ─── AI VULNERABILITY REASONING ────────────────────────────────────────
  async reasonAboutVulnerabilities(techStack: string[], findings: Finding[]): Promise<VulnerabilityReasoning> {
    const findingsList = findings.map(f => `- [${f.severity}] ${f.title}: ${f.description.substring(0, 100)}`).join('\n');

    const result = await this.generateJSON<VulnerabilityReasoning>(
      `You are a zero-day researcher. Analyze the tech stack: ${techStack.join(', ')} and existing findings:\n${findingsList}.\nIdentify: 1) Novel attack vectors not covered by standard scanners, 2) Version-specific risks based on known framework quirks, 3) Bypass techniques for the detected security controls, 4) Chaining opportunities between findings, 5) Indicators of potential zero-day vulnerabilities. Return JSON with keys: novelAttackVectors, versionSpecificRisks, bypassTechniques, chainingOpportunities, zeroDayIndicators.`,
      { maxTokens: 1024, useSecurityModel: true }
    );

    if (result) {
      return {
        novelAttackVectors: result.novelAttackVectors || [],
        versionSpecificRisks: result.versionSpecificRisks || [],
        bypassTechniques: result.bypassTechniques || [],
        chainingOpportunities: result.chainingOpportunities || [],
        zeroDayIndicators: result.zeroDayIndicators || [],
      };
    }
    return this.fallback.reasonAboutVulnerabilities(techStack, findings);
  }

  // ─── AI RECON ASSESSMENT — post-Phase-1, guides attack prioritization ────
  // Returns a structured profile telling the attack phase what to focus on.
  // Uses MITRE ATT&CK-inspired task tree for guided reasoning.
  async assessReconForAttacks(reconSummary: ReconSummary): Promise<AttackRecommendations> {
    const { domain, techStack, openPorts, headers, tlsInfo, dnsInfo, subdomains } = reconSummary;

    const result = await this.generateJSON<AttackRecommendations>(
      `You are a senior penetration tester performing target analysis for ${domain}.

MITRE ATT&CK RECONNAISSANCE FRAMEWORK (T1595):
- T1595.001: Active Scanning: Scan IP Blocks
- T1595.002: Active Scanning: Vulnerability Scanning
- T1595.003: Active Scanning: Wordlist Scanning
- T1592: Gather Victim Host Information
- T1589: Gather Victim Identity Information
- T1590: Gather Victim Network Information

TARGET DATA:
- Domain: ${domain}
- Tech Stack: ${techStack.join(', ') || 'unknown'}
- Open Ports: ${openPorts.join(', ') || 'none detected'}
- Subdomains: ${subdomains.slice(0, 10).join(', ') || 'none'}
- TLS: ${tlsInfo || 'unknown'}
- DNS: ${dnsInfo || 'unknown'}
- HTTP Headers: ${headers}

ANALYSIS INSTRUCTIONS:
Based on the target profile, determine the attack strategy using this reasoning chain:

1. RECONNAISSANCE ANALYSIS (T1595):
   - What does the tech stack reveal about the application framework?
   - What do open ports indicate about exposed services?
   - What does the DNS configuration reveal about infrastructure?
   - What do HTTP headers disclose about the server?

2. WEAPONIZATION PLANNING:
   - Given the tech stack, what injection vectors are most likely?
   - What authentication mechanisms are likely in use?
   - What API patterns does the framework typically expose?
   - Are there known CVEs for the detected versions?

3. DELIVERY ASSESSMENT:
   - Which parameters should be prioritized for testing?
   - What endpoints are most likely to accept user input?
   - Is a WAF present that might block certain payloads?
   - What encoding bypasses might be needed?

4. EXPLOITATION PATH:
   - What vulnerability types have the highest probability of success?
   - What is the expected attack chain (recon → exploit → impact)?
   - What lateral movement opportunities exist?

5. IMPACT ASSESSMENT:
   - What is the worst-case impact if vulnerabilities are found?
   - What sensitive data or systems could be compromised?
   - What compliance frameworks are at risk?

Return JSON:
{
  "priorityAttacks": ["module1","module2",...],
  "focusParams": ["param1","param2",...],
  "likelyVulnTypes": ["vuln1","vuln2",...],
  "wafLikely": false,
  "authRequired": false,
  "apiDetected": false,
  "frameworkSpecificTests": ["test1","test2",...],
  "rationale": "detailed analysis using MITRE ATT&CK reasoning chain"
}

priorityAttacks must be a subset of: activeVuln, brokenAuth, advancedAttacks, apiSecurity, httpMethods, serviceAudit, siteCrawl, subdomainTakeover, cloudSecurity, clientSecurity, supplyChain.
Order by highest expected yield based on the analysis above. Include at minimum 5 modules.`
    );

    return result || {
      priorityAttacks: ['activeVuln', 'brokenAuth', 'advancedAttacks', 'apiSecurity', 'httpMethods', 'serviceAudit', 'siteCrawl', 'subdomainTakeover'],
      focusParams: ['id', 'user', 'token', 'redirect', 'file'],
      likelyVulnTypes: ['SQLi', 'XSS', 'SSRF'],
      wafLikely: false,
      authRequired: false,
      apiDetected: false,
      frameworkSpecificTests: [],
      rationale: 'Default attack prioritization (AI unavailable)',
    };
  }

  // ─── AI TRIAGE — post-scan, enrich + deduplicate + adjust severity ────────
  async triageAndEnrichFindings(
    findings: Finding[],
    domain: string,
    reconContext: string,
  ): Promise<{ findings: Finding[]; chains: VulnerabilityChain[]; attackNarrative: string; remediationPlan: RemediationPhase[] }> {
    if (findings.length === 0) {
      return {
        findings: [],
        chains: [],
        attackNarrative: `No significant security findings were identified for ${domain}.`,
        remediationPlan: [],
      };
    }

    // GPU-optimized: Only process top findings through expensive AI
    // Skip AI for INFO findings and limit to top 20 most severe
    const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const sorted = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
    const topFindings = sorted.filter(f => f.severity !== 'INFO').slice(0, 20);
    const infoFindings = sorted.filter(f => f.severity === 'INFO');

    // Run dedup + chains + narrative in parallel (3 calls instead of 4)
    // Skip remediation plan if < 5 findings (not worth the GPU cycle)
    const runRemediation = topFindings.length >= 5;
    const [deduped, chains, narrative, remPlan] = await Promise.all([
      this.deduplicateFindings(topFindings),
      topFindings.length >= 3 ? this.analyzeVulnerabilityChains(topFindings, domain) : Promise.resolve([]),
      this.generateAttackNarrative(topFindings.slice(0, 10), domain),
      runRemediation ? this.generateRemediationPlan(topFindings, domain) : Promise.resolve([]),
    ]);

    // Severity adjustment depends on dedup results
    const adjusted = await this.adjustSeverityWithContext(deduped, reconContext);

    // AI false-positive filter — remove findings where evidence doesn't support the claim
    const filtered = await this.filterFalsePositives(adjusted, domain);

    // Re-attach INFO findings (no AI processing needed)
    const allAdjusted = [...filtered, ...infoFindings];

    logger.info(`[AI] Triage complete: ${findings.length} raw → ${allAdjusted.length} after dedup+severity+fp-filter for ${domain}`);

    return {
      findings: filtered,
      chains,
      attackNarrative: narrative,
      remediationPlan: remPlan,
    };
  }

  // ─── AI CHAT ─────────────────────────────────────────────────────────────
  async chat(messages: { role: string; content: string }[]): Promise<string> {
    if (!(await this.isAvailable())) return 'AI provider is not available. Make sure Ollama is running.';

    try {
      const body = {
        model: this.model,
        messages: messages.map(m => ({ role: m.role, content: m.content })),
        stream: false,
        options: {
          temperature: 0.4,
          num_predict: 2048,
          top_p: 0.9,
        },
      };

      const res = await fetch(`${this.baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!res.ok) {
        return 'AI request failed with status ' + res.status;
      }

      const data = await res.json() as { message?: { content?: string } };
      return data.message?.content || 'No response from AI';
    } catch (error: any) {
      logger.error('[AI] Chat error: ' + error.message);
      return 'Chat error: ' + error.message;
    }
  }

  // ─── AI CVSS SCORING ─────────────────────────────────────────────────────
  // Assigns a real CVSS-like base score to each finding without a cvssScore.
  async scoreFindingCvss(finding: Finding): Promise<number> {
    const result = await this.generateJSON<{ cvssScore: number; justification: string }>(
      `Assign a CVSS v3.1 Base Score (0.0-10.0) to this security finding.

FINDING:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Description: ${finding.description}
- Evidence: ${finding.evidence}
- Impact: ${finding.impact}

Consider: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact.

Return JSON: {"cvssScore": 7.5, "justification": "brief CVSS breakdown"}
Score must be between 0.0 and 10.0.`,
      { useSecurityModel: true }
    );

    if (result && typeof result.cvssScore === 'number' && result.cvssScore >= 0 && result.cvssScore <= 10) {
      return Math.round(result.cvssScore * 10) / 10;
    }

    // Fallback: map severity to typical CVSS range
    const fallback: Record<string, number> = { CRITICAL: 9.0, HIGH: 7.5, MEDIUM: 5.0, LOW: 2.5, INFO: 0.0 };
    return fallback[finding.severity] ?? 5.0;
  }

  // ─── AI MID-SCAN REASONING ────────────────────────────────────────────
  async reasonMidScan(findings: Finding[], domain: string): Promise<MidScanInsight[]> {
    const findingSummary = findings.slice(0, 10).map(f => `[${f.severity}] ${f.title}: ${f.description?.slice(0, 100)}`).join('\n');
    const prompt = `You are a security analyst monitoring a live scan of ${domain}. Analyze these findings and provide real-time insights:\n\n${findingSummary}\n\nReturn a JSON array of insights (max 3). Each insight has: type ("pattern"|"recommendation"|"risk_update"|"chain_detected"), title, description, severity (optional), confidence (0-1), relatedModules (optional string array).\n\nReturn ONLY valid JSON, no markdown.`;

    const result = await this.generateJSONArray<Record<string, unknown>>(
      prompt,
      { maxTokens: 500 }
    );

    if (!result) return [];
    return result.slice(0, 3).map((i) => ({
      type: (['pattern', 'recommendation', 'risk_update', 'chain_detected'].includes(i.type as string) ? i.type : 'pattern') as MidScanInsight['type'],
      title: (i.title as string) || 'Analysis',
      description: (i.description as string) || '',
      severity: i.severity as string | undefined,
      confidence: (i.confidence as number) || 0.7,
      relatedModules: i.relatedModules as string[] | undefined,
    }));
  }

  // ─── REASONING ENGINE: Build Attack Graph ───────────────────────────────────
  async buildAttackGraph(context: AttackGraphContext): Promise<AttackGraph> {
    const findingsList = context.findings.map(f =>
      `- [${f.severity}] ${f.title} (${f.category}): ${f.description.substring(0, 80)} | Asset: ${f.affectedAsset}`
    ).join('\n');

    const servicesList = context.services.map(s =>
      `${s.host}:${s.port} (${s.service}${s.version ? ` ${s.version}` : ''})`
    ).join('\n');

    const credentialsList = context.credentials.map(c =>
      `${c.type} creds: ${c.username} (${c.accessLevel}) from ${c.source}`
    ).join('\n');

    const result = await this.generateJSON<AttackGraph>(
      `You are a senior red team operator building an attack graph for ${context.domain}.
Target Type: ${context.targetType}
Tech Stack: ${context.techStack.join(', ') || 'unknown'}
Open Ports: ${context.openPorts.join(', ') || 'none'}
Services:
${servicesList}

Credentials:
${credentialsList || 'none'}

Current Findings:
${findingsList || 'none'}

MITRE ATT&CK techniques observed: ${context.mitreTechniques.join(', ') || 'none'}

Build a comprehensive attack graph with:
1. NODES: Each node is an attack step with MITRE ATT&CK technique, prerequisites, outcomes
2. EDGES: Connections between nodes with conditions and probabilities
3. ENTRY POINTS: Initial access vectors
4. CRITICAL PATHS: Full attack chains from entry to impact
5. MITRE COVERAGE: Which techniques are covered vs missing

Return JSON with: nodes, edges, entryPoints, criticalPaths, mitreCoverage.
Each node: {id, type, title, description, technique, prerequisites, outcomes, confidence, evidence}
Each edge: {from, to, condition, probability}
Each path: {nodes, totalProbability, impact, description}
mitreCoverage: {covered, missing, coveragePercent}`,
      { maxTokens: 2048, useReasoningModel: true }
    );

    return result || { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } };
  }

  // ─── REASONING ENGINE: Reason Next Steps ────────────────────────────────────
  async reasonNextSteps(context: ReasoningContext): Promise<ReasoningResult> {
    const findingsList = context.currentFindings.map(f =>
      `- [${f.severity}] ${f.title}: ${f.description.substring(0, 80)}`
    ).join('\n');

    const graphSummary = context.attackGraph.nodes.map(n =>
      `${n.id}: ${n.title} (${n.technique}) - ${n.type}`
    ).join('\n');

    const result = await this.generateJSON<ReasoningResult>(
      `You are a penetration tester mid-assessment. Reason about next steps for ${context.domain}.

TARGET TYPE: ${context.targetType}
TIME BUDGET: ${context.timeBudget}s remaining
RISK TOLERANCE: ${context.riskTolerance}

CURRENT FINDINGS:
${findingsList || 'none'}

ATTACK GRAPH NODES:
${graphSummary}

COMPLETED STEPS: ${context.completedSteps.join(', ') || 'none'}

AVAILABLE CREDENTIALS:
${context.availableCredentials.map(c => `${c.type}: ${c.username} (${c.accessLevel})`).join('\n') || 'none'}

NETWORK ACCESS:
${context.networkAccess.map(n => `${n.cidr} (${n.type}): ${n.hosts.join(', ')}`).join('\n') || 'none'}

Using the attack graph and current state, determine:
1. NEXT ACTIONS: Prioritized list of actions with MITRE techniques, reasoning, priority
2. UPDATED HYPOTHESES: What new hypotheses should be tested
3. PIVOT OPPORTUNITIES: Where can we move laterally or escalate
4. RISK ASSESSMENT: Current risk level and justification

Return JSON with: nextActions, updatedHypotheses, pivotOpportunities, riskAssessment, confidence.
nextActions: [{type, module, target, parameters, reasoning, mitreTechnique, priority, estimatedTime, prerequisites}]
updatedHypotheses: [{id, statement, confidence, status, evidence, testsRun}]
pivotOpportunities: [{from, to, technique, requirements, confidence}]`,
      { maxTokens: 2048, useReasoningModel: true }
    );

    return result || { nextActions: [], updatedHypotheses: [], pivotOpportunities: [], riskAssessment: '', confidence: 0 };
  }

  // ─── UNIVERSAL ATTACK SURFACE ENUMERATION ──────────────────────────────────
  async enumerateAttackSurface(target: AttackSurfaceTarget): Promise<AttackSurfaceMap> {
    const servicesList = target.services.map(s =>
      `${s.host}:${s.port} (${s.service}${s.version ? ` ${s.version}` : ''})`
    ).join('\n');

    const result = await this.generateJSON<AttackSurfaceMap>(
      `You are a penetration tester enumerating the complete attack surface for ${target.domain}.

TARGET TYPE: ${target.targetType}
IP: ${target.ip}
OPEN PORTS: ${target.openPorts.join(', ') || 'none'}
SERVICES:
${servicesList}
TECH STACK: ${target.techStack.join(', ') || 'unknown'}
OS INFO: ${target.osInfo || 'unknown'}
NETWORK CONTEXT: ${target.networkContext.map(n => `${n.cidr} (${n.type})`).join(', ') || 'unknown'}

Enumerate ALL possible attack vectors across ALL categories:
- NETWORK: Port scans, service enumeration, protocol attacks, MITM, pivot
- WEB: OWASP Top 10, API attacks, client-side, framework-specific, CMS-specific
- AD: Kerberos, LDAP, SMB, GPO, delegation, trusts, Azure AD
- LINUX: SSH, sudo, kernel, containers, cron, services, libraries
- WINDOWS: RDP, WinRM, SMB, COM/DCOM, WMI, PowerShell, AD CS
- CLOUD: Metadata, IAM, storage, containers, serverless, CI/CD
- DATABASE: SQL injection, auth bypass, privilege escalation, data exfil
- EMAIL: Phishing, spoofing, relay, enumeration

For each vector, specify: MITRE technique, applicability, confidence, module, payloads, expected evidence.

Return JSON with: vectors, coverage, priorities.
vectors: [{id, category, technique, title, description, prerequisites, applicable, confidence, module, payloads, expectedEvidence}]
coverage: {tested, untested, coveragePercent}
priorities: [{vectorId, priority, reason, estimatedEffort, potentialImpact}]`,
      { maxTokens: 2048, useReasoningModel: true }
    );

    return result || { vectors: [], coverage: { tested: [], untested: [], coveragePercent: 0 }, priorities: [] };
  }

  // ─── CROSS-TARGET PIVOT DETECTION ──────────────────────────────────────────
  async detectPivotChains(context: PivotContext): Promise<PivotChain[]> {
    const findingsList = context.allFindings.map(f =>
      `- [${f.severity}] ${f.title} (${f.category}): ${f.description.substring(0, 80)} | Asset: ${f.affectedAsset}`
    ).join('\n');

    const credentialsList = context.currentAccess.credentials.map(c =>
      `${c.type}: ${c.username} (${c.accessLevel}) from ${c.source}`
    ).join('\n');

    const networkList = context.networkMap.map(n =>
      `${n.cidr} (${n.type}): ${n.hosts.join(', ')}`
    ).join('\n');

    const result = await this.generateJSONArray<PivotChain>(
      `You are a red team operator identifying cross-target pivot chains.

CURRENT ACCESS: ${context.currentAccess.type} on ${context.currentAccess.host}
CREDENTIALS:
${credentialsList || 'none'}

NETWORK MAP:
${networkList || 'unknown'}

ALL FINDINGS:
${findingsList || 'none'}

TARGET TYPES IN SCOPE: ${context.targetTypes.join(', ')}

Identify ALL possible pivot chains from current position to other target types.
Consider:
- AD ↔ Linux: SSH keys, sudo, Kerberos delegation, SMB shares
- AD ↔ Web: Kerberos constrained delegation, SPN, web app impersonation
- Linux ↔ Web: SSH tunnels, file inclusion, container escape, cron
- Windows ↔ AD: Pass-the-hash, Kerberos, DCOM, WMI, WinRM
- Network ↔ All: Pivot via compromised hosts, VPN, proxy

For each chain, specify steps with MITRE techniques, requirements, and confidence.

Return JSON array of pivot chains:
[{steps, totalProbability, finalAccess, mitrePath}]
steps: [{from, to, technique, method, requirements, confidence}]`,
      { maxTokens: 2048, useReasoningModel: true }
    );

    return result || [];
  }

  // ─── FINDING VALIDATION LOOP ───────────────────────────────────────────────
  async validateFinding(finding: Finding, context: ValidationContext): Promise<ValidationResult> {
    const result = await this.generateJSON<ValidationResult>(
      `You are a senior penetration tester validating a finding.

FINDING TO VALIDATE:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Description: ${finding.description}
- Evidence: ${finding.evidence}
- Affected Asset: ${finding.affectedAsset}

TARGET: ${context.target.domain} (${context.target.targetType})
ATTACK GRAPH CONTEXT: ${context.attackGraph.nodes.length} nodes, ${context.attackGraph.edges.length} edges

ORIGINAL EVIDENCE: ${context.originalEvidence}

Determine:
1. Is this finding VALIDATED (true/false) with confidence?
2. What ADDITIONAL EVIDENCE would confirm it?
3. What FALSE POSITIVE INDICATORS exist?
4. What RETEST PLAN should be executed (module, payload, context, reason)?

Return JSON: {validated, confidence, additionalEvidence, falsePositiveIndicators, recommendedRetest}
recommendedRetest: [{module, payload, context, reason}]`,
      { maxTokens: 1024, useReasoningModel: true }
    );

    return result || { validated: false, confidence: 0, additionalEvidence: [], falsePositiveIndicators: [], recommendedRetest: [] };
  }

  // ─── PRE-EXPLOITATION CHECKLISTS ───────────────────────────────────────────
  async generatePreExploitChecklist(targetType: TargetType, context: ChecklistContext): Promise<PreExploitChecklist> {
    const findingsList = context.findings.map(f => `- [${f.severity}] ${f.title}`).join('\n');
    const credsList = context.credentials.map(c => `${c.type}: ${c.username} (${c.accessLevel})`).join('\n');

    const result = await this.generateJSON<PreExploitChecklist>(
      `You are a penetration tester creating a pre-exploitation checklist for a ${targetType} target.

FINDINGS: ${findingsList || 'none'}
CREDENTIALS: ${credsList || 'none'}
NETWORK ACCESS: ${context.networkAccess.map(n => `${n.cidr} (${n.type})`).join(', ') || 'none'}
TIME BUDGET: ${context.timeBudget}s

Generate a comprehensive checklist organized by phases. Each phase has checks with:
- MITRE technique
- Module to run
- Payload to test
- Prerequisites
- Expected evidence

Phases for ${targetType}:
${this.getChecklistPhases(targetType)}

Return JSON: {targetType, phases, totalChecks, completed: 0}
phases: [{name, description, checks: [{id, description, mitreTechnique, module, payload, prerequisites, completed: false}]}]`,
      { maxTokens: 2048, useReasoningModel: true }
    );

    return result || { targetType, phases: [], totalChecks: 0, completed: 0 };
  }

  private getChecklistPhases(targetType: TargetType): string {
    const phases: Record<TargetType, string> = {
      web: `1. RECON: Tech stack, endpoints, APIs, auth mechanisms, WAF
2. INJECTION: SQLi, XSS, SSTI, command injection, SSRF, XXE
3. AUTH: Bypass, enumeration, session, 2FA, password reset, JWT
4. ACCESS CONTROL: IDOR, BOLA, privilege escalation, admin bypass
5. CLIENT-SIDE: CSP, CORS, CSRF, clickjacking, XSS
6. INFRASTRUCTURE: Subdomain takeover, cloud metadata, exposed files
7. POST-EXPLOIT: Data exfil, persistence, lateral movement`,
      activeDirectory: `1. RECON: Domain info, trusts, GPO, OU structure, users/groups
2. ENUMERATION: Kerberos (SPN, AS-REP, delegation), LDAP, SMB, RPC
3. CREDENTIAL ACCESS: Kerberoasting, AS-REP roasting, DCSync, LSASS, NTDS
4. PRIVILEGE ESCALATION: ACL abuse, GPO, adminSDHolder, delegation, trusts
5. LATERAL MOVEMENT: Pass-the-hash/ticket, SMB, WinRM, DCOM, WMI, RDP
6. PERSISTENCE: Golden ticket, silver ticket, Skeleton Key, adminSDHolder
7. DOMINANCE: Domain admin, enterprise admin, forest trust, Azure AD`,
      linux: `1. RECON: Kernel, packages, services, cron, sudo, SUID, capabilities
2. LOCAL ENUM: Users, groups, SSH keys, history, configs, containers
3. PRIVILEGE ESCALATION: Sudo, SUID, kernel exploits, capabilities, cron, PATH
4. LATERAL MOVEMENT: SSH keys, shared libs, containers, NFS, Docker socket
5. PERSISTENCE: SSH keys, cron, systemd, bashrc, LD_PRELOAD, kernel modules
6. DATA ACCESS: Databases, configs, secrets, backups, logs
7. CONTAINER ESCAPE: Docker, containerd, CRI-O, Kubernetes`,
      windows: `1. RECON: OS version, patches, AV/EDR, services, shares, registry
2. CREDENTIAL ACCESS: LSASS, SAM, DPAPI, credential manager, RDP
3. PRIVILEGE ESCALATION: Token impersonation, services, DLL hijack, COM, WMI
4. LATERAL MOVEMENT: SMB, WinRM, RDP, DCOM, WMI, PSRemoting, scheduled tasks
5. PERSISTENCE: Registry, services, WMI, COM, scheduled tasks, startup
6. DEFENSE EVASION: AMSI bypass, ETW, logging, AV/EDR, PowerShell
7. POST-EXPLOIT: Data staging, exfil, cleanup, domain join`,
      network: `1. RECON: Topology, routing, VLANs, ACLs, VPN, firewalls
2. SERVICE ENUM: All open ports, banners, versions, configs
3. NETWORK ATTACKS: MITM, ARP spoof, DHCP, DNS, routing, VLAN hopping
4. PIVOT: SSH, RDP, SMB, proxy, VPN, port forwarding
5. WIRELESS: WPA, WPS, rogue AP, client attacks
6. INFRASTRUCTURE: Router/switch/firewall config, SNMP, management
7. POST-EXPLOIT: Traffic capture, credential harvest, persistence`,
      mixed: `1. RECON: Full topology, all services, trust relationships
2. CROSS-TARGET: AD-Linux, AD-Web, Linux-Web, Windows-Linux pivots
3. CREDENTIAL REUSE: Shared accounts, SSH keys, tokens, certs
4. LATERAL MOVEMENT: All protocols, all directions
5. PRIVILEGE ESCALATION: All target types
6. PERSISTENCE: Multi-platform
7. DATA ACCESS: All data stores, all types`
    };
    return phases[targetType] || phases.network;
  }
}

// ─── Provider Factory ───

export function getAIProvider(): AIProvider {
  // If explicitly configured for OpenAI-compatible
  if (config.aiProvider === 'openai' && config.aiApiKey) {
    return new OpenAICompatibleProvider();
  }
  // Default: try Ollama, fall back to OpenAI-compatible if configured, then template
  return new OllamaProvider();
}

// ─── Singleton ───

let _provider: AIProvider | null = null;
export function getAI(): AIProvider {
  if (!_provider) _provider = getAIProvider();
  return _provider;
}

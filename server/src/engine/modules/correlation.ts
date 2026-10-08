import { Finding, Severity } from '../../types';
import logger from '../../utils/logger';

export interface CorrelatedChain {
  id: string;
  title: string;
  description: string;
  findings: string[];
  severity: Severity;
  attackPath: string[];
  evidence: string;
  impact: string;
  confidence: number;
  mitre: string;
}

export interface CorrelationResult {
  chains: CorrelatedChain[];
  pivots: { from: string; to: string; via: string; confidence: number; evidence: string }[];
  attackPaths: { name: string; steps: string[]; impact: string; evidence: string }[];
  summary: string;
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};

function hasRealEvidence(f: Finding): boolean {
  if (!f.evidence) return false;
  const e = f.evidence;
  if (e.includes('PROOF OF VULNERABILITY')) return true;
  if (e.includes('>> REQUEST') && e.includes('<< RESPONSE')) return true;
  if (e.includes('PAYLOAD:') && (e.includes('RESPONSE:') || e.includes('Body Preview:'))) return true;
  if (e.includes('GET http') || e.includes('POST http')) return true;
  if (e.includes('nmap') && (e.includes('open') || e.includes('filtered'))) return true;
  if (e.includes('HTTP/') && (e.includes('200') || e.includes('301') || e.includes('302') || e.includes('403') || e.includes('401'))) return true;
  return false;
}

function extractPayload(f: Finding): string | null {
  if (!f.evidence) return null;
  const payloadMatch = f.evidence.match(/Payload:\s*(.+?)(?:\n|$)/i);
  if (payloadMatch) return payloadMatch[1].trim();
  const urlMatch = f.evidence.match(/GET\s+(https?:\/\/[^\s]+)/);
  if (urlMatch) return urlMatch[1];
  const postMatch = f.evidence.match(/POST\s+(https?:\/\/[^\s]+)/);
  if (postMatch) return postMatch[1];
  return null;
}

function extractResponse(f: Finding): string | null {
  if (!f.evidence) return null;
  const respMatch = f.evidence.match(/<< RESPONSE\s*\(HTTP (\d+)\)([\s\S]*?)(?=====\s*END|$)/);
  if (respMatch) return `HTTP ${respMatch[1]}${respMatch[2].slice(0, 500)}`;
  const bodyMatch = f.evidence.match(/Body Preview:\s*([\s\S]*?)(?=\n===|\n\n|$)/);
  if (bodyMatch) return bodyMatch[1].trim().slice(0, 500);
  return null;
}

function extractEndpoint(f: Finding): string | null {
  if (!f.affectedAsset) return null;
  const urlMatch = f.affectedAsset.match(/(https?:\/\/[^\s]+)/);
  if (urlMatch) return urlMatch[1];
  const pathMatch = f.affectedAsset.match(/(\/[a-zA-Z0-9_\-/.]+(?:\?[a-zA-Z0-9_=&-]*)?)/);
  if (pathMatch) return pathMatch[1];
  return null;
}

function highestSeverity(findings: Finding[]): Severity {
  let worst = Severity.INFO;
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity as Severity;
  }
  return worst;
}

export function correlateFindings(findings: Finding[], domain: string): CorrelationResult {
  const chains: CorrelatedChain[] = [];
  const pivots: CorrelationResult['pivots'] = [];
  const attackPaths: CorrelationResult['attackPaths'] = [];

  const realFindings = findings.filter(hasRealEvidence);
  const evidencelessFindings = findings.filter(f => !hasRealEvidence(f));

  logger.info(`[Correlation] Analyzing ${findings.length} findings (${realFindings.length} with real evidence) for ${domain}`);

  if (realFindings.length === 0) {
    logger.info(`[Correlation] No findings with real evidence — skipping correlation`);
    return { chains: [], pivots: [], attackPaths: [], summary: 'No correlated attack chains (no findings with real evidence)' };
  }

  const sqliFindings = realFindings.filter(f => f.title.toLowerCase().includes('sql injection') || f.title.toLowerCase().includes('sqli'));
  const authFindings = realFindings.filter(f => f.category === 'Authentication' || f.title.toLowerCase().includes('auth') || f.title.toLowerCase().includes('login') || f.title.toLowerCase().includes('session') || f.title.toLowerCase().includes('default credential'));
  const xssFindings = realFindings.filter(f => f.title.toLowerCase().includes('xss') || f.title.toLowerCase().includes('cross-site'));
  const ssrfFindings = realFindings.filter(f => f.title.toLowerCase().includes('ssrf') || f.title.toLowerCase().includes('server-side request'));
  const lfiFindings = realFindings.filter(f => f.title.toLowerCase().includes('path traversal') || f.title.toLowerCase().includes('lfi'));
  const cmdInjFindings = realFindings.filter(f => f.title.toLowerCase().includes('command injection') || f.title.toLowerCase().includes('os command'));
  const sstiFindings = realFindings.filter(f => f.title.toLowerCase().includes('template injection') || f.title.toLowerCase().includes('ssti'));
  const idorFindings = realFindings.filter(f => f.title.toLowerCase().includes('idor') || f.title.toLowerCase().includes('insecure direct'));
  const redirectFindings = realFindings.filter(f => f.title.toLowerCase().includes('open redirect') || f.title.toLowerCase().includes('redirect'));
  const corsFindings = realFindings.filter(f => f.title.toLowerCase().includes('cors'));
  const credFindings = realFindings.filter(f => f.title.toLowerCase().includes('default credential') || f.title.toLowerCase().includes('weak password') || f.title.toLowerCase().includes('brute force'));
  const exposedServiceFindings = realFindings.filter(f => f.title.toLowerCase().includes('exposed') || f.title.toLowerCase().includes('unauthorized'));
  const cookieFindings = realFindings.filter(f => f.title.toLowerCase().includes('cookie') || f.title.toLowerCase().includes('session') || f.description.toLowerCase().includes('httponly'));
  const internalFindings = realFindings.filter(f => f.title.toLowerCase().includes('internal') || f.title.toLowerCase().includes('metadata') || f.title.toLowerCase().includes('cloud'));

  // ── 1. SQLI → AUTH BYPASS (only if SQLi was tested on auth endpoint) ─────
  if (sqliFindings.length > 0 && authFindings.length > 0) {
    const authEndpoints = authFindings.map(f => extractEndpoint(f)).filter(Boolean);
    const sqliOnAuth = sqliFindings.filter(f => {
      const ep = extractEndpoint(f);
      return ep && authEndpoints.some(ae => ep.includes(ae!) || ae!.includes(ep));
    });
    if (sqliOnAuth.length > 0) {
      const payload = extractPayload(sqliOnAuth[0]);
      const response = extractResponse(sqliOnAuth[0]);
      chains.push({
        id: 'auth-sqli-bypass',
        title: 'Authentication Bypass via SQL Injection',
        description: `SQL injection confirmed on authentication endpoint. Payload ${payload || 'tested'} bypassed credential verification.`,
        findings: [...sqliOnAuth, ...authFindings].map(f => f.id),
        severity: Severity.CRITICAL,
        attackPath: [
          `SQLi on auth endpoint: ${sqliOnAuth[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Server response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Credential verification bypassed',
        ],
        evidence: [
          '=== CHAIN STEP 1: SQL Injection on Auth Endpoint ===',
          sqliOnAuth[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: Authentication Bypass ===',
          `Payload used: ${payload || 'see above'}`,
          `Response indicating bypass: ${response || 'see above'}`,
          '',
          '=== CHAIN VALIDATION ===',
          'Both SQL injection and authentication weakness confirmed with real evidence.',
          'The SQLi finding was tested against an authentication endpoint.',
        ].join('\n'),
        impact: 'Full account takeover, access to all user data and admin functions',
        confidence: 0.9,
        mitre: 'T1190',
      });
    }
  }

  // ── 2. XSS → SESSION HIJACK (only if XSS was confirmed with reflected output) ──
  if (xssFindings.length > 0 && cookieFindings.length > 0) {
    const xssWithReflection = xssFindings.filter(f =>
      f.evidence?.includes('reflected') || f.evidence?.includes('Payload:') || f.description.includes('reflects')
    );
    const missingHttponly = cookieFindings.filter(f =>
      f.severity !== Severity.INFO || f.description.toLowerCase().includes('httponly')
    );
    if (xssWithReflection.length > 0 && missingHttponly.length > 0) {
      const payload = extractPayload(xssWithReflection[0]);
      const response = extractResponse(xssWithReflection[0]);
      chains.push({
        id: 'xss-session-hijack',
        title: 'Session Hijacking via XSS + Missing HttpOnly',
        description: `XSS confirmed with reflected input. Session cookie lacks HttpOnly protection.`,
        findings: [...xssWithReflection.slice(0, 2), ...missingHttponly.slice(0, 2)].map(f => f.id),
        severity: Severity.HIGH,
        attackPath: [
          `XSS confirmed at: ${xssWithReflection[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Response shows reflection: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Session cookie accessible via JavaScript (missing HttpOnly)',
        ],
        evidence: [
          '=== CHAIN STEP 1: XSS Confirmation ===',
          xssWithReflection[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: Cookie Security ===',
          missingHttponly[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'XSS reflects input without sanitization. Cookie lacks HttpOnly flag.',
        ].join('\n'),
        impact: 'Session hijacking, account impersonation, data theft',
        confidence: 0.85,
        mitre: 'T1189',
      });
    }
  }

  // ── 3. SSRF → INTERNAL PIVOT (only if SSRF actually reached internal service) ──
  if (ssrfFindings.length > 0) {
    const ssrfConfirmed = ssrfFindings.filter(f =>
      f.evidence?.includes('169.254.169.254') || f.evidence?.includes('localhost') ||
      f.evidence?.includes('internal') || f.description.includes('internal') ||
      f.severity === Severity.CRITICAL
    );
    if (ssrfConfirmed.length > 0) {
      const payload = extractPayload(ssrfConfirmed[0]);
      const response = extractResponse(ssrfConfirmed[0]);
      const internalEvidence = ssrfConfirmed[0].evidence?.includes('169.254.169.254')
        ? 'Cloud metadata endpoint (169.254.169.254) was accessible'
        : ssrfConfirmed[0].evidence?.includes('localhost')
          ? 'Localhost service was reachable via SSRF'
          : 'Internal service was reachable via SSRF';
      chains.push({
        id: 'ssrf-pivot',
        title: 'SSRF → Internal Network Pivot',
        description: `SSRF confirmed — server made requests to internal services. ${internalEvidence}.`,
        findings: ssrfConfirmed.map(f => f.id),
        severity: Severity.CRITICAL,
        attackPath: [
          `SSRF at: ${ssrfConfirmed[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          internalEvidence,
        ],
        evidence: [
          '=== CHAIN STEP 1: SSRF Confirmation ===',
          ssrfConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: Internal Access ===',
          internalEvidence,
          '',
          '=== CHAIN VALIDATION ===',
          'SSRF successfully reached internal network services.',
        ].join('\n'),
        impact: 'Cloud account compromise, internal network access, credential theft',
        confidence: 0.88,
        mitre: 'T1190',
      });
    }
  }

  // ── 4. LFI → RCE (only if LFI reached /proc or logs AND cmd injection exists) ──
  if (lfiFindings.length > 0 && cmdInjFindings.length > 0) {
    const lfiToProc = lfiFindings.filter(f =>
      f.evidence?.includes('/proc/self') || f.evidence?.includes('/var/log') ||
      f.evidence?.includes('root:') || f.evidence?.includes('/bin/bash')
    );
    if (lfiToProc.length > 0) {
      const payload = extractPayload(lfiToProc[0]);
      const response = extractResponse(lfiToProc[0]);
      const cmdPayload = extractPayload(cmdInjFindings[0]);
      chains.push({
        id: 'lfi-to-rce',
        title: 'Path Traversal → Log Poisoning → RCE',
        description: `LFI confirmed reaching system files. Command injection also confirmed — chain enables RCE via log poisoning.`,
        findings: [...lfiToProc.slice(0, 2), ...cmdInjFindings.slice(0, 1)].map(f => f.id),
        severity: Severity.CRITICAL,
        attackPath: [
          `LFI at: ${lfiToProc[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `System file contents leaked: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          `Command injection confirmed at: ${cmdInjFindings[0].affectedAsset || 'unknown'}`,
          `Cmd injection payload: ${cmdPayload || 'see finding evidence'}`,
        ],
        evidence: [
          '=== CHAIN STEP 1: LFI to System Files ===',
          lfiToProc[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: Command Injection ===',
          cmdInjFindings[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'LFI reaches system files. Command injection exists. Log poisoning enables full RCE.',
        ].join('\n'),
        impact: 'Full server compromise via remote code execution',
        confidence: 0.8,
        mitre: 'T1190',
      });
    }
  }

  // ── 5. IDOR + EXPOSED API → DATA BREACH (only if IDOR was tested and confirmed) ──
  if (idorFindings.length > 0) {
    const idorConfirmed = idorFindings.filter(f =>
      f.evidence?.includes('200') || f.evidence?.includes('data') ||
      f.severity === Severity.HIGH || f.severity === Severity.CRITICAL
    );
    if (idorConfirmed.length > 0) {
      const payload = extractPayload(idorConfirmed[0]);
      const response = extractResponse(idorConfirmed[0]);
      chains.push({
        id: 'idor-data-breach',
        title: 'Mass Data Breach via IDOR on API Endpoints',
        description: `IDOR confirmed — unauthorized access to records via predictable IDs.`,
        findings: idorConfirmed.map(f => f.id),
        severity: Severity.HIGH,
        attackPath: [
          `IDOR at: ${idorConfirmed[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Records accessible without authorization',
        ],
        evidence: [
          '=== CHAIN STEP 1: IDOR Confirmation ===',
          idorConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'IDOR allows unauthorized record access via predictable IDs.',
        ].join('\n'),
        impact: 'Complete data breach of all user records',
        confidence: 0.82,
        mitre: 'T1190',
      });
    }
  }

  // ── 6. OPEN REDIRECT → PHISHING (only if redirect was confirmed) ──
  if (redirectFindings.length > 0) {
    const redirectConfirmed = redirectFindings.filter(f =>
      f.evidence?.includes('302') || f.evidence?.includes('301') ||
      f.evidence?.includes('Location:') || f.severity === Severity.HIGH
    );
    if (redirectConfirmed.length > 0) {
      const payload = extractPayload(redirectConfirmed[0]);
      const response = extractResponse(redirectConfirmed[0]);
      chains.push({
        id: 'redirect-phishing',
        title: 'Open Redirect → OAuth Token Theft / Phishing',
        description: `Open redirect confirmed — server redirects to external URL without validation.`,
        findings: redirectConfirmed.slice(0, 3).map(f => f.id),
        severity: Severity.MEDIUM,
        attackPath: [
          `Redirect at: ${redirectConfirmed[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Redirect to external domain confirmed',
        ],
        evidence: [
          '=== CHAIN STEP 1: Open Redirect Confirmation ===',
          redirectConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'Open redirect allows phishing and OAuth token theft.',
        ].join('\n'),
        impact: 'Account takeover via OAuth token theft, credential phishing',
        confidence: 0.78,
        mitre: 'T1204',
      });
    }
  }

  // ── 7. CORS + XSS → DATA THEFT (only if both confirmed) ──
  if (corsFindings.length > 0 && xssFindings.length > 0) {
    const corsConfirmed = corsFindings.filter(f =>
      f.evidence?.includes('Access-Control-Allow-Origin') || f.severity !== Severity.INFO
    );
    const xssConfirmed = xssFindings.filter(f =>
      f.evidence?.includes('reflected') || f.evidence?.includes('Payload:') || f.severity === Severity.HIGH
    );
    if (corsConfirmed.length > 0 && xssConfirmed.length > 0) {
      const payload = extractPayload(xssConfirmed[0]);
      const response = extractResponse(xssConfirmed[0]);
      chains.push({
        id: 'cors-xss-data-theft',
        title: 'CORS Misconfiguration + XSS → Cross-Origin Data Theft',
        description: `CORS misconfiguration confirmed. XSS confirmed — combined allows cross-origin data exfiltration.`,
        findings: [...corsConfirmed.slice(0, 1), ...xssConfirmed.slice(0, 1)].map(f => f.id),
        severity: Severity.HIGH,
        attackPath: [
          `CORS misconfig: ${corsConfirmed[0].evidence?.slice(0, 200) || 'see finding'}`,
          `XSS at: ${xssConfirmed[0].affectedAsset || 'unknown'}`,
          `XSS Payload: ${payload || 'see finding evidence'}`,
          `XSS Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
        ],
        evidence: [
          '=== CHAIN STEP 1: CORS Misconfiguration ===',
          corsConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: XSS Confirmation ===',
          xssConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'Both CORS misconfiguration and XSS confirmed. Cross-origin data theft possible.',
        ].join('\n'),
        impact: 'Cross-origin data exfiltration, user data theft',
        confidence: 0.8,
        mitre: 'T1189',
      });
    }
  }

  // ── 8. WEAK CREDS + EXPOSED SERVICE (only if creds were tested) ──
  if (credFindings.length > 0 && exposedServiceFindings.length > 0) {
    const credTested = credFindings.filter(f =>
      f.evidence?.includes('successful') || f.evidence?.includes('authenticated') ||
      f.evidence?.includes('default') || f.severity === Severity.CRITICAL
    );
    if (credTested.length > 0) {
      const payload = extractPayload(credTested[0]);
      const response = extractResponse(credTested[0]);
      chains.push({
        id: 'creds-exposed-service',
        title: 'Weak Credentials on Exposed Service → Full Compromise',
        description: `Default/weak credentials confirmed on exposed service.`,
        findings: [...credTested.slice(0, 2), ...exposedServiceFindings.slice(0, 2)].map(f => f.id),
        severity: Severity.CRITICAL,
        attackPath: [
          `Exposed service: ${exposedServiceFindings[0].affectedAsset || 'unknown'}`,
          `Credential test: ${payload || 'see finding evidence'}`,
          `Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Authentication successful with weak credentials',
        ],
        evidence: [
          '=== CHAIN STEP 1: Exposed Service ===',
          exposedServiceFindings[0].evidence || 'No evidence',
          '',
          '=== CHAIN STEP 2: Credential Test ===',
          credTested[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'Weak credentials confirmed on exposed service.',
        ].join('\n'),
        impact: 'Full service compromise, data theft, potential lateral movement',
        confidence: 0.85,
        mitre: 'T1110',
      });
    }
  }

  // ── 9. SSTI → RCE (only if SSTI was confirmed with expression evaluation) ──
  if (sstiFindings.length > 0) {
    const sstiConfirmed = sstiFindings.filter(f =>
      f.evidence?.includes('49') || f.evidence?.includes('evaluated') ||
      f.severity === Severity.CRITICAL
    );
    if (sstiConfirmed.length > 0) {
      const payload = extractPayload(sstiConfirmed[0]);
      const response = extractResponse(sstiConfirmed[0]);
      chains.push({
        id: 'ssti-rce',
        title: 'Server-Side Template Injection → Remote Code Execution',
        description: `SSTI confirmed — template expression evaluated on server.`,
        findings: sstiConfirmed.map(f => f.id),
        severity: Severity.CRITICAL,
        attackPath: [
          `SSTI at: ${sstiConfirmed[0].affectedAsset || 'unknown'}`,
          `Payload: ${payload || 'see finding evidence'}`,
          `Response: ${response ? response.slice(0, 200) : 'see finding evidence'}`,
          'Template expression evaluated — RCE possible',
        ],
        evidence: [
          '=== CHAIN STEP 1: SSTI Confirmation ===',
          sstiConfirmed[0].evidence || 'No evidence',
          '',
          '=== CHAIN VALIDATION ===',
          'SSTI confirmed with expression evaluation. RCE is achievable.',
        ].join('\n'),
        impact: 'Remote code execution, full server compromise',
        confidence: 0.92,
        mitre: 'T1190',
      });
    }
  }

  // ── SUMMARY ───────────────────────────────────────────────────────────────
  const chainCount = chains.length;
  const criticalChains = chains.filter(c => c.severity === Severity.CRITICAL);
  const skippedCount = findings.length - realFindings.length;
  const summary = `Found ${chainCount} correlated attack chain(s) with real evidence: ${criticalChains.length} critical, ${chains.filter(c => c.severity === Severity.HIGH).length} high. ` +
    `${skippedCount} finding(s) skipped (no real evidence). ` +
    `${pivots.length} pivot points identified. ` +
    `Most dangerous: ${chains[0]?.title || 'none'}`;

  logger.info(`[Correlation] ${summary}`);

  return { chains, pivots, attackPaths, summary };
}

export function correlateToFindings(correlations: CorrelationResult, domain: string): Finding[] {
  const findings: Finding[] = [];

  for (const chain of correlations.chains) {
    findings.push({
      id: `chain-${chain.id}`,
      title: `Attack Chain: ${chain.title}`,
      description: chain.description,
      severity: chain.severity,
      category: 'Attack Chain',
      affectedAsset: domain,
      evidence: chain.evidence,
      impact: chain.impact,
      remediation: `Break this attack chain by addressing the earliest step. Focus on the root cause finding.`,
      references: [`https://attack.mitre.org/techniques/${chain.mitre.replace('T', '')}`],
      detectedAt: new Date(),
      confidence: chain.confidence,
    });
  }

  for (const pivot of correlations.pivots) {
    findings.push({
      id: `pivot-${pivot.from}-${pivot.to}`,
      title: `Pivot Point: Cross-Module Attack Link`,
      description: `Vulnerability ${pivot.from} can be chained to exploit ${pivot.to} via: ${pivot.via}.`,
      severity: Severity.HIGH,
      category: 'Attack Chain',
      affectedAsset: domain,
      evidence: pivot.evidence,
      impact: 'Chained exploitation increases overall risk',
      remediation: 'Address the source vulnerability to break the pivot chain',
      references: [],
      detectedAt: new Date(),
      confidence: 0.85,
    });
  }

  for (const path of correlations.attackPaths) {
    findings.push({
      id: `attackpath-${path.name.replace(/\s+/g, '-').toLowerCase()}`,
      title: `Attack Path: ${path.name}`,
      description: `Complete attack path from reconnaissance to impact. Impact: ${path.impact}`,
      severity: Severity.HIGH,
      category: 'Attack Chain',
      affectedAsset: domain,
      evidence: path.evidence,
      impact: path.impact,
      remediation: 'Implement defense-in-depth at each stage of this attack path',
      references: [],
      detectedAt: new Date(),
      confidence: 0.8,
    });
  }

  return findings;
}

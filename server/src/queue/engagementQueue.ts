// ENGAGEMENT-AWARE QUEUE — Wraps existing scan queue with engagement tracking
// Adds engagement context to the scan flow:
//   - Scope enforcement before scan starts
//   - Asset + service discovery persisted to engagement
//   - Evidence captured per finding
//   - Tool execution audit trail

import Bull from 'bull';
import { AssessmentStatus, EngagementStatus, ScanJobStatus, AssetType } from '@prisma/client';
import { config } from '../config';
import { runAssessment, ScanLogEntry, MidScanInsight } from '../engine';
import { setScanContext, clearScanContext } from '../engine/scanLogger';
import { calculateSecurityScore } from '../engine/riskScoring';
import { createFindingsBulk } from '../services/finding.service';
import { generateReport } from '../services/report.service';
import { updateAssessmentStatus } from '../services/assessment.service';
import { importFromScanResults } from '../services/assetInventory.service';
import { createEvidence } from '../services/evidence.service';
import { updateEngagementStatus } from '../services/engagement.service';
import { hypothesisPersistenceService } from '../services/hypothesisPersistence.service';
import { ScanModule } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import redis from '../lib/redis';

// --- Job Data Types ---

export interface EngagementScanJobData {
  assessmentId: string;
  domain: string;
  organizationId: string;
  modules: string[];
  engagementId?: string;
}

// --- Queue ---

const engagementScanQueue = new Bull<EngagementScanJobData>('cyberguard-engagement-scans', config.redisUrl, {
  defaultJobOptions: {
    attempts: 1,
    removeOnComplete: 100,
    removeOnFail: 50,
    timeout: 1800000, // 30 minutes
  },
  settings: {
    stalledInterval: 120000, // 2 min — scans take 10-20 min
    lockDuration: 1800000,   // 30 min lock
    maxStalledCount: 1,
  },
});

// --- Asset Extraction from Findings ---

function extractAssetsFromFindings(domain: string, findings: any[], scanResults?: any[]) {
  const assets: { type: AssetType; value: string; metadata?: Record<string, unknown> }[] = [];
  const services: { assetValue: string; assetType: AssetType; port: number; protocol: string; service: string; version?: string }[] = [];
  const seenAssets = new Set<string>();
  const seenServices = new Set<string>();

  assets.push({ type: AssetType.DOMAIN, value: domain, metadata: { primary: true } });
  seenAssets.add(domain);

  // Helper to add an asset
  function addAsset(type: AssetType, value: string, metadata?: Record<string, unknown>) {
    if (seenAssets.has(value)) return;
    seenAssets.add(value);
    assets.push({ type, value, metadata });
  }

  // Helper to add a service
  function addService(host: string, port: number, serviceName: string) {
    const key = host + ':' + port;
    if (seenServices.has(key)) return;
    seenServices.add(key);
    services.push({ assetValue: host, assetType: AssetType.DOMAIN, port, protocol: 'tcp', service: serviceName });
  }

  // --- Parse port/service info from findings evidence and description ---
  const portServiceMap: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5672: 'AMQP', 5900: 'VNC',
    6379: 'Redis', 6443: 'Kubernetes', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 9418: 'Git',
    11211: 'Memcached', 27017: 'MongoDB',
  };

  function parsePortServicePairs(text: string) {
    // Matches patterns like "21/FTP", "21/FTP, 9418/Git", "80/HTTP-Alt"
    const matches = text.matchAll(/(\d{1,5})\/([A-Za-z0-9_-]+)/gi);
    for (const m of matches) {
      const port = parseInt(m[1]);
      const svc = m[2].toLowerCase();
      if (port > 0 && port <= 65535) {
        addService(domain, port, svc);
      }
    }
  }

  function parsePortsList(text: string) {
    // Matches patterns like "21, 22, 443, 8080" or "21-25"
    const ranges = text.matchAll(/(\d{1,5})-(\d{1,5})/g);
    for (const m of ranges) {
      const start = parseInt(m[1]);
      const end = parseInt(m[2]);
      for (let p = start; p <= end && p <= 65535; p++) {
        const svcName = portServiceMap[p] || 'unknown';
        addService(domain, p, svcName);
      }
    }
    const singles = text.matchAll(/\b(\d{1,5})\b/g);
    for (const m of singles) {
      const port = parseInt(m[1]);
      if (port > 0 && port <= 65535 && !portServiceMap[port]) continue;
      if (port > 0 && port <= 65535) {
        const svcName = portServiceMap[port] || 'unknown';
        addService(domain, port, svcName);
      }
    }
  }

  for (const f of findings) {
    const asset = f.affectedAsset || '';
    const evidence = (f.evidence || '') + ' ' + (f.description || '');

    // Domain
    const domainMatch = asset.match(/^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$/);
    if (domainMatch) addAsset(AssetType.DOMAIN, domainMatch[0]);
    // Also extract subdomains from evidence
    const subdomainMatches = evidence.matchAll(/\b([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.([a-zA-Z]{2,}))\b/g);
    for (const m of subdomainMatches) {
      const sub = m[1].toLowerCase();
      if (sub !== domain && sub.endsWith('.' + domain)) {
        addAsset(AssetType.DOMAIN, sub);
      }
    }

    // IP
    const ipMatch = asset.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipMatch) addAsset(AssetType.IP, ipMatch[1]);
    const ipMatches = evidence.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    for (const m of ipMatches) {
      // Skip private/reserved IPs
      if (!m[1].startsWith('0.') && !m[1].startsWith('127.')) {
        addAsset(AssetType.IP, m[1]);
      }
    }

    // URL
    if (asset.startsWith('http')) {
      try { const url = new URL(asset); addAsset(AssetType.URL, asset); } catch {}
    }

    // Port:service pairs from evidence
    if (f.category === 'Port Scan' || f.category === 'Service Audit') {
      parsePortServicePairs(evidence);
    }

    // Extract service from title for port scan findings
    const portMatch = asset.match(/:(\d+)/);
    if (portMatch) {
      const port = parseInt(portMatch[1]);
      const host = asset.replace(/:\d+$/, '').replace(/^(https?:\/\/)/, '');
      const svcLower = (f.title || '').toLowerCase();
      let serviceName = portServiceMap[port] || 'unknown';
      if (svcLower.includes('ssh')) serviceName = 'ssh';
      else if (svcLower.includes('smb') || svcLower.includes('netbios')) serviceName = 'smb';
      else if (svcLower.includes('rdp')) serviceName = 'rdp';
      else if (svcLower.includes('mysql')) serviceName = 'mysql';
      else if (svcLower.includes('postgresql')) serviceName = 'postgresql';
      else if (svcLower.includes('redis')) serviceName = 'redis';
      else if (svcLower.includes('mongo')) serviceName = 'mongodb';
      addService(host || domain, port, serviceName);
    }
  }

  // --- Also extract services from scanResults portScan module directly ---
  if (scanResults) {
    const portResult = scanResults.find((r: any) => r.module === 'portScan');
    if (portResult) {
      for (const f of portResult.findings) {
        const ev = (f.evidence || '') + ' ' + (f.description || '');
        parsePortServicePairs(ev);
        // Parse from affectedAsset too
        const portMatch = f.affectedAsset?.match(/:(\d+)/);
        if (portMatch) {
          const port = parseInt(portMatch[1]);
          const svcName = portServiceMap[port] || f.title?.toLowerCase().replace(/open\s+port\s+\d+\s*\(?/i, '').replace(/\)/g, '') || 'unknown';
          addService(domain, port, svcName);
        }
      }
      // Also add all open ports from the raw results
      for (const f of portResult.findings) {
        const portMatch = f.affectedAsset?.match(/:(\d+)/);
        if (portMatch) {
          const port = parseInt(portMatch[1]);
          const svcName = portServiceMap[port] || 'unknown';
          addService(domain, port, svcName);
        }
      }
    }
  }

  return { assets, services };
}

// --- AI Hypothesis Generation ---

async function generateHypothesesFromFindings(engagementId: string, domain: string, findings: any[]): Promise<void> {
  try {
    const { getAI } = await import('../services/ai.service');
    const ai = getAI();

    // Generate hypotheses based on findings patterns using MITRE ATT&CK reasoning
    const critical = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    const medium = findings.filter(f => f.severity === 'MEDIUM');
    const categories = [...new Set(findings.map(f => f.category))];

    const hypotheses: Array<{ hypothesis: string; reasoning: string; confidence: number; testAction: string }> = [];

    // Pattern 1: Missing security headers → weak security posture (T1027 - Obfuscated Files)
    const headerFindings = findings.filter(f => f.category === 'Security Headers');
    if (headerFindings.length > 0) {
      const missingHeaders = headerFindings.map(f => f.title).join(', ');
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1027 (Obfuscated Files/Info): Weak security posture — ${domain} is missing critical security headers (${missingHeaders}). This suggests the application lacks security controls that would detect and prevent obfuscated payloads, making XSS and injection attacks more likely to succeed.`,
        reasoning: `Missing security headers indicates the application was not built with defense-in-depth. Without Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options, the application is vulnerable to XSS, clickjacking, and MIME-type confusion attacks. Attackers can use this to deliver malicious payloads.`,
        confidence: 0.85,
        testAction: 'Test for XSS, clickjacking, and MIME-type confusion. Verify if CSP can be bypassed. Check for DOM-based XSS using the lack of CSP.',
      });
    }

    // Pattern 2: TLS issues → downgrade attacks (T1557 - Adversary-in-the-Middle)
    const tlsFindings = findings.filter(f => f.category === 'TLS/SSL' || f.category === 'Cryptographic Issues');
    if (tlsFindings.length > 0) {
      const tlsIssues = tlsFindings.map(f => f.title).join(', ');
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1557 (Adversary-in-the-Middle): Outdated TLS configuration on ${domain}: ${tlsIssues}. This enables man-in-the-middle attacks to intercept credentials, session tokens, and sensitive data in transit.`,
        reasoning: `TLS misconfigurations allow attackers to perform downgrade attacks (T1557.005) and intercept encrypted communications. Weak ciphers and expired certificates indicate the server has not been hardened, potentially exposing it to known CVEs and protocol attacks.`,
        confidence: 0.75,
        testAction: 'Test for TLS downgrade attacks (POODLE, DROWN). Check for certificate pinning bypass. Verify if weak ciphers can be forced.',
      });
    }

    // Pattern 3: Information disclosure → reconnaissance chain (T1592 + T1589)
    const infoFindings = findings.filter(f => f.category === 'Information Disclosure' || f.title.toLowerCase().includes('disclosure') || f.title.toLowerCase().includes('exposure'));
    if (infoFindings.length >= 2) {
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1592/T1589 (Gather Victim Host/Identity Information): Information disclosure chain on ${domain}: Multiple information leaks (${infoFindings.length} findings) can be combined to map the attack surface, identify technologies, and enumerate users for targeted attacks.`,
        reasoning: `Information disclosure findings compound. Server version leaks, error message details, and exposed files provide attackers with the intelligence needed to craft targeted exploits. Combined with T1589 (identity information), this enables credential stuffing and brute force attacks.`,
        confidence: 0.85,
        testAction: 'Correlate all information disclosure findings. Attempt to use disclosed information for targeted attacks against specific technologies identified.',
      });
    }

    // Pattern 4: Authentication weaknesses (T1078 - Valid Accounts)
    const authFindings = findings.filter(f => f.category === 'Authentication' || f.title.toLowerCase().includes('auth') || f.title.toLowerCase().includes('session'));
    if (authFindings.length > 0) {
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1078 (Valid Accounts): Authentication vulnerabilities on ${domain}: ${authFindings.map(f => f.title).join('; ')}. An attacker could gain unauthorized access using weak credentials, session fixation, or authentication bypass.`,
        reasoning: `Authentication weaknesses are high-impact. Combined with T1589 (identity information) and T1592 (host information), an attacker could enumerate users, perform credential attacks, and establish persistent access. This maps to the Initial Access tactic (TA0001).`,
        confidence: 0.7,
        testAction: 'Test for brute force protection, account lockout, session management, and multi-factor authentication. Check for default credentials.',
      });
    }

    // Pattern 5: Exposed configuration → persistence (T1505 - Server Software Component)
    const configFindings = findings.filter(f => f.category === 'Web Configuration' || f.title.toLowerCase().includes('config') || f.title.toLowerCase().includes('default') || f.title.toLowerCase().includes('exposed'));
    if (configFindings.length > 0) {
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1505.003 (Server Software Component: Web Shell): Server misconfiguration on ${domain}: Exposed configuration files (${configFindings.length} findings) may contain credentials, API keys, or internal architecture details that enable persistence and lateral movement.`,
        reasoning: `Exposed configuration files are a direct vulnerability. Attackers routinely scan for .git, .env, backup files, and admin panels (T1190 - Exploit Public-Facing Application). These files can contain database credentials, API keys, or internal paths that enable lateral movement.`,
        confidence: 0.9,
        testAction: 'Check for .git, .env, .DS_Store, backup files, admin panels, and debug endpoints. Attempt to use discovered credentials for lateral movement.',
      });
    }

    // Pattern 6: Open ports → service exploitation (T1190 - Exploit Public-Facing Application)
    const portFindings = findings.filter(f => f.category === 'Port Scan' || f.category === 'Service Exposure');
    if (portFindings.length > 0) {
      hypotheses.push({
        hypothesis: `MITRE ATT&CK T1190 (Exploit Public-Facing Application): Open ports on ${domain} expose services that may contain known vulnerabilities. Unnecessary services increase the attack surface and provide additional entry points.`,
        reasoning: `Each open port represents a potential entry point. Services like FTP, Telnet, or SSH with weak configurations can be exploited. Combined with T1046 (Service Scanning), attackers can map the environment and identify vulnerable services.`,
        confidence: 0.75,
        testAction: 'Test each open service for default credentials, known CVEs, and misconfigurations. Check for unnecessary services that should be disabled.',
      });
    }

    // Always generate an attack surface hypothesis
    const totalVulns = critical.length + medium.length;
    hypotheses.push({
      hypothesis: `MITRE ATT&CK Kill Chain Assessment for ${domain}: ${findings.length} total findings across ${categories.length} security domains. The combination of ${critical.length} critical/high and ${medium.length} medium findings indicates a ${critical.length > 3 ? 'HIGH' : medium.length > 5 ? 'MODERATE' : 'MANAGED'} risk. Attack chain potential: ${critical.length > 0 ? 'Multiple critical findings can be chained for maximum impact' : 'Medium findings may be combinable for elevated risk'}.`,
      reasoning: `Aggregated analysis using MITRE ATT&CK framework: Reconnaissance (TA0043) revealed ${categories.length} attack surfaces. Weaponization potential: ${critical.length} critical vectors. Delivery paths: ${findings.length} attack vectors identified. Expected kill chain progression: ${critical.length > 0 ? 'Reconnaissance → Initial Access → Execution → Impact' : 'Reconnaissance → Initial Access → Potential Impact'}.`,
      confidence: 0.95,
      testAction: 'Review all findings and prioritize remediation based on exploitability and business impact. Focus on breaking the kill chain at the Initial Access stage.',
    });

    // Store hypotheses
    for (const h of hypotheses) {
      try {
        await hypothesisPersistenceService.create({
          engagementId,
          hypothesis: h.hypothesis,
          reasoning: h.reasoning,
          confidence: h.confidence,
          testAction: h.testAction,
        });
      } catch (e) {
        logger.warn('[EngagementQueue] Failed to create hypothesis: ' + e);
      }
    }

    logger.info('[EngagementQueue] Generated ' + hypotheses.length + ' hypotheses for engagement ' + engagementId);
  } catch (e) {
    logger.warn('[EngagementQueue] Hypothesis generation failed: ' + e);
  }
}

// --- Attack Path Creation from AI Chains ---

async function createAttackPathsFromChains(engagementId: string, domain: string, chains: any[], findings: any[]): Promise<void> {
  if (!chains || chains.length === 0) return;

  try {
    for (const chain of chains) {
      if (!chain.title || !chain.attackPath || !Array.isArray(chain.attackPath)) continue;

      const severityMap: Record<string, string> = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' };
      const impactLevel = severityMap[chain.severity] || 'MEDIUM';

      // Create the attack path
      const attackPath = await prisma.attackPath.create({
        data: {
          engagementId,
          title: chain.title,
          description: chain.description || '',
          riskScore: impactLevel === 'CRITICAL' ? 9.0 : impactLevel === 'HIGH' ? 7.5 : impactLevel === 'MEDIUM' ? 5.0 : 3.0,
          confidence: 0.7,
          pathLength: chain.attackPath.length,
          entryPoint: chain.attackPath[0] || 'Unknown entry point',
          impactPoint: chain.attackPath[chain.attackPath.length - 1] || 'Unknown impact',
          impactLevel,
        },
      });

      // Create nodes for each step in the attack path
      const nodeIds: string[] = [];
      for (let i = 0; i < chain.attackPath.length; i++) {
        const step = chain.attackPath[i];
        let nodeType = 'vulnerability';
        if (i === 0) nodeType = 'asset';
        else if (i === chain.attackPath.length - 1) nodeType = 'impact';
        else if (step.toLowerCase().includes('credential') || step.toLowerCase().includes('password') || step.toLowerCase().includes('token')) nodeType = 'credential';
        else if (step.toLowerCase().includes('privilege') || step.toLowerCase().includes('admin') || step.toLowerCase().includes('root')) nodeType = 'permission';
        else if (step.toLowerCase().includes('session') || step.toLowerCase().includes('cookie')) nodeType = 'session';
        else if (step.toLowerCase().includes('service') || step.toLowerCase().includes('port')) nodeType = 'service';

        // Try to match step to a finding
        const matchedFinding = findings.find((f: any) =>
          step.toLowerCase().includes(f.title?.toLowerCase() || '') ||
          f.title?.toLowerCase().includes(step.toLowerCase().slice(0, 20))
        );

        // Extract MITRE technique from chain title if present
        const mitreMatch = chain.title?.match(/T\d{4}(?:\.\d{3})?/g);
        const mitreTechnique = mitreMatch ? mitreMatch[Math.min(i, mitreMatch.length - 1)] : undefined;

        // Build metadata JSON
        const metadata: Record<string, unknown> = {
          stepIndex: i,
          totalSteps: chain.attackPath.length,
          isEntryPoint: i === 0,
          isImpactPoint: i === chain.attackPath.length - 1,
        };
        if (mitreTechnique) metadata.mitreTechnique = mitreTechnique;
        if (matchedFinding) {
          metadata.findingId = matchedFinding.id;
          metadata.findingSeverity = matchedFinding.severity;
          metadata.findingCategory = matchedFinding.category;
        }

        const node = await prisma.attackPathNode.create({
          data: {
            attackPathId: attackPath.id,
            nodeType,
            label: step.substring(0, 200),
            assetValue: i === 0 ? domain : undefined,
            vulnerability: matchedFinding?.title,
            evidence: matchedFinding?.evidence?.substring(0, 2000) || buildStepEvidence(step, nodeType, domain),
            metadata: JSON.stringify(metadata),
          },
        });
        nodeIds.push(node.id);
      }

      // Create edges connecting nodes with descriptive labels
      for (let i = 0; i < nodeIds.length - 1; i++) {
        const currentStep = chain.attackPath[i];
        const nextStep = chain.attackPath[i + 1];

        // Determine edge type based on step content
        let edgeType = 'leads_to';
        if (currentStep.toLowerCase().includes('exploit') || currentStep.toLowerCase().includes('vulnerability')) edgeType = 'exploits';
        else if (currentStep.toLowerCase().includes('escalat') || currentStep.toLowerCase().includes('privilege')) edgeType = 'escalates_to';
        else if (currentStep.toLowerCase().includes('access') || currentStep.toLowerCase().includes('credential')) edgeType = 'accesses';
        else if (currentStep.toLowerCase().includes('discover') || currentStep.toLowerCase().includes('enum')) edgeType = 'discovers';

        // Build edge evidence
        const edgeEvidence = `Step ${i + 1}: ${currentStep}\n-> Step ${i + 2}: ${nextStep}`;

        // Find matching finding for this step
        const stepFinding = findings.find((f: any) =>
          currentStep.toLowerCase().includes(f.title?.toLowerCase() || '') ||
          f.title?.toLowerCase().includes(currentStep.toLowerCase().slice(0, 20))
        );

        await prisma.attackPathEdge.create({
          data: {
            attackPathId: attackPath.id,
            sourceNodeId: nodeIds[i],
            targetNodeId: nodeIds[i + 1],
            edgeType,
            label: `${currentStep.substring(0, 100)} -> ${nextStep.substring(0, 100)}`,
            evidence: edgeEvidence,
            confidence: 0.6 + ((stepFinding as any)?.confidence || 0) * 0.2,
          },
        });
      }

      logger.info('[EngagementQueue] Created attack path: ' + chain.title + ' (' + nodeIds.length + ' nodes)');
    }
  } catch (e) {
    logger.warn('[EngagementQueue] Attack path creation failed: ' + e);
  }
}

function buildStepEvidence(step: string, nodeType: string, domain: string): string {
  const parts: string[] = [];
  parts.push('Step: ' + step);
  parts.push('Type: ' + nodeType);
  parts.push('Target: ' + domain);

  if (nodeType === 'asset') {
    parts.push('Context: Entry point or impact target in the attack chain');
  } else if (nodeType === 'vulnerability') {
    parts.push('Context: Vulnerability that can be exploited to advance the attack');
  } else if (nodeType === 'credential') {
    parts.push('Context: Credential or authentication material that can be harvested or abused');
  } else if (nodeType === 'permission') {
    parts.push('Context: Privilege level that enables further escalation');
  } else if (nodeType === 'service') {
    parts.push('Context: Network service that provides an attack surface');
  }

  return parts.join('\n');
}

// --- Generate Attack Paths from Findings (when AI chains are empty) ---

async function generateAttackPathsFromFindings(engagementId: string, domain: string, findings: any[]): Promise<void> {
  if (findings.length === 0) return;

  try {
    const attackPaths: Array<{ title: string; description: string; findings: string[]; severity: string; entryPoint: string; impactPoint: string; mitreTechniques: string[] }> = [];

    // Pattern 1: Information Disclosure -> Credential Harvesting -> Access (T1592 → T1078 → T1190)
    const infoDisc = findings.filter(f =>
      f.title.toLowerCase().includes('disclosure') || f.title.toLowerCase().includes('exposure') ||
      f.title.toLowerCase().includes('leak') || f.title.toLowerCase().includes('config') ||
      f.title.toLowerCase().includes('file') || f.title.toLowerCase().includes('.git')
    );
    if (infoDisc.length >= 1) {
      attackPaths.push({
        title: 'MITRE T1592→T1078→T1190: Information Disclosure to Targeted Exploit',
        description: `MITRE ATT&CK Kill Chain: (T1592) Gather Victim Host Information via exposed files and configuration on ${domain}. (T1589) Gather Victim Identity Information from disclosed data. (T1078) Use discovered credentials for Valid Accounts. (T1190) Exploit Public-Facing Application using identified vulnerabilities. The attacker follows a structured kill chain from reconnaissance through exploitation.`,
        findings: infoDisc.map(f => f.title),
        severity: 'HIGH',
        entryPoint: infoDisc[0].affectedAsset || domain,
        impactPoint: 'Full application compromise via targeted exploit',
        mitreTechniques: ['T1592', 'T1589', 'T1078', 'T1190'],
      });
    }

    // Pattern 2: Missing Security Headers -> XSS/Clickjacking (T1189 → T1059 → T1071)
    const headerIssues = findings.filter(f =>
      f.category === 'Security Headers' || f.title.toLowerCase().includes('missing') && f.title.toLowerCase().includes('header')
    );
    if (headerIssues.length >= 2) {
      const missingHeaders = headerIssues.map(f => f.title.replace('Missing ', '').replace(' header', '')).join(', ');
      attackPaths.push({
        title: 'MITRE T1189→T1059→T1071: Missing Headers Exploitation',
        description: `MITRE ATT&CK Chain: (T1189) Drive-by Compromise via malicious links exploiting missing CSP. (T1059) Command and Scripting Interpreter via XSS payloads executing in user browsers. (T1071) Application Layer Protocol for data exfiltration. ${domain} is missing ${headerIssues.length} security headers (${missingHeaders}), enabling clickjacking, MIME sniffing, and XSS attacks.`,
        findings: headerIssues.map(f => f.title),
        severity: 'MEDIUM',
        entryPoint: domain,
        impactPoint: 'User credential theft via phishing/clickjacking',
        mitreTechniques: ['T1189', 'T1059', 'T1071'],
      });
    }

    // Pattern 3: TLS/SSL Weakness -> Man-in-the-Middle (T1557 → T1539 → T1555)
    const tlsIssues = findings.filter(f =>
      f.category === 'TLS/SSL' || f.category === 'TLS/HTTPS' || f.category === 'Cryptographic Issues' ||
      f.title.toLowerCase().includes('tls') || f.title.toLowerCase().includes('ssl') || f.title.toLowerCase().includes('certificate')
    );
    if (tlsIssues.length >= 1) {
      attackPaths.push({
        title: 'MITRE T1557→T1539→T1555: TLS Downgrade / MitM Attack',
        description: `MITRE ATT&CK Chain: (T1557) Adversary-in-the-Middle via TLS weaknesses. (T1557.005) Capture credentials via network sniffing on weak TLS. (T1539) Steal Web Session Cookie from intercepted traffic. (T1555) Credentials from Password Store via intercepted authentication data. TLS/SSL weaknesses on ${domain} (${tlsIssues.map(f => f.title).join('; ')}) allow interception of encrypted traffic.`,
        findings: tlsIssues.map(f => f.title),
        severity: 'HIGH',
        entryPoint: 'Network position (WiFi, ISP, DNS hijack)',
        impactPoint: 'Credential interception and session hijacking',
        mitreTechniques: ['T1557', 'T1539', 'T1555'],
      });
    }

    // Pattern 4: Authentication Issues -> Account Takeover (T1078 → T1110 → T1021)
    const authIssues = findings.filter(f =>
      f.category === 'Authentication' || f.title.toLowerCase().includes('auth') ||
      f.title.toLowerCase().includes('session') || f.title.toLowerCase().includes('login') ||
      f.title.toLowerCase().includes('credential')
    );
    if (authIssues.length >= 1) {
      attackPaths.push({
        title: 'MITRE T1078→T1110→T1021: Authentication Bypass / Account Takeover',
        description: `MITRE ATT&CK Chain: (T1078) Valid Accounts via weak/default credentials. (T1110) Brute Force with credential stuffing or password spraying. (T1021) Remote Services via authenticated access. Authentication weaknesses on ${domain} (${authIssues.map(f => f.title).join('; ')}) enable unauthorized access and lateral movement.`,
        findings: authIssues.map(f => f.title),
        severity: 'CRITICAL',
        entryPoint: 'Login form / Authentication endpoint',
        impactPoint: 'Full account takeover and data access',
        mitreTechniques: ['T1078', 'T1110', 'T1021'],
      });
    }

    // Pattern 5: Email Security -> Phishing / BEC (T1566 → T1078 → T1572)
    const emailIssues = findings.filter(f =>
      f.category === 'Email Security' || f.title.toLowerCase().includes('email') ||
      f.title.toLowerCase().includes('spf') || f.title.toLowerCase().includes('dkim') || f.title.toLowerCase().includes('dmarc')
    );
    if (emailIssues.length >= 2) {
      attackPaths.push({
        title: 'MITRE T1566→T1078→T1572: Email Spoofing / Phishing Campaign',
        description: `MITRE ATT&CK Chain: (T1566) Phishing via spoofed emails. (T1566.001) Spearphishing Link with credential harvesting. (T1078) Valid Accounts via harvested credentials. (T1572) Protocol Tunneling for persistent access. Email security misconfigurations on ${domain} (${emailIssues.map(f => f.title).join('; ')}) enable email spoofing and phishing.`,
        findings: emailIssues.map(f => f.title),
        severity: 'HIGH',
        entryPoint: 'Email (SPF/DKIM/DMARC misconfigured)',
        impactPoint: 'Business email compromise and credential theft',
        mitreTechniques: ['T1566', 'T1078', 'T1572'],
      });
    }

    // Pattern 6: DNS Issues -> Subdomain Hijack (T1583 → T1190 → T1078)
    const dnsIssues = findings.filter(f =>
      f.category === 'DNS Security' || f.title.toLowerCase().includes('dns') ||
      f.title.toLowerCase().includes('subdomain') || f.title.toLowerCase().includes('caa')
    );
    if (dnsIssues.length >= 1) {
      attackPaths.push({
        title: 'MITRE T1583→T1190→T1078: DNS-Based Attack Chain',
        description: `MITRE ATT&CK Chain: (T1583) Acquire Infrastructure for subdomain takeover. (T1190) Exploit Public-Facing Application via hijacked subdomain. (T1078) Valid Accounts on the hijacked service. DNS misconfigurations on ${domain} (${dnsIssues.map(f => f.title).join('; ')}) can be exploited for subdomain takeover and traffic redirection.`,
        findings: dnsIssues.map(f => f.title),
        severity: 'MEDIUM',
        entryPoint: 'DNS resolution',
        impactPoint: 'Traffic redirection and credential theft',
        mitreTechniques: ['T1583', 'T1190', 'T1078'],
      });
    }

    // Pattern 7: Broad - Critical/High findings combined (full kill chain)
    const criticalHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    if (criticalHigh.length >= 3) {
      attackPaths.push({
        title: 'MITRE Kill Chain: Multi-Vector Attack Chain',
        description: `MITRE ATT&CK Full Kill Chain: (TA0043 Reconnaissance) ${domain} has ${criticalHigh.length} critical/high severity findings. (TA0001 Initial Access) Multiple entry points via: ${criticalHigh.slice(0, 3).map(f => f.title).join('; ')}. (TA0002 Execution) Exploitation of identified vulnerabilities. (TA0040 Impact) Full system compromise and data exfiltration. An attacker can chain these vulnerabilities for maximum impact.`,
        findings: criticalHigh.map(f => f.title),
        severity: 'CRITICAL',
        entryPoint: 'Any of ' + criticalHigh.length + ' critical/high vulnerabilities',
        impactPoint: 'Full system compromise and data exfiltration',
        mitreTechniques: ['TA0043', 'TA0001', 'TA0002', 'TA0040'],
      });
    }

    // Store attack paths
    for (const ap of attackPaths) {
      try {
        const severityMap: Record<string, number> = { CRITICAL: 9.0, HIGH: 7.5, MEDIUM: 5.0, LOW: 3.0 };
        const riskScore = severityMap[ap.severity] || 5.0;

        const path = await prisma.attackPath.create({
          data: {
            engagementId,
            title: ap.title,
            description: ap.description,
            riskScore,
            confidence: 0.65,
            pathLength: ap.findings.length + 2, // entry + findings + impact
            entryPoint: ap.entryPoint,
            impactPoint: ap.impactPoint,
            impactLevel: ap.severity,
          },
        });

        // Create entry node with full metadata
        const entryNode = await prisma.attackPathNode.create({
          data: {
            attackPathId: path.id,
            nodeType: 'asset',
            label: ap.entryPoint.substring(0, 200),
            assetValue: domain,
            evidence: 'Attack chain entry point: ' + ap.entryPoint + '\nMITRE Techniques: ' + ap.mitreTechniques.join(', ') + '\nRelated findings: ' + ap.findings.slice(0, 3).join('; '),
            metadata: JSON.stringify({
              stepIndex: 0,
              totalSteps: ap.findings.length + 2,
              isEntryPoint: true,
              mitreTechniques: ap.mitreTechniques,
              attackDescription: ap.description,
            }),
          },
        });

        // Create finding nodes with evidence from actual findings
        const nodeIds = [entryNode.id];
        for (const fTitle of ap.findings.slice(0, 5)) {
          const matchedFinding = findings.find((f: any) => f.title === fTitle);
          const findingNode = await prisma.attackPathNode.create({
            data: {
              attackPathId: path.id,
              nodeType: 'vulnerability',
              label: fTitle.substring(0, 200),
              vulnerability: fTitle,
              evidence: matchedFinding?.evidence?.substring(0, 2000) || 'Finding: ' + fTitle + '\nSeverity: ' + (matchedFinding?.severity || 'unknown') + '\nCategory: ' + (matchedFinding?.category || 'unknown'),
              metadata: JSON.stringify({
                findingId: matchedFinding?.id,
                findingSeverity: matchedFinding?.severity,
                findingCategory: matchedFinding?.category,
                confidence: matchedFinding?.confidence,
                cvssScore: matchedFinding?.cvssScore,
              }),
            },
          });
          nodeIds.push(findingNode.id);
        }

        // Create impact node with full context
        const impactNode = await prisma.attackPathNode.create({
          data: {
            attackPathId: path.id,
            nodeType: 'impact',
            label: ap.impactPoint.substring(0, 200),
            evidence: 'Impact: ' + ap.impactPoint + '\nSeverity: ' + ap.severity + '\nRisk Score: ' + riskScore + '/10\nAttack path length: ' + (ap.findings.length + 2) + ' steps',
            metadata: JSON.stringify({
              isImpactPoint: true,
              riskScore,
              impactLevel: ap.severity,
              chainLength: ap.findings.length + 2,
            }),
          },
        });
        nodeIds.push(impactNode.id);

        // Create edges with descriptive labels and evidence
        for (let i = 0; i < nodeIds.length - 1; i++) {
          const isLast = i === nodeIds.length - 2;
          const edgeLabel = i === 0
            ? 'Entry: ' + ap.entryPoint.substring(0, 80)
            : isLast
              ? 'Impact: ' + ap.impactPoint.substring(0, 80)
              : 'Exploits: ' + (ap.findings[i - 1] || '').substring(0, 80);

          const edgeEvidence = i === 0
            ? 'Initial access vector: ' + ap.entryPoint + '\nTechniques: ' + ap.mitreTechniques.join(', ')
            : isLast
              ? 'Final impact: ' + ap.impactPoint + '\nRisk level: ' + ap.severity
              : 'Step ' + (i + 1) + ' -> ' + (i + 2) + ': ' + (ap.findings[i - 1] || '') + ' -> ' + (ap.findings[i] || ap.impactPoint);

          await prisma.attackPathEdge.create({
            data: {
              attackPathId: path.id,
              sourceNodeId: nodeIds[i],
              targetNodeId: nodeIds[i + 1],
              edgeType: i === 0 ? 'accesses' : isLast ? 'leads_to' : 'exploits',
              label: edgeLabel.substring(0, 200),
              evidence: edgeEvidence.substring(0, 2000),
              confidence: 0.6 + (i * 0.05), // Confidence decreases along chain
              metadata: JSON.stringify({
                stepIndex: i,
                mitreTechnique: ap.mitreTechniques[i] || ap.mitreTechniques[ap.mitreTechniques.length - 1],
              }),
            },
          });
        }

        logger.info('[EngagementQueue] Created attack path: ' + ap.title + ' (' + nodeIds.length + ' nodes)');
      } catch (e) {
        logger.warn('[EngagementQueue] Failed to create attack path: ' + e);
      }
    }

    if (attackPaths.length > 0) {
      logger.info('[EngagementQueue] Generated ' + attackPaths.length + ' attack paths from findings');
    }
  } catch (e) {
    logger.warn('[EngagementQueue] Attack path generation from findings failed: ' + e);
  }
}

// --- Evidence Capture ---

async function captureScanEvidence(
  assessmentId: string,
  findings: any[],
  scanResults: any[],
): Promise<void> {
  try {
    for (const result of scanResults) {
      if (result.findings.length > 0) {
        const evidenceContent = JSON.stringify({
          module: result.module,
          findingsCount: result.findings.length,
          duration: result.duration,
          findings: result.findings.map((f: any) => ({
            title: f.title,
            severity: f.severity,
            affectedAsset: f.affectedAsset,
          })),
        }, null, 2);

        await createEvidence({
          assessmentId,
          type: 'tool_output',
          title: result.module + ' scan results',
          content: evidenceContent.substring(0, 50000),
          contentType: 'application/json',
          metadata: { module: result.module, duration: result.duration },
        });
      }
    }
  } catch (e) {
    logger.warn('[EngagementQueue] Failed to capture evidence: ' + e);
  }
}

// --- Queue Processor ---

engagementScanQueue.process(async (job) => {
  const { assessmentId, domain, organizationId, modules, engagementId } = job.data;

  let scanJob: { id: string } | null = null;
  try {
    scanJob = await prisma.scanJob.create({
      data: {
        assessmentId,
        status: ScanJobStatus.PROCESSING,
        modulesToRun: JSON.stringify(modules),
      },
    });

    await updateAssessmentStatus(assessmentId, AssessmentStatus.RUNNING);
    setScanContext(assessmentId);

    if (engagementId) {
      await updateEngagementStatus(engagementId, organizationId, EngagementStatus.ACTIVE);
      logger.info('[EngagementQueue] Scan started for engagement ' + engagementId + ' - ' + domain);
    }

    logger.info('[EngagementQueue] Scan queued for ' + domain + ' - ' + modules.length + ' modules');
    await job.progress(5);

    let credentials = null;
    try {
      const { listCredentials } = await import('../services/credential.service');
      const creds = await listCredentials(assessmentId);
      if (creds.length > 0) {
        credentials = creds[0];
        logger.info('[EngagementQueue] Using authenticated scanning with credential: ' + credentials.name);
      }
    } catch (e) {
      logger.debug('[EngagementQueue] No credentials found for scanning');
    }

    const progressKey = 'engagement:' + engagementId + ':progress';
    const logsKey = 'scan:' + assessmentId + ':logs';
    const modulesRun: { name: string; duration: number; findings: number }[] = [];

    const SCAN_SAFETY_TIMEOUT = 1500000; // 25 minutes

    // Cancellation checker — polls Redis every 5s for cancel flag
    let scanCancelled = false;
    const cancelCheckInterval = setInterval(async () => {
      try {
        const v = await redis.get('scan:' + assessmentId + ':cancelled');
        if (v === '1') {
          scanCancelled = true;
          logger.info('[EngagementQueue] Cancellation flag detected for ' + assessmentId);
        }
      } catch {}
    }, 5000);

    // Module weights for accurate progress calculation
    const MODULE_WEIGHTS: Record<string, number> = {
      dns: 2, tls: 2, headers: 1, webConfig: 2, technology: 1, portScan: 3, osFingerprint: 1, dnsDeep: 1, emailSecurity: 2,
      activeVuln: 5, kaliTools: 15, modernAttacks: 5, exploitChain: 5, exploitation: 6, brokenAuth: 4, apiSecurity: 4, businessLogic: 4,
      supplyChain: 3, supplyChainIntel: 3, sourceAnalysis: 2, behavioral: 3, liveCve: 3, cloudSecurity: 3, clientSecurity: 3,
      serviceAudit: 3, advancedAttacks: 4, httpMethods: 2, subdomains: 3, subdomainTakeover: 3, siteCrawl: 3,
      cveCorrelation: 2, tlsDeep: 2, windowsSystem: 3, linuxSystem: 3, activeDirectory: 5, networkPentest: 5,
      smarterRecon: 4, correlation: 2,
      deepDiscovery: 5, adaptiveReasoning: 1,
      aiCveResearch: 6,
      autonomousPentester: 8,
    };
    const totalWeight = modules.reduce((sum, m) => sum + (MODULE_WEIGHTS[m] || 3), 0);
    let completedWeight = 0;

    const scanResults = await Promise.race([
      runAssessment(domain, modules as ScanModule[], (moduleName, index, total) => {
        // Check cancellation before each module
        if (scanCancelled) throw new Error('Scan cancelled by user');
        // Weighted progress: heavier modules contribute more to progress bar
        // Weighted progress: heavier modules contribute more to progress bar
        const prevModules = modules.slice(0, index);
        completedWeight = prevModules.reduce((sum, m) => sum + (MODULE_WEIGHTS[m] || 3), 0);
        const progress = Math.min(95, Math.round(5 + (completedWeight / totalWeight) * 80));
        const moduleLabels: Record<string, string> = {
          dns: 'Enumerating DNS records, subdomains, and zone data',
          tls: 'Analyzing TLS/SSL certificates, cipher suites, and protocol versions',
          headers: 'Inspecting HTTP security headers (CSP, HSTS, X-Frame-Options)',
          webConfig: 'Probing for exposed configuration files and admin panels',
          technology: 'Fingerprinting web technologies, frameworks, and versions',
          subdomains: 'Discovering subdomains via DNS brute-force and certificate transparency',
          emailSecurity: 'Validating SPF, DKIM, and DMARC email security policies',
          portScan: 'Scanning network ports and identifying running services',
          sslLabs: 'Evaluating SSL/TLS configuration and certificate chain',
          whoisLookup: 'Gathering WHOIS registration and ownership data',
          wafDetection: 'Detecting web application firewalls and security layers',
          apiSecurity: 'Testing API endpoints for authentication and authorization flaws',
          authScan: 'Probing authentication mechanisms for weaknesses',
          inputValidation: 'Testing input fields for injection vulnerabilities',
          businessLogic: 'Analyzing business logic flows for bypass opportunities',
          cryptoAnalysis: 'Examining cryptographic implementations for weaknesses',
          dataExposure: 'Scanning for sensitive data leakage in responses',
          injection: 'Testing for SQL, NoSQL, and command injection vectors',
          misconfiguration: 'Identifying security misconfigurations and default settings',
          openSourceIntel: 'Gathering open-source intelligence and public exposure',
          networkScan: 'Mapping network topology and identifying attack surface',
          vulnerabilityScan: 'Running vulnerability scans against known CVEs',
          complianceCheck: 'Checking compliance with security standards and best practices',
          cloudSecurity: 'Evaluating cloud resource configurations and permissions',
          containerSecurity: 'Assessing container and orchestration security',
          activeDirectory: 'Analyzing Active Directory configuration and trust relationships',
          socialEngineering: 'Assessing social engineering attack vectors',
          wirelessSecurity: 'Evaluating wireless network security configurations',
          exploitation: 'Exploiting XSS, SQL injection, command injection, path traversal, IDOR, and open redirect vulnerabilities',
          smarterRecon: 'AI-driven recon: analyzing tech stack, generating attack hypotheses, enumerating framework-specific endpoints',
          correlation: 'Correlating findings across modules to identify attack chains and pivot points',
          deepDiscovery: 'Deep content discovery: JavaScript parsing, wordlist fuzzing, backup file detection, API surface mapping',
          adaptiveReasoning: 'Adaptive strategy: analyzing patterns, generating targeted follow-up attacks, pivoting strategy based on findings',
          aiCveResearch: 'AI CVE Research: discovering CVEs for detected software, planning and executing safe PoC validation tests',
          autonomousPentester: 'Autonomous Pentest: querying NVD/OSV databases, AI reasoning about attack vectors, safe PoC execution, iterative replanning',
        };
        const aiActivity = moduleLabels[moduleName] || `Executing ${moduleName} module`;
        const progressData = JSON.stringify({ progress, currentModule: moduleName, aiActivity, status: 'RUNNING', moduleIndex: index + 1, totalModules: total });
        redis.set(progressKey, progressData, 'EX', 600).catch(() => {});
        const channel = 'engagement:' + engagementId + ':events';
        redis.publish(channel, progressData).catch(() => {});
        // Store activity log entry
        redis.rpush(logsKey, JSON.stringify({ ts: new Date().toISOString(), type: 'module_start', module: moduleName, message: aiActivity })).catch(() => {});
        redis.ltrim(logsKey, -200, -1).catch(() => {});
        redis.expire(logsKey, 900).catch(() => {});
      }, (entry) => {
        redis.rpush(logsKey, JSON.stringify(entry)).catch(() => {});
        redis.ltrim(logsKey, -200, -1).catch(() => {});
        redis.expire(logsKey, 900).catch(() => {});
      }, (insight: MidScanInsight) => {
        const channel = 'engagement:' + engagementId + ':events';
        redis.publish(channel, JSON.stringify({
          type: 'ai_insight',
          insight,
          ts: new Date().toISOString(),
        })).catch(() => {});
        redis.rpush(logsKey, JSON.stringify({
          ts: new Date().toISOString(),
          type: 'ai_insight',
          module: 'AI',
          message: `[${insight.type}] ${insight.title}: ${insight.description.slice(0, 200)}`,
        })).catch(() => {});
        redis.ltrim(logsKey, -200, -1).catch(() => {});
      }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Scan safety timeout after ' + (SCAN_SAFETY_TIMEOUT / 60000) + ' minutes')), SCAN_SAFETY_TIMEOUT)),
    ]);

    clearInterval(cancelCheckInterval);
    // Clear cancellation flag
    await redis.del('scan:' + assessmentId + ':cancelled').catch(() => {});

    const { results: scanModuleResults, aiEnriched, aiTriageResult, classification } = scanResults;

    for (const result of scanModuleResults) {
      modulesRun.push({
        name: result.module,
        duration: result.duration,
        findings: result.findings.length,
      });
      // Publish module completion event
      const channel = 'engagement:' + engagementId + ':events';
      redis.publish(channel, JSON.stringify({
        type: 'module_complete',
        module: result.module,
        findings: result.findings.length,
        duration: result.duration,
        message: `${result.module} completed: ${result.findings.length} findings in ${(result.duration / 1000).toFixed(1)}s`,
      })).catch(() => {});
    }

    await redis.set(progressKey + ':modulesRun', JSON.stringify(modulesRun), 'EX', 600);
    if (classification) {
      await redis.set(progressKey + ':classification', JSON.stringify({
        primary: classification.primary,
        confidence: classification.confidence,
        services: classification.services,
        webTech: classification.webTech,
        osGuess: classification.osGuess,
        openPorts: classification.openPorts,
        reasons: classification.reasons,
      }), 'EX', 600);
    }
    if (aiTriageResult) {
      await redis.set(progressKey + ':aiChains', JSON.stringify(aiTriageResult.chains || []), 'EX', 600);
      await redis.set(progressKey + ':attackNarrative', aiTriageResult.attackNarrative || '', 'EX', 600);
      await redis.set(progressKey + ':remediationPlan', JSON.stringify(aiTriageResult.remediationPlan || []), 'EX', 600);
    }

    await redis.del(progressKey + ':activeModule');
    await job.progress(70);

    // Publish AI activity events
    const channel = 'engagement:' + engagementId + ':events';
    redis.publish(channel, JSON.stringify({ type: 'ai_activity', message: 'AI analyzing findings and generating attack paths...', phase: 'enrichment' })).catch(() => {});

    const allFindings = scanModuleResults.flatMap((r) => r.findings);

    if (engagementId) {
      redis.publish(channel, JSON.stringify({ type: 'ai_activity', message: 'Importing ' + allFindings.length + ' findings into engagement...', phase: 'import' })).catch(() => {});
      logger.info('[EngagementQueue] Importing scan results into engagement ' + engagementId);
      const { assets, services } = extractAssetsFromFindings(domain, allFindings, scanModuleResults);
      await importFromScanResults(engagementId, { assets, services });
      await captureScanEvidence(assessmentId, allFindings, scanModuleResults);

      // --- Generate AI Hypotheses ---
      if (allFindings.length > 0) {
        redis.publish(channel, JSON.stringify({ type: 'ai_activity', message: 'Generating attack hypotheses from ' + allFindings.length + ' findings...', phase: 'hypotheses' })).catch(() => {});
        await generateHypothesesFromFindings(engagementId, domain, allFindings);
      }

      // --- Create Attack Paths from AI Chains ---
      if (aiTriageResult?.chains && aiTriageResult.chains.length > 0) {
        redis.publish(channel, JSON.stringify({ type: 'ai_activity', message: 'Building ' + aiTriageResult.chains.length + ' attack paths from vulnerability chains...', phase: 'attack_paths' })).catch(() => {});
        await createAttackPathsFromChains(engagementId, domain, aiTriageResult.chains, allFindings);
      } else if (allFindings.length > 0) {
        // No AI chains — generate attack paths from finding patterns
        redis.publish(channel, JSON.stringify({ type: 'ai_activity', message: 'Generating attack paths from ' + allFindings.length + ' findings...', phase: 'attack_paths' })).catch(() => {});
        await generateAttackPathsFromFindings(engagementId, domain, allFindings);
      }

      for (const result of scanModuleResults) {
        try {
          await prisma.toolExecution.create({
            data: {
              engagementId,
              toolName: result.module,
              category: 'recon',
              command: 'module:' + result.module,
              target: domain,
              status: 'completed',
              exitCode: 0,
              findingsCount: result.findings.length,
              durationMs: result.duration,
              completedAt: new Date(),
            },
          });
        } catch (e) {
          logger.warn('[EngagementQueue] Failed to record tool execution: ' + e);
        }
      }
    }

    if (allFindings.length > 0) {
      await createFindingsBulk(
        allFindings.map((f) => ({
          assessmentId,
          title: f.title,
          description: f.description,
          severity: f.severity,
          category: f.category,
          cvssScore: f.cvssScore,
          affectedAsset: f.affectedAsset,
          evidence: f.evidence,
          impact: f.impact,
          remediation: f.remediation,
          references: f.references,
        }))
      );
    }

    // After findings are saved, compare with previous scan
    const { compareWithPreviousScan } = await import('../services/historyComparison.service');
    try {
      const comparison = await compareWithPreviousScan(domain, organizationId, allFindings);
        if (comparison.previousAssessmentId) {
        logger.info('[EngagementQueue] Delta comparison: ' + comparison.summary);
        if (engagementId) {
          const delta = {
            previousAssessmentId: comparison.previousAssessmentId,
            previousDate: comparison.previousDate,
            newFindingsCount: comparison.newFindings.length,
            fixedFindingsCount: comparison.fixedFindings.length,
            regressionDetected: comparison.regressionDetected,
            improvementDetected: comparison.improvementDetected,
            summary: comparison.summary,
          };
          const engagement = await prisma.engagement.findUnique({ where: { id: engagementId } });
          const existingConfig = engagement?.config ? JSON.parse(engagement.config) : {};
          await prisma.engagement.update({
            where: { id: engagementId },
            data: {
              config: JSON.stringify({ ...existingConfig, delta }),
            },
          });
        }
      }
    } catch (e) {
      logger.warn('[EngagementQueue] Delta comparison failed: ' + e);
    }

    await job.progress(80);

    const riskResult = calculateSecurityScore(allFindings);
    await generateReport(assessmentId, organizationId, modules as ScanModule[], modulesRun);

    await prisma.scanJob.update({
      where: { id: scanJob.id },
      data: { status: ScanJobStatus.COMPLETED, progress: 100 },
    });

    await updateAssessmentStatus(assessmentId, AssessmentStatus.COMPLETED, riskResult.score);

    if (engagementId) {
      await updateEngagementStatus(engagementId, organizationId, EngagementStatus.COMPLETED);
      logger.info('[EngagementQueue] Engagement ' + engagementId + ' completed - ' + allFindings.length + ' findings');
    }

    await redis.set(progressKey, JSON.stringify({ progress: 100, status: 'COMPLETED' }), 'EX', 600);
    const completeChannel = 'engagement:' + engagementId + ':events';
    await redis.publish(completeChannel, JSON.stringify({ progress: 100, status: 'COMPLETED' })).catch(() => {});

    await job.progress(100);
    // Delay deletion so SSE subscribers can read it
    setTimeout(() => redis.del(progressKey).catch(() => {}), 5000);
    clearScanContext();

    return { assessmentId, findingsCount: allFindings.length, riskScore: riskResult.score, engagementId };
  } catch (error) {
    clearScanContext();
    logger.error('[EngagementQueue] Scan job failed for assessment ' + assessmentId + ': ' + error);

    if (engagementId) {
      try {
        await updateEngagementStatus(engagementId, organizationId, EngagementStatus.FAILED);
      } catch (e) {
        logger.warn('[EngagementQueue] Failed to update engagement status: ' + (e instanceof Error ? e.message : String(e)));
      }
    }

    try {
      if (scanJob) {
        await Promise.race([
          prisma.scanJob.update({
            where: { id: scanJob.id },
            data: { status: ScanJobStatus.FAILED },
          }),
          new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 5000)),
        ]);
      }
    } catch (e) {
      logger.warn('[EngagementQueue] Failed to update scan job status: ' + (e instanceof Error ? e.message : String(e)));
    }

    try {
      await Promise.race([
        updateAssessmentStatus(assessmentId, AssessmentStatus.FAILED),
        new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 5000)),
      ]);
    } catch (e) {
      logger.warn('[EngagementQueue] Failed to update assessment status: ' + (e instanceof Error ? e.message : String(e)));
    }
  }
});

// --- Orphan Recovery ---

async function recoverOrphanedJobs() {
  try {
    const orphaned = await prisma.scanJob.updateMany({
      where: { status: 'PROCESSING' },
      data: { status: 'FAILED' },
    });
    if (orphaned.count > 0) {
      await prisma.assessment.updateMany({
        where: { status: 'RUNNING' },
        data: { status: 'FAILED', completedAt: new Date() },
      });
      await prisma.engagement.updateMany({
        where: { status: 'ACTIVE' },
        data: { status: 'FAILED', completedAt: new Date() },
      });
      logger.warn('[EngagementQueue] Recovered ' + orphaned.count + ' orphaned scan job(s)');
    }
  } catch (e) {
    logger.error('[EngagementQueue] Orphan recovery failed: ' + e);
  }
}

recoverOrphanedJobs();

engagementScanQueue.on('completed', (job, result) => {
  logger.info('[EngagementQueue] Job ' + job.id + ' completed', result);
});

engagementScanQueue.on('failed', (job, err) => {
  logger.error('[EngagementQueue] Job ' + (job?.id) + ' failed: ' + err.message);
});

export async function addEngagementScanJob(data: EngagementScanJobData): Promise<Bull.Job<EngagementScanJobData>> {
  return engagementScanQueue.add(data, {
    priority: 1,
    delay: 0,
  });
}

export async function cancelScan(assessmentId: string): Promise<boolean> {
  try {
    // Search both queues for the job
    const queues = [engagementScanQueue];
    try {
      const { scanQueue } = await import('./index');
      queues.push(scanQueue);
    } catch {}

    for (const queue of queues) {
      const jobs = await queue.getJobs(['active', 'waiting', 'delayed', 'completed', 'failed']);
      for (const job of jobs) {
        if (job.data.assessmentId === assessmentId) {
          try {
            await job.remove();
            logger.info('[EngagementQueue] Removed job for assessment: ' + assessmentId);
          } catch (e) {
            // Job may be active and can't be removed — abort it
            logger.warn('[EngagementQueue] Could not remove job, attempting abort: ' + e);
            try { await job.progress(-1); } catch {}
          }
          return true;
        }
      }
    }

    // Even if no Bull job found, set the cancellation flag so any running loop stops
    const cancelKey = 'scan:' + assessmentId + ':cancelled';
    await redis.set(cancelKey, '1', 'EX', 3600);
    logger.info('[EngagementQueue] Set cancellation flag for assessment: ' + assessmentId);
    return true;
  } catch (e) {
    logger.warn('[EngagementQueue] Failed to cancel scan: ' + e);
    return false;
  }
}

async function gracefulShutdown() {
  logger.info('[EngagementQueue] Shutting down...');
  await engagementScanQueue.close();
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

export { engagementScanQueue };

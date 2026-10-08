import { Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logVuln, logDone } from '../scanLogger';
import { getAI, AttackSurfaceTarget, AttackSurfaceMap, AttackVector, PriorityVector, TargetType } from '../../services/ai.service';

const MODULE_NAME = 'universalAttackSurface';

export interface UniversalAttackSurfaceResult {
  attackSurfaceMap: AttackSurfaceMap;
  coverage: { tested: string[]; untested: string[]; coveragePercent: number };
  priorityVectors: PriorityVector[];
  newFindings: Finding[];
}

export async function runUniversalAttackSurface(domain: string, priorFindings: Finding[] = []): Promise<UniversalAttackSurfaceResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  logInfo(MODULE_NAME, `Starting universal attack surface enumeration for ${domain}`);

  try {
    // Build target profile from prior findings
    const target = buildAttackSurfaceTarget(domain, priorFindings);

    // Use AI to enumerate complete attack surface
    const ai = getAI();
    const attackSurfaceMap = await ai.enumerateAttackSurface(target);

    // Generate findings for high-priority untested vectors
    for (const priority of attackSurfaceMap.priorities.slice(0, 10)) {
      const vector = attackSurfaceMap.vectors.find(v => v.id === priority.vectorId);
      if (vector && vector.applicable && priority.priority > 7) {
        findings.push(generateFinding(
          `Untested Attack Vector: ${vector.title}`,
          `High-priority attack vector not yet tested: ${vector.description}. 
Technique: ${vector.technique}
Module: ${vector.module}
Prerequisites: ${vector.prerequisites.join(', ') || 'none'}
Suggested payloads: ${vector.payloads.slice(0, 3).join(', ')}`,
          priority.potentialImpact === 'critical' ? Severity.CRITICAL :
            priority.potentialImpact === 'high' ? Severity.HIGH :
              priority.potentialImpact === 'medium' ? Severity.MEDIUM : Severity.LOW,
          'Attack Surface Enumeration',
          domain,
          `Test this vector using module ${vector.module} with the suggested payloads. Expected evidence: ${vector.expectedEvidence.join(', ')}`,
          `If exploited, potential impact: ${priority.potentialImpact}. Could lead to ${vector.category} compromise.`,
          `Run ${vector.module} module against this target. Monitor for: ${vector.expectedEvidence.join(', ')}`,
          [vector.technique]
        ));
      }
    }

    // Add coverage finding
    findings.push(generateFinding(
      `Attack Surface Coverage Analysis`,
      `Universal attack surface enumeration completed for ${domain}.
Target Type: ${target.targetType}
Total Vectors Identified: ${attackSurfaceMap.vectors.length}
Coverage: ${attackSurfaceMap.coverage.coveragePercent}%
Tested: ${attackSurfaceMap.coverage.tested.length}
Untested: ${attackSurfaceMap.coverage.untested.length}

Categories: ${[...new Set(attackSurfaceMap.vectors.map(v => v.category))].join(', ')}`,
      Severity.INFO,
      'Attack Surface Enumeration',
      domain,
      `Priority vectors to test next: ${attackSurfaceMap.priorities.slice(0, 5).map(p => p.vectorId).join(', ')}`,
      'Low coverage areas represent blind spots in the assessment',
      'Focus testing on high-priority untested vectors to improve coverage',
      ['T1595']
    ));

    logDone(MODULE_NAME, `Attack surface enumeration complete: ${attackSurfaceMap.vectors.length} vectors, ${attackSurfaceMap.coverage.coveragePercent}% coverage`, Date.now() - startTime);

    return {
      attackSurfaceMap,
      coverage: attackSurfaceMap.coverage,
      priorityVectors: attackSurfaceMap.priorities,
      newFindings: findings,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    errors.push(msg);
    logInfo(MODULE_NAME, `Attack surface enumeration failed: ${msg}`);
    return {
      attackSurfaceMap: { vectors: [], coverage: { tested: [], untested: [], coveragePercent: 0 }, priorities: [] },
      coverage: { tested: [], untested: [], coveragePercent: 0 },
      priorityVectors: [],
      newFindings: findings,
    };
  }
}

function buildAttackSurfaceTarget(domain: string, priorFindings: Finding[]): AttackSurfaceTarget {
  // Extract tech stack from findings
  const techStack = extractTechStack(priorFindings);
  
  // Extract open ports from findings
  const openPorts = extractOpenPorts(priorFindings);
  
  // Extract services from findings
  const services = extractServices(priorFindings);
  
  // Determine target type from findings
  const targetType = determineTargetType(priorFindings);
  
  // Extract OS info
  const osInfo = extractOSInfo(priorFindings);
  
  // Build network context
  const networkContext = buildNetworkContext(priorFindings);

  // Get IP (would need DNS resolution in real implementation)
  const ip = domain; // placeholder

  return {
    domain,
    targetType,
    ip,
    openPorts,
    services,
    techStack,
    osInfo,
    networkContext,
  };
}

function extractTechStack(findings: Finding[]): string[] {
  const tech: string[] = [];
  for (const f of findings) {
    if (f.category === 'Technology Detection' || f.category.includes('Technology')) {
      const match = f.description.match(/Detected:?\s*(.+)/i);
      if (match) {
        tech.push(...match[1].split(',').map(s => s.trim()));
      }
    }
  }
  return [...new Set(tech)];
}

function extractOpenPorts(findings: Finding[]): number[] {
  const ports: number[] = [];
  for (const f of findings) {
    const match = f.affectedAsset?.match(/:(\d+)/);
    if (match) {
      ports.push(parseInt(match[1]));
    }
    // Also check for port scan findings
    if (f.title.includes('Port') || f.title.includes('port')) {
      const portMatch = f.title.match(/(\d+)/);
      if (portMatch) ports.push(parseInt(portMatch[1]));
    }
  }
  return [...new Set(ports)].filter(p => p > 0 && p < 65536);
}

function extractServices(findings: Finding[]): AttackSurfaceTarget['services'] {
  const services: AttackSurfaceTarget['services'] = [];
  for (const f of findings) {
    if (f.category === 'Port Scan' || f.category === 'Service Detection') {
      const portMatch = f.affectedAsset?.match(/:(\d+)/);
      if (portMatch) {
        const port = parseInt(portMatch[1]);
        const service = f.description.match(/Service:\s*(\S+)/i)?.[1] || 'unknown';
        const version = f.description.match(/Version:\s*(\S+)/i)?.[1];
        services.push({
          host: f.affectedAsset.split(':')[0],
          port,
          protocol: 'tcp',
          service,
          version,
          banner: f.evidence?.substring(0, 200),
        });
      }
    }
  }
  return services;
}

function determineTargetType(findings: Finding[]): TargetType {
  const hasAD = findings.some(f => 
    f.category === 'Active Directory' || 
    f.title.toLowerCase().includes('kerberos') ||
    f.title.toLowerCase().includes('ldap') ||
    f.title.toLowerCase().includes('smb') ||
    f.title.toLowerCase().includes('active directory')
  );
  
  const hasWeb = findings.some(f =>
    f.category === 'Web Application' ||
    f.category === 'Technology Detection' ||
    f.title.toLowerCase().includes('http') ||
    f.title.toLowerCase().includes('web') ||
    f.affectedAsset?.includes('http')
  );
  
  const hasLinux = findings.some(f =>
    f.category === 'Linux' ||
    f.title.toLowerCase().includes('ssh') ||
    f.title.toLowerCase().includes('linux')
  );
  
  const hasWindows = findings.some(f =>
    f.category === 'Windows' ||
    f.title.toLowerCase().includes('rdp') ||
    f.title.toLowerCase().includes('winrm') ||
    f.title.toLowerCase().includes('windows')
  );

  if (hasAD) return 'activeDirectory';
  if (hasWeb && (hasLinux || hasWindows)) return 'mixed';
  if (hasWeb) return 'web';
  if (hasLinux) return 'linux';
  if (hasWindows) return 'windows';
  return 'network';
}

function extractOSInfo(findings: Finding[]): string {
  for (const f of findings) {
    if (f.category === 'OS Fingerprint' || f.title.toLowerCase().includes('os')) {
      return f.description + ' ' + f.evidence;
    }
  }
  return 'unknown';
}

function buildNetworkContext(findings: Finding[]): AttackSurfaceTarget['networkContext'] {
  // Simplified - in real implementation would use actual network mapping
  const segments: AttackSurfaceTarget['networkContext'] = [];
  const uniqueIPs = new Set<string>();
  
  for (const f of findings) {
    const ipMatch = f.affectedAsset?.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) uniqueIPs.add(ipMatch[1]);
  }
  
  // Group by /24
  const networks = new Map<string, string[]>();
  for (const ip of uniqueIPs) {
    const parts = ip.split('.');
    const cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    if (!networks.has(cidr)) networks.set(cidr, []);
    networks.get(cidr)!.push(ip);
  }
  
  for (const [cidr, hosts] of networks) {
    segments.push({ cidr, hosts, type: 'unknown', segmentation: 'none' });
  }
  
  return segments;
}
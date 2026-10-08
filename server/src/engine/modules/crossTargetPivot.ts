import { Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logVuln, logDone } from '../scanLogger';
import { getAI, PivotContext, PivotChain, PivotStep, TargetType, NetworkSegment, Credential } from '../../services/ai.service';

const MODULE_NAME = 'crossTargetPivot';

export interface CrossTargetPivotResult {
  pivotChains: PivotChain[];
  newFindings: Finding[];
  recommendations: string[];
}

export async function runCrossTargetPivot(domain: string, priorFindings: Finding[], targetType: TargetType, context: {
  currentAccess: { type: TargetType; host: string; credentials: Credential[] };
  networkMap: NetworkSegment[];
  allFindings: Finding[];
  targetTypes: TargetType[];
}): Promise<CrossTargetPivotResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  logInfo(MODULE_NAME, `Detecting cross-target pivot chains from ${context.currentAccess.type} on ${context.currentAccess.host}`);

  try {
    const ai = getAI();

    const pivotContext: PivotContext = {
      currentAccess: context.currentAccess,
      networkMap: context.networkMap,
      allFindings: priorFindings,
      targetTypes: context.targetTypes,
    };

    const pivotChains = await ai.detectPivotChains(pivotContext);

    // Generate findings for each pivot chain
    for (const chain of pivotChains) {
      const finalSeverity = chain.totalProbability > 0.7 ? Severity.CRITICAL :
        chain.totalProbability > 0.5 ? Severity.HIGH : Severity.MEDIUM;

      const chainDescription = chain.steps.map(s =>
        `${s.from.type} (${s.from.host}) → ${s.to.type} (${s.to.host}) via ${s.technique}: ${s.method}`
      ).join('\n');

      findings.push(generateFinding(
        `Cross-Target Pivot Chain: ${chain.steps[0]?.from.type || 'unknown'} → ${chain.finalAccess.type}`,
        `Complete pivot chain detected with ${(chain.totalProbability * 100).toFixed(0)}% probability:
${chainDescription}

Final Access: ${chain.finalAccess.type} (${chain.finalAccess.level})
MITRE Path: ${chain.mitrePath.join(' → ')}`,
        finalSeverity,
        'Cross-Target Pivot',
        domain,
        `Pivot chain requires: ${chain.steps.map(s => s.requirements.join(', ')).join('; ')}
Test each step in sequence.`,
        `Successful pivot leads to ${chain.finalAccess.level} access on ${chain.finalAccess.type}. 
This enables lateral movement across target types.`,
        'Validate each pivot step. Implement network segmentation and credential hygiene.',
        chain.mitrePath
      ));

      // Add individual step findings
      for (const step of chain.steps) {
        if (step.confidence > 0.6) {
          findings.push(generateFinding(
            `Pivot Step: ${step.from.type} → ${step.to.type}`,
            `Pivot technique: ${step.technique}
Method: ${step.method}
Requirements: ${step.requirements.join(', ') || 'none'}
Confidence: ${(step.confidence * 100).toFixed(0)}%`,
            step.confidence > 0.8 ? Severity.HIGH : Severity.MEDIUM,
            'Pivot Technique',
            domain,
            `Test pivot from ${step.from.host} to ${step.to.host} using ${step.technique}.
Requirements: ${step.requirements.join(', ') || 'none'}`,
            `Successful pivot enables access to ${step.to.type} (${step.to.host})`,
            'Implement network segmentation. Monitor for lateral movement indicators.',
            [step.technique]
          ));
        }
      }
    }

    // Generate recommendations
    const recommendations = generatePivotRecommendations(pivotChains, context.targetTypes);

    logDone(MODULE_NAME, `Cross-target pivot detection complete: ${pivotChains.length} chains found`, Date.now() - startTime);

    return {
      pivotChains,
      newFindings: findings,
      recommendations,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    errors.push(msg);
    logInfo(MODULE_NAME, `Cross-target pivot detection failed: ${msg}`);
    return {
      pivotChains: [],
      newFindings: findings,
      recommendations: [],
    };
  }
}

function generatePivotRecommendations(chains: PivotChain[], targetTypes: TargetType[]): string[] {
  const recs: string[] = [];

  if (chains.length === 0) {
    recs.push('No cross-target pivot chains detected. Ensure network segmentation between different target types.');
    return recs;
  }

  // Check for AD ↔ Web pivots
  const hasADWeb = chains.some(c =>
    c.steps.some(s => (s.from.type === 'activeDirectory' && s.to.type === 'web') || (s.from.type === 'web' && s.to.type === 'activeDirectory'))
  );
  if (hasADWeb) {
    recs.push('AD-Web pivot detected: Implement strict Kerberos delegation controls. Disable unconstrained delegation. Monitor for SPN abuse.');
  }

  // Check for AD ↔ Linux pivots
  const hasADLinux = chains.some(c =>
    c.steps.some(s => (s.from.type === 'activeDirectory' && s.to.type === 'linux') || (s.from.type === 'linux' && s.to.type === 'activeDirectory'))
  );
  if (hasADLinux) {
    recs.push('AD-Linux pivot detected: Audit SSH key trust relationships. Disable password auth for service accounts. Monitor for sudo abuse.');
  }

  // Check for Linux ↔ Web pivots
  const hasLinuxWeb = chains.some(c =>
    c.steps.some(s => (s.from.type === 'linux' && s.to.type === 'web') || (s.from.type === 'web' && s.to.type === 'linux'))
  );
  if (hasLinuxWeb) {
    recs.push('Linux-Web pivot detected: Isolate web server from internal network. Disable shell access for web user. Containerize web applications.');
  }

  // Check for Windows ↔ AD pivots
  const hasWindowsAD = chains.some(c =>
    c.steps.some(s => (s.from.type === 'windows' && s.to.type === 'activeDirectory') || (s.from.type === 'activeDirectory' && s.to.type === 'windows'))
  );
  if (hasWindowsAD) {
    recs.push('Windows-AD pivot detected: Enforce tiered administration. Disable NTLM where possible. Monitor for Pass-the-Hash/Ticket.');
  }

  // General recommendations
  recs.push('Implement network segmentation between all target types (AD, Linux, Web, Windows).');
  recs.push('Enforce least privilege and credential hygiene across all systems.');
  recs.push('Deploy lateral movement detection (EDR, network monitoring, deception).');
  recs.push('Regular audit of trust relationships, delegation, and service accounts.');

  return recs;
}

export function buildPivotContext(priorFindings: Finding[], targetType: TargetType): PivotContext {
  // Extract credentials from findings
  const credentials = extractCredentials(priorFindings);
  
  // Build network map
  const networkMap = buildNetworkMap(priorFindings);
  
  // Determine all target types present
  const targetTypes = determineTargetTypes(priorFindings);
  
  // Determine current access (simplified - would use actual session data)
  const currentAccess = determineCurrentAccess(priorFindings, targetType);

  return {
    currentAccess,
    networkMap,
    allFindings: priorFindings,
    targetTypes,
  };
}

function extractCredentials(findings: Finding[]): Credential[] {
  const creds: Credential[] = [];
  
  for (const f of findings) {
    if (f.category === 'Credential Access' || f.title.toLowerCase().includes('credential')) {
      // Parse credential info from finding
      const userMatch = f.description.match(/user:\s*(\S+)/i) || f.evidence?.match(/user:\s*(\S+)/i);
      if (userMatch) {
        creds.push({
          type: 'domain',
          username: userMatch[1],
          accessLevel: 'user',
          source: f.title,
          password: undefined,
          hash: undefined,
        });
      }
    }
  }
  
  return creds;
}

function buildNetworkMap(findings: Finding[]): NetworkSegment[] {
  const segments = new Map<string, { hosts: string[]; type: string }>();
  
  for (const f of findings) {
    const ipMatch = f.affectedAsset?.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) {
      const ip = ipMatch[1];
      const parts = ip.split('.');
      const cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      
      if (!segments.has(cidr)) {
        segments.set(cidr, { hosts: [], type: 'unknown' });
      }
      segments.get(cidr)!.hosts.push(ip);
    }
  }
  
  return Array.from(segments.entries()).map(([cidr, data]) => ({
    cidr,
    hosts: [...new Set(data.hosts)],
    type: 'unknown' as const,
    segmentation: 'none' as const,
  }));
}

function determineTargetTypes(findings: Finding[]): TargetType[] {
  const types = new Set<TargetType>();
  
  for (const f of findings) {
    if (f.category === 'Active Directory' || f.title.toLowerCase().includes('kerberos') || f.title.toLowerCase().includes('ldap')) {
      types.add('activeDirectory');
    }
    if (f.category === 'Web Application' || f.title.toLowerCase().includes('http') || f.affectedAsset?.includes('http')) {
      types.add('web');
    }
    if (f.category === 'Linux' || f.title.toLowerCase().includes('ssh')) {
      types.add('linux');
    }
    if (f.category === 'Windows' || f.title.toLowerCase().includes('rdp') || f.title.toLowerCase().includes('winrm')) {
      types.add('windows');
    }
  }
  
  return Array.from(types).length > 0 ? Array.from(types) : ['network'];
}

function determineCurrentAccess(priorFindings: Finding[], targetType: TargetType): { type: TargetType; host: string; credentials: Credential[] } {
  // Find the primary host from findings
  let host = 'unknown';
  for (const f of priorFindings) {
    const ipMatch = f.affectedAsset?.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) {
      host = ipMatch[1];
      break;
    }
  }
  
  return {
    type: targetType,
    host,
    credentials: extractCredentials(priorFindings),
  };
}
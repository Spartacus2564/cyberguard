import { Finding, Severity, ScanModule } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logDone } from '../scanLogger';
import { 
  getScanContext as getPersistentScanContext, 
  CoverageVector, 
  CoverageTracker 
} from './persistentScanContext';

const MODULE_NAME = 'coverageTracker';

// ─── COVERAGE TRACKER MODULE ────────────────────────────────────────────────
// Tracks tested vs possible attack vectors per target type
// Identifies blind spots and prioritizes untested high-value vectors

export interface CoverageTrackerResult {
  coverageReport: CoverageTracker | null;
  gapFindings: Finding[];
  priorityVectors: CoverageVector[];
  recommendations: string[];
}

export async function runCoverageTracker(domain: string, priorFindings: Finding[] = []): Promise<CoverageTrackerResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  logInfo(MODULE_NAME, `Running coverage analysis for ${domain}`);

  try {
    const context = getPersistentScanContext();
    if (!context) {
      findings.push(generateFinding(
        'Coverage Tracker: No Scan Context',
        'Persistent scan context not initialized. Cannot perform coverage analysis.',
        Severity.LOW,
        'Coverage Analysis',
        domain,
        'Initialize scan context before running coverage tracker',
        'Blind spots cannot be identified without scan context',
        'Call initializeScanContext() at scan start',
        []
      ));
      return { coverageReport: null, gapFindings: findings, priorityVectors: [], recommendations: [] };
    }

    const coverage = context.coverageTracker;
    const untestedVectors = coverage.vectors.filter(v => v.applicable && !v.tested);
    const topGaps = untestedVectors
      .sort((a, b) => b.priority - a.priority)
      .slice(0, 10);

    // Generate gap findings
    for (const gap of topGaps) {
      const severity = gap.priority >= 8 ? Severity.HIGH : 
        gap.priority >= 5 ? Severity.MEDIUM : Severity.LOW;
      
      findings.push(generateFinding(
        `Coverage Gap: ${gap.title}`,
        `High-priority attack vector not tested: ${gap.title}
Category: ${gap.category}
MITRE Technique: ${gap.technique}
Priority: ${gap.priority}/10
Confidence: ${gap.confidence}
Applicable: ${gap.applicable ? 'Yes' : 'No'}

This vector is applicable to the target but has not been tested by any module.`,
        severity,
        'Coverage Analysis',
        domain,
        `Run appropriate module to test this vector. Recommended modules: ${getModulesForVector(gap)}`,
        `Untested attack vectors represent blind spots. If exploitable, could lead to ${gap.category} compromise.`,
        `Test vector ${gap.id} using recommended modules. Update coverage tracker after testing.`,
        [gap.technique]
      ));
    }

    // Coverage summary finding
    const coveragePercent = coverage.coveragePercent;
    let severity: Severity;
    let coverageDesc: string;
    
    if (coveragePercent >= 80) {
      severity = Severity.INFO;
      coverageDesc = 'Good coverage';
    } else if (coveragePercent >= 50) {
      severity = Severity.LOW;
      coverageDesc = 'Moderate coverage';
    } else if (coveragePercent >= 25) {
      severity = Severity.MEDIUM;
      coverageDesc = 'Low coverage';
    } else {
      severity = Severity.HIGH;
      coverageDesc = 'Very low coverage';
    }

    findings.push(generateFinding(
      `Attack Surface Coverage: ${coveragePercent}% (${coverageDesc})`,
      `Coverage analysis for ${domain} (${coverage.targetType}):
Total Vectors: ${coverage.totalVectors}
Tested: ${coverage.testedVectors}
Untested: ${coverage.totalVectors - coverage.testedVectors}
Coverage: ${coveragePercent}%

Top Gaps:
${topGaps.map(g => `- ${g.title} (${g.technique}, priority: ${g.priority})`).join('\n') || 'None'}

Categories: ${[...new Set(coverage.vectors.map(v => v.category))].join(', ')}`,
      severity,
      'Coverage Analysis',
      domain,
      `Focus on testing top ${topGaps.length} gap vectors to improve coverage`,
      `Low coverage means significant attack surface is untested`,
      'Run modules for untested high-priority vectors. Re-run coverage tracker after testing.',
      ['T1595']
    ));

    // Recommendations
    const recommendations = generateCoverageRecommendations(coverage, topGaps);

    logDone(MODULE_NAME, `Coverage analysis complete: ${coveragePercent}% coverage, ${topGaps.length} high-priority gaps`, Date.now() - startTime);

    return {
      coverageReport: coverage,
      gapFindings: findings,
      priorityVectors: topGaps,
      recommendations,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    errors.push(msg);
    logInfo(MODULE_NAME, `Coverage analysis failed: ${msg}`);
    return {
      coverageReport: null,
      gapFindings: findings,
      priorityVectors: [],
      recommendations: [],
    };
  }
}

function getModulesForVector(vector: CoverageVector): string[] {
  const moduleMap: Record<string, string[]> = {
    // Network
    'T1595.001': ['portScan', 'kaliTools'],
    'T1595.002': ['kaliTools', 'serviceAudit'],
    'T1595.003': ['deepDiscovery', 'siteCrawl'],
    'T1046': ['portScan', 'networkPentest'],
    'T1069.002': ['activeDirectory', 'networkPentest'],
    
    // Web
    'T1190': ['activeVuln', 'exploitation', 'apiSecurity'],
    'T1193': ['siteCrawl', 'deepDiscovery'],
    'T1189': ['activeVuln', 'exploitation'],
    'T1059.007': ['activeVuln', 'exploitation', 'advancedAttacks'],
    'T1059.006': ['activeVuln', 'exploitation', 'advancedAttacks'],
    'T1505.003': ['siteCrawl', 'sourceAnalysis'],
    
    // AD
    'T1558.003': ['activeDirectory', 'modernAttacks'],
    'T1558.004': ['activeDirectory', 'modernAttacks'],
    'T1208': ['activeDirectory', 'kaliTools'],
    'T1003.001': ['activeDirectory', 'windowsSystem'],
    'T1003.006': ['activeDirectory'],
    'T1550.002': ['activeDirectory', 'networkPentest'],
    'T1550.003': ['activeDirectory', 'networkPentest'],
    'T1021.004': ['activeDirectory', 'networkPentest', 'windowsSystem'],
    'T1021.006': ['windowsSystem', 'networkPentest'],
    'T1021.003': ['windowsSystem', 'networkPentest'],
    'T1021.002': ['windowsSystem', 'networkPentest'],
    'T1021.005': ['windowsSystem', 'networkPentest'],
    
    // Linux
    'T1068': ['linuxSystem', 'networkPentest'],
    'T1548.003': ['linuxSystem'],
    'T1543.002': ['linuxSystem'],
    'T1053.003': ['linuxSystem'],
    'T1574.001': ['linuxSystem'],
    
    // Cloud
    'T1530': ['cloudSecurity', 'kaliTools'],
    'T1526': ['cloudSecurity'],
    'T1080': ['cloudSecurity'],
  };

  return moduleMap[vector.technique] || ['kaliTools', 'serviceAudit'];
}

function generateCoverageRecommendations(coverage: CoverageTracker, topGaps: CoverageVector[]): string[] {
  const recs: string[] = [];

  if (coverage.coveragePercent < 25) {
    recs.push('CRITICAL: Coverage below 25%. Run kaliTools (nmap/nikto/nuclei) for baseline enumeration first.');
    recs.push('Run portScan to discover all open ports and services.');
  } else if (coverage.coveragePercent < 50) {
    recs.push('Coverage below 50%. Prioritize kaliTools and serviceAudit for service enumeration.');
  }

  if (topGaps.length > 0) {
    const topGap = topGaps[0];
    recs.push(`HIGHEST PRIORITY: Test ${topGap.title} (${topGap.technique}) using modules: ${getModulesForVector(topGap).join(', ')}`);
  }

  // Category-specific recommendations
  const categories = [...new Set(coverage.vectors.map(v => v.category))];
  for (const cat of categories) {
    const catVectors = coverage.vectors.filter(v => v.category === cat);
    const catTested = catVectors.filter(v => v.tested).length;
    const catTotal = catVectors.length;
    const catPercent = catTotal > 0 ? Math.round((catTested / catTotal) * 100) : 0;
    
    if (catPercent < 30 && catTotal > 2) {
      recs.push(`Category "${cat}" has only ${catPercent}% coverage. Run ${getCategoryModules(cat).join(', ')} modules.`);
    }
  }

  recs.push('Re-run coverage tracker after each major module batch to track progress.');
  recs.push('Focus on vectors with high priority AND high confidence that are untested.');

  return recs;
}

function getCategoryModules(category: string): string[] {
  const map: Record<string, string[]> = {
    'network': ['portScan', 'kaliTools', 'networkPentest', 'osFingerprint'],
    'web': ['activeVuln', 'exploitation', 'siteCrawl', 'apiSecurity', 'advancedAttacks', 'brokenAuth', 'businessLogic'],
    'activeDirectory': ['activeDirectory', 'networkPentest', 'modernAttacks', 'kaliTools'],
    'linux': ['linuxSystem', 'networkPentest', 'kaliTools'],
    'windows': ['windowsSystem', 'networkPentest', 'kaliTools'],
    'cloud': ['cloudSecurity', 'serviceAudit', 'kaliTools'],
    'database': ['serviceAudit', 'kaliTools'],
    'email': ['emailSecurity', 'kaliTools'],
  };
  return map[category] || ['kaliTools'];
}

export function initializeCoverageForTargetType(targetType: string): void {
  const context = getPersistentScanContext();
  if (!context) return;

  // Define attack vectors per target type
  const vectorsByType: Record<string, Omit<CoverageVector, 'id' | 'tested' | 'testedBy' | 'findings' | 'confidence' | 'priority'>[]> = {
    web: [
      { category: 'web', technique: 'T1190', title: 'Exploit Public-Facing Application', applicable: true },
      { category: 'web', technique: 'T1193', title: 'Spearphishing Attachment', applicable: true },
      { category: 'web', technique: 'T1189', title: 'Drive-by Compromise', applicable: true },
      { category: 'web', technique: 'T1059.007', title: 'Command Injection', applicable: true },
      { category: 'web', technique: 'T1059.006', title: 'SQL Injection', applicable: true },
      { category: 'web', technique: 'T1505.003', title: 'Web Shell', applicable: true },
      { category: 'web', technique: 'T1552.001', title: 'Credentials in Files', applicable: true },
      { category: 'web', technique: 'T1552.002', title: 'Credentials in Registry', applicable: true },
      { category: 'web', technique: 'T1552.003', title: 'Credentials in Config', applicable: true },
      { category: 'web', technique: 'T1040', title: 'Network Sniffing', applicable: true },
      { category: 'web', technique: 'T1557', title: 'MITM', applicable: true },
      { category: 'web', technique: 'T1185', title: 'Browser Session Hijacking', applicable: true },
      { category: 'web', technique: 'T1550.001', title: 'Application Access Token', applicable: true },
      { category: 'web', technique: 'T1606', title: 'Forge Web Credentials', applicable: true },
      { category: 'web', technique: 'T1556', title: 'Modify Authentication Process', applicable: true },
    ],
    activeDirectory: [
      { category: 'activeDirectory', technique: 'T1558.003', title: 'Kerberoasting', applicable: true },
      { category: 'activeDirectory', technique: 'T1558.004', title: 'AS-REP Roasting', applicable: true },
      { category: 'activeDirectory', technique: 'T1208', title: 'Kerberos Delegation Abuse', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.001', title: 'LSASS Memory', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.006', title: 'DCSync', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.004', title: 'NTDS.dit', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.002', title: 'Pass the Hash', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.003', title: 'Pass the Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.004', title: 'Pass the Hash (SMB)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.006', title: 'Remote Services (WinRM)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.003', title: 'Remote Services (DCOM)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.002', title: 'Remote Services (SMB)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.005', title: 'Remote Services (WMI)', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.001', title: 'Golden Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.004', title: 'Silver Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1556.002', title: 'Password Filter', applicable: true },
      { category: 'activeDirectory', technique: 'T1484.001', title: 'Group Policy Modification', applicable: true },
      { category: 'activeDirectory', technique: 'T1505.003', title: 'Web Shell (AD CS)', applicable: true },
      { category: 'activeDirectory', technique: 'T1098', title: 'Account Manipulation', applicable: true },
    ],
    linux: [
      { category: 'linux', technique: 'T1068', title: 'Exploitation for Privilege Escalation', applicable: true },
      { category: 'linux', technique: 'T1548.003', title: 'Sudo and Sudo Caching', applicable: true },
      { category: 'linux', technique: 'T1543.002', title: 'Systemd Service', applicable: true },
      { category: 'linux', technique: 'T1053.003', title: 'Cron', applicable: true },
      { category: 'linux', technique: 'T1574.001', title: 'LD_PRELOAD', applicable: true },
      { category: 'linux', technique: 'T1556.003', title: 'Pluggable Authentication Modules', applicable: true },
      { category: 'linux', technique: 'T1021.004', title: 'Pass the Hash (SSH Keys)', applicable: true },
      { category: 'linux', technique: 'T1021.003', title: 'Remote Services (SSH)', applicable: true },
      { category: 'linux', technique: 'T1021.005', title: 'Remote Services (Docker)', applicable: true },
      { category: 'linux', technique: 'T1611', title: 'Escape to Host', applicable: true },
      { category: 'linux', technique: 'T1552.001', title: 'Credentials in Files', applicable: true },
      { category: 'linux', technique: 'T1552.004', title: 'Private Keys', applicable: true },
      { category: 'linux', technique: 'T1083', title: 'File and Directory Discovery', applicable: true },
      { category: 'linux', technique: 'T1082', title: 'System Information Discovery', applicable: true },
      { category: 'linux', technique: 'T1135', title: 'Network Share Discovery', applicable: true },
    ],
    windows: [
      { category: 'windows', technique: 'T1068', title: 'Exploitation for Privilege Escalation', applicable: true },
      { category: 'windows', technique: 'T1548.002', title: 'Bypass User Account Control', applicable: true },
      { category: 'windows', technique: 'T1543.003', title: 'Windows Service', applicable: true },
      { category: 'windows', technique: 'T1053.005', title: 'Scheduled Task', applicable: true },
      { category: 'windows', technique: 'T1574.002', title: 'DLL Search Order Hijacking', applicable: true },
      { category: 'windows', technique: 'T1556.002', title: 'Password Filter', applicable: true },
      { category: 'windows', technique: 'T1003.001', title: 'LSASS Memory', applicable: true },
      { category: 'windows', technique: 'T1550.002', title: 'Pass the Hash', applicable: true },
      { category: 'windows', technique: 'T1021.006', title: 'WinRM', applicable: true },
      { category: 'windows', technique: 'T1021.003', title: 'DCOM', applicable: true },
      { category: 'windows', technique: 'T1021.002', title: 'SMB', applicable: true },
      { category: 'windows', technique: 'T1021.005', title: 'WMI', applicable: true },
      { category: 'windows', technique: 'T1562.001', title: 'Disable or Modify Tools', applicable: true },
      { category: 'windows', technique: 'T1562.002', title: 'Disable Windows Event Logging', applicable: true },
      { category: 'windows', technique: 'T1059.001', title: 'PowerShell', applicable: true },
    ],
    network: [
      { category: 'network', technique: 'T1595.001', title: 'Active Scanning: Scan IP Blocks', applicable: true },
      { category: 'network', technique: 'T1595.002', title: 'Active Scanning: Vulnerability Scanning', applicable: true },
      { category: 'network', technique: 'T1595.003', title: 'Active Scanning: Wordlist Scanning', applicable: true },
      { category: 'network', technique: 'T1046', title: 'Network Service Scanning', applicable: true },
      { category: 'network', technique: 'T1069.002', title: 'Permission Groups Discovery', applicable: true },
      { category: 'network', technique: 'T1018', title: 'Remote System Discovery', applicable: true },
      { category: 'network', technique: 'T1016', title: 'System Network Configuration Discovery', applicable: true },
      { category: 'network', technique: 'T1040', title: 'Network Sniffing', applicable: true },
      { category: 'network', technique: 'T1557', title: 'MITM', applicable: true },
      { category: 'network', technique: 'T1021.001', title: 'Remote Services (RDP)', applicable: true },
      { category: 'network', technique: 'T1021.004', title: 'SMB', applicable: true },
      { category: 'network', technique: 'T1021.003', title: 'DCOM', applicable: true },
      { category: 'network', technique: 'T1021.005', title: 'WMI', applicable: true },
      { category: 'network', technique: 'T1590.005', title: 'Active Directory Reconnaissance', applicable: true },
    ],
    mixed: [],
    cloud: [],
    database: [],
    email: [],
  };

  const vectors = (vectorsByType[targetType] || []).map((v, i) => ({
    ...v,
    id: `cov-${v.technique}-${targetType}`,
    tested: false,
    testedBy: [],
    findings: [],
    confidence: 0.7,
    priority: Math.max(1, 10 - i), // Higher priority for first vectors
  }));

  context.coverageTracker = {
    targetType,
    vectors,
    totalVectors: vectors.length,
    testedVectors: 0,
    coveragePercent: 0,
    lastUpdated: Date.now(),
  };

  logInfo(MODULE_NAME, `Initialized coverage tracker for ${targetType}: ${vectors.length} vectors`);
}
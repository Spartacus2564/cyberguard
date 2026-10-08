import { Finding, Severity } from '../types';
import logger from '../utils/logger';

// ─── Types ───

export interface ComplianceMapping {
  framework: string;
  controlId: string;
  controlName: string;
  category: string;
  description: string;
  status: 'pass' | 'fail' | 'partial' | 'not_applicable';
  evidence: string[];
  recommendation: string;
}

export interface ComplianceControl {
  id: string;
  name: string;
  category: string;
  description: string;
  status: 'pass' | 'fail' | 'partial' | 'not_applicable';
  findings: string[];
  evidence: string[];
  recommendations: string[];
}

export interface ComplianceReport {
  framework: string;
  version: string;
  assessmentDomain: string;
  generatedAt: Date;
  summary: string;
  complianceScore: number;
  controls: ComplianceControl[];
  evidence: ComplianceEvidence[];
  recommendations: string[];
}

export interface ComplianceEvidence {
  controlId: string;
  findingId: string;
  findingTitle: string;
  severity: string;
  evidence: string;
  timestamp: Date;
}

// ─── SOC 2 Control Mappings ───

const SOC2_CONTROLS: Record<string, { name: string; category: string; description: string }> = {
  'CC6.1': {
    name: 'Logical Access Controls',
    category: 'Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
  },
  'CC6.2': {
    name: 'System Access Authentication',
    category: 'Security',
    description: 'The entity authenticates users before allowing access to system components.',
  },
  'CC6.3': {
    name: 'Access Authorization',
    category: 'Security',
    description: 'The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles.',
  },
  'CC6.6': {
    name: 'Boundary Protection',
    category: 'Security',
    description: 'The entity implements controls to prevent or detect and correct the introduction of unauthorized or unintended modifications to configuration.',
  },
  'CC6.7': {
    name: 'Data Transmission',
    category: 'Security',
    description: 'The entity restricts the transmission, movement, and removal of information to authorized users and processes.',
  },
  'CC7.1': {
    name: 'Vulnerability Management',
    category: 'Security',
    description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.',
  },
  'CC7.2': {
    name: 'Security Incident Response',
    category: 'Security',
    description: 'The entity monitors system components and the operation of those components for anomalies indicative of malicious acts, natural disasters, and errors.',
  },
  'CC8.1': {
    name: 'Change Management',
    category: 'Processing Integrity',
    description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.',
  },
};

// ─── ISO 27001 Control Mappings ───

const ISO27001_CONTROLS: Record<string, { name: string; category: string; description: string }> = {
  'A.5.1.1': {
    name: 'Policies for Information Security',
    category: 'A.5 Organizational Controls',
    description: 'Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties.',
  },
  'A.8.1': {
    name: 'User Endpoint Devices',
    category: 'A.8 Technological Controls',
    description: 'Information stored on, processed by or accessible via user endpoint devices shall be protected.',
  },
  'A.8.2': {
    name: 'Privileged Access Rights',
    category: 'A.8 Technological Controls',
    description: 'The allocation and use of privileged access rights shall be restricted and managed.',
  },
  'A.8.3': {
    name: 'Information Access Restriction',
    category: 'A.8 Technological Controls',
    description: 'Access to information and other protected information assets shall be restricted in accordance with the established topic-specific policy on access control.',
  },
  'A.8.5': {
    name: 'Secure Authentication',
    category: 'A.8 Technological Controls',
    description: 'Secure authentication technologies and procedures shall be established and implemented based on information access restrictions and the topic-specific policy on access control.',
  },
  'A.8.9': {
    name: 'Configuration Management',
    category: 'A.8 Technological Controls',
    description: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.',
  },
  'A.8.20': {
    name: 'Network Security',
    category: 'A.8 Technological Controls',
    description: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.',
  },
  'A.8.24': {
    name: 'Use of Cryptography',
    category: 'A.8 Technological Controls',
    description: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.',
  },
  'A.8.25': {
    name: 'Secure Development Life Cycle',
    category: 'A.8 Technological Controls',
    description: 'Rules for the secure development of software and systems shall be established and applied.',
  },
  'A.8.26': {
    name: 'Application Security Requirements',
    category: 'A.8 Technological Controls',
    description: 'Information security requirements shall be identified, specified and approved when developing or acquiring applications.',
  },
  'A.12.6': {
    name: 'Technical Vulnerability Management',
    category: 'A.12 Operations Security',
    description: 'Information about technical vulnerabilities of information systems being used shall be obtained, the organization\'s exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.',
  },
  'A.12.6.1': {
    name: 'Management of Technical Vulnerabilities',
    category: 'A.12 Operations Security',
    description: 'Information about technical vulnerabilities of information systems in use shall be obtained in a timely manner, the organization\'s exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken to address the associated risk.',
  },
};

// ─── Finding to Control Mapping ───

const FINDING_CONTROL_MAP: Record<string, { soc2: string[]; iso27001: string[] }> = {
  'Business Logic': {
    soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
    iso27001: ['A.8.2', 'A.8.3', 'A.8.26'],
  },
  'Authentication': {
    soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
    iso27001: ['A.8.5', 'A.8.2'],
  },
  'API Security': {
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
    iso27001: ['A.8.9', 'A.8.20', 'A.12.6.1'],
  },
  'Injection': {
    soc2: ['CC6.1', 'CC7.1'],
    iso27001: ['A.8.25', 'A.8.26', 'A.12.6.1'],
  },
  'Cross-Site Scripting': {
    soc2: ['CC6.1', 'CC6.6'],
    iso27001: ['A.8.25', 'A.8.26'],
  },
  'Security Headers': {
    soc2: ['CC6.1', 'CC6.7'],
    iso27001: ['A.8.9', 'A.8.20'],
  },
  'TLS/SSL': {
    soc2: ['CC6.1', 'CC6.7'],
    iso27001: ['A.8.24', 'A.8.20'],
  },
  'DNS Security': {
    soc2: ['CC6.6'],
    iso27001: ['A.8.20'],
  },
  'Technology Detection': {
    soc2: ['CC7.1', 'CC8.1'],
    iso27001: ['A.12.6.1', 'A.8.9'],
  },
  'Port Scan': {
    soc2: ['CC6.6', 'CC7.1'],
    iso27001: ['A.8.20', 'A.12.6.1'],
  },
  'Information Disclosure': {
    soc2: ['CC6.1', 'CC6.3'],
    iso27001: ['A.8.3', 'A.8.1'],
  },
  'Cryptographic Issues': {
    soc2: ['CC6.1', 'CC6.7'],
    iso27001: ['A.8.24'],
  },
  'Access Control': {
    soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
    iso27001: ['A.8.2', 'A.8.3', 'A.8.5'],
  },
  'Cloud Security': {
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
    iso27001: ['A.5.1.1', 'A.8.9', 'A.8.20'],
  },
  'Supply Chain': {
    soc2: ['CC7.1', 'CC8.1'],
    iso27001: ['A.5.1.1', 'A.12.6.1'],
  },
};

// ─── Helper Functions ───

function mapFindingToControls(finding: Finding, framework: 'soc2' | 'iso27001'): string[] {
  const categoryKey = Object.keys(FINDING_CONTROL_MAP).find(
    (key) => finding.category.toLowerCase().includes(key.toLowerCase()) ||
             finding.title.toLowerCase().includes(key.toLowerCase()),
  );

  if (categoryKey) {
    return FINDING_CONTROL_MAP[categoryKey][framework] || [];
  }

  // Default mappings based on severity
  if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH) {
    return framework === 'soc2' ? ['CC6.1', 'CC7.1'] : ['A.8.3', 'A.12.6.1'];
  }

  return framework === 'soc2' ? ['CC6.1'] : ['A.8.9'];
}

function getControlStatus(
  controlId: string,
  findings: Finding[],
  framework: 'soc2' | 'iso27001',
): 'pass' | 'fail' | 'partial' | 'not_applicable' {
  const controls = framework === 'soc2' ? SOC2_CONTROLS : ISO27001_CONTROLS;
  if (!controls[controlId]) return 'not_applicable';

  const mappedFindings = findings.filter((f) => {
    const controlIds = mapFindingToControls(f, framework);
    return controlIds.includes(controlId);
  });

  if (mappedFindings.length === 0) return 'pass';

  const criticalOrHigh = mappedFindings.filter(
    (f) => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH,
  );

  if (criticalOrHigh.length > 0) return 'fail';
  if (mappedFindings.length > 0) return 'partial';

  return 'pass';
}

// ─── SOC 2 Report Generator ───

export function generateSOC2Report(findings: Finding[], assessment: any): ComplianceReport {
  logger.info(`[Compliance] Generating SOC 2 report for ${assessment.domain}`);

  const controlIds = Object.keys(SOC2_CONTROLS);
  const controls: ComplianceControl[] = controlIds.map((id) => {
    const control = SOC2_CONTROLS[id];
    const status = getControlStatus(id, findings, 'soc2');
    const mappedFindings = findings.filter((f) => mapFindingToControls(f, 'soc2').includes(id));

    return {
      id,
      name: control.name,
      category: control.category,
      description: control.description,
      status,
      findings: mappedFindings.map((f) => f.title),
      evidence: mappedFindings.map((f) => f.evidence),
      recommendations: [generateSOC2Recommendation(id, status, mappedFindings)],
    };
  });

  const evidence: ComplianceEvidence[] = [];
  for (const finding of findings) {
    const controlIds = mapFindingToControls(finding, 'soc2');
    for (const controlId of controlIds) {
      evidence.push({
        controlId,
        findingId: finding.id,
        findingTitle: finding.title,
        severity: finding.severity,
        evidence: finding.evidence,
        timestamp: finding.detectedAt,
      });
    }
  }

  const passed = controls.filter((c) => c.status === 'pass').length;
  const failed = controls.filter((c) => c.status === 'fail').length;
  const partial = controls.filter((c) => c.status === 'partial').length;
  const notApplicable = controls.filter((c) => c.status === 'not_applicable').length;
  const score = Math.round(((passed + partial * 0.5) / (controlIds.length - notApplicable)) * 100);

  return {
    framework: 'SOC 2 Type II',
    version: '2017',
    assessmentDomain: assessment.domain,
    generatedAt: new Date(),
    summary: `${passed} passed, ${failed} failed, ${partial} partial out of ${controlIds.length} controls. Compliance score: ${score}%`,
    complianceScore: score,
    controls,
    evidence,
    recommendations: generateSOC2Recommendations(findings, controls),
  };
}

function generateSOC2Recommendation(controlId: string, status: string, findings: Finding[]): string {
  if (status === 'pass') return `${SOC2_CONTROLS[controlId]?.name} controls are properly implemented.`;

  const severity = findings.some((f) => f.severity === Severity.CRITICAL) ? 'critical' : 'non-critical';

  const recommendations: Record<string, string> = {
    'CC6.1': 'Implement role-based access control (RBAC) on all system components. Ensure least-privilege principles are enforced.',
    'CC6.2': 'Enforce multi-factor authentication (MFA) for all privileged access. Implement session management with appropriate timeouts.',
    'CC6.3': 'Review and update access permissions quarterly. Remove inactive accounts and revoke unnecessary privileges.',
    'CC6.6': 'Deploy network segmentation and firewall rules. Implement intrusion detection/prevention systems.',
    'CC6.7': 'Enforce TLS 1.2+ for all data in transit. Implement certificate pinning for sensitive communications.',
    'CC7.1': 'Establish a vulnerability management program with regular scanning and patching. Track remediation SLAs.',
    'CC7.2': 'Implement centralized logging and monitoring. Establish a security incident response plan.',
    'CC8.1': 'Implement change management procedures with approval workflows. Test changes in staging before production.',
  };

  return recommendations[controlId] || `Address ${severity} findings mapped to this control.`;
}

function generateSOC2Recommendations(findings: Finding[], controls: ComplianceControl[]): string[] {
  const recommendations: string[] = [];

  const failedControls = controls.filter((c) => c.status === 'fail');
  if (failedControls.length > 0) {
    recommendations.push(
      `${failedControls.length} SOC 2 controls have critical failures that require immediate remediation.`,
    );
  }

  const partialControls = controls.filter((c) => c.status === 'partial');
  if (partialControls.length > 0) {
    recommendations.push(
      `${partialControls.length} SOC 2 controls have partial compliance. Address remaining findings to achieve full compliance.`,
    );
  }

  const criticalFindings = findings.filter((f) => f.severity === Severity.CRITICAL);
  if (criticalFindings.length > 0) {
    recommendations.push(
      `Remediate ${criticalFindings.length} critical findings immediately, as they impact SOC 2 compliance.`,
    );
  }

  if (findings.some((f) => f.category.includes('Authentication'))) {
    recommendations.push('Strengthen authentication controls: implement MFA, enforce password policies, and review session management.');
  }

  if (findings.some((f) => f.category.includes('Encryption') || f.category.includes('TLS'))) {
    recommendations.push('Update cryptographic configurations: enforce TLS 1.2+, disable weak cipher suites, and implement proper key management.');
  }

  return recommendations;
}

// ─── ISO 27001 Report Generator ───

export function generateISO27001Report(findings: Finding[], assessment: any): ComplianceReport {
  logger.info(`[Compliance] Generating ISO 27001 report for ${assessment.domain}`);

  const controlIds = Object.keys(ISO27001_CONTROLS);
  const controls: ComplianceControl[] = controlIds.map((id) => {
    const control = ISO27001_CONTROLS[id];
    const status = getControlStatus(id, findings, 'iso27001');
    const mappedFindings = findings.filter((f) => mapFindingToControls(f, 'iso27001').includes(id));

    return {
      id,
      name: control.name,
      category: control.category,
      description: control.description,
      status,
      findings: mappedFindings.map((f) => f.title),
      evidence: mappedFindings.map((f) => f.evidence),
      recommendations: [generateISO27001Recommendation(id, status, mappedFindings)],
    };
  });

  const evidence: ComplianceEvidence[] = [];
  for (const finding of findings) {
    const controlIds = mapFindingToControls(finding, 'iso27001');
    for (const controlId of controlIds) {
      evidence.push({
        controlId,
        findingId: finding.id,
        findingTitle: finding.title,
        severity: finding.severity,
        evidence: finding.evidence,
        timestamp: finding.detectedAt,
      });
    }
  }

  const passed = controls.filter((c) => c.status === 'pass').length;
  const failed = controls.filter((c) => c.status === 'fail').length;
  const partial = controls.filter((c) => c.status === 'partial').length;
  const notApplicable = controls.filter((c) => c.status === 'not_applicable').length;
  const score = Math.round(((passed + partial * 0.5) / (controlIds.length - notApplicable)) * 100);

  return {
    framework: 'ISO 27001:2022',
    version: '2022',
    assessmentDomain: assessment.domain,
    generatedAt: new Date(),
    summary: `${passed} passed, ${failed} failed, ${partial} partial out of ${controlIds.length} controls. Compliance score: ${score}%`,
    complianceScore: score,
    controls,
    evidence,
    recommendations: generateISO27001Recommendations(findings, controls),
  };
}

function generateISO27001Recommendation(controlId: string, status: string, findings: Finding[]): string {
  if (status === 'pass') return `${ISO27001_CONTROLS[controlId]?.name} is compliant.`;

  const recommendations: Record<string, string> = {
    'A.5.1.1': 'Establish and communicate information security policies covering all relevant areas.',
    'A.8.1': 'Implement controls to protect information on user endpoint devices, including encryption and remote wipe capabilities.',
    'A.8.2': 'Implement the principle of least privilege. Use privileged access management (PAM) solutions.',
    'A.8.3': 'Implement access control lists and role-based access control. Review access rights regularly.',
    'A.8.5': 'Implement multi-factor authentication for critical systems. Use secure password storage (bcrypt, argon2).',
    'A.8.9': 'Establish configuration baselines. Implement automated configuration management and drift detection.',
    'A.8.20': 'Implement network segmentation, firewalls, and intrusion detection. Monitor network traffic for anomalies.',
    'A.8.24': 'Use approved cryptographic algorithms and protocols. Implement proper key lifecycle management.',
    'A.8.25': 'Integrate security into the software development lifecycle. Perform security code reviews and SAST/DAST.',
    'A.8.26': 'Define security requirements for application development. Validate inputs and implement output encoding.',
    'A.12.6': 'Establish a vulnerability management program. Subscribe to vulnerability intelligence feeds.',
    'A.12.6.1': 'Implement automated vulnerability scanning. Track remediation with defined SLAs based on severity.',
  };

  return recommendations[controlId] || `Address findings mapped to ISO 27001 control ${controlId}.`;
}

function generateISO27001Recommendations(findings: Finding[], controls: ComplianceControl[]): string[] {
  const recommendations: string[] = [];

  const failedControls = controls.filter((c) => c.status === 'fail');
  if (failedControls.length > 0) {
    recommendations.push(
      `${failedControls.length} ISO 27001 Annex A controls have non-conformities that require corrective action.`,
    );
  }

  const partialControls = controls.filter((c) => c.status === 'partial');
  if (partialControls.length > 0) {
    recommendations.push(
      `${partialControls.length} controls have partial implementation. Document compensating controls or complete implementation.`,
    );
  }

  const criticalFindings = findings.filter((f) => f.severity === Severity.CRITICAL);
  if (criticalFindings.length > 0) {
    recommendations.push(
      `Critical findings detected: ${criticalFindings.length} issues require immediate corrective action per ISO 27001 clause 10.2.`,
    );
  }

  if (findings.some((f) => f.category.includes('Authentication') || f.category.includes('Access Control'))) {
    recommendations.push('Review and enhance access control policies per Annex A controls A.5.15, A.8.2, and A.8.3.');
  }

  if (findings.some((f) => f.category.includes('Network') || f.category.includes('TLS'))) {
    recommendations.push('Review network security controls per Annex A control A.8.20. Ensure proper segmentation and monitoring.');
  }

  recommendations.push('Document all findings and corrective actions in the Statement of Applicability (SoA).');
  recommendations.push('Conduct management review of security findings per ISO 27001 clause 9.3.');

  return recommendations;
}

// ─── Generic Mapping Function ───

export function getComplianceMapping(finding: Finding): ComplianceMapping[] {
  const mappings: ComplianceMapping[] = [];

  // SOC 2 mapping
  const soc2Controls = mapFindingToControls(finding, 'soc2');
  for (const controlId of soc2Controls) {
    const control = SOC2_CONTROLS[controlId];
    if (control) {
      mappings.push({
        framework: 'SOC 2 Type II',
        controlId,
        controlName: control.name,
        category: control.category,
        description: control.description,
        status: 'fail',
        evidence: [finding.evidence],
        recommendation: generateSOC2Recommendation(controlId, 'fail', [finding]),
      });
    }
  }

  // ISO 27001 mapping
  const isoControls = mapFindingToControls(finding, 'iso27001');
  for (const controlId of isoControls) {
    const control = ISO27001_CONTROLS[controlId];
    if (control) {
      mappings.push({
        framework: 'ISO 27001:2022',
        controlId,
        controlName: control.name,
        category: control.category,
        description: control.description,
        status: 'fail',
        evidence: [finding.evidence],
        recommendation: generateISO27001Recommendation(controlId, 'fail', [finding]),
      });
    }
  }

  return mappings;
}

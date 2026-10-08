import { Finding, Severity } from '../types';

export type ExportFormat = 'json' | 'csv' | 'sarif' | 'junit';

/**
 * Export findings in the specified format
 */
export function exportFindings(findings: Finding[], format: ExportFormat, domain: string, assessmentId: string): string {
  switch (format) {
    case 'json': return exportJson(findings, domain, assessmentId);
    case 'csv': return exportCsv(findings);
    case 'sarif': return exportSarif(findings, domain, assessmentId);
    case 'junit': return exportJUnit(findings, domain, assessmentId);
    default: return exportJson(findings, domain, assessmentId);
  }
}

function exportJson(findings: Finding[], domain: string, assessmentId: string): string {
  return JSON.stringify({
    assessmentId,
    domain,
    exportedAt: new Date().toISOString(),
    totalFindings: findings.length,
    summary: {
      critical: findings.filter(f => f.severity === Severity.CRITICAL).length,
      high: findings.filter(f => f.severity === Severity.HIGH).length,
      medium: findings.filter(f => f.severity === Severity.MEDIUM).length,
      low: findings.filter(f => f.severity === Severity.LOW).length,
      info: findings.filter(f => f.severity === Severity.INFO).length,
    },
    findings: findings.map(f => ({
      id: f.id,
      title: f.title,
      description: f.description,
      severity: f.severity,
      cvssScore: f.cvssScore,
      confidence: f.confidence,
      category: f.category,
      affectedAsset: f.affectedAsset,
      evidence: f.evidence,
      impact: f.impact,
      remediation: f.remediation,
      references: f.references,
      detectedAt: f.detectedAt,
    })),
  }, null, 2);
}

function exportCsv(findings: Finding[]): string {
  const headers = ['ID', 'Title', 'Severity', 'CVSS', 'Confidence', 'Category', 'Asset', 'Description', 'Impact', 'Remediation', 'References', 'Detected At'];
  const rows = findings.map(f => [
    f.id,
    '"' + (f.title || '').replace(/"/g, '""') + '"',
    f.severity,
    f.cvssScore?.toString() || '',
    f.confidence?.toString() || '',
    '"' + (f.category || '').replace(/"/g, '""') + '"',
    '"' + (f.affectedAsset || '').replace(/"/g, '""') + '"',
    '"' + (f.description || '').replace(/"/g, '""').slice(0, 200) + '"',
    '"' + (f.impact || '').replace(/"/g, '""').slice(0, 200) + '"',
    '"' + (f.remediation || '').replace(/"/g, '""').slice(0, 200) + '"',
    '"' + (f.references || []).join('; ').replace(/"/g, '""') + '"',
    f.detectedAt?.toISOString() || '',
  ]);
  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

function exportSarif(findings: Finding[], domain: string, assessmentId: string): string {
  const sarifFindings = findings.map(f => ({
    ruleId: f.id,
    level: severityToSarifLevel(f.severity),
    message: {
      text: f.description || f.title,
    },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: domain },
        region: { startLine: 1 },
      },
    }],
    properties: {
      severity: f.severity,
      cvssScore: f.cvssScore,
      confidence: f.confidence,
      category: f.category,
      remediation: f.remediation,
      evidence: (f.evidence || '').slice(0, 1000),
    },
  }));

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'CyberGuard',
          version: '1.0.0',
          informationUri: 'https://cyberguard.io',
          rules: sarifFindings.map(f => ({
            id: f.ruleId,
            shortDescription: { text: f.message.text.slice(0, 100) },
            fullDescription: { text: f.message.text },
            helpUri: undefined,
            properties: f.properties,
          })),
        },
      },
      results: sarifFindings,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

function exportJUnit(findings: Finding[], domain: string, assessmentId: string): string {
  const failures = findings.filter(f => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH);
  const warnings = findings.filter(f => f.severity === Severity.MEDIUM);
  const infos = findings.filter(f => f.severity === Severity.LOW || f.severity === Severity.INFO);

  const failureXml = failures.map(f => `
    <failure message="${escapeXml(f.title)}" type="${f.severity}">
      ${escapeXml(f.description || '')}
      Evidence: ${escapeXml((f.evidence || '').slice(0, 500))}
      Remediation: ${escapeXml(f.remediation || '')}
    </failure>`).join('');

  const warningXml = warnings.map(f => `
    <system-out>[MEDIUM] ${escapeXml(f.title)}: ${escapeXml(f.description || '').slice(0, 200)}</system-out>`).join('');

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="CyberGuard Security Scan" tests="${findings.length}" failures="${failures.length}" errors="0" warnings="${warnings.length}">
    <testcase name="Security Assessment of ${escapeXml(domain)}" classname="cyberguard.scan">
      ${failureXml}
      ${warningXml}
    </testcase>
    <testcase name="Informational Findings" classname="cyberguard.info">
      ${infos.map(f => `<system-out>[INFO] ${escapeXml(f.title)}</system-out>`).join('\n      ')}
    </testcase>
  </testsuite>
</testsuites>`;
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL: return 'error';
    case Severity.HIGH: return 'error';
    case Severity.MEDIUM: return 'warning';
    case Severity.LOW: return 'note';
    case Severity.INFO: return 'note';
    default: return 'warning';
  }
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

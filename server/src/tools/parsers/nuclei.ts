// ═══════════════════════════════════════════════════════════════════════════════
// NUCLEI OUTPUT PARSER — Converts nuclei JSON/line output to NormalizedFindings
// ═══════════════════════════════════════════════════════════════════════════════

import { ToolOutput, NormalizedFinding } from '../types';
import { Severity } from '../../types';

const SEVERITY_MAP: Record<string, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
  info: Severity.INFO,
  unknown: Severity.MEDIUM,
};

export default function parseNuclei(output: ToolOutput): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const lines = output.stdout.split('\n').filter(l => l.trim());

  const seenTemplates = new Set<string>();

  for (const line of lines) {
    // Nuclei line format: [template-id] [type] [severity] url [extra]
    const match = line.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)/);
    if (!match) continue;

    const [, templateId, type, severity, targetUrl, extra] = match;

    // Deduplicate
    const key = `${templateId}:${targetUrl}`;
    if (seenTemplates.has(key)) continue;
    seenTemplates.add(key);

    const sev = SEVERITY_MAP[severity.toLowerCase()] || Severity.MEDIUM;
    const templateUrl = `https://github.com/projectdiscovery/nuclei-templates/blob/main/http/${type}/${templateId}.yaml`;

    findings.push({
      title: `Nuclei: ${templateId} (${type})`,
      description: `Nuclei template ${templateId} (${type}) detected at ${targetUrl}. ${extra}`.trim(),
      severity: sev,
      category: 'Automated Vulnerability Detection',
      affectedAsset: targetUrl,
      evidence: line.trim(),
      impact: `Nuclei template ${templateId} indicates a confirmed vulnerability`,
      remediation: `Investigate and remediate the ${type} vulnerability`,
      references: [templateUrl],
      toolName: 'nuclei',
      toolOutput: line.trim(),
      validationStatus: 'DISCOVERED',
      confidence: sev === Severity.CRITICAL ? 0.95 : sev === Severity.HIGH ? 0.85 : 0.7,
    });
  }

  return findings;
}

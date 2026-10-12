import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { IRModuleResult, IRCase, Evidence, TimelineEvent, IOC, ContainmentAction, Finding, Severity, IRScanContext } from '../../../types';
import { logInfo, logDone } from '../../scanLogger';

const MODULE_NAME = 'irReport';

export async function runIRReport(context: IRScanContext, caseData: Partial<IRCase>): Promise<IRModuleResult> {
  const startTime = Date.now();
  const result: IRModuleResult = {
    findings: [],
    errors: [],
  };

  logInfo(MODULE_NAME, `Generating IR report for case ${context.caseId}`);

  const outputDir = join(process.cwd(), 'ir-output', context.caseId);
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const pageSize = { width: 612, height: 792 };
  let page = pdfDoc.addPage(pageSize);
  let y = pageSize.height - 50;

  const addText = (text: string, x: number, yPos: number, fontSize: number = 10, fontRef = font, color = rgb(0, 0, 0)) => {
    page.drawText(text, { x, y: yPos, size: fontSize, font: fontRef, color });
  };

  const addLine = (yPos: number) => {
    page.drawLine({ start: { x: 50, y: yPos }, end: { x: pageSize.width - 50, y: yPos }, thickness: 0.5, color: rgb(0.7, 0.7, 0.7) });
  };

  const checkNewPage = (requiredSpace: number) => {
    if (y - requiredSpace < 50) {
      page = pdfDoc.addPage(pageSize);
      y = pageSize.height - 50;
    }
  };

  // Title Page
  addText('INCIDENT RESPONSE REPORT', 50, y, 24, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 40;
  addText(`Case: ${caseData.name || context.caseId}`, 50, y, 16, boldFont);
  y -= 25;
  addText(`Case ID: ${context.caseId}`, 50, y, 12);
  y -= 18;
  addText(`Date: ${new Date().toISOString().split('T')[0]}`, 50, y, 12);
  y -= 18;
  addText(`Status: ${caseData.status || 'investigating'}`, 50, y, 12);
  y -= 18;
  addText(`Severity: ${caseData.severity || 'medium'}`, 50, y, 12);
  y -= 18;
  addText(`Scope: ${context.targetScope.join(', ')}`, 50, y, 12);
  y -= 18;
  addText(`Assigned To: ${caseData.assignedTo?.join(', ') || 'IR Team'}`, 50, y, 12);
  y -= 40;
  addLine(y);
  y -= 20;
  addText('EXECUTIVE SUMMARY', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;
  const summary = caseData.description || 'This report documents the investigation of a security incident. Evidence was collected, analyzed, and containment actions were planned.';
  const summaryLines = wrapText(summary, 500, font, 10);
  for (const line of summaryLines) {
    checkNewPage(15);
    addText(line, 50, y, 10);
    y -= 14;
  }

  // Evidence Section
  y -= 10;
  checkNewPage(100);
  addLine(y);
  y -= 10;
  addText('EVIDENCE COLLECTED', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const evidence: Evidence[] = caseData.evidence || [];
  if (evidence.length === 0) {
    addText('No evidence recorded.', 50, y, 10);
    y -= 16;
  } else {
    const typeCounts: Record<string, number> = {};
    for (const ev of evidence) {
      typeCounts[ev.type] = (typeCounts[ev.type] || 0) + 1;
    }
    for (const [type, count] of Object.entries(typeCounts)) {
      checkNewPage(15);
      addText(`${type}: ${count} items`, 60, y, 10, boldFont);
      y -= 14;
    }
    y -= 5;
    for (const ev of evidence.slice(0, 20)) {
      checkNewPage(20);
      addText(`${ev.id} | ${ev.type} | ${ev.source} | ${ev.path}`, 60, y, 8);
      y -= 11;
      addText(`  Hash: ${ev.hash.sha256} | Size: ${formatBytes(ev.size)} | Collected: ${new Date(ev.collectedAt).toISOString()}`, 60, y, 7, font, rgb(0.4, 0.4, 0.4));
      y -= 10;
    }
    if (evidence.length > 20) {
      checkNewPage(15);
      addText(`... and ${evidence.length - 20} more evidence items`, 60, y, 9, font, rgb(0.5, 0.5, 0.5));
      y -= 14;
    }
  }

  // Timeline Section
  y -= 10;
  checkNewPage(120);
  addLine(y);
  y -= 10;
  addText('INCIDENT TIMELINE', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const timeline: TimelineEvent[] = caseData.timeline || [];
  if (timeline.length === 0) {
    addText('No timeline events recorded.', 50, y, 10);
    y -= 16;
  } else {
    const highSeverity = timeline.filter(e => ['high', 'critical'].includes(e.severity));
    addText(`Total Events: ${timeline.length} | High/Critical: ${highSeverity.length}`, 50, y, 10);
    y -= 16;
    
    for (const event of highSeverity.slice(0, 30)) {
      checkNewPage(25);
      addText(`${new Date(event.timestamp).toISOString()} | ${event.severity.toUpperCase()} | ${event.eventType}`, 60, y, 9, boldFont);
      y -= 12;
      addText(`  ${event.description}`, 60, y, 8);
      y -= 10;
      if (event.mitreTechniques.length > 0) {
        addText(`  MITRE: ${event.mitreTechniques.join(', ')}`, 60, y, 7, font, rgb(0.4, 0.4, 0.4));
        y -= 9;
      }
    }
    if (highSeverity.length > 30) {
      checkNewPage(15);
      addText(`... and ${highSeverity.length - 30} more high-severity events`, 60, y, 9, font, rgb(0.5, 0.5, 0.5));
      y -= 14;
    }
  }

  // IOCs Section
  y -= 10;
  checkNewPage(100);
  addLine(y);
  y -= 10;
  addText('INDICATORS OF COMPROMISE (IOCs)', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const iocs: IOC[] = caseData.iocs || [];
  if (iocs.length === 0) {
    addText('No IOCs extracted.', 50, y, 10);
    y -= 16;
  } else {
    const typeCountsIOC: Record<string, number> = {};
    for (const ioc of iocs) {
      typeCountsIOC[ioc.type] = (typeCountsIOC[ioc.type] || 0) + 1;
    }
    for (const [type, count] of Object.entries(typeCountsIOC)) {
      checkNewPage(15);
      addText(`${type}: ${count}`, 60, y, 10, boldFont);
      y -= 14;
    }
    y -= 5;
    const highConf = iocs.filter(i => i.confidence > 0.7).slice(0, 25);
    for (const ioc of highConf) {
      checkNewPage(20);
      addText(`${ioc.type.toUpperCase()}: ${ioc.value}`, 60, y, 9, boldFont);
      y -= 12;
      addText(`  Confidence: ${(ioc.confidence * 100).toFixed(0)}% | ${ioc.description}`, 60, y, 8);
      y -= 10;
      if (ioc.mitreTechniques.length > 0) {
        addText(`  MITRE: ${ioc.mitreTechniques.join(', ')}`, 60, y, 7, font, rgb(0.4, 0.4, 0.4));
        y -= 9;
      }
    }
  }

  // Containment Actions
  y -= 10;
  checkNewPage(100);
  addLine(y);
  y -= 10;
  addText('CONTAINMENT ACTIONS', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const actions: ContainmentAction[] = caseData.containmentActions || [];
  if (actions.length === 0) {
    addText('No containment actions planned.', 50, y, 10);
    y -= 16;
  } else {
    for (const action of actions.slice(0, 20)) {
      checkNewPage(20);
      addText(`${action.type.toUpperCase()} | Target: ${action.target}`, 60, y, 9, boldFont);
      y -= 12;
      addText(`  Status: ${action.status} | Params: ${JSON.stringify(action.parameters)}`, 60, y, 8);
      y -= 10;
    }
  }

  // Findings Section
  y -= 10;
  checkNewPage(100);
  addLine(y);
  y -= 10;
  addText('KEY FINDINGS', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const findings: Finding[] = caseData.findings || [];
  const bySeverity = groupBySeverity(findings);
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
    const sevFindings = bySeverity[sev] || [];
    if (sevFindings.length === 0) continue;
    checkNewPage(20);
    addText(`${sev.toUpperCase()} (${sevFindings.length})`, 50, y, 11, boldFont, severityColor(sev));
    y -= 15;
    for (const f of sevFindings.slice(0, 10)) {
      checkNewPage(20);
      addText(`  ${f.title}`, 60, y, 9);
      y -= 11;
      addText(`  ${f.description.slice(0, 120)}`, 60, y, 8);
      y -= 10;
    }
  }

  // MITRE ATT&CK Coverage
  y -= 10;
  checkNewPage(80);
  addLine(y);
  y -= 10;
  addText('MITRE ATT&CK COVERAGE', 50, y, 14, boldFont, rgb(0.1, 0.2, 0.4));
  y -= 20;

  const coverage = caseData.mitreCoverage || { covered: [], missing: [] };
  addText(`Covered Techniques: ${coverage.covered.length}`, 60, y, 10);
  y -= 14;
  addText(`Missing Techniques: ${coverage.missing.length}`, 60, y, 10);
  y -= 14;
  if (coverage.covered.length > 0) {
    addText('Covered: ' + coverage.covered.slice(0, 15).join(', '), 60, y, 8);
    y -= 12;
  }

  // Save
  const pdfBytes = await pdfDoc.save();
  const reportPath = join(outputDir, `IR-Report-${context.caseId}.pdf`);
  writeFileSync(reportPath, pdfBytes);

  result.findings!.push({
    title: 'IR Report Generated',
    description: `PDF report saved to ${reportPath}`,
    severity: Severity.INFO,
    category: 'reporting',
    target: context.targetScope[0] || 'unknown',
    evidence: { reportPath },
    references: [],
  });

  logDone(MODULE_NAME, `IR report generated: ${reportPath} in ${Date.now() - startTime}ms`);
  return result;
}

function wrapText(text: string, maxWidth: number, font: any, fontSize: number): string[] {
  const words = text.split(' ');
  const lines: string[] = [];
  let currentLine = '';
  
  for (const word of words) {
    const testLine = currentLine + (currentLine ? ' ' : '') + word;
    const width = font.widthOfTextAtSize(testLine, fontSize);
    if (width > maxWidth && currentLine) {
      lines.push(currentLine);
      currentLine = word;
    } else {
      currentLine = testLine;
    }
  }
  if (currentLine) lines.push(currentLine);
  return lines;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  const result: Record<Severity, Finding[]> = {
    critical: [], high: [], medium: [], low: [], info: []
  };
  for (const f of findings) {
    result[f.severity].push(f);
  }
  return result;
}

function severityColor(sev: Severity) {
  const colors: Record<Severity, any> = {
    critical: rgb(0.8, 0, 0),
    high: rgb(0.9, 0.3, 0),
    medium: rgb(0.9, 0.6, 0),
    low: rgb(0, 0.5, 0.8),
    info: rgb(0.3, 0.3, 0.8),
  };
  return colors[sev] || rgb(0, 0, 0);
}

export interface IRReportModule {
  run: typeof runIRReport;
}

export const irReport: IRReportModule = {
  run: runIRReport,
};


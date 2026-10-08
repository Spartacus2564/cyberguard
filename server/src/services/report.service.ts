import PDFDocument from 'pdfkit';
import fs from 'fs';
import path from 'path';
import { config } from '../config';
import {
  calculateSecurityScore,
  CATEGORY_WEIGHTS,
  CATEGORY_DESCRIPTIONS,
  SecurityScoreResult,
} from '../engine/riskScoring';
import { getAIProvider } from './ai.service';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import { OWASP_TOP_10, NIST_CSF } from '../engine/modules/shared';

interface ReportFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  cvssScore?: number | null;
  affectedAsset: string;
  evidence: string;
  impact: string;
  remediation: string;
  references: string[];
  detectedAt: Date;
}

const REPORTS_DIR = path.resolve(config.reportsDir);
const MARGIN = 50;
const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const BOTTOM_LIMIT = PAGE_HEIGHT - 50;

function ensureReportsDir() {
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }
}

function sevColor(s: string): string {
  return ({ CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#6b7280' } as Record<string, string>)[s] || '#6b7280';
}

function scoreColor(s: number): string {
  return s >= 80 ? '#16a34a' : s >= 60 ? '#d97706' : '#dc2626';
}

function gradeInfo(s: number): { letter: string; label: string } {
  if (s >= 95) return { letter: 'A+', label: 'Excellent' };
  if (s >= 90) return { letter: 'A', label: 'Very Good' };
  if (s >= 85) return { letter: 'A-', label: 'Very Good' };
  if (s >= 80) return { letter: 'B+', label: 'Good' };
  if (s >= 75) return { letter: 'B', label: 'Good' };
  if (s >= 70) return { letter: 'B-', label: 'Above Average' };
  if (s >= 65) return { letter: 'C+', label: 'Above Average' };
  if (s >= 60) return { letter: 'C', label: 'Average' };
  if (s >= 55) return { letter: 'C-', label: 'Average' };
  if (s >= 50) return { letter: 'D+', label: 'Below Average' };
  if (s >= 40) return { letter: 'D', label: 'Poor' };
  return { letter: 'F', label: 'Critical' };
}

function needPage(doc: PDFKit.PDFDocument, spaceNeeded: number): boolean {
  return doc.y + spaceNeeded > BOTTOM_LIMIT;
}

function ensureSpace(doc: PDFKit.PDFDocument, spaceNeeded: number) {
  if (needPage(doc, spaceNeeded)) {
    doc.addPage();
  }
}

function trimTrailingBlankPages(doc: PDFKit.PDFDocument) {
  const range = doc.bufferedPageRange();
  if (range.count <= 1) return;
  const lastPageIndex = range.start + range.count - 1;
  doc.switchToPage(lastPageIndex);
  if (doc.y < 120) {
    doc.bufferedPageRange().count--;
  }
}

function drawHeader(doc: PDFKit.PDFDocument, title: string) {
  ensureSpace(doc, 50);
  doc.fontSize(16).fillColor('#0f172a').font('Helvetica-Bold').text(title, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveTo(MARGIN, doc.y + 3).lineTo(PAGE_WIDTH - MARGIN, doc.y + 3).lineWidth(1).stroke('#0f172a');
  doc.moveDown(0.8);
  doc.font('Helvetica');
}

function drawBar(doc: PDFKit.PDFDocument, x: number, y: number, w: number, h: number, value: number, max: number, color: string) {
  doc.save();
  doc.roundedRect(x, y, w, h, h / 2).fill('#e5e7eb');
  const bw = max > 0 ? (value / max) * w : 0;
  if (bw > 0) doc.roundedRect(x, y, Math.max(bw, h), h, h / 2).fill(color);
  doc.restore();
}

// ─── RISK SCORE CALCULATION ──────────────────────────────────────────────────
function calculateRiskScore(findings: ReportFinding[]): number {
  const POINTS: Record<string, number> = {
    CRITICAL: 15,
    HIGH: 8,
    MEDIUM: 3,
    LOW: 1,
    INFO: 0,
  };

  let rawScore = 0;
  for (const f of findings) {
    const base = POINTS[f.severity] ?? 0;
    const confidence = (f as unknown as { confidence?: number }).confidence ?? 0.7;
    rawScore += base * confidence;
  }

  return Math.min(100, Math.round(rawScore));
}

// ─── REMEDIATION PRIORITY MATRIX ─────────────────────────────────────────────
interface PriorityItem {
  priority: string;
  label: string;
  timeframe: string;
  color: string;
  count: number;
  findings: ReportFinding[];
}

function getRemediationPriority(f: ReportFinding): string {
  const confidence = (f as unknown as { confidence?: number }).confidence ?? 0.7;
  if (f.severity === 'CRITICAL' && confidence >= 0.7) return 'P1';
  if (f.severity === 'HIGH' && confidence >= 0.5) return 'P2';
  if (f.severity === 'MEDIUM') return 'P3';
  return 'P4';
}

function remediationPriorityMatrixPage(doc: PDFKit.PDFDocument, findings: ReportFinding[]) {
  doc.addPage();
  drawHeader(doc, 'Remediation Priority Matrix');

  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'Findings are prioritized based on severity and detection confidence to maximize risk reduction.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
  doc.moveDown(0.6);

  // Group findings by priority
  const groups: Record<string, ReportFinding[]> = { P1: [], P2: [], P3: [], P4: [] };
  for (const f of findings) {
    groups[getRemediationPriority(f)].push(f);
  }

  const priorities: PriorityItem[] = [
    { priority: 'P1', label: 'Fix Immediately', timeframe: '0-24 hours', color: '#dc2626', count: groups.P1.length, findings: groups.P1 },
    { priority: 'P2', label: 'Fix This Week', timeframe: '1-7 days', color: '#ea580c', count: groups.P2.length, findings: groups.P2 },
    { priority: 'P3', label: 'Fix This Month', timeframe: '1-4 weeks', color: '#d97706', count: groups.P3.length, findings: groups.P3 },
    { priority: 'P4', label: 'Fix When Convenient', timeframe: 'Backlog', color: '#2563eb', count: groups.P4.length, findings: groups.P4 },
  ];

  // Draw table header
  const colWidths = [50, 120, 100, 60, 180];
  const headers = ['Priority', 'Action', 'Timeframe', 'Count', 'Example Findings'];
  let y = doc.y;

  doc.save();
  doc.rect(MARGIN, y, CONTENT_WIDTH, 18).fill('#0f172a');
  doc.restore();

  let x = MARGIN + 5;
  for (let i = 0; i < headers.length; i++) {
    doc.fontSize(8).fillColor('#ffffff').font('Helvetica-Bold').text(headers[i], x, y + 4, { width: colWidths[i] });
    x += colWidths[i];
  }
  y += 22;

  // Draw table rows
  for (const p of priorities) {
    ensureSpace(doc, 22);
    y = doc.y;

    // Row background
    doc.save();
    doc.rect(MARGIN, y, CONTENT_WIDTH, 18).fill(p.count > 0 ? p.color + '10' : '#f9fafb');
    doc.restore();

    // Priority badge
    doc.save();
    doc.roundedRect(MARGIN + 5, y + 2, 40, 14, 3).fill(p.color);
    doc.fontSize(7).fillColor('#ffffff').font('Helvetica-Bold').text(p.priority, MARGIN + 5, y + 5, { width: 40, align: 'center' });
    doc.restore();

    x = MARGIN + 50;
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica-Bold').text(p.label, x, y + 4, { width: colWidths[1] });
    x += colWidths[1];
    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(p.timeframe, x, y + 4, { width: colWidths[2] });
    x += colWidths[2];
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica-Bold').text(p.count.toString(), x, y + 4, { width: colWidths[3], align: 'center' });
    x += colWidths[3];

    // Example findings
    const examples = p.findings.slice(0, 2).map(f => f.title).join('; ');
    doc.fontSize(7).fillColor('#6b7280').font('Helvetica').text(examples || 'None', x, y + 4, { width: colWidths[4] });

    doc.y = y + 20;
  }

  // Summary row
  doc.moveDown(0.5);
  ensureSpace(doc, 30);
  doc.fontSize(9).fillColor('#0f172a').font('Helvetica-Bold').text('Priority Rules:', MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
  doc.fontSize(8).fillColor('#374151').font('Helvetica');
  const rules = [
    'P1 (Immediate): CRITICAL severity with High confidence (>70%)',
    'P2 (This Week): HIGH severity with Medium+ confidence (>50%)',
    'P3 (This Month): MEDIUM severity findings',
    'P4 (Backlog): LOW and INFO severity findings',
  ];
  for (const r of rules) {
    doc.text(`  ${r}`, { width: CONTENT_WIDTH });
  }
  doc.moveDown(0.5);
}

// ─── ENHANCED COMPLIANCE MAPPING ─────────────────────────────────────────────
function enhancedCompliancePage(doc: PDFKit.PDFDocument, findings: ReportFinding[], risk: SecurityScoreResult) {
  doc.addPage();
  drawHeader(doc, 'Compliance Framework Mapping');

  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'Findings mapped to industry compliance frameworks for audit and regulatory purposes.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
  doc.moveDown(0.6);

  // OWASP Top 10 mapping
  ensureSpace(doc, 40);
  doc.fontSize(12).fillColor('#0f172a').font('Helvetica-Bold').text('OWASP Top 10 2021');
  doc.moveDown(0.3);

  const owaspCategories: Record<string, string[]> = {
    'A01:2021 - Broken Access Control': ['CSRF', 'Path Traversal', 'Open Redirect', 'Subdomain Takeover', 'Authentication', 'HTTP Method Security', 'Authenticated Scanning'],
    'A02:2021 - Cryptographic Failures': ['TLS/HTTPS', 'TLS/SSL Deep', 'Certificate Transparency'],
    'A03:2021 - Injection': ['SQL Injection', 'Cross-Site Scripting', 'Active Vulnerability', 'Header Injection', 'Second-Order Injection'],
    'A04:2021 - Insecure Design': ['Web Configuration', 'Site Crawl', 'Race Condition'],
    'A05:2021 - Security Misconfiguration': ['Security Headers', 'DNS Security', 'DNS Deep', 'Email Security', 'Port Scan', 'Web Configuration', 'Service Exposure', 'HTTP Method Security', 'Cloud Security'],
    'A06:2021 - Vulnerable and Outdated Components': ['CVE Correlation', 'Technology Detection', 'Supply Chain Security'],
    'A07:2021 - Identification and Authentication Failures': ['Active Vulnerability', 'Site Crawl', 'Authentication', 'Authenticated Scanning', 'Client-Side Security'],
    'A08:2021 - Software and Data Integrity Failures': ['Technology Detection', 'Site Crawl', 'Supply Chain Security'],
    'A09:2021 - Security Logging and Monitoring Failures': ['Information Disclosure', 'OS Fingerprinting'],
    'A10:2021 - Server-Side Request Forgery': ['Subdomain Discovery', 'Subdomain Takeover', 'Cloud Security'],
  };

  let y = doc.y;
  for (const [control, categories] of Object.entries(owaspCategories)) {
    if (y > BOTTOM_LIMIT - 20) { doc.addPage(); drawHeader(doc, 'Compliance Framework Mapping (continued)'); y = doc.y; }

    const matchedFindings = findings.filter(f => categories.includes(f.category) && f.severity !== 'INFO');
    const passed = matchedFindings.length === 0;
    const icon = passed ? '\u2713' : '\u2717';
    const color = passed ? '#16a34a' : '#dc2626';

    doc.fontSize(8).fillColor(color).font('Helvetica-Bold').text(icon, MARGIN, y, { width: 15 });
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica').text(control, MARGIN + 18, y, { width: CONTENT_WIDTH - 18 });
    y = doc.y + 2;

    if (!passed && matchedFindings.length > 0) {
      const titles = matchedFindings.slice(0, 3).map(f => f.title).join('; ');
      doc.fontSize(7).fillColor('#6b7280').text(`  ${titles}${matchedFindings.length > 3 ? ` (+${matchedFindings.length - 3} more)` : ''}`, MARGIN + 25, y, { width: CONTENT_WIDTH - 25 });
      y = doc.y + 2;
    }
    doc.moveDown(0.15);
    y = doc.y;
  }

  // NIST CSF mapping
  ensureSpace(doc, 60);
  doc.moveDown(0.5);
  doc.fontSize(12).fillColor('#0f172a').font('Helvetica-Bold').text('NIST Cybersecurity Framework 2.0');
  doc.moveDown(0.3);

  const nistCategories: Record<string, string[]> = {
    'PR.DS - Data Security': ['TLS/HTTPS', 'TLS/SSL Deep', 'Certificate Transparency'],
    'PR.AC - Access Control': ['CSRF', 'Path Traversal', 'Security Headers'],
    'PR.IP - Information Protection': ['Information Disclosure', 'Web Configuration'],
    'DE.CM - Continuous Monitoring': ['Port Scan', 'DNS Security', 'DNS Deep'],
    'DE.AE - Anomaly Detection': ['Active Vulnerability', 'Site Crawl'],
    'RS.RP - Response Planning': ['Email Security', 'OS Fingerprinting'],
    'RC.CO - Communications': ['Technology Detection', 'CVE Correlation'],
  };

  y = doc.y;
  for (const [control, categories] of Object.entries(nistCategories)) {
    if (y > BOTTOM_LIMIT - 20) { doc.addPage(); drawHeader(doc, 'Compliance Framework Mapping (continued)'); y = doc.y; }

    const matchedFindings = findings.filter(f => categories.includes(f.category) && f.severity !== 'INFO');
    const passed = matchedFindings.length === 0;
    const icon = passed ? '\u2713' : '\u2717';
    const color = passed ? '#16a34a' : '#dc2626';

    doc.fontSize(8).fillColor(color).font('Helvetica-Bold').text(icon, MARGIN, y, { width: 15 });
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica').text(control, MARGIN + 18, y, { width: CONTENT_WIDTH - 18 });
    y = doc.y + 2;

    if (!passed && matchedFindings.length > 0) {
      const titles = matchedFindings.slice(0, 3).map(f => f.title).join('; ');
      doc.fontSize(7).fillColor('#6b7280').text(`  ${titles}${matchedFindings.length > 3 ? ` (+${matchedFindings.length - 3} more)` : ''}`, MARGIN + 25, y, { width: CONTENT_WIDTH - 25 });
      y = doc.y + 2;
    }
    doc.moveDown(0.15);
    y = doc.y;
  }

  // PCI DSS mapping
  ensureSpace(doc, 60);
  doc.moveDown(0.5);
  doc.fontSize(12).fillColor('#0f172a').font('Helvetica-Bold').text('PCI DSS 4.0');
  doc.moveDown(0.3);

  const pciCategories: Record<string, string[]> = {
    'Req 1 - Network Security Controls': ['Port Scan', 'OS Fingerprinting'],
    'Req 2 - Secure Configurations': ['Security Headers', 'Web Configuration', 'DNS Security'],
    'Req 3 - Protect Stored Account Data': ['TLS/HTTPS', 'TLS/SSL Deep'],
    'Req 4 - Encrypt Transmissions': ['TLS/HTTPS', 'TLS/SSL Deep'],
    'Req 6 - Develop Secure Systems': ['CVE Correlation', 'Active Vulnerability', 'Technology Detection'],
    'Req 8 - Identify Users': ['CSRF', 'Site Crawl'],
    'Req 10 - Log and Monitor': ['Information Disclosure'],
    'Req 11 - Test Security': ['Subdomain Discovery', 'Subdomain Takeover'],
  };

  y = doc.y;
  for (const [control, categories] of Object.entries(pciCategories)) {
    if (y > BOTTOM_LIMIT - 20) { doc.addPage(); drawHeader(doc, 'Compliance Framework Mapping (continued)'); y = doc.y; }

    const matchedFindings = findings.filter(f => categories.includes(f.category) && f.severity !== 'INFO');
    const passed = matchedFindings.length === 0;
    const icon = passed ? '\u2713' : '\u2717';
    const color = passed ? '#16a34a' : '#dc2626';

    doc.fontSize(8).fillColor(color).font('Helvetica-Bold').text(icon, MARGIN, y, { width: 15 });
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica').text(control, MARGIN + 18, y, { width: CONTENT_WIDTH - 18 });
    y = doc.y + 2;

    if (!passed && matchedFindings.length > 0) {
      const titles = matchedFindings.slice(0, 3).map(f => f.title).join('; ');
      doc.fontSize(7).fillColor('#6b7280').text(`  ${titles}${matchedFindings.length > 3 ? ` (+${matchedFindings.length - 3} more)` : ''}`, MARGIN + 25, y, { width: CONTENT_WIDTH - 25 });
      y = doc.y + 2;
    }
    doc.moveDown(0.15);
    y = doc.y;
  }

  // Summary counts
  ensureSpace(doc, 60);
  doc.moveDown(0.5);
  doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Compliance Summary');
  doc.moveDown(0.3);

  const frameworks = [
    { name: 'OWASP Top 10', controls: owaspCategories, results: risk.complianceFrameworkResults?.['OWASP Top 10 2021'] || {} },
    { name: 'NIST CSF 2.0', controls: nistCategories, results: risk.complianceFrameworkResults?.['NIST CSF 2.0'] || {} },
    { name: 'PCI DSS 4.0', controls: pciCategories, results: risk.complianceFrameworkResults?.['PCI DSS 4.0'] || {} },
  ];

  y = doc.y;
  for (const fw of frameworks) {
    const totalControls = Object.keys(fw.controls).length;
    const passedControls = Object.values(fw.results).filter((r: { passed: boolean }) => r.passed).length;
    const pct = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0;

    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(fw.name, MARGIN, y, { width: 150 });
    drawBar(doc, MARGIN + 155, y + 2, 200, 8, pct, 100, scoreColor(pct));
    doc.fontSize(8).fillColor('#374151').text(`${passedControls}/${totalControls} (${pct}%)`, MARGIN + 365, y, { width: 100 });
    y += 18;
  }
  doc.y = y + 5;
}

// ─── COVER PAGE ───────────────────────────────────────────────────────────────
function coverPage(doc: PDFKit.PDFDocument, assessment: { domain: string; organization: { name: string }; id: string }, risk: SecurityScoreResult, sevCounts: Record<string, number>, total: number, riskScore: number) {
  doc.save();
  doc.rect(0, 0, PAGE_WIDTH, 200).fill('#0f172a');
  doc.restore();

  doc.fontSize(32).fillColor('#ffffff').font('Helvetica-Bold').text('CyberGuard', MARGIN, 50, { width: CONTENT_WIDTH, align: 'center' });
  doc.fontSize(12).fillColor('#94a3b8').font('Helvetica').text('Professional Security Assessment Report', { align: 'center' });

  const cx = PAGE_WIDTH / 2, cy = 155;
  doc.save();
  doc.circle(cx, cy, 26).fill(scoreColor(risk.score));
  doc.fontSize(16).fillColor('#ffffff').font('Helvetica-Bold').text(Math.round(risk.score).toString(), cx - 13, cy - 7, { width: 26, align: 'center' });
  doc.fontSize(7).fillColor('#ffffff').font('Helvetica').text('/100', cx - 13, cy + 7, { width: 26, align: 'center' });
  doc.restore();

  const g = gradeInfo(risk.score);
  const items: [string, string][] = [
    ['Domain', assessment.domain],
    ['Organization', assessment.organization.name],
    ['Assessment ID', assessment.id.slice(0, 8)],
    ['Report Date', new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })],
    ['Security Grade', `${g.letter} - ${g.label}`],
    ['Risk Level', risk.riskLevel],
    ['Total Findings', total.toString()],
    ['Risk Score', `${riskScore}/100`],
  ];

  let y = 225;
  for (const [label, value] of items) {
    doc.fontSize(9).fillColor('#6b7280').font('Helvetica').text(label + ':', MARGIN, y, { width: 110 });
    doc.fontSize(9).fillColor('#1f2937').text(value, MARGIN + 115, y, { width: CONTENT_WIDTH - 115 });
    y += 17;
  }

  y += 15;
  const boxW = 90, gap = 10;
  const totalW = 5 * boxW + 4 * gap;
  const startX = MARGIN + (CONTENT_WIDTH - totalW) / 2;
  const boxData = [
    { l: 'CRITICAL', v: sevCounts.CRITICAL, c: '#dc2626' },
    { l: 'HIGH', v: sevCounts.HIGH, c: '#ea580c' },
    { l: 'MEDIUM', v: sevCounts.MEDIUM, c: '#d97706' },
    { l: 'LOW', v: sevCounts.LOW, c: '#2563eb' },
    { l: 'INFO', v: sevCounts.INFO, c: '#6b7280' },
  ];
  for (let i = 0; i < 5; i++) {
    const bx = startX + i * (boxW + gap);
    doc.save();
    doc.roundedRect(bx, y, boxW, 48, 6).fill(boxData[i].c);
    doc.fontSize(20).fillColor('#ffffff').font('Helvetica-Bold').text(boxData[i].v.toString(), bx, y + 10, { width: boxW, align: 'center' });
    doc.fontSize(7).fillColor('#ffffff').font('Helvetica').text(boxData[i].l, bx, y + 32, { width: boxW, align: 'center' });
    doc.restore();
  }

  doc.y = y + 70;
  doc.fontSize(7).fillColor('#9ca3af').text('CONFIDENTIAL - This report contains sensitive security information.', MARGIN, doc.y, { width: CONTENT_WIDTH, align: 'center' });
}

// ─── TOC ──────────────────────────────────────────────────────────────────────
function tocPage(doc: PDFKit.PDFDocument) {
  doc.addPage();
  drawHeader(doc, 'Table of Contents');
  doc.moveDown(0.5);
  const entries = [
    ['Executive Summary', '3'],
    ['Attack Narrative', '4'],
    ['Security Score', '5'],
    ['Risk Score', '5'],
    ['Risk Summary', '6'],
    ['Category Analysis', '7'],
    ['Compliance Framework Mapping', '8'],
    ['Remediation Priority Matrix', '10'],
    ['Detailed Findings', '11'],
    ['Remediation Roadmap', '12'],
    ['Scoring Breakdown', '13'],
    ['Methodology', '14'],
    ['Disclaimer', '15'],
  ];
  for (const [title, pg] of entries) {
    const dots = Math.max(2, 65 - title.length - pg.length);
    doc.fontSize(10).fillColor('#1f2937').text(`${title} ${'.'.repeat(dots)} ${pg}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.4);
  }
}

// ─── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
function executiveSummaryPage(doc: PDFKit.PDFDocument, summary: string) {
  doc.addPage();
  drawHeader(doc, 'Executive Summary');
  doc.fontSize(10).fillColor('#374151').text(summary || 'No executive summary available.', { width: CONTENT_WIDTH, lineGap: 2 });
}

// ─── ATTACK NARRATIVE (AI-GENERATED WITH TEMPLATE FALLBACK) ──────────────────
function attackNarrativePage(doc: PDFKit.PDFDocument, narrative: string, findings: ReportFinding[]) {
  doc.addPage();
  drawHeader(doc, 'Attack Narrative');

  if (narrative && narrative.length > 20) {
    doc.fontSize(10).fillColor('#374151').font('Helvetica-Oblique').text(
      'The following narrative describes how an attacker could chain the identified vulnerabilities to compromise this target.',
      { width: CONTENT_WIDTH, lineGap: 2 }
    );
    doc.moveDown(0.5);

    const paragraphs = narrative.split(/\n\n+/).filter(p => p.trim().length > 0);
    for (const para of paragraphs) {
      ensureSpace(doc, 60);
      doc.fontSize(10).fillColor('#374151').font('Helvetica').text(para.trim(), { width: CONTENT_WIDTH, lineGap: 2 });
      doc.moveDown(0.5);
    }
  } else {
    // Template fallback when AI narrative is unavailable
    doc.fontSize(10).fillColor('#374151').font('Helvetica').text(
      'This section provides a reconstructed attack narrative based on the identified vulnerabilities.',
      { width: CONTENT_WIDTH, lineGap: 2 }
    );
    doc.moveDown(0.5);

    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    const highFindings = findings.filter(f => f.severity === 'HIGH');

    if (criticalFindings.length > 0 || highFindings.length > 0) {
      doc.fontSize(11).fillColor('#dc2626').font('Helvetica-Bold').text('Attack Chain Overview');
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
        'An attacker targeting this system would likely exploit the following chain of vulnerabilities:',
        { width: CONTENT_WIDTH, lineGap: 2 }
      );
      doc.moveDown(0.3);

      let step = 1;
      for (const f of [...criticalFindings, ...highFindings].slice(0, 5)) {
        ensureSpace(doc, 25);
        doc.fontSize(9).fillColor('#dc2626').font('Helvetica-Bold').text(`Step ${step}: ${f.title}`, MARGIN + 5, doc.y, { width: CONTENT_WIDTH - 5 });
        doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`  ${f.description}`, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15 });
        doc.moveDown(0.3);
        step++;
      }

      ensureSpace(doc, 25);
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Potential Impact');
      doc.moveDown(0.2);
      doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
        'If these vulnerabilities are exploited in sequence, an attacker could gain unauthorized access, exfiltrate sensitive data, or achieve remote code execution on the target system.',
        { width: CONTENT_WIDTH, lineGap: 2 }
      );
    } else {
      doc.fontSize(9).fillColor('#16a34a').font('Helvetica').text(
        'No critical or high severity findings were identified. The attack surface appears well-hardened against common attack vectors.',
        { width: CONTENT_WIDTH, lineGap: 2 }
      );
    }
  }
}

// ─── TARGET CLASSIFICATION ────────────────────────────────────────────────────
function targetClassificationPage(doc: PDFKit.PDFDocument, reportContent: string) {
  let classification: { primary?: string; confidence?: number; services?: Array<{ port: number; service: string }>; osGuess?: string; webTech?: string[]; reasons?: string[]; openPorts?: number[] } | null = null;
  try {
    classification = JSON.parse(reportContent || '{}').classification || null;
  } catch {}
  if (!classification) return;

  doc.addPage();
  drawHeader(doc, 'Target Classification');

  const typeColors: Record<string, string> = {
    web: '#3b82f6', activeDirectory: '#8b5cf6', linux: '#22c55e',
    windows: '#f59e0b', network: '#6b7280', mixed: '#ec4899',
  };
  const typeColor = typeColors[classification.primary || ''] || '#6b7280';

  doc.save();
  doc.roundedRect(MARGIN, doc.y, 200, 30, 6).fill(typeColor);
  doc.fontSize(14).fillColor('#ffffff').font('Helvetica-Bold')
    .text(`Target: ${(classification.primary || 'unknown').toUpperCase()}`, MARGIN, doc.y - 18, { width: 200, align: 'center' });
  doc.fontSize(9).fillColor('#ffffff')
    .text(`Confidence: ${((classification.confidence || 0) * 100).toFixed(0)}%`, MARGIN, doc.y + 2, { width: 200, align: 'center' });
  doc.restore();
  doc.moveDown(1.5);

  if (classification.services && classification.services.length > 0) {
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Detected Services');
    doc.moveDown(0.3);
    const cols = 3;
    let y = doc.y;
    for (let i = 0; i < classification.services.length; i++) {
      const svc = classification.services[i];
      if (y > BOTTOM_LIMIT - 20) { doc.addPage(); drawHeader(doc, 'Target Classification (continued)'); y = doc.y; }
      const col = i % cols;
      const x = MARGIN + col * (CONTENT_WIDTH / cols);
      doc.fontSize(8).fillColor('#374151').font('Helvetica')
        .text(`${svc.port}/${svc.service}`, x, y, { width: CONTENT_WIDTH / cols - 10 });
      y += 13;
      if (col === cols - 1) y = doc.y;
    }
    doc.y = y + 5;
  }

  if (classification.osGuess) {
    ensureSpace(doc, 20);
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Operating System');
    doc.moveDown(0.2);
    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(classification.osGuess);
    doc.moveDown(0.5);
  }

  if (classification.webTech && classification.webTech.length > 0) {
    ensureSpace(doc, 20);
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Web Technology Stack');
    doc.moveDown(0.2);
    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(classification.webTech.join(', '));
    doc.moveDown(0.5);
  }

  if (classification.reasons && classification.reasons.length > 0) {
    ensureSpace(doc, 30);
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Classification Reasoning');
    doc.moveDown(0.2);
    for (const reason of classification.reasons.slice(0, 8)) {
      ensureSpace(doc, 12);
      doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`  ${reason}`, { width: CONTENT_WIDTH - 10 });
      doc.moveDown(0.1);
    }
    doc.moveDown(0.3);
  }

  if (classification.openPorts && classification.openPorts.length > 0) {
    ensureSpace(doc, 20);
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Open Ports');
    doc.moveDown(0.2);
    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(classification.openPorts.join(', '));
  }
}

// ─── SECURITY SCORE ───────────────────────────────────────────────────────────
function securityScorePage(doc: PDFKit.PDFDocument, risk: SecurityScoreResult, sevCounts: Record<string, number>, totalFindings: number) {
  doc.addPage();
  drawHeader(doc, 'Security Score');

  const g = gradeInfo(risk.score);
  const sc = scoreColor(risk.score);

  const gaugeW = 300, gaugeH = 20, gaugeX = MARGIN;
  doc.save();
  doc.roundedRect(gaugeX, doc.y, gaugeW, gaugeH, 10).fill('#e5e7eb');
  const fillW = (risk.score / 100) * gaugeW;
  if (fillW > 0) doc.roundedRect(gaugeX, doc.y, Math.max(fillW, 20), gaugeH, 10).fill(sc);
  doc.fontSize(11).fillColor('#ffffff').font('Helvetica-Bold').text(Math.round(risk.score).toString(), gaugeX, doc.y + 4, { width: gaugeW, align: 'center' });
  doc.restore();
  doc.moveDown(1);

  doc.fontSize(20).fillColor(sc).font('Helvetica-Bold').text(`${g.letter} - ${g.label}`);
  doc.moveDown(0.3);
  doc.fontSize(10).fillColor('#6b7280').font('Helvetica').text(`Risk Assessment: ${risk.riskLevel}`);
  doc.moveDown(0.8);

  doc.fontSize(9).fillColor('#374151');
  const counts = [
    `Critical: ${sevCounts.CRITICAL}`, `High: ${sevCounts.HIGH}`, `Medium: ${sevCounts.MEDIUM}`,
    `Low: ${sevCounts.LOW}`, `Info: ${sevCounts.INFO}`,
  ];
  doc.text(`Total Findings: ${totalFindings}   |   ${counts.join('   |   ')}`, { width: CONTENT_WIDTH });
  doc.moveDown(1.5);
}

// ─── RISK SCORE PAGE ─────────────────────────────────────────────────────────
function riskScorePage(doc: PDFKit.PDFDocument, findings: ReportFinding[], riskScore: number) {
  ensureSpace(doc, 180);
  drawHeader(doc, 'Risk Score');

  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'The risk score quantifies overall exposure based on finding severity, count, and detection confidence.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
  doc.moveDown(0.6);

  // Score display
  const sc = scoreColor(100 - riskScore);
  doc.save();
  doc.roundedRect(MARGIN, doc.y, 120, 50, 8).fill(sc);
  doc.fontSize(28).fillColor('#ffffff').font('Helvetica-Bold').text(`${riskScore}`, MARGIN, doc.y + 8, { width: 120, align: 'center' });
  doc.fontSize(10).fillColor('#ffffff').font('Helvetica').text('/100', MARGIN, doc.y + 2, { width: 120, align: 'center' });
  doc.restore();
  doc.moveDown(2);

  // Breakdown by severity
  doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Score Breakdown by Severity');
  doc.moveDown(0.3);

  const sevPoints: Record<string, number> = { CRITICAL: 15, HIGH: 8, MEDIUM: 3, LOW: 1, INFO: 0 };
  const sevCountsLocal: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    sevCountsLocal[f.severity] = (sevCountsLocal[f.severity] || 0) + 1;
  }

  let y = doc.y;
  for (const [sev, points] of Object.entries(sevPoints)) {
    const count = sevCountsLocal[sev] || 0;
    const total = count * points;
    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(sev, MARGIN, y, { width: 70 });
    doc.fontSize(8).fillColor('#6b7280').text(`${count} findings x ${points} pts`, MARGIN + 75, y, { width: 150 });
    doc.fontSize(8).fillColor('#1f2937').font('Helvetica-Bold').text(`= ${total}`, MARGIN + 230, y, { width: 50, align: 'right' });
    y += 14;
  }
  doc.y = y + 5;

  // Confidence note
  ensureSpace(doc, 30);
  doc.fontSize(8).fillColor('#6b7280').font('Helvetica-Oblique').text(
    'Note: Each finding contribution is weighted by its detection confidence (0.0-1.0). Higher confidence findings contribute more to the risk score.',
    { width: CONTENT_WIDTH, lineGap: 1 }
  );
  doc.moveDown(0.5);
}

// ─── RISK SUMMARY ─────────────────────────────────────────────────────────────
function riskSummaryPage(doc: PDFKit.PDFDocument, sevCounts: Record<string, number>) {
  ensureSpace(doc, 200);
  drawHeader(doc, 'Risk Summary');

  const data = [
    { l: 'Critical', v: sevCounts.CRITICAL, c: '#dc2626' },
    { l: 'High', v: sevCounts.HIGH, c: '#ea580c' },
    { l: 'Medium', v: sevCounts.MEDIUM, c: '#d97706' },
    { l: 'Low', v: sevCounts.LOW, c: '#2563eb' },
    { l: 'Info', v: sevCounts.INFO, c: '#6b7280' },
  ];
  const maxV = Math.max(...data.map(d => d.v), 1);

  let y = doc.y;
  for (const d of data) {
    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(d.l, MARGIN, y, { width: 60, align: 'right' });
    drawBar(doc, MARGIN + 70, y + 2, 300, 10, d.v, maxV, d.c);
    doc.fontSize(9).fillColor('#374151').text(d.v.toString(), MARGIN + 380, y, { width: 40 });
    y += 20;
  }

  y += 10;
  const total = data.reduce((s, d) => s + d.v, 0);
  if (total > 0) {
    const cx = MARGIN + 150, cy = y + 60, r = 55;
    let angle = -Math.PI / 2;
    for (const d of data) {
      if (d.v === 0) continue;
      const slice = (d.v / total) * 2 * Math.PI;
      drawDonutArc(doc, cx, cy, r, r * 0.6, angle, angle + slice, d.c);
      angle += slice;
    }
    doc.fontSize(16).fillColor('#0f172a').font('Helvetica-Bold').text(total.toString(), cx - 20, cy - 10, { width: 40, align: 'center' });
    doc.fontSize(7).fillColor('#6b7280').font('Helvetica').text('findings', cx - 20, cy + 6, { width: 40, align: 'center' });
    y += 130;
  }

  doc.y = y;
}

function drawDonutArc(doc: PDFKit.PDFDocument, cx: number, cy: number, outerR: number, innerR: number, start: number, end: number, color: string) {
  const steps = 50;
  const range = end - start;
  if (range <= 0.01) return;
  doc.save();
  doc.fillColor(color);
  const pts: [number, number][] = [];
  for (let i = 0; i <= steps; i++) {
    const a = start + (i / steps) * range;
    pts.push([cx + outerR * Math.cos(a), cy + outerR * Math.sin(a)]);
  }
  for (let i = steps; i >= 0; i--) {
    const a = start + (i / steps) * range;
    pts.push([cx + innerR * Math.cos(a), cy + innerR * Math.sin(a)]);
  }
  doc.moveTo(pts[0][0], pts[0][1]);
  for (let i = 1; i < pts.length; i++) doc.lineTo(pts[i][0], pts[i][1]);
  doc.closePath();
  doc.fill();
  doc.restore();
}

// ─── CATEGORY ANALYSIS ────────────────────────────────────────────────────────
function categoryAnalysisPage(doc: PDFKit.PDFDocument, risk: SecurityScoreResult) {
  const cats = Object.entries(risk.categoryScores).sort(([, a], [, b]) => a.score - b.score);
  if (cats.length === 0) return;
  doc.addPage();
  drawHeader(doc, 'Category Analysis');

  let y = doc.y;
  for (const [cat, data] of cats) {
    if (y > BOTTOM_LIMIT - 40) { doc.addPage(); drawHeader(doc, 'Category Analysis (continued)'); y = doc.y; }
    const desc = CATEGORY_DESCRIPTIONS[cat] || '';
    doc.fontSize(9).fillColor('#1f2937').font('Helvetica-Bold').text(cat, MARGIN, y, { width: 170 });
    if (desc) doc.fontSize(7).fillColor('#9ca3af').font('Helvetica').text(desc, MARGIN, y + 11, { width: 170 });
    drawBar(doc, MARGIN + 180, y + 3, 200, 8, data.score, 100, scoreColor(data.score));
    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`${data.score}/100`, MARGIN + 390, y, { width: 45 });
    doc.fontSize(8).fillColor('#6b7280').text(`${data.findings} finding${data.findings !== 1 ? 's' : ''}`, MARGIN + 440, y, { width: 60 });
    y += 28;
  }
  doc.y = y + 5;
}

// ─── DETAILED FINDINGS ────────────────────────────────────────────────────────
function detailedFindingsPage(doc: PDFKit.PDFDocument, findings: ReportFinding[]) {
  doc.addPage();
  drawHeader(doc, 'Detailed Findings');

  const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const dedupMap = new Map<string, ReportFinding>();
  for (const f of findings) {
    const key = f.title.toLowerCase().trim();
    const existing = dedupMap.get(key);
    if (!existing || (sevOrder[f.severity] ?? 5) < (sevOrder[existing.severity] ?? 5)) {
      dedupMap.set(key, f);
    }
  }
  const sorted = [...dedupMap.values()].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    ensureSpace(doc, 50);

    const sc = sevColor(f.severity);

    doc.save();
    doc.roundedRect(MARGIN, doc.y, 50, 14, 3).fill(sc);
    doc.fontSize(7).fillColor('#ffffff').font('Helvetica-Bold').text(f.severity, MARGIN + 2, doc.y + 3, { width: 46, align: 'center' });
    doc.restore();

    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text(`${i + 1}. ${f.title}`, MARGIN + 58, doc.y - 11, { width: CONTENT_WIDTH - 58 });
    doc.fontSize(8).fillColor('#6b7280').font('Helvetica').text(`${f.category}  |  ${f.affectedAsset}`, MARGIN + 58, doc.y, { width: CONTENT_WIDTH - 58 });
    doc.moveDown(0.4);

    const details: [string, string, string][] = [
      ['Description', f.description, '#374151'],
      ['Impact', f.impact, '#374151'],
      ['Remediation', f.remediation, '#16a34a'],
    ];
    for (const [label, text, color] of details) {
      if (!text) continue;
      if (needPage(doc, 25)) doc.addPage();
      doc.fontSize(8).fillColor('#9ca3af').font('Helvetica-Bold').text(`${label}: `, MARGIN + 10, doc.y, { continued: true, width: CONTENT_WIDTH - 10 });
      doc.fillColor(color).font('Helvetica').text(text, { width: CONTENT_WIDTH - 10 });
      doc.moveDown(0.15);
    }

    // Proof of Vulnerability section
    if (f.evidence && f.evidence.includes('=== PROOF OF VULNERABILITY ===')) {
      if (needPage(doc, 40)) doc.addPage();
      doc.moveDown(0.3);
      doc.save();
      doc.roundedRect(MARGIN + 10, doc.y, CONTENT_WIDTH - 10, 14, 3).fill('#7c3aed');
      doc.fontSize(7).fillColor('#ffffff').font('Helvetica-Bold').text('PROOF OF VULNERABILITY', MARGIN + 15, doc.y + 3, { width: CONTENT_WIDTH - 20 });
      doc.restore();
      doc.moveDown(0.3);

      const proofLines = f.evidence.split('\n');
      let inProof = false;
      let lineCount = 0;
      for (const line of proofLines) {
        if (line.includes('=== PROOF OF VULNERABILITY ===')) { inProof = true; continue; }
        if (line.includes('=== END PROOF ===')) { break; }
        if (!inProof) continue;
        if (lineCount >= 40) { doc.fontSize(6).fillColor('#6b7280').text('  ... (truncated, see full evidence in JSON export)', { width: CONTENT_WIDTH - 15 }); break; }
        if (needPage(doc, 12)) doc.addPage();

        if (line.startsWith('>>') || line.startsWith('<<')) {
          doc.fontSize(7).fillColor('#7c3aed').font('Helvetica-Bold').text(line, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15 });
        } else if (line.startsWith('  ')) {
          doc.fontSize(6).fillColor('#374151').font('Courier').text(line, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15 });
        } else {
          doc.fontSize(6).fillColor('#374151').font('Helvetica').text(line, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15 });
        }
        lineCount++;
      }
      doc.moveDown(0.3);
    } else if (f.evidence) {
      // Legacy evidence format
      if (needPage(doc, 25)) doc.addPage();
      doc.fontSize(8).fillColor('#9ca3af').font('Helvetica-Bold').text('Evidence: ', MARGIN + 10, doc.y, { continued: true, width: CONTENT_WIDTH - 10 });
      doc.fillColor('#374151').font('Helvetica').text(f.evidence, { width: CONTENT_WIDTH - 10 });
      doc.moveDown(0.15);
    }

    if (f.references && Array.isArray(f.references) && f.references.length > 0) {
      doc.fontSize(7).fillColor('#6b7280').font('Helvetica');
      for (const ref of f.references.slice(0, 2)) {
        doc.text(ref, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15, link: ref });
        doc.moveDown(0.1);
      }
    }

    if (i < sorted.length - 1) {
      doc.moveDown(0.2);
      doc.save();
      doc.moveTo(MARGIN + 10, doc.y).lineTo(PAGE_WIDTH - MARGIN, doc.y).lineWidth(0.5).stroke('#e5e7eb');
      doc.restore();
      doc.moveDown(0.3);
    }
  }
}

// ─── REMEDIATION ROADMAP ──────────────────────────────────────────────────────
function remediationRoadmapPage(doc: PDFKit.PDFDocument, findings: ReportFinding[]) {
  doc.addPage();
  drawHeader(doc, 'Remediation Roadmap');

  const sevOrder2: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const dedupedFindings = new Map<string, ReportFinding>();
  for (const f of findings) {
    const key = f.title.toLowerCase().trim();
    const existing = dedupedFindings.get(key);
    if (!existing || (sevOrder2[f.severity] ?? 5) < (sevOrder2[existing.severity] ?? 5)) {
      dedupedFindings.set(key, f);
    }
  }
  const uniqueFindings = [...dedupedFindings.values()];

  const phases = [
    { title: 'Phase 1: Immediate (0-24 hours)', color: '#dc2626', desc: 'Address all Critical severity findings immediately. These represent active security risks.', filter: (f: ReportFinding) => f.severity === 'CRITICAL', max: Infinity },
    { title: 'Phase 2: Urgent (1-7 days)', color: '#ea580c', desc: 'Resolve all High severity findings within one week.', filter: (f: ReportFinding) => f.severity === 'HIGH', max: Infinity },
    { title: 'Phase 3: Scheduled (1-4 weeks)', color: '#d97706', desc: 'Plan and implement fixes for Medium severity findings.', filter: (f: ReportFinding) => f.severity === 'MEDIUM', max: 10 },
    { title: 'Phase 4: Backlog (1-3 months)', color: '#2563eb', desc: 'Add Low severity findings to the security backlog.', filter: (f: ReportFinding) => f.severity === 'LOW', max: 5 },
  ];

  for (const phase of phases) {
    const items = uniqueFindings.filter(phase.filter).slice(0, phase.max);
    ensureSpace(doc, 50);
    doc.fontSize(11).fillColor(phase.color).font('Helvetica-Bold').text(phase.title, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.2);
    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(phase.desc, { width: CONTENT_WIDTH });
    doc.moveDown(0.4);

    if (items.length === 0) {
      doc.fontSize(9).fillColor('#16a34a').text('  No findings in this category.', { width: CONTENT_WIDTH });
    } else {
      for (const f of items) {
        ensureSpace(doc, 25);
        doc.fontSize(8).fillColor(phase.color).font('Helvetica-Bold').text(`  \u2022 ${f.title}`, MARGIN + 5, doc.y, { width: CONTENT_WIDTH - 5 });
        doc.fontSize(7).fillColor('#6b7280').font('Helvetica').text(`    ${f.remediation}`, MARGIN + 15, doc.y, { width: CONTENT_WIDTH - 15 });
        doc.moveDown(0.3);
      }
    }
    doc.moveDown(0.8);
  }
}

// ─── SCORING BREAKDOWN ────────────────────────────────────────────────────────
function scoringBreakdownPage(doc: PDFKit.PDFDocument, risk: SecurityScoreResult) {
  doc.addPage();
  drawHeader(doc, 'Scoring Breakdown');

  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'The security score starts at 100 points and is reduced by each finding based on severity and category weight. Diminishing returns apply after thresholds.',
    { width: CONTENT_WIDTH }
  );
  doc.moveDown(0.8);

  doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Severity Penalties');
  doc.moveDown(0.3);
  doc.fontSize(8).fillColor('#374151').font('Helvetica');
  const penalties = [
    'Critical: -25 points per finding (max 3 full deductions)',
    'High: -15 points per finding (max 5 full deductions)',
    'Medium: -8 points per finding (max 10 full deductions)',
    'Low: -3 points per finding (max 15 full deductions)',
    'Info: 0 points (informational only)',
  ];
  for (const p of penalties) doc.text(`    ${p}`, { width: CONTENT_WIDTH });
  doc.moveDown(0.8);

  doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Category Multipliers');
  doc.moveDown(0.3);
  const sorted = Object.entries(CATEGORY_WEIGHTS).sort(([, a], [, b]) => b - a);
  let y = doc.y;
  for (const [cat, w] of sorted) {
    if (y > BOTTOM_LIMIT - 15) { doc.addPage(); drawHeader(doc, 'Scoring Breakdown (continued)'); y = doc.y; }
    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`    ${cat}: ${w}x`, MARGIN, y, { width: CONTENT_WIDTH });
    y += 13;
  }
  doc.y = y + 8;

  ensureSpace(doc, 40);
  doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('Top Scoring Deductions');
  doc.moveDown(0.3);

  const top = risk.scoringBreakdown.slice(0, 15);
  y = doc.y;
  for (const item of top) {
    if (y > BOTTOM_LIMIT - 15) { doc.addPage(); drawHeader(doc, 'Scoring Breakdown (continued)'); y = doc.y; }
    const sc = sevColor(item.severity);
    doc.fontSize(8).fillColor(sc).font('Helvetica-Bold').text(`[${item.severity}]`, MARGIN, y, { width: 55 });
    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(item.title, MARGIN + 58, y, { width: CONTENT_WIDTH - 150 });
    doc.fontSize(8).fillColor('#dc2626').text(`-${item.adjustedDeduction}`, MARGIN + CONTENT_WIDTH - 85, y, { width: 45, align: 'right' });
    doc.fontSize(7).fillColor('#9ca3af').text(`${item.cumulativeScore}`, MARGIN + CONTENT_WIDTH - 35, y, { width: 35, align: 'right' });
    y += 13;
  }
  doc.y = y + 5;
}

// ─── METHODOLOGY ──────────────────────────────────────────────────────────────
function methodologyPage(doc: PDFKit.PDFDocument) {
  doc.addPage();
  drawHeader(doc, 'Methodology');
  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'This assessment was conducted using CyberGuard\'s AI-augmented automated security scanning platform. ' +
    'The scan engine runs 23 specialized modules across 4 phases, guided at each transition by an Ollama-based ' +
    'AI model that re-prioritizes attack vectors based on live recon intelligence -- mirroring how a manual ' +
    'penetration tester operates.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
  doc.moveDown(0.4);

  const phases = [
    {
      title: 'Phase 1 -- Reconnaissance (Passive)',
      mods: [
        'DNS Security: SPF, DKIM, DMARC, DNSSEC, CAA, zone transfer',
        'TLS/HTTPS: Certificate chain, protocols, HSTS, OCSP stapling',
        'Security Headers: CSP, CORS, X-Frame-Options, Permissions-Policy, cookie flags',
        'Web Configuration: Sensitive files, error handling, technology leakage',
        'Technology Detection: Server fingerprinting, framework, CDN, SRI',
      ],
    },
    {
      title: 'Phase 2 -- Infrastructure Mapping',
      mods: [
        'Subdomain Discovery: CT logs, DNS resolution, wildcard detection',
        'Email Security: MX, SPF/DKIM/DMARC, MTA-STS, SMTP TLS',
        'Port Scanning: 34 common ports, banners, service identification',
        'DNS Deep Analysis: DANE/TLSA, SOA, nameserver diversity, IPv6',
        'TLS Deep Analysis: Certificate chain, HTTP/2, HTTP/3, cipher suites',
        'OS Fingerprinting: Server headers, version detection, outdated software',
      ],
    },
    {
      title: 'Phase 3 -- Active Exploitation (AI-Prioritized)',
      mods: [
        'AI Recon Analysis: Ollama reviews Phase 1-2 data, reorders attack modules by expected yield',
        'Active Vulnerability Testing: SQLi, XSS, SSRF, XXE, JWT, path traversal, open redirect',
        'Broken Authentication: Enumeration, session config, lockout, 2FA bypass, mass assignment',
        'Advanced Injection: SSTI, OS command injection, LDAP, XPath, deserialization, prototype pollution',
        'HTTP Methods Audit: TRACE/XST, PUT file write, verb tampering, method override, open proxy',
        'API Security (OWASP API Top 10): BOLA/IDOR, excessive data, function auth, GraphQL, rate limiting',
        'CVE Correlation: Technology stack vs. known vulnerability database',
        'Site Crawl: Forms, CSRF, credential exposure, mixed content',
        'Subdomain Takeover: Dangling CNAMEs, cloud service verification',
      ],
    },
    {
      title: 'Phase 4 -- Infrastructure & Supply Chain Audit',
      mods: [
        'Service Audit: DB exposure, cloud metadata, default credentials, container exposure',
        'Supply Chain: Exposed package files, CDN SRI, vulnerable library versions, dep confusion',
        'Cloud Security: IMDS metadata, public S3/GCS buckets, Kubernetes API, Docker Remote API, CI/CD',
        'Client-Side Security: CSP quality, CORS origin reflection, cookie audit, caching, COOP/COEP',
        'AI Post-Scan Triage: Deduplication, CVSS scoring, severity adjustment, chain analysis',
      ],
    },
  ];

  for (const phase of phases) {
    ensureSpace(doc, 30);
    doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text(phase.title, { width: CONTENT_WIDTH });
    doc.moveDown(0.2);
    for (const m of phase.mods) {
      ensureSpace(doc, 15);
      doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`  \u2022 ${m}`, { width: CONTENT_WIDTH - 5 });
      doc.moveDown(0.15);
    }
    doc.moveDown(0.4);
  }

  ensureSpace(doc, 40);
  doc.fontSize(9).fillColor('#374151').text(
    'Findings are classified using CVSS v3.1-aligned severity ratings. The AI model (Ollama, local) scores each ' +
    'finding, identifies multi-step attack chains, and adjusts severity based on environmental context ' +
    '(WAF presence, authentication requirements, technology stack). All analysis is performed locally with ' +
    'no data sent to third-party services.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
}

// ─── DISCLAIMER ───────────────────────────────────────────────────────────────
function disclaimerPage(doc: PDFKit.PDFDocument) {
  ensureSpace(doc, 120);
  drawHeader(doc, 'Disclaimer');
  doc.fontSize(9).fillColor('#374151').font('Helvetica').text(
    'This report is generated by an automated security assessment tool and is intended for informational ' +
    'purposes only. While CyberGuard strives for accuracy, automated scans may not identify all potential ' +
    'security vulnerabilities. This report does not constitute a guarantee of security. Organizations should ' +
    'supplement automated scanning with manual penetration testing and regular security audits. The findings ' +
    'and recommendations in this report should be reviewed by qualified security professionals before ' +
    'implementation.',
    { width: CONTENT_WIDTH, lineGap: 2 }
  );
}

// ─── VULNERABILITY CHAINS (AI-GENERATED) ─────────────────────────────────────
interface ChainData {
  title: string;
  description: string;
  severity: string;
  findings: string[];
  attackPath: string[];
  impact: string;
}

function vulnerabilityChainsPage(doc: PDFKit.PDFDocument, chains: ChainData[]) {
  if (!chains || chains.length === 0) return;
  doc.addPage();
  drawHeader(doc, 'Vulnerability Chains');
  doc.fontSize(10).fillColor('#6b7280').font('Helvetica').text(
    'The following attack chains were identified by correlating multiple vulnerabilities that can be combined for greater impact.',
    { width: CONTENT_WIDTH }
  );
  doc.moveDown(0.5);

  for (const chain of chains) {
    ensureSpace(doc, 80);

    const chainSevColor = chain.severity === 'CRITICAL' ? '#dc2626' : chain.severity === 'HIGH' ? '#ea580c' : '#d97706';
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#111827').text(`Chain: ${chain.title}`);
    doc.fontSize(9).font('Helvetica-Bold').fillColor(chainSevColor).text(`Overall Severity: ${chain.severity}`);
    doc.moveDown(0.3);

    doc.fontSize(9).fillColor('#374151').font('Helvetica').text(chain.description, { width: CONTENT_WIDTH, lineGap: 1 });
    doc.moveDown(0.3);

    if (chain.attackPath && chain.attackPath.length > 0) {
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#1f2937').text('Attack Path:');
      for (let i = 0; i < chain.attackPath.length; i++) {
        doc.fontSize(9).fillColor('#374151').text(`  ${i + 1}. ${chain.attackPath[i]}`, { width: CONTENT_WIDTH });
      }
      doc.moveDown(0.2);
    }

    if (chain.findings && chain.findings.length > 0) {
      doc.fontSize(8).fillColor('#6b7280').font('Helvetica-Oblique').text(`Involved: ${chain.findings.join(' -> ')}`, { width: CONTENT_WIDTH });
      doc.moveDown(0.2);
    }

    if (chain.impact) {
      doc.fontSize(9).fillColor('#dc2626').font('Helvetica-Bold').text('Impact: ');
      doc.fontSize(9).fillColor('#374151').font('Helvetica').text(chain.impact, { width: CONTENT_WIDTH, lineGap: 1 });
    }
    doc.moveDown(0.8);
  }
}

// ─── AI REMEDIATION PLAN (AI-GENERATED) ──────────────────────────────────────
interface PhaseData {
  phase: string;
  timeframe: string;
  findings: string[];
  actions: string[];
  riskReduction: string;
}

function aiRemediationPlanPage(doc: PDFKit.PDFDocument, plan: PhaseData[]) {
  if (!plan || plan.length === 0) return;
  doc.addPage();
  drawHeader(doc, 'AI-Generated Remediation Plan');

  const phaseColors: Record<string, string> = {
    'Phase 1': '#dc2626',
    'Phase 2': '#ea580c',
    'Phase 3': '#d97706',
    'Phase 4': '#2563eb',
  };

  for (const phase of plan) {
    ensureSpace(doc, 70);
    const color = phaseColors[phase.phase.split(' ')[0]] || '#6b7280';

    doc.fontSize(12).font('Helvetica-Bold').fillColor(color).text(phase.phase);
    doc.fontSize(9).fillColor('#6b7280').font('Helvetica').text(`Timeframe: ${phase.timeframe} | Risk Reduction: ${phase.riskReduction || 'Estimated'}`);
    doc.moveDown(0.3);

    if (phase.findings && phase.findings.length > 0) {
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#374151').text('Findings:');
      for (const f of phase.findings.slice(0, 10)) {
        doc.fontSize(8).fillColor('#374151').text(`  \u2022 ${f}`, { width: CONTENT_WIDTH });
      }
      if (phase.findings.length > 10) {
        doc.fontSize(8).fillColor('#6b7280').text(`  ... and ${phase.findings.length - 10} more`, { width: CONTENT_WIDTH });
      }
      doc.moveDown(0.2);
    }

    if (phase.actions && phase.actions.length > 0) {
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#374151').text('Actions:');
      for (const a of phase.actions) {
        doc.fontSize(8).fillColor('#374151').text(`  -> ${a}`, { width: CONTENT_WIDTH });
      }
    }
    doc.moveDown(0.8);
  }
}

// ─── FOOTER ───────────────────────────────────────────────────────────────────
function footers(doc: PDFKit.PDFDocument, domain: string) {
  const count = doc.bufferedPageRange().count;
  for (let i = 0; i < count; i++) {
    doc.switchToPage(i);
    const y = PAGE_HEIGHT - 30;
    doc.save();
    doc.moveTo(MARGIN, y).lineTo(PAGE_WIDTH - MARGIN, y).lineWidth(0.5).stroke('#e5e7eb');
    doc.fontSize(7).fillColor('#9ca3af').font('Helvetica');
    doc.text(`CyberGuard Security Assessment - ${domain}`, MARGIN, y + 5, { width: 300 });
    doc.text(`Page ${i + 1} of ${count}`, MARGIN, y + 5, { width: CONTENT_WIDTH, align: 'right' });
    doc.text('CONFIDENTIAL', MARGIN, y + 15, { width: CONTENT_WIDTH, align: 'right' });
    doc.restore();
  }
}

// ─── MAIN EXPORTS ─────────────────────────────────────────────────────────────

export async function generateReport(assessmentId: string, organizationId: string, modules?: string[], modulesRun?: { name: string; duration: number; findings: number }[]) {
  const assessment = await prisma.assessment.findFirst({
    where: { id: assessmentId, organizationId },
    include: { findings: true, organization: true },
  });
  if (!assessment) throw new Error('Assessment not found or access denied');

  const findings = assessment.findings.map(f => ({ ...f, references: JSON.parse(f.references || '[]') }));
  const risk = calculateSecurityScore(findings as any);
  const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { sevCounts[f.severity]++; });

  const riskScore = calculateRiskScore(findings as any);

  let executiveSummary = 'No executive summary available.';
  let attackNarrative = '';
  let vulnerabilityChains: ChainData[] = [];
  let remediationPlan: PhaseData[] = [];
  let classification: Record<string, unknown> | null = null;

  try {
    const ai = getAIProvider();

    const redis = (await import('../lib/redis')).default;
    const progressKey = `scan:${assessmentId}:progress`;
    let usedCachedTriage = false;

    try {
      const [cachedChains, cachedNarrative, cachedPlan, cachedClassification] = await Promise.all([
        redis.get(`${progressKey}:aiChains`),
        redis.get(`${progressKey}:attackNarrative`),
        redis.get(`${progressKey}:remediationPlan`),
        redis.get(`${progressKey}:classification`),
      ]);

      if (cachedChains) {
        vulnerabilityChains = JSON.parse(cachedChains);
        usedCachedTriage = true;
        logger.info('[Report] Reusing AI chains from scan triage cache');
      }
      if (cachedNarrative && cachedNarrative.length > 10) {
        attackNarrative = cachedNarrative;
        logger.info('[Report] Reusing AI attack narrative from scan triage cache');
      }
      if (cachedPlan) {
        remediationPlan = JSON.parse(cachedPlan);
        logger.info('[Report] Reusing AI remediation plan from scan triage cache');
      }
      if (cachedClassification) {
        classification = JSON.parse(cachedClassification);
        logger.info('[Report] Reusing target classification from scan cache');
      }
    } catch {}

    if (!usedCachedTriage) {
      logger.info('[Report] No cached triage found, generating AI analyses now...');

      const [narrativeResult, chainsResult, planResult] = await Promise.allSettled([
        ai.generateAttackNarrative(findings as any, assessment.domain),
        ai.analyzeVulnerabilityChains(findings as any, assessment.domain),
        ai.generateRemediationPlan(findings as any, assessment.domain),
      ]);

      attackNarrative = narrativeResult.status === 'fulfilled' ? narrativeResult.value : '';
      vulnerabilityChains = chainsResult.status === 'fulfilled' ? chainsResult.value : [];
      remediationPlan = planResult.status === 'fulfilled' ? planResult.value : [];
    }

    logger.info('[Report] Enriching critical/high finding evidence...');
    const topFindings = (findings as any[]).filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 8);
    const enrichedResults = await Promise.allSettled(
      topFindings.map(f =>
        ai.enrichFindingEvidence(f, `Domain: ${assessment.domain}, Organization: ${assessment.organization.name}`)
      )
    );
    for (const result of enrichedResults) {
      if (result.status === 'fulfilled') {
        const enriched = result.value;
        const idx = findings.findIndex(f => f.id === enriched.id);
        if (idx >= 0) (findings as any[])[idx] = enriched;
      }
    }

    try {
      executiveSummary = await ai.generateExecutiveSummary(findings as any, assessment.domain);
    } catch {}

    logger.info('[Report] AI report generation complete.');
  } catch (e) {
    logger.error('[Report] AI generation error:', { error: String(e) });
  }

  const content = JSON.stringify({
    summary: { totalFindings: findings.length, ...sevCounts, riskScore: risk.score, grade: risk.grade, gradeLabel: risk.gradeLabel, riskLevel: risk.riskLevel },
    findings: findings.map(f => ({ id: f.id, title: f.title, severity: f.severity, category: f.category, affectedAsset: f.affectedAsset })),
    categoryScores: risk.categoryScores,
    complianceMapping: risk.complianceMapping,
    complianceFrameworkResults: risk.complianceFrameworkResults,
    scoringBreakdown: risk.scoringBreakdown,
    executiveSummary,
    attackNarrative,
    vulnerabilityChains,
    remediationPlan,
    classification,
    riskScore,
    modulesRun: modulesRun || [],
    generatedAt: new Date().toISOString(),
  });

  const existing = await prisma.report.findUnique({ where: { assessmentId } });
  const report = existing
    ? await prisma.report.update({ where: { assessmentId }, data: { content, executiveSummary } })
    : await prisma.report.create({ data: { assessmentId, organizationId, content, executiveSummary } });
  return report;
}

export async function generatePdfReport(reportId: string): Promise<string> {
  ensureReportsDir();
  const report = await prisma.report.findUnique({
    where: { id: reportId },
    include: { assessment: { include: { findings: true, organization: true } } },
  });
  if (!report) throw new Error('Report not found');

  const assessment = report.assessment;
  const findings = assessment.findings.map(f => ({ ...f, references: JSON.parse(f.references || '[]') }));
  const risk = calculateSecurityScore(findings as any);
  const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { sevCounts[f.severity]++; });

  const riskScore = calculateRiskScore(findings as any);

  const filename = `report-${reportId.slice(0, 8)}-${Date.now()}.pdf`;
  const filePath = path.join(REPORTS_DIR, filename);

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: MARGIN, bufferPages: true, info: {
      Title: `CyberGuard Security Assessment - ${assessment.domain}`,
      Author: 'CyberGuard Security Platform',
      Subject: 'Cybersecurity Assessment Report',
    }});
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    coverPage(doc, assessment, risk, sevCounts, findings.length, riskScore);
    tocPage(doc);
    executiveSummaryPage(doc, report.executiveSummary || '');

    // Attack narrative with template fallback
    try {
      const content = JSON.parse(report.content || '{}');
      attackNarrativePage(doc, content.attackNarrative || '', findings as any);
    } catch {
      attackNarrativePage(doc, '', findings as any);
    }

    targetClassificationPage(doc, report.content);
    securityScorePage(doc, risk, sevCounts, findings.length);
    riskScorePage(doc, findings as any, riskScore);
    riskSummaryPage(doc, sevCounts);
    categoryAnalysisPage(doc, risk);

    // AI-generated pages
    try {
      const content = JSON.parse(report.content || '{}');
      if (content.vulnerabilityChains?.length) vulnerabilityChainsPage(doc, content.vulnerabilityChains);
      if (content.remediationPlan?.length) aiRemediationPlanPage(doc, content.remediationPlan);
    } catch {}

    // Compliance framework mapping (replaces old compliance matrix)
    enhancedCompliancePage(doc, findings as any, risk);

    // Remediation priority matrix (new)
    remediationPriorityMatrixPage(doc, findings as any);

    detailedFindingsPage(doc, findings as any);
    remediationRoadmapPage(doc, findings as any);
    scoringBreakdownPage(doc, risk);
    methodologyPage(doc);
    disclaimerPage(doc);
    footers(doc, assessment.domain);

    doc.end();
    stream.on('finish', async () => {
      await prisma.report.update({ where: { id: reportId }, data: { pdfPath: filePath } });
      resolve(filePath);
    });
    stream.on('error', reject);
  });
}

export async function getReportById(reportId: string, organizationId: string) {
  const report = await prisma.report.findFirst({
    where: { id: reportId, organizationId },
    include: { assessment: { include: { findings: true } }, organization: { select: { name: true } } },
  });
  if (!report) throw new Error('Report not found or access denied');
  return report;
}

export async function getReportByAssessment(assessmentId: string, organizationId: string) {
  const report = await prisma.report.findFirst({
    where: { assessmentId, organizationId },
    include: { assessment: { include: { findings: true } }, organization: { select: { name: true } } },
  });
  if (!report) throw new Error('Report not found or access denied');
  return report;
}

// ─── JSON EXPORT ──────────────────────────────────────────────────────────────
export async function generateJsonReport(assessmentId: string, organizationId: string): Promise<object> {
  const assessment = await prisma.assessment.findFirst({
    where: { id: assessmentId, organizationId },
    include: { findings: true, organization: true, report: true },
  });
  if (!assessment) throw new Error('Assessment not found or access denied');

  const findings = assessment.findings.map(f => ({
    id: f.id,
    title: f.title,
    description: f.description,
    severity: f.severity,
    category: f.category,
    cvssScore: f.cvssScore,
    affectedAsset: f.affectedAsset,
    evidence: f.evidence,
    impact: f.impact,
    remediation: f.remediation,
    references: JSON.parse(f.references || '[]'),
    detectedAt: f.detectedAt.toISOString(),
  }));

  const risk = calculateSecurityScore(findings as any);
  const riskScore = calculateRiskScore(findings as any);

  let reportContent: Record<string, unknown> = {};
  try { reportContent = JSON.parse(assessment.report?.content || '{}'); } catch {}

  return {
    meta: {
      domain: assessment.domain,
      organization: assessment.organization.name,
      assessmentId: assessment.id,
      status: assessment.status,
      createdAt: assessment.createdAt.toISOString(),
      completedAt: assessment.completedAt?.toISOString(),
      generatedAt: new Date().toISOString(),
    },
    score: {
      total: Math.round(risk.score),
      grade: risk.grade,
      gradeLabel: risk.gradeLabel,
      riskLevel: risk.riskLevel,
      categoryScores: risk.categoryScores,
    },
    riskScore,
    summary: {
      totalFindings: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length,
    },
    findings,
    aiAnalysis: {
      executiveSummary: reportContent.executiveSummary || null,
      attackNarrative: reportContent.attackNarrative || null,
      vulnerabilityChains: reportContent.vulnerabilityChains || [],
      remediationPlan: reportContent.remediationPlan || [],
    },
    compliance: {
      frameworks: risk.complianceFrameworkResults,
      categoryMapping: risk.complianceMapping,
    },
    modulesRun: reportContent.modulesRun || [],
    scoringBreakdown: risk.scoringBreakdown,
  };
}

// ─── CSV EXPORT ───────────────────────────────────────────────────────────────
export async function generateCsvReport(assessmentId: string, organizationId: string): Promise<string> {
  const assessment = await prisma.assessment.findFirst({
    where: { id: assessmentId, organizationId },
    include: { findings: true },
  });
  if (!assessment) throw new Error('Assessment not found or access denied');

  const headers = ['ID', 'Title', 'Severity', 'Category', 'CVSS', 'Affected Asset', 'Description', 'Impact', 'Remediation'];
  const rows = assessment.findings.map(f => [
    f.id,
    `"${f.title.replace(/"/g, '""')}"`,
    f.severity,
    f.category,
    f.cvssScore?.toString() || '',
    `"${f.affectedAsset.replace(/"/g, '""')}"`,
    `"${f.description.replace(/"/g, '""')}"`,
    `"${f.impact.replace(/"/g, '""')}"`,
    `"${f.remediation.replace(/"/g, '""')}"`,
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

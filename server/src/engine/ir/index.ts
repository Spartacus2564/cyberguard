import { IRScanContext, IRCase, IRModuleResult, Evidence, TimelineEvent, IOC, ContainmentAction, Finding, Severity } from './types';
import { logInfo, logDone } from '../scanLogger';

// Re-export types
export type { IRScanContext, IRCase, IRModuleResult, Evidence, TimelineEvent, IOC, ContainmentAction } from './types';
export { Severity } from './types';
import { evidenceCollector } from './modules/evidenceCollector';
import { logTimeline } from './modules/logTimeline';
import { iocExtractor } from './modules/iocExtractor';
import { malwareTriage } from './modules/malwareTriage';
import { containmentPlanner } from './modules/containmentPlanner';
import { irReport } from './modules/irReport';

const MODULE_NAME = 'ir-engine';

export interface IRPhaseResult {
  phase: string;
  result: IRModuleResult;
  duration: number;
}

export interface IRScanResult {
  caseId: string;
  caseData: IRCase;
  phaseResults: IRPhaseResult[];
  totalDuration: number;
  errors: string[];
}

const IR_PHASES = [
  { name: 'collection', module: evidenceCollector, run: evidenceCollector.run },
  { name: 'timeline', module: logTimeline, run: logTimeline.run },
  { name: 'ioc-extraction', module: iocExtractor, run: iocExtractor.run },
  { name: 'malware-triage', module: malwareTriage, run: malwareTriage.run },
  { name: 'containment-planning', module: containmentPlanner, run: containmentPlanner.run },
  { name: 'reporting', module: irReport, run: irReport.run },
] as const;

export async function runIRScan(context: IRScanContext): Promise<IRScanResult> {
  const startTime = Date.now();
  const phaseResults: IRPhaseResult[] = [];
  const errors: string[] = [];

  let caseData: Partial<IRCase> = {
    id: context.caseId,
    name: `IR Case ${context.caseId}`,
    description: `Incident response investigation for ${context.targetScope.join(', ')}`,
    status: 'investigating',
    severity: 'medium',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    assignedTo: ['ir-team'],
    evidence: [],
    timeline: [],
    iocs: [],
    containmentActions: [],
    findings: [],
    mitreCoverage: { covered: [], missing: [] },
  };

  logInfo(MODULE_NAME, `Starting IR scan for case ${context.caseId}`);

  for (const phase of IR_PHASES) {
    const phaseStart = Date.now();
    logInfo(MODULE_NAME, `Phase: ${phase.name}`);

    try {
      let result: IRModuleResult;

      if (phase.name === 'reporting') {
        result = await phase.run(context, caseData);
      } else {
        result = await phase.run(context);
      }

      // Aggregate results into caseData
      if (result.evidence) caseData.evidence!.push(...result.evidence);
      if (result.timelineEvents) caseData.timeline!.push(...result.timelineEvents);
      if (result.iocs) caseData.iocs!.push(...result.iocs);
      if (result.containmentActions) caseData.containmentActions!.push(...result.containmentActions);
      if (result.findings) caseData.findings!.push(...result.findings);

      caseData.updatedAt = Date.now();

      if (result.errors && result.errors.length > 0) {
        errors.push(...result.errors.map(e => `[${phase.name}] ${e}`));
      }

      const duration = Date.now() - phaseStart;
      phaseResults.push({ phase: phase.name, result, duration });
      logDone(MODULE_NAME, `Phase ${phase.name} completed in ${duration}ms`);

    } catch (e) {
      const errorMsg = `[${phase.name}] ${e}`;
      errors.push(errorMsg);
      logInfo(MODULE_NAME, `Phase ${phase.name} failed: ${e}`);
      phaseResults.push({ phase: phase.name, result: { errors: [errorMsg] }, duration: Date.now() - phaseStart });
    }
  }

  // Build MITRE coverage
  const allTechniques = new Set<string>();
  for (const event of caseData.timeline || []) {
    event.mitreTechniques.forEach(t => allTechniques.add(t));
  }
  for (const ioc of caseData.iocs || []) {
    ioc.mitreTechniques.forEach(t => allTechniques.add(t));
  }
  for (const finding of caseData.findings || []) {
    (finding.evidence?.mitre || []).forEach(t => allTechniques.add(t));
  }

  const MITRE_TECHNIQUES = [
    'T1078', 'T1078.001', 'T1078.002', 'T1078.003', 'T1078.004',
    'T1110', 'T1110.001', 'T1110.003', 'T1110.004',
    'T1059', 'T1059.001', 'T1059.003', 'T1059.005', 'T1059.006', 'T1059.007',
    'T1053', 'T1053.003', 'T1053.005',
    'T1021', 'T1021.001', 'T1021.002', 'T1021.003', 'T1021.004', 'T1021.005', 'T1021.006',
    'T1003', 'T1003.001', 'T1003.006',
    'T1555', 'T1555.003', 'T1556', 'T1556.002',
    'T1041', 'T1048', 'T1567', 'T1537',
    'T1486', 'T1490',
    'T1505', 'T1505.003', 'T1505.004',
    'T1547', 'T1543', 'T1137',
    'T1046', 'T1043', 'T1071', 'T1071.001', 'T1071.004',
    'T1070', 'T1070.001', 'T1027', 'T1082', 'T1083', 'T1016', 'T1018',
  ];

  const covered = Array.from(allTechniques);
  const missing = MITRE_TECHNIQUES.filter(t => !allTechniques.has(t));
  caseData.mitreCoverage = { covered, missing };

  // Determine final severity from findings
  const sevOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of sevOrder) {
    if ((caseData.findings || []).some(f => f.severity === sev)) {
      caseData.severity = sev;
      break;
    }
  }

  // Update case status based on progress
  if (caseData.containmentActions && caseData.containmentActions.length > 0) {
    caseData.status = 'contained';
  }

  const totalDuration = Date.now() - startTime;
  logDone(MODULE_NAME, `IR scan completed in ${totalDuration}ms. Phases: ${phaseResults.length}, Errors: ${errors.length}`);

  return {
    caseId: context.caseId,
    caseData: caseData as IRCase,
    phaseResults,
    totalDuration,
    errors,
  };
}

export async function runIRPhase(context: IRScanContext, phaseName: string): Promise<IRModuleResult> {
  const phase = IR_PHASES.find(p => p.name === phaseName);
  if (!phase) throw new Error(`Unknown IR phase: ${phaseName}`);

  logInfo(MODULE_NAME, `Running single IR phase: ${phaseName}`);
  if (phaseName === 'reporting') {
    return phase.run(context, {} as any);
  }
  return phase.run(context);
}

export function getIRPhases(): string[] {
  return IR_PHASES.map(p => p.name);
}

export interface IREngine {
  run: typeof runIRScan;
  runPhase: typeof runIRPhase;
  getPhases: typeof getIRPhases;
}

export const irEngine: IREngine = {
  run: runIRScan,
  runPhase: runIRPhase,
  getPhases: getIRPhases,
};
import { Finding, Severity, TargetType } from '../../types';
import { logInfo, logDone } from '../scanLogger';
import { getAI, AttackGraphContext, AttackGraph, ReasoningContext, ReasoningResult, AttackNode, AttackEdge, AttackPath, MitreCoverage, DetectedService, Credential, NetworkSegment } from '../../services/ai.service';

const MODULE_NAME = 'attackGraph';

export interface AttackGraphResult {
  attackGraph: AttackGraph;
  entryPoints: string[];
  criticalPaths: AttackPath[];
  mitreCoverage: MitreCoverage;
  newFindings: Finding[];
}

export async function runAttackGraph(domain: string, priorFindings: Finding[], targetType: TargetType, context: {
  techStack: string[];
  openPorts: number[];
  services: DetectedService[];
  credentials: Credential[];
  networkMap: NetworkSegment[];
  mitreTechniques: string[];
}): Promise<AttackGraphResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  logInfo(MODULE_NAME, `Building attack graph for ${domain} (${targetType})`);

  try {
    const ai = getAI();

    // Build attack graph context
    const graphContext: AttackGraphContext = {
      domain,
      targetType,
      target: { domain, targetType: targetType as any, ip: domain, openPorts: context.openPorts, services: context.services, techStack: context.techStack, osInfo: 'unknown', networkContext: context.networkMap },
      findings: priorFindings,
      techStack: context.techStack,
      openPorts: context.openPorts,
      services: context.services,
      credentials: context.credentials,
      networkMap: context.networkMap,
      mitreTechniques: context.mitreTechniques,
    };

    // Generate attack graph using AI
    const attackGraph = await ai.buildAttackGraph(graphContext);

    // Generate findings from attack graph
    // 1. Entry points
    for (const entryPoint of attackGraph.entryPoints) {
      findings.push(createFinding(
        `Attack Graph Entry Point: ${entryPoint}`,
        `Identified initial access vector: ${entryPoint}. This is a potential starting point for an attack chain.`,
        Severity.INFO,
        domain,
        'Entry points represent initial access opportunities. Prioritize testing these vectors.',
        'If exploited, attacker gains initial foothold in the environment.',
        'Validate this entry point with targeted testing.',
        []
      ));
    }

    // 2. Critical paths
    for (const path of attackGraph.criticalPaths.slice(0, 5)) {
      const impactSeverity = path.impact === 'critical' ? Severity.CRITICAL :
        path.impact === 'high' ? Severity.HIGH : Severity.MEDIUM;

      findings.push(createFinding(
        `Critical Attack Path: ${path.description}`,
        `Complete attack chain identified with ${path.totalProbability * 100}% probability: ${path.nodes.join(' → ')}.
MITRE Path: ${path.nodes.join(', ')}
Impact: ${path.impact}`,
        impactSeverity,
        domain,
        `This attack path combines ${path.nodes.length} techniques. Each step must be validated.
Test sequence: ${path.nodes.join(' → ')}`,
        `Successful execution leads to ${path.impact} impact. Full compromise path documented.`,
        'Test each step in sequence. Focus on the highest probability path first.',
        path.nodes
      ));
    }

    // 3. MITRE coverage gaps
    if (attackGraph.mitreCoverage.coveragePercent < 80) {
      findings.push(createFinding(
        `MITRE ATT&CK Coverage Gap: ${attackGraph.mitreCoverage.coveragePercent}%`,
        `Attack graph covers only ${attackGraph.mitreCoverage.coveragePercent}% of relevant MITRE ATT&CK techniques.
Missing techniques: ${attackGraph.mitreCoverage.missing.join(', ')}
These represent blind spots in the assessment.`,
        Severity.MEDIUM,
        domain,
        `Add testing for missing techniques: ${attackGraph.mitreCoverage.missing.join(', ')}`,
        `Missing ${attackGraph.mitreCoverage.missing.length} techniques means potential attack vectors are untested.`,
        'Run modules that cover missing MITRE techniques.',
        attackGraph.mitreCoverage.missing
      ));
    }

    // 4. Unexploited nodes
    const unexploitedNodes = attackGraph.nodes.filter(n => 
      n.confidence > 0.7 && !priorFindings.some(f => f.title.includes(n.title))
    );
    for (const node of unexploitedNodes.slice(0, 5)) {
      findings.push(createFinding(
        `Unexploited Attack Node: ${node.title}`,
        `Attack graph identifies ${node.title} (${node.technique}) as a viable step with ${node.confidence * 100}% confidence.
Prerequisites: ${node.prerequisites.join(', ') || 'none'}
Outcomes: ${node.outcomes.join(', ') || 'none'}
Evidence: ${node.evidence.join(', ') || 'none'}`,
        node.confidence > 0.9 ? Severity.HIGH : Severity.MEDIUM,
        domain,
        `Test this attack step using appropriate module. Prerequisites: ${node.prerequisites.join(', ') || 'none'}`,
        `If successful, enables: ${node.outcomes.join(', ') || 'further access'}`,
        'Validate with targeted testing. Monitor for expected outcomes.',
        [node.technique]
      ));
    }

    logDone(MODULE_NAME, `Attack graph built: ${attackGraph.nodes.length} nodes, ${attackGraph.edges.length} edges, ${attackGraph.criticalPaths.length} critical paths, ${attackGraph.mitreCoverage.coveragePercent}% MITRE coverage`, Date.now() - startTime);

    return {
      attackGraph,
      entryPoints: attackGraph.entryPoints,
      criticalPaths: attackGraph.criticalPaths,
      mitreCoverage: attackGraph.mitreCoverage,
      newFindings: findings,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    errors.push(msg);
    logInfo(MODULE_NAME, `Attack graph generation failed: ${msg}`);
    return {
      attackGraph: { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } },
      entryPoints: [],
      criticalPaths: [],
      mitreCoverage: { covered: [], missing: [], coveragePercent: 0 },
      newFindings: findings,
    };
  }
}

function createFinding(title: string, description: string, severity: Severity, domain: string, evidence: string, impact: string, remediation: string, references: string[]): Finding {
  return {
    id: `ag-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    title,
    description,
    severity,
    category: 'Attack Graph',
    affectedAsset: domain,
    evidence,
    impact,
    remediation,
    references,
    detectedAt: new Date(),
    confidence: 0.8,
  };
}

export async function runReasoningEngine(domain: string, currentFindings: Finding[], attackGraph: any, context: {
  targetType: TargetType;
  completedSteps: string[];
  availableCredentials: Credential[];
  networkAccess: NetworkSegment[];
  timeBudget: number;
  riskTolerance: 'low' | 'medium' | 'high';
}): Promise<ReasoningResult> {
  const ai = getAI();

  const reasoningContext: ReasoningContext = {
    domain,
    targetType: context.targetType,
    currentFindings,
    attackGraph,
    completedSteps: context.completedSteps,
    availableCredentials: context.availableCredentials,
    networkAccess: context.networkAccess,
    timeBudget: context.timeBudget,
    riskTolerance: context.riskTolerance,
  };

  return await ai.reasonNextSteps(reasoningContext);
}
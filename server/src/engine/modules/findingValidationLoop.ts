import { Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logVuln, logDone } from '../scanLogger';
import { getAI, ValidationContext, ValidationResult, RetestPlan, RetestResult, AttackGraph } from '../../services/ai.service';

const MODULE_NAME = 'findingValidationLoop';

// ─── FINDING VALIDATION LOOP MODULE ───────────────────────────────────────────
// Re-tests findings with different payloads/contexts to validate and enrich them
// Removes false positives, confirms true positives, and enriches evidence

export interface FindingValidationResult {
  validatedFindings: Finding[];
  removedFalsePositives: Finding[];
  enrichedFindings: Finding[];
  retestResults: RetestSummary[];
}

export interface RetestSummary {
  findingId: string;
  findingTitle: string;
  retestPlans: RetestPlan[];
  results: RetestResult[];
  finalStatus: 'confirmed' | 'refuted' | 'inconclusive';
  confidence: number;
}

export async function runFindingValidationLoop(domain: string, priorFindings: Finding[], attackGraph: AttackGraph | null): Promise<FindingValidationResult> {
  const startTime = Date.now();
  const validatedFindings: Finding[] = [];
  const removedFalsePositives: Finding[] = [];
  const enrichedFindings: Finding[] = [];
  const retestResults: RetestSummary[] = [];

  logInfo(MODULE_NAME, `Starting finding validation loop for ${domain} (${priorFindings.length} findings)`);

  try {
    const ai = getAI();

    // Focus on HIGH and CRITICAL findings first
    const highPriorityFindings = priorFindings.filter(f => 
      f.severity === 'CRITICAL' || f.severity === 'HIGH'
    );

    for (const finding of highPriorityFindings.slice(0, 10)) { // Limit to top 10
      logInfo(MODULE_NAME, `Validating finding: ${finding.title}`);

      // Build validation context
      const validationContext: ValidationContext = {
        finding,
        target: buildValidationTarget(domain, priorFindings),
        attackGraph: attackGraph || { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } },
        originalEvidence: finding.evidence,
      };

      // Get AI validation and retest plan
      const validationResult = await ai.validateFinding(finding, validationContext);

      // Execute retest plans
      const retestResultsForFinding: RetestResult[] = [];
      for (const plan of validationResult.recommendedRetest.slice(0, 3)) { // Limit retests
        const result = await executeRetestPlan(domain, plan);
        retestResultsForFinding.push(result);
      }

      // Determine final status
      const successfulRetests = retestResultsForFinding.filter(r => r.result === 'success').length;
      let finalStatus: 'confirmed' | 'refuted' | 'inconclusive';
      let finalConfidence: number;

      if (successfulRetests > 0) {
        finalStatus = 'confirmed';
        finalConfidence = Math.min(95, finding.confidence + successfulRetests * 15);
      } else if (retestResultsForFinding.length > 0 && retestResultsForFinding.every(r => r.result === 'failure')) {
        finalStatus = 'refuted';
        finalConfidence = Math.max(5, finding.confidence - 30);
      } else {
        finalStatus = 'inconclusive';
        finalConfidence = finding.confidence;
      }

      // Process based on final status
      if (finalStatus === 'confirmed') {
        // Enrich finding with retest evidence
        const enrichedFinding = enrichFindingWithRetest(finding, retestResultsForFinding, finalConfidence);
        enrichedFindings.push(enrichedFinding);
        validatedFindings.push(enrichedFinding);
        logVuln(MODULE_NAME, `CONFIRMED: ${finding.title} (confidence: ${finalConfidence}%)`, Severity.HIGH);
      } else if (finalStatus === 'refuted') {
        // Mark as false positive
        const falsePositiveFinding = {
          ...finding,
          severity: Severity.INFO,
          title: `FALSE POSITIVE: ${finding.title}`,
          description: `Originally reported as ${finding.severity}. Retesting failed to confirm. ${validationResult.falsePositiveIndicators.join(', ')}`,
          evidence: finding.evidence + '\n\nVALIDATION: Retesting failed. ' + retestResultsForFinding.map(r => `${r.plan.module}: ${r.output}`).join('; '),
          confidence: 10,
        };
        removedFalsePositives.push(falsePositiveFinding);
        logInfo(MODULE_NAME, `REFUTED (false positive): ${finding.title}`);
      } else {
        // Inconclusive - keep but mark
        const inconclusiveFinding = {
          ...finding,
          description: finding.description + '\n\nVALIDATION: Inconclusive - requires manual verification.',
          confidence: finalConfidence,
        };
        validatedFindings.push(inconclusiveFinding);
        logInfo(MODULE_NAME, `INCONCLUSIVE: ${finding.title}`);
      }

      retestResults.push({
        findingId: finding.id,
        findingTitle: finding.title,
        retestPlans: validationResult.recommendedRetest,
        results: retestResultsForFinding,
        finalStatus,
        confidence: finalConfidence,
      });
    }

    // Add MEDIUM findings that weren't tested
    const mediumFindings = priorFindings.filter(f => f.severity === 'MEDIUM');
    for (const finding of mediumFindings.slice(0, 5)) {
      validatedFindings.push(finding); // Pass through for now
    }

    // Add LOW/INFO findings
    const lowInfoFindings = priorFindings.filter(f => f.severity === 'LOW' || f.severity === 'INFO');
    for (const finding of lowInfoFindings) {
      validatedFindings.push(finding);
    }

    // Summary finding
    const summary = generateFinding(
      `Finding Validation Loop Summary`,
      `Validated ${highPriorityFindings.length} high-priority findings:
- Confirmed: ${retestResults.filter(r => r.finalStatus === 'confirmed').length}
- Refuted (False Positives): ${retestResults.filter(r => r.finalStatus === 'refuted').length}
- Inconclusive: ${retestResults.filter(r => r.finalStatus === 'inconclusive').length}

False positives removed: ${removedFalsePositives.length}
Findings enriched: ${enrichedFindings.length}`,
      Severity.INFO,
      'Finding Validation',
      domain,
      `Review refuted findings for potential false positive patterns.
Review inconclusive findings for manual verification.`,
      `Validation loop improves finding quality and reduces false positive rate.`,
      'Investigate refuted findings to improve scanner accuracy.',
      ['T1595']
    );

    logDone(MODULE_NAME, `Validation loop complete: ${retestResults.filter(r => r.finalStatus === 'confirmed').length} confirmed, ${retestResults.filter(r => r.finalStatus === 'refuted').length} refuted`, Date.now() - startTime);

    return {
      validatedFindings,
      removedFalsePositives,
      enrichedFindings,
      retestResults,
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logInfo(MODULE_NAME, `Validation loop failed: ${msg}`);
    // Return original findings on error
    return {
      validatedFindings: priorFindings,
      removedFalsePositives: [],
      enrichedFindings: [],
      retestResults: [],
    };
  }
}

function buildValidationTarget(domain: string, priorFindings: Finding[]): ValidationContext['target'] {
  const techStack = priorFindings
    .filter(f => f.category === 'Technology Detection')
    .flatMap(f => f.description.match(/Detected:?\s*(.+)/i)?.[1].split(',').map(s => s.trim()) || []);

  const openPorts = priorFindings
    .flatMap(f => f.affectedAsset?.match(/:(\d+)/)?.[1])
    .filter(Boolean)
    .map(Number);

  const services = priorFindings
    .filter(f => f.category === 'Port Scan' || f.category === 'Service Detection')
    .map(f => ({
      host: f.affectedAsset?.split(':')[0] || domain,
      port: parseInt(f.affectedAsset?.match(/:(\d+)/)?.[1] || '0'),
      protocol: 'tcp',
      service: f.description.match(/Service:\s*(\S+)/i)?.[1] || 'unknown',
      version: f.description.match(/Version:\s*(\S+)/i)?.[1],
      banner: f.evidence?.substring(0, 200),
    }));

  const targetType = priorFindings.some(f => f.category === 'Active Directory') ? 'activeDirectory' :
    priorFindings.some(f => f.category === 'Web Application') ? 'web' :
    priorFindings.some(f => f.category === 'Linux') ? 'linux' :
    priorFindings.some(f => f.category === 'Windows') ? 'windows' : 'network';

  return {
    domain,
    targetType: targetType as any,
    ip: domain,
    openPorts,
    services,
    techStack,
    osInfo: 'unknown',
    networkContext: [],
  };
}

async function executeRetestPlan(domain: string, plan: RetestPlan): Promise<RetestResult> {
  // In a real implementation, this would execute the actual module with the payload
  // For now, we simulate with a placeholder
  logInfo(MODULE_NAME, `Executing retest: ${plan.module} with payload: ${plan.payload}`);
  
  // Simulate execution - in real implementation, call the actual module
  // const result = await runModule(plan.module, domain, plan.payload, plan.context);
  
  // Placeholder result
  return {
    plan,
    result: 'inconclusive', // Would be actual result
    output: `Simulated retest for ${plan.module}`,
    evidence: `Retest executed: ${plan.module} with payload ${plan.payload}`,
    timestamp: Date.now(),
  };
}

function enrichFindingWithRetest(finding: Finding, retestResults: RetestResult[], newConfidence: number): Finding {
  let newEvidence = finding.evidence;
  
  for (const result of retestResults) {
    if (result.result === 'success') {
      newEvidence += `\n\nRETEST CONFIRMATION (${result.plan.module}):
Payload: ${result.plan.payload}
Context: ${result.plan.context}
Output: ${result.output}
Evidence: ${result.evidence}`;
    }
  }
  
  return {
    ...finding,
    evidence: newEvidence,
    confidence: newConfidence,
    cvssScore: finding.cvssScore,
  };
}

export async function runBatchValidation(domain: string, findings: Finding[], attackGraph: AttackGraph | null, maxConcurrent: number = 3): Promise<FindingValidationResult> {
  // Process in batches for efficiency
  const highPriority = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const results: FindingValidationResult = {
    validatedFindings: [],
    removedFalsePositives: [],
    enrichedFindings: [],
    retestResults: [],
  };

  for (let i = 0; i < highPriority.length; i += maxConcurrent) {
    const batch = highPriority.slice(i, i + maxConcurrent);
    const batchResults = await Promise.all(
      batch.map(f => validateSingleFinding(domain, f, attackGraph))
    );

    for (const r of batchResults) {
      results.validatedFindings.push(...r.validatedFindings);
      results.removedFalsePositives.push(...r.removedFalsePositives);
      results.enrichedFindings.push(...r.enrichedFindings);
      results.retestResults.push(...r.retestResults);
    }
  }

  // Add remaining findings
  const otherFindings = findings.filter(f => f.severity !== 'CRITICAL' && f.severity !== 'HIGH');
  results.validatedFindings.push(...otherFindings);

  return results;
}

async function validateSingleFinding(domain: string, finding: Finding, attackGraph: AttackGraph | null): Promise<FindingValidationResult> {
  const ai = getAI();
  const validationContext = {
    finding,
    target: buildValidationTarget(domain, [finding]),
    attackGraph: attackGraph || { nodes: [], edges: [], entryPoints: [], criticalPaths: [], mitreCoverage: { covered: [], missing: [], coveragePercent: 0 } },
    originalEvidence: finding.evidence,
  };

  const validationResult = await ai.validateFinding(finding, validationContext);
  
  const retestResultsForFinding: RetestResult[] = [];
  for (const plan of validationResult.recommendedRetest.slice(0, 2)) {
    const result = await executeRetestPlan(domain, plan);
    retestResultsForFinding.push(result);
  }

  const successfulRetests = retestResultsForFinding.filter(r => r.result === 'success').length;
  let finalStatus: 'confirmed' | 'refuted' | 'inconclusive';
  let finalConfidence: number;

  if (successfulRetests > 0) {
    finalStatus = 'confirmed';
    finalConfidence = Math.min(95, finding.confidence + successfulRetests * 15);
  } else if (retestResultsForFinding.length > 0 && retestResultsForFinding.every(r => r.result === 'failure')) {
    finalStatus = 'refuted';
    finalConfidence = Math.max(5, finding.confidence - 30);
  } else {
    finalStatus = 'inconclusive';
    finalConfidence = finding.confidence;
  }

  if (finalStatus === 'confirmed') {
    const enriched = enrichFindingWithRetest(finding, retestResultsForFinding, finalConfidence);
    return {
      validatedFindings: [enriched],
      removedFalsePositives: [],
      enrichedFindings: [enriched],
      retestResults: [{
        findingId: finding.id,
        findingTitle: finding.title,
        retestPlans: validationResult.recommendedRetest,
        results: retestResultsForFinding,
        finalStatus,
        confidence: finalConfidence,
      }],
    };
  } else if (finalStatus === 'refuted') {
    const falsePositive = {
      ...finding,
      severity: Severity.INFO,
      title: `FALSE POSITIVE: ${finding.title}`,
      description: `Retesting failed to confirm. ${validationResult.falsePositiveIndicators.join(', ')}`,
      confidence: 10,
    };
    return {
      validatedFindings: [],
      removedFalsePositives: [falsePositive],
      enrichedFindings: [],
      retestResults: [{
        findingId: finding.id,
        findingTitle: finding.title,
        retestPlans: validationResult.recommendedRetest,
        results: retestResultsForFinding,
        finalStatus,
        confidence: finalConfidence,
      }],
    };
  }

  return {
    validatedFindings: [{ ...finding, confidence: finalConfidence }],
    removedFalsePositives: [],
    enrichedFindings: [],
    retestResults: [{
      findingId: finding.id,
      findingTitle: finding.title,
      retestPlans: validationResult.recommendedRetest,
      results: retestResultsForFinding,
      finalStatus,
      confidence: finalConfidence,
    }],
  };
}
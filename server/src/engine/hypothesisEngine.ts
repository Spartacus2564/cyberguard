// ═══════════════════════════════════════════════════════════════════════════════
// HYPOTHESIS ENGINE — AI-driven test → observe → refine reasoning loop
// ═══════════════════════════════════════════════════════════════════════════════
// Inspired by Horizon3.ai NodeZero's autonomous reasoning:
//   1. OBSERVE: Analyze recon findings
//   2. HYPOTHESIZE: Generate testable hypotheses about vulnerabilities
//   3. TEST: Execute targeted scans to validate hypotheses
//   4. OBSERVE: Analyze test results
//   5. REFINE: Update knowledge, generate new hypotheses
//   6. REPEAT until confidence threshold or max iterations
// ═══════════════════════════════════════════════════════════════════════════════

import { HypothesisStatus } from '@prisma/client';
import { config } from '../config';
import { executeTool, parseToolOutput } from '../tools/executor';
import { getToolRegistry } from '../tools/registry';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Hypothesis {
  id?: string;
  statement: string;
  rationale: string;
  category: string;          // 'vulnerability', 'misconfiguration', 'exposure', 'credential', 'chain'
  priority: number;          // 1-10 (10 = highest)
  confidence: number;        // 0.0 - 1.0
  status: HypothesisStatus;
  toolsToTest: string[];     // Tool names to validate this hypothesis
  testPlan: string;          // Description of how to test
  testResults?: TestResult[];
  findings?: any[];
}

export interface TestResult {
  tool: string;
  target: string;
  success: boolean;
  findingsCount: number;
  hypothesisSupported: boolean;
  evidence: string;
  duration: number;
}

export interface ReasoningCycle {
  cycleNumber: number;
  hypothesesGenerated: number;
  hypothesesConfirmed: number;
  hypothesesRefuted: number;
  findingsDiscovered: number;
  toolsExecuted: number;
  duration: number;
}

export interface ReasoningResult {
  cycles: ReasoningCycle[];
  totalHypotheses: number;
  confirmedHypotheses: number;
  totalFindings: number;
  confidence: number;
  knowledgeSummary: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_CYCLES = 5;
const CONFIDENCE_THRESHOLD = 0.85;
const MAX_HYPOTHESES_PER_CYCLE = 8;
const MIN_PRIORITY = 5;

// --- Direct Ollama call for hypothesis generation ---

async function ollamaChat(prompt: string, options: { temperature?: number; maxTokens?: number } = {}): Promise<string> {
  try {
    const ollamaUrl = config.ollamaBaseUrl || 'http://localhost:11434';
    const response = await fetch(ollamaUrl + '/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: config.securityModel || 'dolphin3:8b',
        prompt,
        stream: false,
        options: {
          temperature: options.temperature || 0.7,
          num_predict: options.maxTokens || 2000,
        },
      }),
    });

    if (!response.ok) {
      throw new Error('Ollama responded with ' + response.status);
    }

    const data = await response.json();
    return data.response || '';
  } catch (e) {
    logger.error('[Hypothesis] Ollama call failed: ' + e);
    return '';
  }
}

// ─── Hypothesis Generation ───────────────────────────────────────────────────

async function generateHypotheses(
  engagementId: string,
  domain: string,
  currentFindings: any[],
  knowledge: string,
  cycleNumber: number,
): Promise<Hypothesis[]> {
  const context = 'Target: ' + domain + '\nCycle: ' + cycleNumber + '\nCurrent findings: ' + currentFindings.length + '\nKnowledge so far: ' + (knowledge || 'None') + '\n\nPrevious findings:\n' + currentFindings.slice(-20).map(function(f: any) { return '- [' + f.severity + '] ' + f.title + ': ' + f.affectedAsset; }).join('\n');

  const prompt = 'You are an autonomous penetration tester analyzing ' + domain + '.\n\nBased on the current intelligence, generate TESTABLE HYPOTHESES about potential security issues.\nEach hypothesis should be specific, testable, and actionable.\n\nContext:\n' + context + '\n\nGenerate up to ' + MAX_HYPOTHESES_PER_CYCLE + ' hypotheses as a JSON array.\nEach hypothesis object must have:\n- statement: Clear testable statement\n- rationale: Why this hypothesis is plausible\n- category: One of: vulnerability, misconfiguration, exposure, credential, chain\n- priority: 1-10 (10 = most critical)\n- toolsToTest: Array of tool names (e.g., ["nmap", "nuclei", "nikto"])\n- testPlan: Brief description of how to test\n\nFocus on: RCE, SQLi, auth bypass, misconfigurations, credential weaknesses, attack chains.\n\nRespond with ONLY a valid JSON array. No markdown, no explanation.';

  try {
    const response = await ollamaChat(prompt, { temperature: 0.7, maxTokens: 2000 });

    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      logger.warn('[Hypothesis] AI response was not valid JSON');
      return [];
    }

    const parsed = JSON.parse(jsonMatch[0]);
    const hypotheses: Hypothesis[] = parsed.map(function(h: any) {
      return {
        statement: h.statement || 'Unknown hypothesis',
        rationale: h.rationale || '',
        category: h.category || 'vulnerability',
        priority: Math.min(10, Math.max(1, h.priority || 5)),
        confidence: 0.3,
        status: 'PROPOSED' as HypothesisStatus,
        toolsToTest: h.toolsToTest || ['nuclei'],
        testPlan: h.testPlan || 'Run automated scan',
      };
    });

    logger.info('[Hypothesis] Generated ' + hypotheses.length + ' hypotheses for cycle ' + cycleNumber);
    return hypotheses.slice(0, MAX_HYPOTHESES_PER_CYCLE);
  } catch (e) {
    logger.error('[Hypothesis] Failed to generate hypotheses: ' + e);
    return [];
  }
}

// ─── Hypothesis Testing ──────────────────────────────────────────────────────

async function testHypothesis(
  hypothesis: Hypothesis,
  domain: string,
  engagementId?: string,
): Promise<Hypothesis> {
  const registry = await getToolRegistry();
  const results: TestResult[] = [];

  logger.info(`[Hypothesis] Testing: "${hypothesis.statement}"`);

  for (const toolName of hypothesis.toolsToTest) {
    const tool = registry.getTool(toolName);
    if (!tool || !tool.installed) {
      logger.warn(`[Hypothesis] Tool ${toolName} not available, skipping`);
      continue;
    }

    try {
      const output = await executeTool(toolName, {
        target: domain,
        timeout: tool.timeout,
      }, {
        engagementId,
      });

      const findings = await parseToolOutput(output);
      const hypothesisSupported = findings.length > 0;

      results.push({
        tool: toolName,
        target: domain,
        success: output.success,
        findingsCount: findings.length,
        hypothesisSupported,
        evidence: output.stdout.substring(0, 2000),
        duration: output.duration,
      });

      // Store findings for this hypothesis
      if (!hypothesis.findings) hypothesis.findings = [];
      hypothesis.findings.push(...findings);

    } catch (e) {
      logger.warn(`[Hypothesis] Tool ${toolName} failed: ${e}`);
      results.push({
        tool: toolName,
        target: domain,
        success: false,
        findingsCount: 0,
        hypothesisSupported: false,
        evidence: `Error: ${e}`,
        duration: 0,
      });
    }
  }

  hypothesis.testResults = results;

  // Update confidence based on test results
  const supportedCount = results.filter(r => r.hypothesisSupported).length;
  const totalTests = results.length;

  if (totalTests > 0) {
    const supportRatio = supportedCount / totalTests;
    hypothesis.confidence = supportRatio;
    hypothesis.status = supportRatio >= 0.5 ? 'CONFIRMED' : 'REFUTED';
  } else {
    hypothesis.status = 'ABANDONED';
  }

  logger.info(`[Hypothesis] Result: "${hypothesis.statement}" → ${hypothesis.status} (confidence: ${hypothesis.confidence.toFixed(2)})`);
  return hypothesis;
}

// ─── Knowledge Update ────────────────────────────────────────────────────────

function updateKnowledge(
  currentKnowledge: string,
  hypotheses: Hypothesis[],
): string {
  const lines: string[] = [];

  for (const h of hypotheses) {
    if (h.status === 'CONFIRMED') {
      lines.push('[CONFIRMED] ' + h.statement);
      if (h.testResults) {
        for (const r of h.testResults) {
          if (r.hypothesisSupported) {
            lines.push('  Evidence: ' + r.tool + ' found ' + r.findingsCount + ' finding(s)');
          }
        }
      }
    } else if (h.status === 'REFUTED') {
      lines.push('[REFUTED] ' + h.statement);
    }
  }

  return currentKnowledge ? currentKnowledge + '\n' + lines.join('\n') : lines.join('\n');
}

// ─── Main Reasoning Loop ─────────────────────────────────────────────────────

export async function runReasoningLoop(
  engagementId: string,
  domain: string,
  initialFindings: any[],
  onCycle?: (cycle: ReasoningCycle) => void,
): Promise<ReasoningResult> {
  const startTime = Date.now();
  const cycles: ReasoningCycle[] = [];
  let allFindings = [...initialFindings];
  let knowledge = '';
  let totalHypotheses = 0;
  let confirmedHypotheses = 0;
  let toolsExecuted = 0;

  logger.info('[Hypothesis] Starting reasoning loop for ' + domain + ' - ' + initialFindings.length + ' initial findings');

  for (let cycle = 1; cycle <= MAX_CYCLES; cycle++) {
    const cycleStart = Date.now();
    logger.info('[Hypothesis] === Cycle ' + cycle + '/' + MAX_CYCLES + ' ===');

    // 1. Generate hypotheses
    const hypotheses = await generateHypotheses(engagementId, domain, allFindings, knowledge, cycle);
    if (hypotheses.length === 0) {
      logger.info('[Hypothesis] No hypotheses generated, stopping loop');
      break;
    }

    totalHypotheses += hypotheses.length;

    // 2. Test hypotheses (in parallel, max 3 at a time)
    const testedHypotheses: Hypothesis[] = [];
    for (let i = 0; i < hypotheses.length; i += 3) {
      const batch = hypotheses.slice(i, i + 3);
      const results = await Promise.allSettled(
        batch.map(function(h) { return testHypothesis(h, domain, engagementId); })
      );
      for (const r of results) {
        if (r.status === 'fulfilled') {
          testedHypotheses.push(r.value);
        }
      }
    }

    toolsExecuted += testedHypotheses.reduce(function(sum, h) {
      return sum + (h.testResults ? h.testResults.length : 0);
    }, 0);

    // 3. Update knowledge
    knowledge = updateKnowledge(knowledge, testedHypotheses);

    // 4. Collect new findings
    const newFindings = testedHypotheses
      .filter(function(h) { return h.status === 'CONFIRMED'; })
      .reduce(function(acc: any[], h) { return acc.concat(h.findings || []); }, []);

    allFindings = allFindings.concat(newFindings);
    confirmedHypotheses += testedHypotheses.filter(function(h) { return h.status === 'CONFIRMED'; }).length;

    const cycleDuration = Date.now() - cycleStart;
    const cycleResult: ReasoningCycle = {
      cycleNumber: cycle,
      hypothesesGenerated: hypotheses.length,
      hypothesesConfirmed: testedHypotheses.filter(function(h) { return h.status === 'CONFIRMED'; }).length,
      hypothesesRefuted: testedHypotheses.filter(function(h) { return h.status === 'REFUTED'; }).length,
      findingsDiscovered: newFindings.length,
      toolsExecuted: testedHypotheses.reduce(function(sum, h) { return sum + (h.testResults ? h.testResults.length : 0); }, 0),
      duration: cycleDuration,
    };

    cycles.push(cycleResult);
    if (onCycle) onCycle(cycleResult);

    logger.info('[Hypothesis] Cycle ' + cycle + ' complete: ' + cycleResult.hypothesesConfirmed + ' confirmed, ' + cycleResult.findingsDiscovered + ' new findings (' + (cycleDuration / 1000).toFixed(1) + 's)');

    // 5. Check termination conditions
    const overallConfidence = confirmedHypotheses / Math.max(totalHypotheses, 1);
    if (overallConfidence >= CONFIDENCE_THRESHOLD) {
      logger.info('[Hypothesis] Confidence threshold reached (' + overallConfidence.toFixed(2) + '), stopping loop');
      break;
    }

    if (cycle < MAX_CYCLES) {
      await new Promise(function(resolve) { setTimeout(resolve, 1000); });
    }
  }

  const totalDuration = Date.now() - startTime;
  const finalConfidence = totalHypotheses > 0 ? confirmedHypotheses / totalHypotheses : 0;

  logger.info('[Hypothesis] Reasoning loop complete: ' + cycles.length + ' cycles, ' + totalHypotheses + ' hypotheses, ' + confirmedHypotheses + ' confirmed, ' + allFindings.length + ' total findings');

  return {
    cycles,
    totalHypotheses,
    confirmedHypotheses,
    totalFindings: allFindings.length,
    confidence: finalConfidence,
    knowledgeSummary: knowledge,
  };
}

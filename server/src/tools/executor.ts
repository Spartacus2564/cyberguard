// ═══════════════════════════════════════════════════════════════════════════════
// TOOL EXECUTOR — Safe execution with scope enforcement, timeout, and audit
// ═══════════════════════════════════════════════════════════════════════════════

import { exec } from 'child_process';
import { promisify } from 'util';
import { v4 as uuid } from 'uuid';
import { ToolInput, ToolOutput, ToolEvidence, ToolExecutionRecord, NormalizedFinding } from './types';
import { getToolRegistry } from './registry';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

const execAsync = promisify(exec);

// ─── Scope Validation ────────────────────────────────────────────────────────
// Validates that a target is within the engagement's authorized scope.

export interface ScopeRule {
  type: 'allow' | 'deny';
  targetType: 'domain' | 'cidr' | 'ip' | 'url' | 'regex';
  value: string;
}

function ipToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isInCIDR(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const ipLong = ipToLong(ip);
  const networkLong = ipToLong(network);
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipLong & mask) === (networkLong & mask);
}

function matchesDomain(target: string, rule: string): boolean {
  const lower = target.toLowerCase();
  const ruleLower = rule.toLowerCase();
  return lower === ruleLower || lower.endsWith('.' + ruleLower);
}

function matchesRule(target: string, rule: ScopeRule): boolean {
  switch (rule.targetType) {
    case 'domain':
      return matchesDomain(target, rule.value);
    case 'cidr':
      try {
        return isInCIDR(target, rule.value);
      } catch {
        return false;
      }
    case 'ip':
      return target === rule.value;
    case 'url':
      try {
        const url = new URL(rule.value);
        return target.includes(url.hostname);
      } catch {
        return target.includes(rule.value);
      }
    case 'regex':
      try {
        return new RegExp(rule.value, 'i').test(target);
      } catch {
        return false;
      }
    default:
      return false;
  }
}

export function isTargetInScope(target: string, rules: ScopeRule[]): boolean {
  // Check deny rules first (deny takes precedence)
  const denyRules = rules.filter(r => r.type === 'deny');
  for (const rule of denyRules) {
    if (matchesRule(target, rule)) {
      logger.info(`[Scope] Target "${target}" DENIED by rule: ${rule.targetType}=${rule.value}`);
      return false;
    }
  }

  // Check allow rules
  const allowRules = rules.filter(r => r.type === 'allow');
  if (allowRules.length === 0) {
    // No allow rules = everything is allowed (legacy mode)
    return true;
  }

  for (const rule of allowRules) {
    if (matchesRule(target, rule)) {
      return true;
    }
  }

  logger.warn(`[Scope] Target "${target}" NOT in scope (no matching allow rule)`);
  return false;
}

// ─── Command Builder ─────────────────────────────────────────────────────────

function buildCommand(binary: string, target: string, args: string[]): string {
  // Safety: quote the target to prevent injection
  const safeTarget = target.replace(/[^a-zA-Z0-9.\-:\/\@]/g, '');
  return `${binary} ${args.join(' ')} ${safeTarget}`;
}

// ─── Executor ────────────────────────────────────────────────────────────────

export interface ExecuteOptions {
  engagementId?: string;
  scopeRules?: ScopeRule[];
  onProgress?: (message: string) => void;
}

export async function executeTool(
  toolName: string,
  input: ToolInput,
  options: ExecuteOptions = {},
): Promise<ToolOutput> {
  const startTime = Date.now();
  const registry = await getToolRegistry();
  const tool = registry.getTool(toolName);

  if (!tool) {
    return {
      tool: toolName,
      target: input.target,
      success: false,
      exitCode: -1,
      stdout: '',
      stderr: `Tool "${toolName}" not found in registry`,
      duration: 0,
      findings: [],
      rawFindings: [],
      evidence: [],
      error: `Tool "${toolName}" not registered`,
    };
  }

  if (!tool.installed) {
    return {
      tool: toolName,
      target: input.target,
      success: false,
      exitCode: -1,
      stdout: '',
      stderr: `Tool "${toolName}" is not installed`,
      duration: 0,
      findings: [],
      rawFindings: [],
      evidence: [],
      error: `Tool "${toolName}" not installed`,
    };
  }

  // Scope validation
  if (options.scopeRules && options.scopeRules.length > 0) {
    if (!isTargetInScope(input.target, options.scopeRules)) {
      return {
        tool: toolName,
        target: input.target,
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: `Target "${input.target}" is not in scope`,
        duration: 0,
        findings: [],
        rawFindings: [],
        evidence: [],
        error: `Scope violation: target "${input.target}" not authorized`,
      };
    }
  }

  // Build command
  const args = [...tool.defaultArgs, ...(input.args || [])];
  const command = buildCommand(tool.binary, input.target, args);
  const timeout = input.timeout || tool.timeout;
  const executionId = uuid();

  logger.info(`[ToolExec] ${toolName} → ${input.target} (timeout: ${timeout}ms)`);
  options.onProgress?.(`Executing ${tool.displayName}...`);

  // Record execution start
  let executionRecord: { id: string } | null = null;
  if (options.engagementId) {
    try {
      const record = await prisma.toolExecution.create({
        data: {
          engagementId: options.engagementId,
          toolName,
          category: tool.category,
          command,
          target: input.target,
          status: 'running',
          startedAt: new Date(),
        },
      });
      executionRecord = record;
    } catch (e) {
      logger.warn(`[ToolExec] Failed to record execution: ${e}`);
    }
  }

  // Execute
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let error: string | undefined;

  try {
    const result = await execAsync(command, {
      timeout,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      env: { ...process.env, ...input.env },
    });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (e: any) {
    exitCode = e.code || 1;
    stdout = e.stdout || '';
    stderr = e.stderr || e.message || String(e);
    error = e.message;

    if (e.killed || e.signal === 'SIGTERM') {
      error = `Tool timed out after ${timeout}ms`;
      logger.warn(`[ToolExec] ${toolName} timed out on ${input.target}`);
    } else {
      logger.error(`[ToolExec] ${toolName} failed on ${input.target}: ${error}`);
    }
  }

  const duration = Date.now() - startTime;
  const success = exitCode === 0 || (stdout.length > 0 && exitCode < 10);

  // Collect evidence
  const evidence: ToolEvidence[] = [];
  if (stdout.trim()) {
    evidence.push({
      type: 'command_output',
      title: `${tool.displayName} output`,
      content: stdout.substring(0, 50000),
      contentType: 'text/plain',
      metadata: { command, exitCode, duration },
    });
  }

  const output: ToolOutput = {
    tool: toolName,
    target: input.target,
    success,
    exitCode,
    stdout,
    stderr,
    duration,
    findings: [],  // To be populated by parser
    rawFindings: [],
    evidence,
    error,
  };

  // Update execution record
  if (executionRecord && options.engagementId) {
    try {
      await prisma.toolExecution.update({
        where: { id: executionRecord.id },
        data: {
          status: success ? 'completed' : (error?.includes('timed out') ? 'timeout' : 'failed'),
          exitCode,
          stdout: stdout.substring(0, 50000),
          stderr: stderr.substring(0, 10000),
          findingsCount: output.findings.length,
          durationMs: duration,
          completedAt: new Date(),
          error: error || null,
        },
      });
    } catch (e) {
      logger.warn(`[ToolExec] Failed to update execution record: ${e}`);
    }
  }

  logger.info(`[ToolExec] ${toolName} → ${input.target} completed in ${(duration / 1000).toFixed(1)}s (exit: ${exitCode}, findings: ${output.findings.length})`);
  return output;
}

// ─── Batch Execution ─────────────────────────────────────────────────────────

export async function executeToolsBatch(
  executions: { toolName: string; input: ToolInput }[],
  options: ExecuteOptions = {},
): Promise<ToolOutput[]> {
  const registry = await getToolRegistry();
  const results: ToolOutput[] = [];

  // Group by tool to respect maxConcurrent limits
  const grouped = new Map<string, typeof executions>();
  for (const exec of executions) {
    const existing = grouped.get(exec.toolName) || [];
    existing.push(exec);
    grouped.set(exec.toolName, existing);
  }

  for (const [toolName, toolExecs] of grouped) {
    const tool = registry.getTool(toolName);
    const concurrency = tool?.maxConcurrent || 1;

    // Execute in batches respecting concurrency
    for (let i = 0; i < toolExecs.length; i += concurrency) {
      const batch = toolExecs.slice(i, i + concurrency);
      const batchResults = await Promise.allSettled(
        batch.map(e => executeTool(e.toolName, e.input, options))
      );

      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          results.push({
            tool: toolName,
            target: '',
            success: false,
            exitCode: -1,
            stdout: '',
            stderr: result.reason?.message || 'Execution failed',
            duration: 0,
            findings: [],
            rawFindings: [],
            evidence: [],
            error: result.reason?.message,
          });
        }
      }
    }
  }

  return results;
}

// ─── Tool Output Parsers ─────────────────────────────────────────────────────

export async function parseToolOutput(output: ToolOutput): Promise<NormalizedFinding[]> {
  const { default: parseNmap } = await import('./parsers/nmap');
  const { default: parseNuclei } = await import('./parsers/nuclei');

  switch (output.tool) {
    case 'nmap':
      return parseNmap(output);
    case 'nuclei':
      return parseNuclei(output);
    // Other parsers will be added as tools are integrated
    default:
      // For unregistered parsers, return findings only if the tool found something
      return [];
  }
}

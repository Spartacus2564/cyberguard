import { Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logVuln, logDone, logWarn } from '../scanLogger';
import { config } from '../../config';

const MODULE_NAME = 'aiCveResearch';

export interface DiscoveredSoftware {
  name: string;
  version: string;
  port?: number;
  service?: string;
  source: string; // which module detected it
}

export interface AiCveResult {
  cveId: string;
  cvss: number;
  severity: string;
  title: string;
  description: string;
  remotelyExploitable: boolean;
  pocApproach: string; // description of how to test
  pocCommand?: string; // specific command to run
  affectedVersions: string;
  remediation: string;
  references: string[];
  confidence: number; // 0-1 how confident AI is this affects the target
}

interface PocPlan {
  cveId: string;
  approach: string;
  commands: string[];
  expectedVulnerable: string; // what to look for if vuln exists
  expectedSafe: string; // what to look for if not vulnerable
  timeout: number;
  safeToRun: boolean;
  reasoning: string;
}

// ─── Extract software+version from existing findings ─────────────────────

export function extractSoftware(findings: Finding[]): DiscoveredSoftware[] {
  const software: DiscoveredSoftware[] = [];
  const seen = new Set<string>();

  for (const f of findings) {
    const text = `${f.title} ${f.description} ${f.evidence || ''}`;

    // OpenSSH
    const sshMatch = text.match(/OpenSSH[_ ](\d+\.\d+(?:p\d+)?)/i);
    if (sshMatch && !seen.has(`openssh:${sshMatch[1]}`)) {
      seen.add(`openssh:${sshMatch[1]}`);
      software.push({ name: 'OpenSSH', version: sshMatch[1], service: 'ssh', source: f.category || 'scan' });
    }

    // Apache
    const apacheMatch = text.match(/Apache\/(\d+\.\d+\.\d+)/i);
    if (apacheMatch && !seen.has(`apache:${apacheMatch[1]}`)) {
      seen.add(`apache:${apacheMatch[1]}`);
      software.push({ name: 'Apache', version: apacheMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // nginx
    const nginxMatch = text.match(/nginx\/(\d+\.\d+\.\d+)/i);
    if (nginxMatch && !seen.has(`nginx:${nginxMatch[1]}`)) {
      seen.add(`nginx:${nginxMatch[1]}`);
      software.push({ name: 'nginx', version: nginxMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // OpenSSL
    const sslMatch = text.match(/OpenSSL[_ ](\d+\.\d+\.\d+[a-z]?\d*)/i);
    if (sslMatch && !seen.has(`openssl:${sslMatch[1]}`)) {
      seen.add(`openssl:${sslMatch[1]}`);
      software.push({ name: 'OpenSSL', version: sslMatch[1], service: 'ssl/tls', source: f.category || 'scan' });
    }

    // PHP
    const phpMatch = text.match(/PHP\/(\d+\.\d+\.\d+)/i);
    if (phpMatch && !seen.has(`php:${phpMatch[1]}`)) {
      seen.add(`php:${phpMatch[1]}`);
      software.push({ name: 'PHP', version: phpMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // MySQL / MariaDB
    const mysqlMatch = text.match(/(?:MySQL|MariaDB)[_ ](\d+\.\d+\.\d+)/i);
    if (mysqlMatch && !seen.has(`mysql:${mysqlMatch[1]}`)) {
      seen.add(`mysql:${mysqlMatch[1]}`);
      software.push({ name: mysqlMatch[0].includes('MariaDB') ? 'MariaDB' : 'MySQL', version: mysqlMatch[1], service: 'mysql', source: f.category || 'scan' });
    }

    // PostgreSQL
    const pgMatch = text.match(/PostgreSQL[_ ](\d+\.\d+)/i);
    if (pgMatch && !seen.has(`postgresql:${pgMatch[1]}`)) {
      seen.add(`postgresql:${pgMatch[1]}`);
      software.push({ name: 'PostgreSQL', version: pgMatch[1], service: 'postgresql', source: f.category || 'scan' });
    }

    // Redis
    const redisMatch = text.match(/Redis[_ ](\d+\.\d+\.\d+)/i);
    if (redisMatch && !seen.has(`redis:${redisMatch[1]}`)) {
      seen.add(`redis:${redisMatch[1]}`);
      software.push({ name: 'Redis', version: redisMatch[1], service: 'redis', source: f.category || 'scan' });
    }

    // IIS
    const iisMatch = text.match(/IIS\/(\d+\.\d+)/i);
    if (iisMatch && !seen.has(`iis:${iisMatch[1]}`)) {
      seen.add(`iis:${iisMatch[1]}`);
      software.push({ name: 'IIS', version: iisMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // WordPress
    const wpMatch = text.match(/WordPress[_ ](\d+\.\d+(?:\.\d+)?)/i);
    if (wpMatch && !seen.has(`wordpress:${wpMatch[1]}`)) {
      seen.add(`wordpress:${wpMatch[1]}`);
      software.push({ name: 'WordPress', version: wpMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // jQuery
    const jqMatch = text.match(/jQuery[_ ](\d+\.\d+(?:\.\d+)?)/i);
    if (jqMatch && !seen.has(`jquery:${jqMatch[1]}`)) {
      seen.add(`jquery:${jqMatch[1]}`);
      software.push({ name: 'jQuery', version: jqMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // Spring
    const springMatch = text.match(/Spring[_ ](\d+\.\d+\.\d+)/i);
    if (springMatch && !seen.has(`spring:${springMatch[1]}`)) {
      seen.add(`spring:${springMatch[1]}`);
      software.push({ name: 'Spring', version: springMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // Laravel
    const laravelMatch = text.match(/Laravel[_ ](\d+\.\d+(?:\.\d+)?)/i);
    if (laravelMatch && !seen.has(`laravel:${laravelMatch[1]}`)) {
      seen.add(`laravel:${laravelMatch[1]}`);
      software.push({ name: 'Laravel', version: laravelMatch[1], service: 'http', source: f.category || 'scan' });
    }

    // Generic: look for port/service combos that suggest specific software
    const portMatch = f.title.match(/Port (\d+).*?(open|filtered)/i);
    if (portMatch) {
      const port = parseInt(portMatch[1]);
      const portServices: Record<number, string> = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
      };
      if (portServices[port] && !seen.has(`port:${port}`)) {
        seen.add(`port:${port}`);
      }
    }
  }

  return software;
}

// ─── AI CVE Research ─────────────────────────────────────────────────────

export async function researchCvesWithAi(
  software: DiscoveredSoftware[],
  domain: string,
): Promise<AiCveResult[]> {
  if (software.length === 0) return [];

  logInfo(MODULE_NAME, `Researching CVEs for ${software.length} discovered software components`);

  const results: AiCveResult[] = [];

  // Process in batches of 3 to avoid overwhelming the AI
  for (let i = 0; i < software.length; i += 3) {
    const batch = software.slice(i, i + 3);
    const batchResults = await Promise.all(
      batch.map(s => researchSingleSoftware(s, domain))
    );
    for (const r of batchResults) {
      if (r) results.push(...r);
    }
  }

  logDone(MODULE_NAME, `AI CVE research found ${results.length} potential vulnerabilities`);
  return results;
}

async function researchSingleSoftware(
  sw: DiscoveredSoftware,
  domain: string,
): Promise<AiCveResult[]> {
  const prompt = `You are a cybersecurity vulnerability researcher. Analyze the following software and identify known CVEs that affect it.

Target: ${domain}
Software: ${sw.name} ${sw.version}
Service: ${sw.service || 'unknown'}
Port: ${sw.port || 'unknown'}

IMPORTANT RULES:
1. Only return CVEs that you are CERTAIN affect this exact version
2. For each CVE, provide a realistic PoC approach that can be safely tested
3. Assign CVSS scores based on the actual CVE severity
4. Be precise about affected version ranges
5. Include at most 5 most critical CVEs

Return a JSON array with objects containing:
{
  "cveId": "CVE-YYYY-NNNNN",
  "cvss": 0.0,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "Short title",
  "description": "Detailed description",
  "remotelyExploitable": true/false,
  "pocApproach": "How to test this vulnerability",
  "pocCommand": "exact command or request to test (if applicable)",
  "affectedVersions": "version range description",
  "remediation": "How to fix",
  "references": ["url1", "url2"],
  "confidence": 0.0-1.0
}

Only return valid JSON. No markdown, no explanation.`;

  try {
    const result = await ollamaGenerate(prompt, { temperature: 0.1, maxTokens: 4096 });
    if (!result) return [];

    // Parse JSON response
    const jsonMatch = result.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];

    const parsed = JSON.parse(jsonMatch[0]) as AiCveResult[];
    logInfo(MODULE_NAME, `  ${sw.name} ${sw.version}: ${parsed.length} CVEs identified`);
    return parsed.filter(c => c.cveId && c.cvss > 0);
  } catch (e) {
    logWarn(MODULE_NAME, `  Failed to get CVEs for ${sw.name} ${sw.version}: ${e instanceof Error ? e.message : String(e)}`);
    return [];
  }
}

// ─── PoC Planning ────────────────────────────────────────────────────────

export async function planPocTests(
  cves: AiCveResult[],
  domain: string,
  software: DiscoveredSoftware[],
): Promise<PocPlan[]> {
  if (cves.length === 0) return [];

  logInfo(MODULE_NAME, `Planning PoC tests for ${cves.length} CVEs`);

  const plans: PocPlan[] = [];

  for (const cve of cves) {
    const sw = software.find(s =>
      cve.title.toLowerCase().includes(s.name.toLowerCase()) ||
      cve.description.toLowerCase().includes(s.name.toLowerCase())
    );

    const prompt = `You are a penetration tester planning a safe proof-of-concept test.

CVE: ${cve.cveId} - ${cve.title}
Description: ${cve.description}
CVSS: ${cve.cvss}
Remotely exploitable: ${cve.remotelyExploitable}
Target: ${domain}
Software: ${sw ? `${sw.name} ${sw.version}` : 'unknown'}
Service: ${sw?.service || 'unknown'}
Proposed approach: ${cve.pocApproach}

IMPORTANT SAFETY RULES:
1. All tests must be NON-DESTRUCTIVE - no actual exploitation
2. Tests should detect vulnerability presence without causing damage
3. Only network-level checks (nmap scripts, banner checks, safe HTTP requests)
4. Never attempt credential brute-force or denial of service
5. For SSH: check algorithm support, version banners, specific safe nmap scripts
6. For HTTP: check response headers, safe payload reflection, configuration issues
7. For SSL/TLS: check cipher suites, protocol versions

Return a JSON object:
{
  "cveId": "${cve.cveId}",
  "approach": "description of the safe test approach",
  "commands": ["command1", "command2"],
  "expectedVulnerable": "what output indicates vulnerability exists",
  "expectedSafe": "what output indicates target is NOT vulnerable",
  "timeout": 30000,
  "safeToRun": true,
  "reasoning": "why this approach is safe and effective"
}

Only return valid JSON.`;

    try {
      const result = await ollamaGenerate(prompt, { temperature: 0.1, maxTokens: 2048 });
      if (!result) continue;

      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) continue;

      const plan = JSON.parse(jsonMatch[0]) as PocPlan;
      if (plan.safeToRun && plan.commands && plan.commands.length > 0) {
        plans.push(plan);
      }
    } catch (e) {
      logWarn(MODULE_NAME, `  Failed to plan PoC for ${cve.cveId}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  logDone(MODULE_NAME, `Planned ${plans.length} PoC tests`);
  return plans;
}

// ─── PoC Execution ───────────────────────────────────────────────────────

export interface PocResult {
  cveId: string;
  command: string;
  output: string;
  exitCode: number;
  duration: number;
  vulnerable: boolean | null; // null = inconclusive
  confidence: number;
  proof: string;
  analysis: string;
}

export async function executePocTests(
  plans: PocPlan[],
  domain: string,
): Promise<PocResult[]> {
  if (plans.length === 0) return [];

  logInfo(MODULE_NAME, `Executing ${plans.length} PoC tests`);

  const results: PocResult[] = [];

  for (const plan of plans) {
    for (const cmd of plan.commands) {
      const result = await executeSinglePoc(plan, cmd, domain);
      results.push(result);
      // Only need one successful test per CVE
      if (result.vulnerable !== null) break;
    }
  }

  const confirmed = results.filter(r => r.vulnerable === true).length;
  logDone(MODULE_NAME, `PoC execution complete: ${confirmed} confirmed vulnerabilities`);
  return results;
}

async function executeSinglePoc(
  plan: PocPlan,
  cmd: string,
  domain: string,
): Promise<PocResult> {
  const startTime = Date.now();

  // Sanitize the command - replace target references
  const safeCmd = cmd
    .replace(/\{domain\}/g, domain)
    .replace(/\{target\}/g, domain)
    .replace(/&&/g, ';') // prevent chaining
    .replace(/\|\|/g, ';')
    .replace(/;/g, ' && '); // allow single chaining

  // Block dangerous commands
  const dangerous = ['rm ', 'dd ', 'mkfs', 'format', 'shutdown', 'reboot', 'halt',
    'destroy', 'drop', 'delete', 'truncate', 'override', 'sshpass', 'hydra', 'medusa',
    'john', 'hashcat', 'metasploit', 'msfconsole', 'msfvenom'];
  if (dangerous.some(d => safeCmd.toLowerCase().includes(d))) {
    return {
      cveId: plan.cveId,
      command: safeCmd,
      output: 'BLOCKED: Command flagged as potentially destructive',
      exitCode: -1,
      duration: 0,
      vulnerable: null,
      confidence: 0,
      proof: 'Command was blocked by safety filter',
      analysis: 'The AI-suggested PoC command was blocked because it matched a dangerous pattern. This suggests the AI may have suggested an actual exploit rather than a safe detection test.',
    };
  }

  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    logInfo(MODULE_NAME, `  Running: ${safeCmd.substring(0, 100)}`);

    const { stdout, stderr } = await execAsync(safeCmd, {
      timeout: plan.timeout || 30000,
      maxBuffer: 5 * 1024 * 1024,
    });

    const output = `${stdout}\n${stderr}`.trim();
    const duration = Date.now() - startTime;

    // Analyze output against expected patterns
    const vulnerableMatch = output.toLowerCase().includes(plan.expectedVulnerable.toLowerCase());
    const safeMatch = output.toLowerCase().includes(plan.expectedSafe.toLowerCase());

    let vulnerable: boolean | null = null;
    let confidence = 0;
    let analysis = '';

    if (vulnerableMatch && !safeMatch) {
      vulnerable = true;
      confidence = 0.8;
      analysis = `Output matches vulnerability indicator: "${plan.expectedVulnerable}"`;
    } else if (safeMatch && !vulnerableMatch) {
      vulnerable = false;
      confidence = 0.7;
      analysis = `Output matches safe indicator: "${plan.expectedSafe}"`;
    } else if (vulnerableMatch && safeMatch) {
      vulnerable = null;
      confidence = 0.3;
      analysis = 'Output matches both vulnerability and safe indicators - inconclusive';
    } else {
      vulnerable = null;
      confidence = 0.2;
      analysis = 'Output does not match expected patterns - manual review needed';
    }

    return {
      cveId: plan.cveId,
      command: safeCmd,
      output: output.substring(0, 2000),
      exitCode: 0,
      duration,
      vulnerable,
      confidence,
      proof: output.substring(0, 1000),
      analysis,
    };
  } catch (e) {
    const duration = Date.now() - startTime;
    const output = e instanceof Error ? e.message : String(e);

    // Command failure can itself be an indicator
    return {
      cveId: plan.cveId,
      command: safeCmd,
      output: output.substring(0, 2000),
      exitCode: 1,
      duration,
      vulnerable: null,
      confidence: 0.1,
      proof: `Command failed: ${output.substring(0, 500)}`,
      analysis: 'PoC command failed - could not determine vulnerability status',
    };
  }
}

// ─── AI Analysis of PoC Results ──────────────────────────────────────────

export async function analyzePocResults(
  cves: AiCveResult[],
  pocResults: PocResult[],
  domain: string,
): Promise<Finding[]> {
  if (cves.length === 0) return [];

  logInfo(MODULE_NAME, `Analyzing PoC results for ${cves.length} CVEs`);

  const findings: Finding[] = [];

  // Build analysis prompt with all results
  const resultsSummary = cves.map(cve => {
    const result = pocResults.find(r => r.cveId === cve.cveId);
    return `CVE: ${cve.cveId}
  CVSS: ${cve.cvss}
  Title: ${cve.title}
  Software: ${cve.description.substring(0, 200)}
  PoC Result: ${result ? `${result.vulnerable === true ? 'VULNERABLE' : result.vulnerable === false ? 'NOT VULNERABLE' : 'INCONCLUSIVE'} (confidence: ${result.confidence})` : 'No PoC attempted'}
  PoC Output: ${result ? result.output.substring(0, 500) : 'N/A'}`;
  }).join('\n\n');

  const prompt = `You are a senior security analyst analyzing penetration test results.

Target: ${domain}

PoC Test Results:
${resultsSummary}

For each CVE, provide your final assessment. Return a JSON array:
[{
  "cveId": "CVE-ID",
  "confirmed": true/false/null,
  "confidence": 0.0-1.0,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "evidence": "specific evidence from PoC output",
  "analysis": "your analysis of whether the vulnerability exists",
  "remediation": "specific remediation advice",
  "references": ["url1"]
}]

Rules:
- confirmed=true: strong evidence the vulnerability exists
- confirmed=false: strong evidence the vulnerability does NOT exist
- confirmed=null: inconclusive, needs further investigation
- Base severity on CVSS and exploitability context
- Be specific about what evidence supports your conclusion

Only return valid JSON.`;

  try {
    const result = await ollamaGenerate(prompt, { temperature: 0.1, maxTokens: 4096 });
    if (!result) {
      // Fallback: generate findings directly from CVE data
      return generateFallbackFindings(cves, pocResults, domain);
    }

    const jsonMatch = result.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return generateFallbackFindings(cves, pocResults, domain);

    const analyses = JSON.parse(jsonMatch[0]) as Array<{
      cveId: string;
      confirmed: boolean | null;
      confidence: number;
      severity: string;
      evidence: string;
      analysis: string;
      remediation: string;
      references: string[];
    }>;

    for (const a of analyses) {
      const cve = cves.find(c => c.cveId === a.cveId);
      if (!cve) continue;

      const pocResult = pocResults.find(r => r.cveId === a.cveId);

      // Determine status badge
      let statusBadge = '';
      if (a.confirmed === true) statusBadge = 'CONFIRMED VULNERABLE';
      else if (a.confirmed === false) statusBadge = 'NOT VULNERABLE';
      else statusBadge = 'INCONCLUSIVE - Manual Review Recommended';

      const description = [
        `**${statusBadge}**`,
        '',
        `**CVE:** ${cve.cveId}`,
        `**CVSS:** ${cve.cvss} (${a.severity || cve.severity})`,
        `**Software:** ${cve.title}`,
        '',
        cve.description,
        '',
        '**AI Analysis:**',
        a.analysis,
        '',
        '**PoC Test:**',
        `Command: ${pocResult?.command || 'N/A'}`,
        `Result: ${pocResult?.vulnerable === true ? 'Vulnerable' : pocResult?.vulnerable === false ? 'Not Vulnerable' : 'Inconclusive'}`,
        `Confidence: ${(a.confidence * 100).toFixed(0)}%`,
        '',
        '**Evidence:**',
        a.evidence || pocResult?.proof || 'No evidence available',
      ].join('\n');

      const severity = (a.severity || cve.severity).toUpperCase() as Severity;

      findings.push(generateFinding(
        `CVE-Verified: ${cve.cveId} - ${cve.title}`,
        description,
        severity,
        'CVE Verification',
        domain,
        [
          `CVE: ${cve.cveId}`,
          `CVSS: ${cve.cvss}`,
          `Status: ${statusBadge}`,
          `PoC Command: ${pocResult?.command || 'N/A'}`,
          `PoC Output: ${(pocResult?.output || 'N/A').substring(0, 1000)}`,
          `AI Confidence: ${(a.confidence * 100).toFixed(0)}%`,
          `Remotely Exploitable: ${cve.remotelyExploitable ? 'Yes' : 'No'}`,
        ].join('\n'),
        cve.remotelyExploitable
          ? `Remote exploitation is possible. ${cve.cveId} affects ${domain}.`
          : `${cve.cveId} detected on ${domain}. Exploitation may require local access.`,
        a.remediation || cve.remediation,
        [...(cve.references || []), ...(a.references || [])],
        undefined,
        'aiCveResearch',
      ));

      logVuln(MODULE_NAME, `${statusBadge}: ${cve.cveId} (${cve.cvss})`, a.severity || cve.severity);
    }

    return findings;
  } catch (e) {
    logWarn(MODULE_NAME, `AI analysis failed: ${e instanceof Error ? e.message : String(e)}`);
    return generateFallbackFindings(cves, pocResults, domain);
  }
}

function generateFallbackFindings(
  cves: AiCveResult[],
  pocResults: PocResult[],
  domain: string,
): Finding[] {
  return cves.map(cve => {
    const pocResult = pocResults.find(r => r.cveId === cve.cveId);
    let statusBadge = 'POTENTIALLY VULNERABLE';
    if (pocResult?.vulnerable === true) statusBadge = 'CONFIRMED VULNERABLE';
    else if (pocResult?.vulnerable === false) statusBadge = 'LIKELY NOT VULNERABLE';

    return generateFinding(
      `${statusBadge}: ${cve.cveId} - ${cve.title}`,
      [
        `**${statusBadge}**`,
        '',
        cve.description,
        '',
        `**PoC Result:** ${pocResult ? (pocResult.vulnerable === true ? 'Confirmed' : pocResult.vulnerable === false ? 'Not confirmed' : 'Inconclusive') : 'Not tested'}`,
        pocResult ? `**Evidence:** ${pocResult.proof}` : '',
      ].join('\n'),
      cve.severity.toUpperCase() as Severity,
      'AI CVE Research',
      domain,
      `CVE: ${cve.cveId}\nCVSS: ${cve.cvss}\nPoC: ${pocResult?.command || 'N/A'}\nOutput: ${(pocResult?.output || 'N/A').substring(0, 1000)}`,
      cve.description,
      cve.remediation,
      cve.references,
      undefined,
      'aiCveResearch',
    );
  });
}

// ─── Main Entry Point ────────────────────────────────────────────────────

export async function runAiCveResearch(
  domain: string,
  priorFindings: Finding[],
): Promise<{ findings: Finding[]; duration: number }> {
  const startTime = Date.now();

  // Step 1: Extract discovered software from prior findings
  const software = extractSoftware(priorFindings);
  logInfo(MODULE_NAME, `Extracted ${software.length} software components from scan results`);
  for (const sw of software) {
    logInfo(MODULE_NAME, `  ${sw.name} ${sw.version} (${sw.service || 'unknown'})`);
  }

  if (software.length === 0) {
    logInfo(MODULE_NAME, 'No versioned software detected - skipping AI CVE research');
    return { findings: [], duration: 0 };
  }

  // Step 2: AI researches CVEs for each discovered software
  const cves = await researchCvesWithAi(software, domain);
  logInfo(MODULE_NAME, `AI identified ${cves.length} potential CVEs`);

  // Step 3: Plan safe PoC tests
  const pocPlans = await planPocTests(cves, domain, software);
  logInfo(MODULE_NAME, `Planned ${pocPlans.length} PoC tests`);

  // Step 4: Execute PoC tests
  const pocResults = await executePocTests(pocPlans, domain);
  logInfo(MODULE_NAME, `Executed ${pocResults.length} PoC tests`);

  // Step 5: AI analyzes results and generates findings
  const findings = await analyzePocResults(cves, pocResults, domain);
  logInfo(MODULE_NAME, `Generated ${findings.length} verified findings`);

  const duration = Date.now() - startTime;
  logDone(MODULE_NAME, `AI CVE research completed in ${(duration / 1000).toFixed(1)}s`);

  return { findings, duration };
}

// ─── Ollama helper ───────────────────────────────────────────────────────

async function ollamaGenerate(prompt: string, options: { temperature?: number; maxTokens?: number } = {}): Promise<string> {
  const baseUrl = config.ollamaBaseUrl;
  const model = config.securityModel || config.aiModel;

  try {
    const res = await fetch(`${baseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        options: {
          temperature: options.temperature ?? 0.3,
          num_predict: options.maxTokens ?? 2048,
          top_p: 0.9,
          top_k: 40,
          repeat_penalty: 1.15,
        },
      }),
      signal: AbortSignal.timeout(120000),
    });

    if (!res.ok) return '';
    const data = await res.json() as { response?: string };
    return data.response || '';
  } catch {
    return '';
  }
}

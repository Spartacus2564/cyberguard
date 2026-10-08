import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logExploit, logVuln } from '../scanLogger';
import { getAI } from '../../services/ai.service';
import {
  generateSSTIPayloads,
  generateOSCommandPayloads,
  generateLDAPPayloads,
  generateXPathPayloads,
  generateDeserializationPayloads,
  generatePrototypePollutionPayloads,
  generateHPPPayloads,
  measureTiming,
} from './shared-attack';

// ─── HTTP Client ───
function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  timeoutOrBody: number | string = 6000
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; redirectUrl?: string; duration: number }> {
  const timeout = typeof timeoutOrBody === 'number' ? timeoutOrBody : 6000;
  const body = typeof timeoutOrBody === 'string' ? timeoutOrBody : '';
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers,
      timeout,
      rejectUnauthorized: false,
    }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 1048576) { req.destroy(); return; }
        data += chunk.toString();
      });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, redirectUrl: res.headers.location, duration: Date.now() - start });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function safeRequest(targetUrl: string, method: string = 'GET', headers: Record<string, string> = {}, body: string = ''): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; redirectUrl?: string; duration: number }> {
  try {
    return await makeRequest(targetUrl, method, headers, body);
  } catch {
    return { statusCode: 0, headers: {}, body: '', duration: 0 };
  }
}

// ─── MODULE: Server-Side Template Injection (SSTI) ───
async function testSSTI(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('advancedAttacks', 'SSTI', baseUrl, 'Testing server-side template injection via Jinja2/Twig/FreeMarker payloads');
  try {
    const payloads = generateSSTIPayloads();
    const testParams = ['name', 'template', 'page', 'render', 'view', 'preview', 'message', 'greeting', 'title', 'username', 'content', 'body', 'subject'];

    for (const param of testParams) {
      let found = false;
      for (const { payload, indicator, type } of payloads) {
        if (found) break;
        try {
          const encoded = encodeURIComponent(payload);
          // Test in URL parameter
          const res = await safeRequest(`${baseUrl}?${param}=${encoded}`, 'GET', {}, '');
          if (indicator && res.body.includes(indicator)) {
            findings.push(generateFinding(
              'Server-Side Template Injection (SSTI)',
              `The application renders user input in a server-side template via parameter "${param}", allowing template injection.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Engine type: ${type}, Payload: ${payload}, Response contains evaluated expression`,
              'SSTI can lead to remote code execution, file read, environment variable disclosure, and full server compromise',
              'Do not render user input server-side; use context-aware auto-escaping; validate and whitelist template inputs',
              ['https://portswigger.net/web-security/server-side-template-injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection']
            ));
            found = true;
          }
        } catch {}
      }

      // Also test POST body
      if (!found) {
        try {
          const body = JSON.stringify({ [param]: '{{7*7}}' });
          const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/json' }, body);
          if (res.body.includes('49')) {
            findings.push(generateFinding(
              'Server-Side Template Injection (SSTI)',
              `The application renders POST body input "${param}" in a server-side template.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Parameter: ${param} in POST body, Payload: {{7*7}}, Response contains 49`,
              'SSTI enables remote code execution and server compromise when combined with engine-specific gadgets',
              'Use allowlists for template variables; never embed user input in template expressions',
              ['https://portswigger.net/web-security/server-side-template-injection']
            ));
            break;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`SSTI: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: OS Command Injection ───
async function testCommandInjection(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('advancedAttacks', 'CMDi', baseUrl, 'Testing OS command injection via pipe/semicolon/backtick operators');
  try {
    const payloads = generateOSCommandPayloads();
    const testParams = ['cmd', 'command', 'exec', 'run', 'ping', 'host', 'hostname', 'ip', 'path', 'dir', 'file', 'filename', 'url', 'download', 'check', 'test', 'debug'];
    const endpoints = ['/', '/ping', '/exec', '/cmd', '/run', '/api/exec', '/api/ping', '/api/command', '/shell', '/admin/ping'];

    for (const endpoint of endpoints) {
      for (const param of testParams) {
        let found = false;
        let timingFound = false;
        for (const { payload, indicator, type } of payloads) {
          if (found || timingFound) break;
          try {
            const encoded = encodeURIComponent(payload);
            const res = await safeRequest(`${baseUrl}${endpoint}?${param}=${encoded}`, 'GET', {}, '');

            // Direct output-based detection
            if (indicator && indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
              findings.push(generateFinding(
                'OS Command Injection',
                `The application passes user input to an OS command via parameter "${param}" at ${endpoint}.`,
                Severity.CRITICAL,
                'Active Vulnerability',
                domain,
                `Endpoint: ${endpoint}, Parameter: ${param}, Type: ${type}, Payload: ${payload}, Command output in response`,
                'OS command injection allows attackers to execute arbitrary commands, steal data, and compromise the server',
                'Never pass user input to OS commands; use parameterized APIs; whitelist inputs; run with least-privilege accounts',
                ['https://owasp.org/www-community/attacks/Command_Injection', 'https://portswigger.net/web-security/os-command-injection']
              ));
              found = true;
            }
          } catch {}
        }

        // Timing-based blind detection
        if (!found) {
          try {
            const requestFn = async (p: string) => {
              const res = await safeRequest(`${baseUrl}${endpoint}?${param}=${encodeURIComponent(p)}`, 'GET', {}, '');
              return res.duration;
            };
            const timing = await measureTiming(
              requestFn,
              [`${baseUrl}${endpoint}?${param}=1`, `${baseUrl}${endpoint}?${param}=2`],
              [
                { label: 'sleep', payload: 'sleep 5', expectedDelayMs: 4000 },
                { label: 'ping', payload: 'ping -n 5 127.0.0.1', expectedDelayMs: 4000 },
                { label: 'py-sleep', payload: 'python -c "import time;time.sleep(5)"', expectedDelayMs: 4000 },
              ],
              { threshold: 3000, confidenceThreshold: 1 }
            );
            if (timing.isBlind(3000)) {
              findings.push(generateFinding(
                'Blind OS Command Injection (Timing)',
                `Parameter "${param}" at ${endpoint} may be vulnerable to blind command injection via timing difference.`,
                Severity.CRITICAL,
                'Active Vulnerability',
                domain,
                `Endpoint: ${endpoint}, Parameter: ${param}, Baseline: ${timing.baseline}ms, Confidence: ${timing.confidence}`,
                'Blind command injection allows data exfiltration via timing side-channels or out-of-band callbacks',
                'Use parameterized command execution; validate inputs strictly; apply network egress filtering',
                ['https://portswigger.net/web-security/os-command-injection']
              ));
              timingFound = true;
            }
          } catch {}
        }
      }
    }
  } catch (e) { errors.push(`OS Injection: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: LDAP Injection ───
async function testLDAP(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('advancedAttacks', 'LDAP', baseUrl, 'Testing LDAP injection via filter metacharacters');
  try {
    const payloads = generateLDAPPayloads();
    const endpoints = ['/search', '/ldap', '/api/search', '/users', '/api/users', '/login'];
    const params = ['user', 'username', 'uid', 'cn', 'filter', 'query', 'q', 'search'];

    for (const endpoint of endpoints) {
      for (const param of params) {
        for (const { payload, type } of payloads) {
          try {
            const encoded = encodeURIComponent(payload);
            const res = await safeRequest(`${baseUrl}${endpoint}?${param}=${encoded}`, 'GET', {}, '');
            // LDAP errors leak via specific indicators
            const bodyLower = res.body.toLowerCase();
            const ldapError = bodyLower.includes('ldap') || bodyLower.includes('bad search filter') ||
              bodyLower.includes('invalid search') || bodyLower.includes('unexpected') ||
              bodyLower.includes('filter') || bodyLower.includes('malformed');
            if (res.statusCode === 500 && ldapError) {
              findings.push(generateFinding(
                'LDAP Injection',
                `The application appears to use LDAP queries with unvalidated input via parameter "${param}".`,
                Severity.CRITICAL,
                'Active Vulnerability',
                domain,
                `Endpoint: ${endpoint}, Parameter: ${param}, Type: ${type}, LDAP error in response`,
                'LDAP injection can bypass authentication, extract directory data (usernames, emails, groups), and modify directory entries',
                'Escape LDAP special characters; use parameterized LDAP queries; validate and sanitize input',
                ['https://owasp.org/www-community/attacks/LDAP_Injection', 'https://www.cgisecurity.com/lib/LDAPInjection_Presentation.pdf']
              ));
              break;
            }
          } catch {}
        }
      }
    }
  } catch (e) { errors.push(`LDAP: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: XPath Injection ───
async function testXPath(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('advancedAttacks', 'XPath', baseUrl, 'Testing XPath injection via quote manipulation');
  try {
    const payloads = generateXPathPayloads();
    const endpoints = ['/search', '/query', '/api/search', '/search/user', '/api/user', '/find'];
    const params = ['name', 'search', 'q', 'user', 'username', 'email', 'query'];

    for (const endpoint of endpoints) {
      for (const param of params) {
        let found = false;
        for (const { payload, indicator, type } of payloads) {
          if (found) break;
          try {
            const encoded = encodeURIComponent(payload);
            const res = await safeRequest(`${baseUrl}${endpoint}?${param}=${encoded}`, 'GET', {}, '');
            const bodyLower = res.body.toLowerCase();
            const xpathError = bodyLower.includes('xpath') || bodyLower.includes('xml xpath') ||
              bodyLower.includes('invalid expression') || bodyLower.includes('xpath expression') ||
              bodyLower.includes('parsing error');
            if (res.statusCode === 500 && xpathError) {
              findings.push(generateFinding(
                'XPath Injection',
                `The application appears to use XPath queries with unvalidated input via parameter "${param}".`,
                Severity.HIGH,
                'Active Vulnerability',
                domain,
                `Endpoint: ${endpoint}, Parameter: ${param}, Type: ${type}, XPath error in response`,
                'XPath injection can access the entire XML document, bypass authentication, and extract sensitive data',
                'Use parameterized XPath queries; escape XPath special characters; validate input',
                ['https://owasp.org/www-community/attacks/XPATH_Injection']
              ));
              found = true;
            } else if (indicator && indicator.split('|').some(i => bodyLower.includes(i))) {
              findInjectionEvidence(findings, domain, endpoint, param, payload, type, res.body);
              found = true;
            }
          } catch {}
        }
      }
    }
  } catch (e) { errors.push(`XPath: ${e instanceof Error ? e.message : String(e)}`); }
}

function findInjectionEvidence(findings: Finding[], domain: string, endpoint: string, param: string, payload: string, type: string, body: string): void {
  const searchTerms = ['user', 'name', 'email', 'account', 'profile', 'id', 'uid'];
  const matchedTerms = searchTerms.filter(t => body.toLowerCase().includes(t));
  if (matchedTerms.length >= 2) {
    findings.push(generateFinding(
      'XPath Injection',
      `The application returns expanded data for XPath manipulation via "${param}".`,
      Severity.HIGH,
      'Active Vulnerability',
      domain,
      `Endpoint: ${endpoint}, Parameter: ${param}, Type: ${type}, Payload: ${payload}`,
      'XPath injection can expose the full underlying XML data structure',
      'Parameterize XPath queries; validate and sanitize user input',
      ['https://owasp.org/www-community/attacks/XPATH_Injection']
    ));
  }
}

// ─── MODULE: Insecure Deserialization ───
async function testDeserialization(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generateDeserializationPayloads();
    const endpoints = ['/', '/api', '/api/data', '/api/v1', '/data', '/import', '/upload', '/rest', '/api/v1/data'];

    for (const endpoint of endpoints) {
      let found = false;
      for (const { payload, indicator, type } of payloads) {
        if (found) break;
        try {
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/octet-stream' }, payload);
          const bodyLower = res.body.toLowerCase();
          const deserIndicators = ['deserialize', 'serialize', 'unserialize', 'objectstream', 'class', 'java.io', 'exception', 'error', 'cannot cast', 'typeahead', 'mismatch'];
          const hit = deserIndicators.some(i => bodyLower.includes(i)) || (indicator && indicator.split('|').some(i => bodyLower.includes(i)));
          if (hit && res.statusCode >= 400 && res.statusCode < 600) {
            findings.push(generateFinding(
              `Insecure Deserialization (${type})`,
              `The application attempts to deserialize attacker-controlled data at ${endpoint}.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Type: ${type}, Payload type: ${type.replace(/-/g, ' ')}, Server processed serialized data`,
              'Insecure deserialization can lead to remote code execution, SQL injection, and server compromise using gadget chains',
              'Do not deserialize untrusted data; use allowlists of classes; use safe formats like JSON with schema validation',
              ['https://owasp.org/www-project-cheat-sheets/cheatsheets/Deserialization_Cheat_Sheet.html', 'https://portswigger.net/web-security/deserialization']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`Deserialization: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Server-Side Prototype Pollution ───
async function testPrototypePollution(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generatePrototypePollutionPayloads();
    const endpoints = ['/', '/api/users', '/api/data', '/api/update', '/api/validate', '/api/config', '/api/parse'];

    for (const endpoint of endpoints) {
      let found = false;
      for (const { payload, indicator, type } of payloads) {
        if (found) break;
        try {
          const isForm = type.includes('qs');
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', {
            'Content-Type': isForm ? 'application/x-www-form-urlencoded' : 'application/json',
          }, payload);
          if (indicator && res.body.toLowerCase().includes(indicator.toLowerCase())) {
            findings.push(generateFinding(
              'Server-Side Prototype Pollution',
              `The application merges user input into internal objects via "prototype" keys at ${endpoint}.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Type: ${type}, Response echoes "polluted" marker`,
              'Prototype pollution can lead to privilege escalation, RCE (with gadgets), and bypass of input filters',
              'Use Object.assign with allowlisted keys; reject __proto__/constructor keys; use strict merge libraries (lodash.merge with prototype:false)',
              ['https://portswigger.net/research/server-side-prototype-pollution']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`Prototype Pollution: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: HTTP Parameter Pollution (HPP) ───
async function testHPP(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generateHPPPayloads();
    const endpoints = ['/api/users', '/api/profile', '/api/admin', '/admin', '/user', '/account', '/api/search'];

    for (const endpoint of endpoints) {
      let found = false;
      for (const { payload, indicator, type } of payloads) {
        if (found) break;
        try {
          const res = await safeRequest(`${baseUrl}${endpoint}?${payload}`, 'GET', {}, '');
          if (indicator && res.body.toLowerCase().includes(indicator.toLowerCase())) {
            findings.push(generateFinding(
              'HTTP Parameter Pollution',
              `The application accepts duplicate parameter values (${type}), potentially choosing attacker-preferred values.`,
              Severity.MEDIUM,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Payload: ${payload}, Type: ${type}`,
              'HPP can bypass security controls, override server-side decisions, and enable cache poisoning',
              'Reject duplicate parameters; define explicit parameter precedence; validate each occurrence',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`HPP: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── Main Entry Point ───
export async function runAdvancedAttacksScan(domain: string, _profile?: unknown): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const baseUrl = `https://${domain}`;
    const httpUrl = `http://${domain}`;

    // Verify connectivity
    let connectivityOk = false;
    try { await makeRequest(baseUrl); connectivityOk = true; } catch {
      try { await makeRequest(httpUrl); connectivityOk = true; } catch {}
    }
    if (!connectivityOk) {
      errors.push(`Could not connect to ${domain}`);
      const duration = Date.now() - startTime;
      return { module: 'advancedAttacks', findings, duration, errors };
    }

    // Run test groups in parallel
    const batch1 = [
      testSSTI(domain, baseUrl, findings, errors),
      testCommandInjection(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch1);

    const batch2 = [
      testLDAP(domain, baseUrl, findings, errors),
      testXPath(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch2);

    const batch3 = [
      testDeserialization(domain, baseUrl, findings, errors),
      testPrototypePollution(domain, baseUrl, findings, errors),
      testHPP(domain, baseUrl, findings, errors),
    ];
await Promise.allSettled(batch3);

    // AI-enhanced advanced attack analysis - exploit payload crafting
    try {
      const ai = getAI();
      const advFindings = findings.filter(f =>
        f.category === 'SSTI' || f.category === 'Command Injection' ||
        f.category === 'LDAP Injection' || f.category === 'XPath Injection' ||
        f.category === 'Deserialization' || f.category === 'Prototype Pollution'
      );
      if (advFindings.length > 0) {
        // Generate novel payloads for each advanced attack type
        const attackTypes = [...new Set(advFindings.map(f => f.category))];
        for (const attackType of attackTypes) {
          try {
            const payloads = await ai.generateNovelPayloads(['web', attackType], 'unknown', attackType);
            if (payloads.length > 0) {
              findings.push(generateFinding(
                `AI-Generated Novel Payloads for ${attackType}`,
                `AI generated ${payloads.length} novel payloads for ${attackType}: ${payloads.slice(0, 3).join(', ')}...`,
                Severity.INFO,
                'AI Payload Generation',
                domain,
                `Test these AI-generated ${attackType} payloads: ${payloads.join(' | ')}`,
                'AI-generated payloads may bypass WAFs and find missed advanced injection vulnerabilities',
                'Test AI-generated payloads against the target endpoints',
                [],
              ));
            }
          } catch {}
        }
        // AI reasoning about vulnerability chaining
        const aiResult = await ai.reasonAboutVulnerabilities(attackTypes, advFindings);
        if (aiResult.chainingOpportunities.length > 0) {
          for (const chain of aiResult.chainingOpportunities) {
            findings.push(generateFinding(
              `AI-Detected Advanced Attack Chain: ${chain}`,
              `AI identified chaining opportunity: ${chain}. This may indicate multi-stage exploitation paths.`,
              Severity.HIGH,
              'AI Advanced Attack Analysis',
              domain,
              'Review the attack chain and implement targeted defenses at each stage',
              'Chained advanced attacks can lead to remote code execution',
              'Implement defense-in-depth: WAF rules, input validation, output encoding',
              [],
            ));
          }
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return { module: 'advancedAttacks', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'advancedAttacks',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

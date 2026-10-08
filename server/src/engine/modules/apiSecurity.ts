import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, OWASP_TOP_10 } from './shared';
import { getAI } from '../../services/ai.service';

function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body: string = '',
  timeoutMs: number = 8000,
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; duration: number }> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    const mod = parsed.protocol === 'https:' ? https : http;
    const reqHeaders: Record<string, string> = {
      'User-Agent': 'CYBERGUARD-APISecurity/1.0',
      'Accept': 'application/json',
      ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body).toString() } : {}),
      ...headers,
    };
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: reqHeaders,
      timeout: timeoutMs,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 2097152) { req.destroy(); return; }
        data += chunk.toString();
      });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, duration: Date.now() - start }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function safe(url: string, method = 'GET', headers: Record<string, string> = {}, body = '') {
  try { return await makeRequest(url, method, headers, body); }
  catch { return { statusCode: 0, headers: {}, body: '', duration: 0 }; }
}

const API_ENDPOINTS = [
  '/api', '/api/v1', '/api/v2', '/graphql', '/api/users', '/api/user',
  '/api/auth', '/api/login', '/api/me', '/api/profile', '/api/admin',
  '/api/config', '/api/settings', '/api/search', '/api/query', '/api/export',
  '/api/import', '/api/upload', '/api/files', '/api/reports', '/api/keys',
  '/api/tokens', '/api/webhooks', '/api/callbacks', '/api/internal',
  '/rest/api', '/swagger', '/swagger.json', '/api-docs', '/openapi.json',
  '/api/docs', '/api/health', '/api/status', '/api/version',
];

const GRAPHQL_INTROSPECTION = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name } } } } } }"}';

export async function runApiSecurityScan(domain: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;

  // 1) Discover API endpoints (parallel with concurrency limit)
  const liveEndpoints: { path: string; status: number; body: string; contentType: string }[] = [];
  const API_BATCH = 10;
  for (let i = 0; i < API_ENDPOINTS.length; i += API_BATCH) {
    const batch = API_ENDPOINTS.slice(i, i + API_BATCH);
    const results = await Promise.allSettled(
      batch.map(async (path) => {
        const res = await safe(base + path);
        return { path, res };
      })
    );
    for (const r of results) {
      if (r.status === 'fulfilled') {
        const { path, res } = r.value;
        if (res.statusCode && res.statusCode > 0 && res.statusCode !== 404 && res.statusCode !== 403) {
          liveEndpoints.push({
            path,
            status: res.statusCode,
            body: res.body.slice(0, 2000),
            contentType: String(res.headers['content-type'] || ''),
          });
        }
      }
    }
  }

  // 2) GraphQL introspection
  const graphqlPaths = liveEndpoints.filter(e => e.path.includes('graphql'));
  for (const gp of graphqlPaths) {
    const gqlRes = await safe(base + gp.path, 'POST', { 'Content-Type': 'application/json' }, GRAPHQL_INTROSPECTION);
    if (gqlRes.statusCode === 200 && gqlRes.body.includes('__schema')) {
      let types: string[] = [];
      try {
        const parsed = JSON.parse(gqlRes.body);
        types = (parsed?.data?.__schema?.types || []).map((t: any) => t.name).filter((n: string) => !n.startsWith('__'));
      } catch {}
      findings.push(generateFinding({
        title: 'GraphQL Introspection Enabled — Full Schema Exposed',
        description: `GraphQL introspection query succeeded at ${gp.path}, exposing the entire API schema (${types.length} types: ${types.slice(0, 10).join(', ')}${types.length > 10 ? '...' : ''}). An attacker can discover all queries, mutations, types, and relationships.`,
        severity: Severity.HIGH,
        category: 'API Security',
        affectedAsset: base + gp.path,
        evidence: `POST ${gp.path} → introspection query returned ${types.length} types\nSample types: ${types.slice(0, 15).join(', ')}\nFull response length: ${gqlRes.body.length}`,
        impact: 'Full API schema disclosure enables attackers to discover hidden endpoints, understand data relationships, and craft targeted attacks against all GraphQL operations.',
        remediation: 'Disable introspection in production. In Apollo Server: introspection: false. In Hasura: enable allowlist queries. Implement query depth limiting and rate limiting.',
        references: [
          'https://graphql.org/learn/introspection/',
          'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        ],
      }));

      // 3) GraphQL batching / DoS
      const batchPayload = JSON.stringify([
        { query: '{ __typename }' },
        { query: '{ __typename }' },
        { query: '{ __typename }' },
        { query: '{ __typename }' },
        { query: '{ __typename }' },
      ]);
      const batchRes = await safe(base + gp.path, 'POST', { 'Content-Type': 'application/json' }, batchPayload);
      if (batchRes.statusCode === 200) {
        findings.push(generateFinding({
          title: 'GraphQL Query Batching Enabled — Denial of Service Risk',
          description: `The GraphQL endpoint at ${gp.path} accepts batched queries (multiple operations in a single request). Without limits, an attacker can send hundreds of operations to exhaust server resources.`,
          severity: Severity.MEDIUM,
          category: 'API Security',
          affectedAsset: base + gp.path,
          evidence: `POST ${gp.path} → batch of 5 queries accepted → HTTP ${batchRes.statusCode}`,
          impact: 'Attackers can send large batches of expensive queries to cause denial of service, CPU exhaustion, and database overload.',
          remediation: 'Limit the maximum number of operations per batch (recommended: 5-10). Implement query complexity analysis and rate limiting per client.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
        }));
      }

      // 4) GraphQL depth攻击 — nested queries
      const deepQuery = JSON.stringify({ query: '{ a: __typename ...on Query { b: __typename ...on Query { c: __typename ...on Query { d: __typename ...on Query { e: __typename } } } } }' });
      const depthRes = await safe(base + gp.path, 'POST', { 'Content-Type': 'application/json' }, deepQuery);
      if (depthRes.statusCode === 200 && depthRes.body.includes('__typename')) {
        findings.push(generateFinding({
          title: 'GraphQL — No Query Depth Limiting',
          description: `The GraphQL endpoint at ${gp.path} accepts deeply nested queries without depth limiting. An attacker can craft deeply nested queries to cause CPU/memory exhaustion.`,
          severity: Severity.MEDIUM,
          category: 'API Security',
          affectedAsset: base + gp.path,
          evidence: `POST ${gp.path} → deeply nested query accepted → HTTP ${depthRes.statusCode}`,
          impact: 'Denial of service via deeply nested GraphQL queries that consume excessive server resources.',
          remediation: 'Implement query depth limiting (recommended max depth: 7-10). Use query complexity analysis with cost-based limits.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
        }));
      }
    }
  }

  // 5) REST API — missing authentication (only flag JSON responses, not HTML SPA catch-all)
  const authPaths = liveEndpoints.filter(e =>
    (e.path.includes('/admin') || e.path.includes('/users') || e.path.includes('/profile') ||
    e.path.includes('/settings') || e.path.includes('/config') || e.path.includes('/export') ||
    e.path.includes('/keys') || e.path.includes('/tokens') || e.path.includes('/internal')) &&
    e.contentType.includes('json')
  );
  for (const ep of authPaths) {
    if (ep.status === 200 && ep.body.length > 10) {
      findings.push(generateFinding({
        title: `Unauthenticated API Access: ${ep.path}`,
        description: `The API endpoint ${ep.path} returns data (${ep.body.length} bytes) without requiring authentication. Sensitive data may be exposed to unauthenticated users.`,
        severity: ep.path.includes('admin') || ep.path.includes('internal') || ep.path.includes('keys') ? Severity.CRITICAL : Severity.HIGH,
        category: 'API Security',
        affectedAsset: base + ep.path,
        evidence: `GET ${ep.path} → HTTP ${ep.status}, Content-Type: ${ep.contentType}\nBody preview: ${ep.body.slice(0, 300)}`,
        impact: 'Sensitive data exposure, unauthorized access to administrative functions, potential data breach.',
        remediation: 'Implement authentication on all sensitive API endpoints. Use OAuth 2.0 / JWT tokens with proper validation. Apply the principle of least privilege.',
        references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
      }));
    }
  }

  // 6) API — verbose error messages
  for (const ep of liveEndpoints.slice(0, 10)) {
    const errRes = await safe(base + ep.path + '?__cyberguard_err_test=1');
    if (errRes.body.length > 50 && (
      errRes.body.includes('stack') || errRes.body.includes('trace') ||
      errRes.body.includes('Exception') || errRes.body.includes('at line') ||
      errRes.body.includes('File:') || errRes.body.includes('SELECT *') ||
      errRes.body.includes('sql') || errRes.body.includes('Stack Trace')
    )) {
      findings.push(generateFinding({
        title: `Verbose Error Messages in API: ${ep.path}`,
        description: `The API endpoint ${ep.path} returns verbose error messages that may leak implementation details, database schema, file paths, or internal logic.`,
        severity: Severity.MEDIUM,
        category: 'API Security',
        affectedAsset: base + ep.path,
        evidence: `GET ${ep.path}?__cyberguard_err_test=1\nResponse contains stack trace / verbose error:\n${errRes.body.slice(0, 500)}`,
        impact: 'Attackers can gather intelligence about the application architecture, database structure, and internal paths to craft more targeted attacks.',
        remediation: 'Implement generic error handling that returns consistent error responses without implementation details. Log detailed errors server-side only.',
        references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/'],
      }));
      break;
    }
  }

  // 7) API rate limiting
  const rateTestPath = liveEndpoints[0]?.path || '/api';
  const rateResults: number[] = [];
  const burst = 30;
  const promises: Promise<void>[] = [];
  for (let i = 0; i < burst; i++) {
    promises.push(safe(base + rateTestPath).then(r => { rateResults.push(r.statusCode); }));
  }
  await Promise.all(promises);
  const rateLimited = rateResults.filter(s => s === 429).length;
  if (rateLimited === 0 && rateResults.filter(s => s === 200).length >= burst * 0.8) {
    findings.push(generateFinding({
      title: 'No API Rate Limiting — Brute Force / Enumeration Possible',
      description: `Sent ${burst} concurrent requests to ${rateTestPath} with no rate limiting (0 received HTTP 429). The API is vulnerable to brute force attacks, credential stuffing, and data enumeration.`,
      severity: Severity.MEDIUM,
      category: 'API Security',
      affectedAsset: base + rateTestPath,
      evidence: `Sent ${burst} requests, ${rateResults.filter(s => s === 200).length} returned 200, ${rateLimited} returned 429`,
      impact: 'Attackers can perform unlimited brute force attempts against authentication endpoints, enumerate users, and abuse API functionality.',
      remediation: 'Implement rate limiting (e.g., 100 requests/minute per IP, 5 login attempts/minute per user). Use progressive delays and account lockout for auth endpoints.',
      references: ['https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'],
    }));
  }

  // 8) API versioning — old versions exposed
  const versionPaths = ['/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3'];
  const liveVersions: string[] = [];
  for (const vp of versionPaths) {
    const r = await safe(base + vp);
    if (r.statusCode >= 200 && r.statusCode < 400) liveVersions.push(vp);
  }
  if (liveVersions.length > 1) {
    findings.push(generateFinding({
      title: `Multiple API Versions Exposed: ${liveVersions.join(', ')}`,
      description: `Multiple API versions are simultaneously accessible (${liveVersions.join(', ')}). Old versions may contain unpatched vulnerabilities and are often forgotten during security updates.`,
      severity: Severity.LOW,
      category: 'API Security',
      affectedAsset: base + liveVersions.join(', '),
      evidence: `Live API versions: ${liveVersions.join(', ')}`,
      impact: 'Attackers can target older, less-secure API versions that may lack recent security patches.',
      remediation: 'Deprecate and remove old API versions. Implement sunset headers and version migration. Ensure all versions have the same security controls.',
      references: ['https://swagger.io/docs/open-source-tools/swagger-ui/usage/api-versioning/'],
    }));
  }

  // AI-enhanced API security analysis - schema analysis, BOLA/IDOR detection
  try {
    const ai = getAI();
    const apiEndpoints = findings.filter(f => f.category === 'API Security').map(f => f.affectedAsset).filter(Boolean);
    if (apiEndpoints.length > 0) {
      const endpointsList = apiEndpoints.slice(0, 20).join('\n');
      const aiResult = await ai.reasonAboutVulnerabilities(['API', 'REST', 'GraphQL'], findings.filter(f => f.category === 'API Security'));
      if (aiResult.chainingOpportunities.length > 0) {
        for (const chain of aiResult.chainingOpportunities) {
          findings.push(generateFinding(
            `AI-Detected API Attack Chain: ${chain}`,
            `AI identified potential API attack chain: ${chain}. This may indicate BOLA/IDOR or authentication bypass opportunities.`,
            Severity.HIGH,
            'AI API Analysis',
            domain,
            'Review API authorization logic for object-level and function-level access control',
            'Chained API vulnerabilities can lead to full account takeover or data exfiltration',
            'Implement proper object-level authorization (BOLA protection) and function-level authorization',
            [],
          ));
        }
      }
      if (aiResult.novelAttackVectors.length > 0) {
        for (const vector of aiResult.novelAttackVectors) {
          findings.push(generateFinding(
            `AI-Detected Novel API Attack: ${vector}`,
            `AI identified novel attack vector for API: ${vector}. This may not be covered by standard OWASP API Top 10 checks.`,
            Severity.MEDIUM,
            'AI API Analysis',
            domain,
            'Investigate the specific attack vector and implement targeted defenses',
            'Novel attack vectors may bypass existing WAF rules and security controls',
            'Add custom security tests for this attack vector',
            [],
          ));
        }
      }
    }
  } catch {}

  return { module: 'apiSecurity', findings, duration: 0, errors };
}

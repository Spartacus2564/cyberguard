import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logExploit, logVuln } from '../scanLogger';
import { getAI } from '../../services/ai.service';

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

// ─── MODULE: User Enumeration ───
async function testUserEnumeration(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('brokenAuth', 'UserEnum', baseUrl, 'Testing user enumeration via login error messages and timing');
  try {
    const endpoints = ['/login', '/api/login', '/login/admin', '/api/v1/login', '/signin'];
    const knownUsers = ['admin', 'root', 'administrator', 'user', 'test', 'info', 'support', 'webmaster'];
    const unknownUser = 'nonexistentusercg9821';

    for (const endpoint of endpoints) {
      try {
        // Compare responses for existing vs non-existing user (POST JSON)
        const knownBodies: { user: string; status: number; bodyLen: number }[] = [];
        const unknownResult = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ username: unknownUser, password: 'invalidpass123' }));

        if (!unknownResult.statusCode || unknownResult.statusCode === 0) continue;

        for (const user of knownUsers) {
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ username: user, password: 'invalidpass123' }));
          knownBodies.push({ user, status: res.statusCode, bodyLen: res.body.length });

          // Different HTTP status code = user enumeration
          if (res.statusCode !== unknownResult.statusCode) {
            findings.push(generateFinding(
              'User Enumeration via Login Response',
              `The login endpoint at ${endpoint} returns different status codes for existing vs. non-existing usernames, allowing account enumeration.`,
              Severity.MEDIUM,
              'Authentication',
              domain,
              `Endpoint: ${endpoint}, Username "${user}" → HTTP ${res.statusCode}, Non-existent user → HTTP ${unknownResult.statusCode}`,
              'Attackers can enumerate valid usernames to target with phishing, credential stuffing, or brute force attacks',
              'Return identical responses for all usernames; use generic error messages; implement rate limiting',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account']
            ));
            break;
          }
        }

        // Compare response body lengths — different body length for valid vs invalid users
        const unknownLen = unknownResult.body.length;
        const bodyDiffs = knownBodies.filter(b => Math.abs(b.bodyLen - unknownLen) > 50);
        if (bodyDiffs.length > 0 && knownBodies.length >= 2) {
          const diffUsers = bodyDiffs.map(d => d.user).join(', ');
          findings.push(generateFinding(
            'User Enumeration via Response Body Length',
            `The login endpoint at ${endpoint} returns responses with different body lengths for valid vs. invalid usernames.`,
            Severity.MEDIUM,
            'Authentication',
            domain,
            `Endpoint: ${endpoint}\nUnknown user "${unknownUser}" body: ${unknownLen} bytes\nKnown users (${diffUsers}) body: ${bodyDiffs[0].bodyLen} bytes\nKnown user statuses: ${knownBodies.map(b => `${b.user}=${b.status}/${b.bodyLen}b`).join(', ')}`,
            'Different response lengths allow attackers to enumerate valid usernames by measuring response size',
            'Return identical response body length for all login attempts regardless of username validity',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account']
          ));
        }
      } catch {}
    }
  } catch (e) { errors.push(`User Enum: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Login Form Over HTTP (Auth Transport) ───
async function testLoginOverHttp(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const httpUrl = `http://${domain}`;
    const endpoints = ['/login', '/signin', '/auth', '/account/login'];

    for (const endpoint of endpoints) {
      try {
        const res = await makeRequest(`${httpUrl}${endpoint}`, 'GET', {}, '');
        if (res.statusCode === 200) {
          const finalUrl = `${httpUrl}${endpoint}`;
          const bodyLower = res.body.toLowerCase();
          if (bodyLower.includes('password') || bodyLower.includes('login') || bodyLower.includes('signin')) {
            findings.push(generateFinding(
              'Authentication Form Served Over Cleartext HTTP',
              `The authentication interface is served over cleartext HTTP at ${finalUrl}, exposing credentials in transit.`,
              Severity.CRITICAL,
              'Authentication',
              domain,
              `URL: ${finalUrl}, Response contains login fields`,
              'Credentials transmitted over HTTP can be intercepted by network attackers (MITM, packet sniffing)',
              'Serve the entire application over HTTPS; enforce HSTS; redirect all HTTP traffic to HTTPS',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/']
            ));
            break;
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`Login HTTP: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Session Configuration Issues ───
async function testSessionConfig(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const res = await safeRequest(baseUrl, 'GET', {}, '');
    const setCookies = Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : (res.headers['set-cookie'] ? [String(res.headers['set-cookie'])] : []);
    if (setCookies.length === 0) return;

    for (const cookie of setCookies) {
      const cookieLower = cookie.toLowerCase();
      const name = cookie.split('=')[0].trim();

      // Session cookie without Secure flag
      if (!cookieLower.includes('secure')) {
        findings.push(generateFinding(
          'Session Cookie Without Secure Flag',
          `The session cookie "${name}" is not marked Secure, allowing transmission over HTTP.`,
          Severity.HIGH,
          'Authentication',
          domain,
          `Set-Cookie: ${cookie.substring(0, 200)}`,
          'Session cookies sent over HTTP can be intercepted, enabling session hijacking',
          'Add the Secure attribute to all session cookies; enforce HTTPS',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes']
        ));
      }

      // Session cookie without HttpOnly
      if (!cookieLower.includes('httponly')) {
        findings.push(generateFinding(
          'Session Cookie Without HttpOnly Flag',
          `The session cookie "${name}" is not marked HttpOnly, so it can be read by JavaScript.`,
          Severity.HIGH,
          'Authentication',
          domain,
          `Set-Cookie: ${cookie.substring(0, 200)}`,
          'XSS attacks can steal session cookies via document.cookie, leading to session hijacking',
          'Add the HttpOnly attribute to session cookies',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes']
        ));
      }

      // Short session lifetime
      const maxAgeMatch = cookieLower.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        if (maxAge > 86400) {
          findings.push(generateFinding(
            'Long-Lived Session Cookie',
            `Session cookie "${name}" has a Max-Age of ${maxAge}s (${Math.floor(maxAge / 86400)} days), increasing the window for session hijacking.`,
            Severity.MEDIUM,
            'Authentication',
            domain,
            `Set-Cookie: ${cookie.substring(0, 200)}`,
            'Long-lived sessions are vulnerable to prolonged session hijacking if a token is stolen',
            'Use short session lifetimes (1-24h); implement idle and absolute timeouts',
            ['https://owasp.org/www-community/Session_Management_Cheat_Sheet']
          ));
        }
      }

      // Session ID appears predictable/incremental
      const sessionId = cookie.split(';')[0].split('=').slice(1).join('=').trim();
      if (/^\d+$/.test(sessionId)) {
        findings.push(generateFinding(
          'Predictable Session Identifier',
          `Session cookie "${name}" uses a numeric sequential identifier (${sessionId}), which is highly predictable.`,
          Severity.CRITICAL,
          'Authentication',
          domain,
          `Session ID: ${sessionId}`,
          'Predictable session IDs allow attackers to guess and hijack active sessions by brute force',
          'Use cryptographically random session identifiers (128+ bits) generated by a secure PRNG',
          ['https://owasp.org/www-community/Session_Management_Cheat_Sheet']
        ));
      }
    }
  } catch (e) { errors.push(`Session: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Default Web Credentials & Admin Interfaces ───
async function testDefaultCreds(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('brokenAuth', 'DefaultCreds', baseUrl, 'Testing default credentials on admin interfaces');
  try {
    const adminEndpoints = [
      '/admin', '/panel', '/administrator', '/wp-admin', '/admin/login',
      '/api/admin/login', '/manage', '/management', '/control', '/console',
      '/phpmyadmin', '/pma', '/dbadmin', '/pgadmin', '/adminer',
      '/jenkins/login', '/actuator', '/console/login',
    ];
    let exposedAdminPanel = false;

    for (const path of adminEndpoints) {
      try {
        const res = await safeRequest(`${baseUrl}${path}`, 'GET', {}, '');
        if (res.statusCode === 200 && (res.body.toLowerCase().includes('password') || res.body.toLowerCase().includes('login') || res.body.toLowerCase().includes('username'))) {
          exposedAdminPanel = true;
          // Check for default credential patterns
          const bodyLower = res.body.toLowerCase();
          if (bodyLower.includes('default password') || bodyLower.includes('default credentials') || bodyLower.includes('admin/admin') || bodyLower.includes('change password')) {
            findings.push(generateFinding(
              'Default Credentials Documented',
              `Admin panel at ${path} documents default credentials, indicating they may still be in use.`,
              Severity.HIGH,
              'Authentication',
              domain,
              `URL: ${baseUrl}${path}, Page references default credentials`,
              'Default credentials allow immediate unauthorized admin access if not changed',
              'Remove default accounts and credentials; enforce strong password policy on first login',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/']
            ));
          }
        }
      } catch {}
    }

    // Test common default web credentials on login endpoints
    const loginEndpoints = ['/login', '/admin/login', '/wp-login.php', '/api/login'];
    const defaultCreds = [
      { user: 'admin', pass: 'admin' },
      { user: 'admin', pass: 'password' },
      { user: 'admin', pass: '12345678' },
      { user: 'root', pass: 'root' },
      { user: 'test', pass: 'test' },
    ];
    if (exposedAdminPanel) {
      for (const endpoint of loginEndpoints) {
        for (const cred of defaultCreds) {
          try {
            const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ username: cred.user, password: cred.pass, email: cred.user }));
            if (res.statusCode === 200 && (res.body.toLowerCase().includes('welcome') || res.body.toLowerCase().includes('dashboard') || res.body.toLowerCase().includes('token') || res.body.toLowerCase().includes('success'))) {
              findings.push(generateFinding(
                'Default Credentials Accepted',
                `The application accepted default credentials ${cred.user}/${cred.pass} at ${endpoint}.`,
                Severity.CRITICAL,
                'Authentication',
                domain,
                `Endpoint: ${endpoint}, Credentials: ${cred.user}/${cred.pass}, Response indicates successful login`,
                'Default credentials provide immediate unauthorized access to the application',
                'Disable all default accounts; enforce password change on first login; implement strong password policy',
                ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Bypassing_Authentication_Schema']
              ));
              return;
            }
          } catch {}
        }
      }
    }
  } catch (e) { errors.push(`Default Creds: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Account Lockout & Brute Force Protection ───
async function testAccountLockout(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const loginEndpoints = ['/login', '/api/login', '/signin', '/auth/login'];
    for (const endpoint of loginEndpoints) {
      const results: number[] = [];
      for (let i = 0; i < 10; i++) {
        try {
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ username: 'lockouttestuser', password: 'wrongpass' }));
          results.push(res.statusCode);
        } catch {
          results.push(0);
        }
      }
      const http200 = results.filter(c => c === 200).length;
      const http401 = results.filter(c => c === 401).length;
      const http429 = results.filter(c => c === 429).length;
      const http302 = results.filter(c => c === 302).length;
      const allSame = (http200 === 10) || (http401 === 10) || (http302 === 10);

      if (allSame && http429 === 0) {
        findings.push(generateFinding(
          'No Account Lockout / Brute Force Protection',
          `The login endpoint at ${endpoint} does not lock accounts or rate-limit after repeated failures (10 attempts, no 429/throttling).`,
          Severity.HIGH,
          'Authentication',
          domain,
          `Endpoint: ${endpoint}, 10 failed attempts returned statuses: ${[...new Set(results)].join(', ')}`,
          'Without lockout, attackers can brute-force credentials and perform credential stuffing attacks',
          'Implement account lockout after N failures, progressive delays, and CAPTCHA after repeated attempts',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/']
        ));
      }
    }
  } catch (e) { errors.push(`Lockout: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Registration & Privilege Escalation ───
async function testRegistration(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const registerEndpoints = ['/api/register', '/register', '/api/signup', '/signup', '/api/v1/register', '/api/users'];
    const roleParams = ['role', 'isAdmin', 'is_admin', 'admin', 'permissions', 'userType', 'type', 'level'];
    const payload = {
      email: `test${Date.now()}@example.com`,
      password: 'Password123!',
      username: 'testuser',
    };
    const payloads: Record<string, unknown>[] = [];
    for (const rp of roleParams) {
      payloads.push({ ...payload, [rp]: 'admin' });
      payloads.push({ ...payload, [rp]: true });
    }

    for (const endpoint of registerEndpoints) {
      try {
        // Baseline registration without role
        const base = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify(payload));
        if (base.statusCode !== 200 && base.statusCode !== 201) continue;

        for (const p of payloads) {
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify(p));
          const bodyLower = res.body.toLowerCase();
          const adminInResponse = bodyLower.includes('"role":"admin"') || bodyLower.includes('"isadmin":true') || bodyLower.includes('"admin":true');
          if (res.statusCode === 200 || res.statusCode === 201) {
            if (adminInResponse) {
              findings.push(generateFinding(
                'Privilege Escalation via Registration (Mass Assignment)',
                `The registration endpoint ${endpoint} accepts privileged fields (${Object.keys(p).filter(k => roleParams.includes(k)).join(', ')}) and reflects elevated privileges.`,
                Severity.CRITICAL,
                'Authentication',
                domain,
                `Endpoint: ${endpoint}, Payload: ${JSON.stringify(p)}, Response indicates admin role granted`,
                'Attackers can register with admin privileges, granting full control of the application',
                'Never allow clients to set privilege fields; use server-side role assignment; apply allowlists for mass assignment',
                ['https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/']
              ));
              return;
            }
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`Registration: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: 2FA Bypass Detection ───
async function test2FA(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('brokenAuth', '2FA-Bypass', baseUrl, 'Testing 2FA bypass via direct endpoint access and response manipulation');
  try {
    // Detect 2FA enforcement gaps via common MFA endpoints / headers
    const res = await safeRequest(baseUrl, 'GET', {}, '');
    const body = res.body.toLowerCase();

    // If 2FA is referenced, check for common weaknesses in its enforcement
    if (body.includes('two-factor') || body.includes('two factor') || body.includes('2fa') || body.includes('otp')) {
      // Check if the login response returns a session before 2FA completes
      const loginRes = await safeRequest(`${baseUrl}/login`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ username: 'test', password: 'test' }));
      if (loginRes.headers['set-cookie'] && loginRes.statusCode === 200) {
        findings.push(generateFinding(
          'Potential 2FA Bypass - Session Issued Before Verification',
          `The application appears to use 2FA but issues a session cookie before OTP verification completes.`,
          Severity.HIGH,
          'Authentication',
          domain,
          `Login response issued Set-Cookie before MFA step`,
          'If a session is created before 2FA verification, attackers can bypass MFA with just the password',
          'Only issue session cookies after ALL authentication factors are verified',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/']
        ));
      }
    }
  } catch (e) { errors.push(`2FA: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── Main Entry Point ───
export async function runBrokenAuthScan(domain: string, _profile?: unknown): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const baseUrl = `https://${domain}`;

    // Verify connectivity
    let connectivityOk = false;
    try { await makeRequest(baseUrl); connectivityOk = true; } catch {
      try { await makeRequest(`http://${domain}`); connectivityOk = true; } catch {}
    }
    if (!connectivityOk) {
      errors.push(`Could not connect to ${domain}`);
      const duration = Date.now() - startTime;
      return { module: 'brokenAuth', findings, duration, errors };
    }

    const batch1 = [
      testUserEnumeration(domain, baseUrl, findings, errors),
      testLoginOverHttp(domain, findings, errors),
      testSessionConfig(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch1);

    const batch2 = [
      testDefaultCreds(domain, baseUrl, findings, errors),
      testAccountLockout(domain, baseUrl, findings, errors),
      testRegistration(domain, baseUrl, findings, errors),
      test2FA(domain, baseUrl, findings, errors),
    ];
await Promise.allSettled(batch2);

    // AI-enhanced authentication analysis - session analysis, auth flow reasoning
    try {
      const ai = getAI();
      const authFindings = findings.filter(f => f.category === 'Authentication' || f.category === 'Broken Authentication');
      if (authFindings.length > 0) {
        const authTypes = [...new Set(authFindings.map(f => f.title))].join(', ');
        // Use AI to reason about authentication vulnerabilities
        const aiResult = await ai.reasonAboutVulnerabilities(['Authentication', 'Session Management'], authFindings);
        if (aiResult.chainingOpportunities.length > 0) {
          for (const chain of aiResult.chainingOpportunities) {
            findings.push(generateFinding(
              `AI-Detected Auth Chain: ${chain}`,
              `AI identified authentication attack chain: ${chain}. This may indicate session fixation, credential stuffing, or 2FA bypass paths.`,
              Severity.HIGH,
              'AI Auth Analysis',
              domain,
              'Review authentication flow for chaining opportunities. Implement proper session invalidation, rate limiting, and 2FA enforcement.',
              'Chained authentication vulnerabilities can lead to full account takeover',
              'Implement defense-in-depth: rate limiting, session rotation, 2FA, breach detection',
              [],
            ));
          }
        }
        if (aiResult.bypassTechniques.length > 0) {
          for (const bypass of aiResult.bypassTechniques) {
            findings.push(generateFinding(
              `AI-Detected Auth Bypass: ${bypass}`,
              `AI identified potential authentication bypass technique: ${bypass}. This may not be covered by standard auth tests.`,
              Severity.HIGH,
              'AI Auth Analysis',
              domain,
              'Investigate and test the specific bypass technique. Add targeted defenses.',
              'Authentication bypass techniques can completely circumvent access controls',
              'Add custom tests for this bypass technique in authentication flow',
              [],
            ));
          }
        }
        // Enrich top auth findings
        const criticalAuth = authFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 2);
        for (const f of criticalAuth) {
          try {
            await ai.enrichFindingEvidence(f, `Target: ${domain}, Auth findings: ${authTypes}`);
          } catch {}
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return { module: 'brokenAuth', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'brokenAuth',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

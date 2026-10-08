import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface HttpResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function request(
  method: string,
  rawUrl: string,
  body?: string,
  headers?: Record<string, string>,
  timeoutMs = 5000
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return reject(new Error(`Invalid URL: ${rawUrl}`));
    }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const port = parsed.port
      ? parseInt(parsed.port, 10)
      : isHttps
      ? 443
      : 80;

    const options = {
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'User-Agent': 'CyberGuard-AuthScanner/1.0',
        ...(body ? { 'Content-Length': Buffer.byteLength(body).toString() } : {}),
        ...headers,
      },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean };

    const chunks: Buffer[] = [];
    const req = lib.request(options, (res) => {
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers as Record<string, string | string[] | undefined>,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy(new Error(`Request timed out: ${rawUrl}`));
    });
    req.on('error', reject);

    if (body) req.write(body);
    req.end();
  });
}

function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string {
  const val = headers[name.toLowerCase()];
  if (!val) return '';
  return Array.isArray(val) ? val[0] : val;
}

function extractCookies(
  headers: Record<string, string | string[] | undefined>
): string {
  const raw = headers['set-cookie'];
  if (!raw) return '';
  const arr = Array.isArray(raw) ? raw : [raw];
  return arr
    .map((c) => c.split(';')[0].trim())
    .join('; ');
}

function tryParseJson(body: string): Record<string, unknown> | null {
  try {
    return JSON.parse(body) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function bodyContainsField(body: string, fields: string[]): string[] {
  const lower = body.toLowerCase();
  return fields.filter((f) => lower.includes(`"${f.toLowerCase()}":`));
}

// Derive a base URL (scheme + host[:port]) from the domain string
function baseUrl(domain: string): string {
  if (domain.startsWith('http://') || domain.startsWith('https://')) {
    const u = new URL(domain);
    return `${u.protocol}//${u.host}`;
  }
  // Default to https; caller can pass http://… explicitly
  return `https://${domain}`;
}

// ---------------------------------------------------------------------------
// Login attempt
// ---------------------------------------------------------------------------

interface LoginResult {
  success: boolean;
  token: string | null;
  cookieHeader: string;
  userId: string | null;
  sessionTokenBefore: string;
}

async function attemptLogin(
  base: string,
  username: string,
  password: string,
  loginUrlOverride: string | null
): Promise<LoginResult> {
  const loginPaths = loginUrlOverride
    ? [loginUrlOverride]
    : [
        `${base}/api/login`,
        `${base}/login`,
        `${base}/api/auth/login`,
      ];

  const jsonBody = JSON.stringify({ username, password });
  const formBody = `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;

  // We'll try a unique pre-login token to detect session fixation
  const preLoginToken = `cyberguard-preflight-${Date.now()}`;

  for (const url of loginPaths) {
    // --- JSON attempt ---
    for (const [contentType, body] of [
      ['application/json', jsonBody],
      ['application/x-www-form-urlencoded', formBody],
    ]) {
      try {
        const res = await request('POST', url, body, {
          'Content-Type': contentType,
          'X-Preflight-Token': preLoginToken,
        });

        if (res.statusCode === 200 || res.statusCode === 201) {
          // Look for JWT in body
          let token: string | null = null;
          const json = tryParseJson(res.body);
          if (json) {
            for (const key of ['token', 'access_token', 'accessToken', 'jwt', 'id_token']) {
              if (typeof json[key] === 'string') {
                token = json[key] as string;
                break;
              }
            }
          }

          const cookieHeader = extractCookies(res.headers);
          const authHeader = getHeader(res.headers, 'authorization');
          if (!token && authHeader.toLowerCase().startsWith('bearer ')) {
            token = authHeader.slice(7);
          }

          let userId: string | null = null;
          if (json) {
            for (const key of ['id', 'userId', 'user_id', 'sub']) {
              if (json[key] !== undefined) {
                userId = String(json[key]);
                break;
              }
              const user = json['user'] as Record<string, unknown> | undefined;
              if (user && user[key] !== undefined) {
                userId = String(user[key]);
                break;
              }
            }
          }

          if (token || cookieHeader) {
            return {
              success: true,
              token,
              cookieHeader,
              userId,
              sessionTokenBefore: preLoginToken,
            };
          }
        }
      } catch {
        // Try next
      }
    }
  }

  return {
    success: false,
    token: null,
    cookieHeader: '',
    userId: null,
    sessionTokenBefore: preLoginToken,
  };
}

function authHeaders(login: LoginResult): Record<string, string> {
  const h: Record<string, string> = {};
  if (login.token) h['Authorization'] = `Bearer ${login.token}`;
  if (login.cookieHeader) h['Cookie'] = login.cookieHeader;
  return h;
}

// ---------------------------------------------------------------------------
// Individual test suites
// ---------------------------------------------------------------------------

async function testIdorBola(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  const paths = [
    '/api/users/1',
    '/api/users/2',
    '/api/v1/users/1',
    '/api/profile/1',
  ];

  for (const path of paths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200) {
        const json = tryParseJson(res.body);
        if (json) {
          // If a userId is known and the response has a different one, BOLA
          let returnedId: string | null = null;
          for (const key of ['id', 'userId', 'user_id']) {
            if (json[key] !== undefined) {
              returnedId = String(json[key]);
              break;
            }
          }
          const isBola =
            login.userId &&
            returnedId &&
            returnedId !== login.userId;

          if (isBola || json) {
            findings.push(
              generateFinding({
                title: 'IDOR / BOLA – Unauthorized Object Access',
                description: `Endpoint ${path} returned data for a different user without ownership validation.`,
                severity: Severity.CRITICAL,
                category: 'Authenticated Scanning',
                affectedAsset: base,
                evidence: `GET ${base}${path} → HTTP ${res.statusCode}\n${res.body.slice(0, 500)}`,
                impact:
                  'Attackers can access any user\'s data by enumerating object IDs, leading to full data exposure.',
                remediation:
                  'Enforce server-side ownership checks on every object-level endpoint. Never rely on IDs alone; validate that the authenticated user owns the requested resource.',
                references: [
                  'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
                ],
              })
            );
            break; // One BOLA finding is enough
          }
        }
      }
    } catch (e) {
      errors.push(`IDOR test ${path}: ${(e as Error).message}`);
    }
  }
}

async function testPrivilegeEscalation(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  const adminPaths = ['/api/admin', '/api/admin/users', '/api/settings/all'];

  for (const path of adminPaths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200 && res.body.trim().length > 0) {
        findings.push(
          generateFinding({
            title: 'Privilege Escalation – Unauthorized Admin Endpoint Access',
            description: `A low-privilege session accessed the administrative endpoint ${path} and received a 200 response with data.`,
            severity: Severity.CRITICAL,
            category: 'Authenticated Scanning',
            affectedAsset: base,
            evidence: `GET ${base}${path} → HTTP ${res.statusCode}\n${res.body.slice(0, 500)}`,
            impact:
              'A regular user can perform administrative actions, potentially modifying or viewing all application data.',
            remediation:
              'Implement role-based access control (RBAC) on all admin endpoints. Validate the user\'s role server-side on every request.',
            references: [
              'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
            ],
          })
        );
      }
    } catch (e) {
      errors.push(`Privilege escalation test ${path}: ${(e as Error).message}`);
    }
  }
}

async function testForcedBrowsing(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  const paths = ['/api/v1/admin/users', '/api/v1/admin/settings', '/api/users'];

  for (const path of paths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200 && res.body.trim().length > 0) {
        findings.push(
          generateFinding({
            title: 'Forced Browsing – Privileged Endpoint Accessible',
            description: `Endpoint ${path} is accessible to authenticated users who should not have access.`,
            severity: Severity.HIGH,
            category: 'Authenticated Scanning',
            affectedAsset: base,
            evidence: `GET ${base}${path} → HTTP ${res.statusCode}\n${res.body.slice(0, 400)}`,
            impact:
              'Attackers can enumerate internal endpoints and access data or functionality beyond their permission level.',
            remediation:
              'Apply function-level authorization checks. Ensure endpoints not intended for regular users return 401 or 403 for non-admin sessions.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema',
            ],
          })
        );
      }
    } catch (e) {
      errors.push(`Forced browsing test ${path}: ${(e as Error).message}`);
    }
  }
}

async function testSensitiveDataExposure(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  const sensitiveFields = [
    'password',
    'password_hash',
    'passwordHash',
    'ssn',
    'social_security',
    'credit_card',
    'creditCard',
    'card_number',
    'cardNumber',
    'private_key',
    'privateKey',
    'secret',
    'api_key',
    'apiKey',
  ];

  const profilePaths = ['/api/me', '/api/profile'];

  for (const path of profilePaths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200) {
        const found = bodyContainsField(res.body, sensitiveFields);
        if (found.length > 0) {
          findings.push(
            generateFinding({
              title: 'Sensitive Data Exposure in Authenticated Response',
              description: `The endpoint ${path} returns sensitive fields in the response body: ${found.join(', ')}.`,
              severity: Severity.HIGH,
              category: 'Authenticated Scanning',
              affectedAsset: base,
              evidence: `GET ${base}${path} → HTTP ${res.statusCode}\nSensitive fields detected: ${found.join(', ')}\n${res.body.slice(0, 400)}`,
              impact:
                'Credentials, PII, or cryptographic material exposed in API responses can be harvested by an attacker with a valid session.',
              remediation:
                'Apply allowlist-based serialisation. Never return password hashes, raw credentials, SSNs, or card data in API responses. Mask or omit sensitive fields.',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
              ],
            })
          );
        }
      }
    } catch (e) {
      errors.push(`Sensitive data test ${path}: ${(e as Error).message}`);
    }
  }
}

async function testSessionFixation(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  // After login, check if the token issued equals the pre-login sentinel we sent
  // (some apps echo back whatever session ID they received)
  try {
    const issuedToken = login.token ?? login.cookieHeader;
    if (issuedToken && issuedToken.includes(login.sessionTokenBefore)) {
      findings.push(
        generateFinding({
          title: 'Session Fixation – Pre-Login Token Reused After Authentication',
          description:
            'The application issued the same session token that was present before login, allowing an attacker to set a known session ID and hijack the authenticated session.',
          severity: Severity.HIGH,
          category: 'Authenticated Scanning',
          affectedAsset: base,
          evidence: `Pre-login token: ${login.sessionTokenBefore}\nPost-login token: ${issuedToken.slice(0, 200)}`,
          impact:
            'An attacker who can set a victim\'s session ID before login can take over their authenticated session.',
          remediation:
            'Generate a new, cryptographically random session token upon successful authentication and invalidate any pre-login token.',
          references: [
            'https://owasp.org/www-community/attacks/Session_fixation',
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
          ],
        })
      );
    }
  } catch (e) {
    errors.push(`Session fixation test: ${(e as Error).message}`);
  }
}

async function testLogoutInvalidation(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success) return;

  const logoutPaths = ['/logout', '/api/logout', '/api/auth/logout'];

  // Try to log out
  for (const path of logoutPaths) {
    try {
      await request('POST', `${base}${path}`, undefined, authHeaders(login));
      break;
    } catch {
      // Try GET as fallback
      try {
        await request('GET', `${base}${path}`, undefined, authHeaders(login));
        break;
      } catch {
        // Continue
      }
    }
  }

  // After logout, retry the session token on /api/me
  const checkPaths = ['/api/me', '/api/profile'];
  for (const path of checkPaths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200 && res.body.trim().length > 0) {
        findings.push(
          generateFinding({
            title: 'Session Token Not Invalidated After Logout',
            description: `After calling the logout endpoint, the session token still grants access to ${path}. The server-side session was not invalidated.`,
            severity: Severity.HIGH,
            category: 'Authenticated Scanning',
            affectedAsset: base,
            evidence: `POST/GET logout, then GET ${base}${path} → HTTP ${res.statusCode}\n${res.body.slice(0, 300)}`,
            impact:
              'Stolen or intercepted tokens remain valid after the user logs out, enabling persistent session hijacking.',
            remediation:
              'Invalidate session tokens server-side upon logout. Maintain a token revocation list or use short-lived tokens with no refresh after logout.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration',
            ],
          })
        );
        break;
      }
    } catch (e) {
      errors.push(`Logout invalidation test ${path}: ${(e as Error).message}`);
    }
  }
}

async function testHorizontalPrivilegeEscalation(
  base: string,
  login: LoginResult,
  findings: Finding[],
  errors: string[]
): Promise<void> {
  if (!login.success || !login.userId) return;

  // Try to derive a different numeric user ID by incrementing/decrementing
  const myId = parseInt(login.userId, 10);
  if (isNaN(myId)) return;

  const otherId = myId === 1 ? 2 : myId - 1;

  const targetPaths = [
    `/api/users/${otherId}/profile`,
    `/api/users/${otherId}`,
    `/api/orders/${otherId}`,
    `/api/profile/${otherId}`,
  ];

  for (const path of targetPaths) {
    try {
      const res = await request('GET', `${base}${path}`, undefined, authHeaders(login));
      if (res.statusCode === 200 && res.body.trim().length > 0) {
        const json = tryParseJson(res.body);
        // Confirm it really is a different user's data
        let returnedId: string | null = null;
        if (json) {
          for (const key of ['id', 'userId', 'user_id']) {
            if (json[key] !== undefined) {
              returnedId = String(json[key]);
              break;
            }
          }
        }
        if (!returnedId || returnedId !== login.userId) {
          findings.push(
            generateFinding({
              title: 'Horizontal Privilege Escalation – Access to Another User\'s Resources',
              description: `User ${login.userId} was able to access resources belonging to user ${otherId} via ${path}.`,
              severity: Severity.CRITICAL,
              category: 'Authenticated Scanning',
              affectedAsset: base,
              evidence: `GET ${base}${path} (logged in as user ${login.userId}) → HTTP ${res.statusCode}\n${res.body.slice(0, 400)}`,
              impact:
                'Any authenticated user can read or modify another user\'s data by changing an ID in the URL.',
              remediation:
                'Enforce ownership checks on every resource endpoint. Reject requests where the authenticated user ID does not match the resource owner ID.',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
              ],
            })
          );
          break;
        }
      }
    } catch (e) {
      errors.push(`Horizontal privilege escalation test ${path}: ${(e as Error).message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function runAuthScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  const username = process.env.SCAN_USERNAME ?? 'admin';
  const password = process.env.SCAN_PASSWORD ?? 'admin';
  const loginUrlOverride = process.env.SCAN_LOGIN_URL ?? null;

  const base = baseUrl(domain);

  // Gate: total scan must complete within 30 s
  const SCAN_DEADLINE = startTime + 30_000;

  const withDeadline = async (fn: () => Promise<void>): Promise<void> => {
    if (Date.now() >= SCAN_DEADLINE) return;
    try {
      await fn();
    } catch (e) {
      errors.push((e as Error).message);
    }
  };

  // Step 1: Attempt login
  let login: LoginResult = {
    success: false,
    token: null,
    cookieHeader: '',
    userId: null,
    sessionTokenBefore: '',
  };

  try {
    login = await attemptLogin(base, username, password, loginUrlOverride);
  } catch (e) {
    errors.push(`Login attempt failed: ${(e as Error).message}`);
  }

  // Step 2: Run all authenticated tests
  await withDeadline(() => testIdorBola(base, login, findings, errors));
  await withDeadline(() => testPrivilegeEscalation(base, login, findings, errors));
  await withDeadline(() => testForcedBrowsing(base, login, findings, errors));
  await withDeadline(() => testSensitiveDataExposure(base, login, findings, errors));
  await withDeadline(() => testSessionFixation(base, login, findings, errors));
  // Logout invalidation test should run last as it logs out the session
  await withDeadline(() => testLogoutInvalidation(base, login, findings, errors));
  await withDeadline(() => testHorizontalPrivilegeEscalation(base, login, findings, errors));

  const duration = Date.now() - startTime;

  return {
    module: 'authScan' as any,
    findings,
    duration,
    errors,
  };
}

import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface RequestResult {
  status: number;
  body: string;
  error?: string;
}

function makeRequest(
  url: string,
  method: string,
  body: string,
  headers: Record<string, string> = {},
  timeoutMs = 8000
): Promise<RequestResult> {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: RequestResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      settle({ status: 0, body: '', error: `Invalid URL: ${url}` });
      return;
    }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const bodyBuf = Buffer.from(body, 'utf8');

    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(bodyBuf.length),
        'User-Agent': 'CyberGuard-RaceConditionScanner/1.0',
        ...headers,
      },
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () =>
        settle({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') })
      );
      res.on('error', (err) => settle({ status: 0, body: '', error: err.message }));
    });

    req.on('error', (err) => settle({ status: 0, body: '', error: err.message }));

    const timer = setTimeout(() => settle({ status: 0, body: '', error: 'Request timeout' }), timeoutMs);
    req.on('close', () => clearTimeout(timer));

    req.write(bodyBuf);
    req.end();
  });
}

/** Fire `count` identical requests in true parallel and return all results. */
async function burstRequests(
  url: string,
  method: string,
  body: string,
  count: number,
  headers?: Record<string, string>
): Promise<RequestResult[]> {
  const tasks = Array.from({ length: count }, () => makeRequest(url, method, body, headers));
  return Promise.all(tasks);
}

/** Wrap a test in a 15-second overall timeout. */
function withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Test "${label}" timed out after 15s`)), 15_000)
    ),
  ]);
}

function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

function countSuccesses(results: RequestResult[]): number {
  return results.filter((r) => isSuccess(r.status)).length;
}

function evidence(successes: number, total: number): string {
  return `${successes} of ${total} parallel requests succeeded`;
}

// ---------------------------------------------------------------------------
// Individual test runners
// ---------------------------------------------------------------------------

async function testCouponRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const endpoints = ['/api/coupons/apply', '/api/promo/apply', '/api/vouchers/redeem'];
  const body = JSON.stringify({ code: 'TESTCODE2024', coupon_code: 'TESTCODE2024' });

  for (const path of endpoints) {
    try {
      const results = await burstRequests(`${base}${path}`, 'POST', body, 10);
      const successes = countSuccesses(results);
      if (successes > 1) {
        findings.push(
          generateFinding({
            title: 'Race Condition in Coupon/Voucher Redemption',
            description: `Endpoint ${path} accepted the same coupon code in ${successes} concurrent requests. This allows a single-use code to be redeemed multiple times. Evidence: ${evidence(successes, 10)}`,
            severity: Severity.CRITICAL,
            category: 'Race Condition',
            affectedAsset: path,
            evidence: `${evidence(successes, 10)}`,
            impact: 'A single-use coupon or voucher can be redeemed multiple times, causing financial loss.',
            remediation: 'Implement idempotency keys or server-side locking to ensure a coupon code can only be applied once per user.',
          })
        );
      }
    } catch (err) {
      errors.push(`Coupon race (${path}): ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}

async function testRegistrationRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const body = JSON.stringify({
    username: 'race_test_user_' + Date.now(),
    email: `race_test_${Date.now()}@example.com`,
    password: 'TestPassword123!',
  });

  try {
    const results = await burstRequests(`${base}/api/register`, 'POST', body, 5);
    const successes = countSuccesses(results);
    if (successes > 1) {
      findings.push(
        generateFinding({
          title: 'Race Condition in User Registration -- Duplicate Account Creation',
          description: `${successes} concurrent registration requests with the same username/email all succeeded, potentially creating duplicate accounts. Evidence: ${evidence(successes, 5)}`,
          severity: Severity.HIGH,
          category: 'Race Condition',
          affectedAsset: '/api/register',
          evidence: `${evidence(successes, 5)}`,
          impact: 'Duplicate user accounts can be created, leading to data integrity issues and potential privilege escalation.',
          remediation: 'Use database unique constraints or application-level locking to prevent duplicate registrations.',
        })
      );
    }
  } catch (err) {
    errors.push(`Registration race: ${(err as Error).message}`);
  }
  return { findings, errors };
}

async function testFundTransferRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const endpoints = ['/api/transfer', '/api/payment', '/api/withdraw', '/api/redeem'];
  const body = JSON.stringify({ amount: 1, to: 'test_recipient', currency: 'USD' });

  for (const path of endpoints) {
    try {
      const results = await burstRequests(`${base}${path}`, 'POST', body, 10);
      const successes = countSuccesses(results);
      if (successes > 1) {
        findings.push(
          generateFinding({
            title: 'Race Condition in Fund/Balance Transfer',
            description: `Endpoint ${path} processed ${successes} identical transfer requests simultaneously. Double-spend or overdraft may be possible. Evidence: ${evidence(successes, 10)}`,
            severity: Severity.CRITICAL,
            category: 'Race Condition',
            affectedAsset: path,
            evidence: `${evidence(successes, 10)}`,
            impact: 'Users can double-spend or withdraw more than their balance allows, resulting in direct financial loss.',
            remediation: 'Use database transactions with proper isolation levels, or implement distributed locks to serialize fund operations.',
          })
        );
      }
    } catch (err) {
      errors.push(`Fund transfer race (${path}): ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}

async function testLikeVoteRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const endpoints = ['/api/posts/1/like', '/api/items/1/vote', '/api/articles/1/upvote'];

  for (const path of endpoints) {
    try {
      const results = await burstRequests(`${base}${path}`, 'POST', '{}', 10);
      const successes = countSuccesses(results);
      if (successes > 1) {
        findings.push(
          generateFinding({
            title: 'Race Condition in Like/Vote Deduplication',
            description: `Endpoint ${path} accepted ${successes} concurrent like/vote actions from the same context. Counter may be inflated beyond 1. Evidence: ${evidence(successes, 10)}`,
            severity: Severity.MEDIUM,
            category: 'Race Condition',
            affectedAsset: path,
            evidence: `${evidence(successes, 10)}`,
            impact: 'Like/vote counters can be artificially inflated, distorting engagement metrics.',
            remediation: 'Use idempotent operations or database-level deduplication to ensure only one action is counted per user per resource.',
          })
        );
      }
    } catch (err) {
      errors.push(`Like/vote race (${path}): ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}

async function testSessionCreationRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const body = JSON.stringify({ username: 'test_user', password: 'TestPassword123!' });

  try {
    const results = await burstRequests(`${base}/api/login`, 'POST', body, 5);
    const successes = countSuccesses(results);
    if (successes > 1) {
      // Check if multiple distinct session tokens were returned
      const tokens = results
        .filter((r) => isSuccess(r.status))
        .map((r) => {
          try {
            const parsed = JSON.parse(r.body);
            return parsed.token ?? parsed.session_id ?? parsed.access_token ?? null;
          } catch {
            return null;
          }
        })
        .filter(Boolean);
      const uniqueTokens = new Set(tokens).size;
      if (uniqueTokens > 1 || successes > 1) {
        findings.push(
          generateFinding({
            title: 'Potential Session Token Race on Login',
            description: `${successes} concurrent login requests all succeeded, producing ${uniqueTokens} distinct session token(s). Parallel session creation may bypass single-session enforcement. Evidence: ${evidence(successes, 5)}`,
            severity: Severity.MEDIUM,
            category: 'Race Condition',
            affectedAsset: '/api/login',
            evidence: `${evidence(successes, 5)}`,
            impact: 'Multiple valid sessions can be created simultaneously, potentially bypassing single-session or concurrency limits.',
            remediation: 'Invalidate existing sessions before creating new ones, or use distributed locks to serialize session creation.',
          })
        );
      }
    }
  } catch (err) {
    errors.push(`Session creation race: ${(err as Error).message}`);
  }
  return { findings, errors };
}

async function testOtpVerificationRace(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const endpoints = ['/api/verify-otp', '/api/verify-email', '/api/confirm-email'];
  const body = JSON.stringify({ otp: '123456', token: 'test_verification_token', code: '123456' });

  for (const path of endpoints) {
    try {
      const results = await burstRequests(`${base}${path}`, 'POST', body, 5);
      const successes = countSuccesses(results);
      if (successes > 1) {
        findings.push(
          generateFinding({
            title: 'Race Condition in OTP/Email Verification',
            description: `Endpoint ${path} accepted the same OTP/verification token ${successes} times concurrently. A single-use verification code may be reused. Evidence: ${evidence(successes, 5)}`,
            severity: Severity.HIGH,
            category: 'Race Condition',
            affectedAsset: path,
            evidence: `${evidence(successes, 5)}`,
            impact: 'A single-use OTP or verification token can be consumed multiple times, bypassing the intended one-time-use protection.',
            remediation: 'Mark tokens as used atomically before validating them, using a database transaction or distributed lock.',
          })
        );
      }
    } catch (err) {
      errors.push(`OTP verification race (${path}): ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}

async function testToctouFileUpload(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const filename = `race_test_${Date.now()}.txt`;
  const body = JSON.stringify({ filename, content: 'race condition test payload' });

  try {
    const results = await burstRequests(`${base}/api/upload`, 'POST', body, 5);
    const successResults = results.filter((r) => isSuccess(r.status));
    if (successResults.length > 1) {
      // Extract file IDs or paths from responses
      const ids = successResults
        .map((r) => {
          try {
            const parsed = JSON.parse(r.body);
            return parsed.id ?? parsed.file_id ?? parsed.path ?? parsed.url ?? null;
          } catch {
            return null;
          }
        })
        .filter(Boolean);
      const uniqueIds = new Set(ids).size;
      if (uniqueIds > 1 || successResults.length > 1) {
        findings.push(
          generateFinding({
            title: 'TOCTOU Vulnerability in File Upload Handling',
            description: `${successResults.length} concurrent uploads of the same filename succeeded, returning ${uniqueIds} distinct resource ID(s). This indicates a Time-of-Check-Time-of-Use (TOCTOU) race in file path/ID assignment. Evidence: ${evidence(successResults.length, 5)}`,
            severity: Severity.MEDIUM,
            category: 'Race Condition',
            affectedAsset: '/api/upload',
            evidence: `${evidence(successResults.length, 5)}`,
            impact: 'Concurrent file uploads with the same name can overwrite or bypass file path checks, leading to data corruption or unauthorized file access.',
            remediation: 'Use unique temporary filenames and rename atomically after validation, or use object storage with unique keys.',
          })
        );
      }
    }
  } catch (err) {
    errors.push(`TOCTOU file upload: ${(err as Error).message}`);
  }
  return { findings, errors };
}

async function testRateLimitBypass(base: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const body = JSON.stringify({ username: 'rate_limit_test', password: 'WrongPassword!' });

  try {
    const results = await burstRequests(`${base}/api/login`, 'POST', body, 20);
    const nonRateLimited = results.filter((r) => r.status !== 429 && r.status !== 0).length;
    if (nonRateLimited === 20) {
      findings.push(
        generateFinding({
          title: 'Rate Limiting Bypassed via Concurrent Requests',
          description: `All 20 simultaneous login requests were processed without triggering a 429 rate-limit response. The rate limiter likely operates per-sequential-request rather than on burst traffic, allowing brute-force via parallelism. Evidence: ${evidence(nonRateLimited, 20)} returned non-429`,
          severity: Severity.MEDIUM,
          category: 'Race Condition',
          affectedAsset: '/api/login',
          evidence: `${evidence(nonRateLimited, 20)} returned non-429`,
          impact: 'Attackers can bypass rate limiting by sending requests in parallel, enabling brute-force attacks.',
          remediation: 'Implement rate limiting at the network or load-balancer level using sliding window counters or token buckets that account for burst traffic.',
        })
      );
    }
  } catch (err) {
    errors.push(`Rate limit bypass: ${(err as Error).message}`);
  }
  return { findings, errors };
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function runRaceConditionScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const allFindings: Finding[] = [];
  const allErrors: string[] = [];

  // Normalise base URL
  const base = domain.startsWith('http') ? domain.replace(/\/$/, '') : `https://${domain}`;

  const tests: Array<{ label: string; fn: () => Promise<{ findings: Finding[]; errors: string[] }> }> = [
    { label: 'Coupon/Promo Race',        fn: () => testCouponRace(base) },
    { label: 'Registration Race',        fn: () => testRegistrationRace(base) },
    { label: 'Fund Transfer Race',       fn: () => testFundTransferRace(base) },
    { label: 'Like/Vote Dedup Race',     fn: () => testLikeVoteRace(base) },
    { label: 'Session Creation Race',    fn: () => testSessionCreationRace(base) },
    { label: 'OTP Verification Race',    fn: () => testOtpVerificationRace(base) },
    { label: 'TOCTOU File Upload',       fn: () => testToctouFileUpload(base) },
    { label: 'Rate Limit Burst Bypass',  fn: () => testRateLimitBypass(base) },
  ];

  for (const test of tests) {
    try {
      const { findings, errors } = await withTimeout(test.fn(), test.label);
      allFindings.push(...findings);
      allErrors.push(...errors);
    } catch (err) {
      allErrors.push(`${test.label}: ${(err as Error).message}`);
    }
  }

  return {
    module: 'raceCondition' as any,
    findings: allFindings,
    duration: Date.now() - startTime,
    errors: allErrors,
  };
}

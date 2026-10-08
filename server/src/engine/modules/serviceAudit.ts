import { Finding, Severity } from '../../types';
import { generateFinding, fetchUrl } from './shared';
import { randomUUID } from 'crypto';
import net from 'net';
import dns from 'dns';

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function measureTcp(host: string, port: number, timeout = 5000): Promise<{ open: boolean; banner: string; latency: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let banner = '';
    socket.setTimeout(timeout);
    socket.on('connect', () => {
      const latency = Date.now() - start;
      // Try to grab banner
      socket.once('data', (data) => {
        banner = data.toString().trim().substring(0, 512);
        socket.destroy();
        resolve({ open: true, banner, latency });
      });
      // Send HTTP request to grab banner if no banner comes
      setTimeout(() => {
        if (banner) return;
        try { socket.write(`GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n`); } catch {}
        setTimeout(() => {
          socket.destroy();
          resolve({ open: true, banner, latency });
        }, 1000);
      }, 500);
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ open: false, banner: '', latency: timeout }); });
    socket.on('error', () => { socket.destroy(); resolve({ open: false, banner: '', latency: Date.now() - start }); });
    socket.connect(port, host);
  });
}

function resolveHost(domain: string): Promise<string[]> {
  return new Promise((resolve) => {
    dns.resolve4(domain, (err, addresses) => {
      if (err) resolve([]);
      else resolve(addresses);
    });
  });
}

// ─── DATABASE EXPOSURE ──────────────────────────────────────────────────────
const DATABASE_PORTS = [
  { port: 3306, name: 'MySQL', protocol: 'mysql' },
  { port: 5432, name: 'PostgreSQL', protocol: 'postgresql' },
  { port: 27017, name: 'MongoDB', protocol: 'mongodb' },
  { port: 6379, name: 'Redis', protocol: 'redis' },
  { port: 9200, name: 'Elasticsearch', protocol: 'elasticsearch' },
  { port: 9300, name: 'Elasticsearch (transport)', protocol: 'elasticsearch' },
  { port: 5984, name: 'CouchDB', protocol: 'couchdb' },
  { port: 8529, name: 'ArangoDB', protocol: 'arangodb' },
  { port: 7474, name: 'Neo4j HTTP', protocol: 'neo4j' },
  { port: 7687, name: 'Neo4j Bolt', protocol: 'neo4j' },
  { port: 1433, name: 'MS SQL Server', protocol: 'mssql' },
  { port: 1521, name: 'Oracle DB', protocol: 'oracle' },
  { port: 50000, name: 'SAP HANA', protocol: 'sap' },
  { port: 11211, name: 'Memcached', protocol: 'memcached' },
  { port: 11212, name: 'Memcached (alt)', protocol: 'memcached' },
  { port: 6370, name: 'Redis (alt)', protocol: 'redis' },
  { port: 27018, name: 'MongoDB Shard', protocol: 'mongodb' },
  { port: 5080, name: 'Cassandra', protocol: 'cassandra' },
  { port: 9042, name: 'Cassandra Native', protocol: 'cassandra' },
  { port: 9092, name: 'Apache Kafka', protocol: 'kafka' },
  { port: 8086, name: 'InfluxDB', protocol: 'influxdb' },
  { port: 5439, name: 'Amazon Redshift', protocol: 'redshift' },
  { port: 51298, name: 'Couchbase', protocol: 'couchbase' },
  { port: 9100, name: 'ClickHouse HTTP', protocol: 'clickhouse' },
  { port: 9000, name: 'ClickHouse Native', protocol: 'clickhouse' },
];

async function testDatabaseExposure(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ips = await resolveHost(domain);
  if (ips.length === 0) return findings;
  const ip = ips[0];

  // Test common database ports
  const portTests = await Promise.all(
    DATABASE_PORTS.map(async (db) => {
      const result = await measureTcp(ip, db.port, 4000);
      return { ...db, ...result };
    })
  );

  for (const db of portTests) {
    if (!db.open) continue;

    // Check for unauthenticated access
    let unauthenticated = false;
    let evidence = `Port ${db.port} (${db.name}) is open on ${ip}.`;
    if (db.banner) evidence += `\nBanner: ${db.banner}`;

    // Redis: try PING
    if (db.protocol === 'redis') {
      try {
        const sock = new net.Socket();
        await new Promise<void>((resolve) => {
          sock.setTimeout(3000);
          sock.connect(db.port, ip, () => {
            sock.write('PING\r\n');
          });
          sock.on('data', (data) => {
            const resp = data.toString();
            if (resp.includes('PONG') || resp.includes('+OK')) {
              unauthenticated = true;
              evidence += '\nRedis PING returned PONG — unauthenticated access confirmed.';
            }
            sock.destroy();
            resolve();
          });
          sock.on('error', () => { sock.destroy(); resolve(); });
          sock.on('timeout', () => { sock.destroy(); resolve(); });
        });
      } catch {}
    }

    // Elasticsearch: try _cat/indices
    if (db.protocol === 'elasticsearch') {
      try {
        const res = await fetchUrl(`http://${ip}:${db.port}/_cat/indices?format=json`, 3000);
        if (res.statusCode === 200) {
          unauthenticated = true;
          const indices = res.body.substring(0, 500);
          evidence += `\nElasticsearch _cat/indices accessible without auth. Indices: ${indices}`;
        }
      } catch {}
    }

    // MongoDB: check if wire protocol responds
    if (db.protocol === 'mongodb') {
      try {
        const sock = new net.Socket();
        await new Promise<void>((resolve) => {
          sock.setTimeout(3000);
          sock.connect(db.port, ip, () => {
            // MongoDB isMaster command
            const cmd = Buffer.from(
              '\x39\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00isMaster\x00\x00\x00\x00\x00',
              'binary'
            );
            sock.write(cmd);
          });
          sock.on('data', (data) => {
            if (data.length > 0) {
              unauthenticated = true;
              evidence += '\nMongoDB wire protocol responded — may allow unauthenticated queries.';
            }
            sock.destroy();
            resolve();
          });
          sock.on('error', () => { sock.destroy(); resolve(); });
          sock.on('timeout', () => { sock.destroy(); resolve(); });
        });
      } catch {}
    }

    // CouchDB: try /_all_dbs
    if (db.protocol === 'couchdb') {
      try {
        const res = await fetchUrl(`http://${ip}:${db.port}/_all_dbs`, 3000);
        if (res.statusCode === 200) {
          unauthenticated = true;
          evidence += `\nCouchDB _all_dbs accessible: ${res.body.substring(0, 300)}`;
        }
      } catch {}
    }

    // Neo4j: try /db/data/
    if (db.protocol === 'neo4j') {
      try {
        const res = await fetchUrl(`http://${ip}:${db.port}/db/data/`, 3000);
        if (res.statusCode === 200) {
          unauthenticated = true;
          evidence += '\nNeo4j browser/data API accessible without auth.';
        }
      } catch {}
    }

    // Memcached: try stats command
    if (db.protocol === 'memcached') {
      try {
        const sock = new net.Socket();
        await new Promise<void>((resolve) => {
          sock.setTimeout(3000);
          sock.connect(db.port, ip, () => {
            sock.write('stats\r\n');
          });
          sock.on('data', (data) => {
            const resp = data.toString();
            if (resp.includes('STAT version') || resp.includes('STAT uptime')) {
              unauthenticated = true;
              evidence += `\nMemcached stats command succeeded without auth. Stats output: ${resp.substring(0, 300)}`;
            }
            sock.destroy();
            resolve();
          });
          sock.on('error', () => { sock.destroy(); resolve(); });
          sock.on('timeout', () => { sock.destroy(); resolve(); });
        });
      } catch {}
    }

    // InfluxDB: try /ping
    if (db.protocol === 'influxdb') {
      try {
        const res = await fetchUrl(`http://${ip}:${db.port}/ping`, 3000);
        if (res.statusCode === 204 || res.statusCode === 200) {
          unauthenticated = true;
          evidence += '\nInfluxDB responds to /ping without auth — write/read may be unauthenticated.';
        }
      } catch {}
    }

    // Cassandra: try native protocol banner
    if (db.protocol === 'cassandra') {
      try {
        const sock = new net.Socket();
        await new Promise<void>((resolve) => {
          sock.setTimeout(3000);
          sock.connect(db.port, ip, () => {
            // Cassandra startup message
            sock.write(Buffer.from('\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'binary'));
          });
          sock.on('data', (data) => {
            if (data.length > 0) {
              unauthenticated = true;
              evidence += '\nCassandra native protocol responded without auth.';
            }
            sock.destroy();
            resolve();
          });
          sock.on('error', () => { sock.destroy(); resolve(); });
          sock.on('timeout', () => { sock.destroy(); resolve(); });
        });
      } catch {}
    }

    const severity = unauthenticated ? Severity.CRITICAL : Severity.HIGH;
    findings.push(generateFinding(
      `${db.name} Database Exposed${unauthenticated ? ' (Unauthenticated)' : ''}`,
      `${db.name} is accessible on ${ip}:${db.port}${unauthenticated ? ' without authentication' : ''}. ${unauthenticated ? 'This allows unauthorized access to the database and all its data.' : 'The service should not be exposed to the public internet.'}`,
      severity,
      'Service Exposure',
      `${ip}:${db.port}`,
      evidence,
      unauthenticated
        ? `Full database access including data read/write, potential data breach, and server compromise. Attacker can ${db.protocol === 'redis' ? 'execute arbitrary commands' : db.protocol === 'elasticsearch' ? 'query all indices' : 'access all databases'}.`
        : `${db.name} service information disclosure. Open ports increase the attack surface and may leak version information.`,
      unauthenticated
        ? `Immediately restrict ${db.name} access to trusted IPs only. Implement authentication. Use firewall rules or cloud security groups to block port ${db.port} from public access.`
        : `Close port ${db.port} on the public firewall. If remote access is needed, use VPN or IP whitelisting.`,
      db.protocol === 'redis' ? ['https://redis.io/docs/get-started/faqs/'] :
      db.protocol === 'elasticsearch' ? ['https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html'] :
      []
    ));
  }

  return findings;
}

// ─── CLOUD METADATA EXPOSURE ────────────────────────────────────────────────
const CLOUD_METADATA_ENDPOINTS = [
  // AWS
  { url: 'http://169.254.169.254/latest/meta-data/', provider: 'AWS', path: '/latest/meta-data/' },
  { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', provider: 'AWS IAM', path: '/latest/meta-data/iam/security-credentials/' },
  { url: 'http://169.254.169.254/latest/user-data', provider: 'AWS User Data', path: '/latest/user-data' },
  // GCP
  { url: 'http://metadata.google.internal/computeMetadata/v1/', provider: 'GCP', path: '/computeMetadata/v1/', headers: { 'Metadata-Flavor': 'Google' } },
  // Azure
  { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', provider: 'Azure', path: '/metadata/instance', headers: { 'Metadata': 'true' } },
  // DigitalOcean
  { url: 'http://169.254.169.254/metadata/v1.json', provider: 'DigitalOcean', path: '/metadata/v1.json' },
  // Kubernetes
  { url: 'https://kubernetes.default.svc.cluster.local/version', provider: 'Kubernetes', path: '/version' },
  { url: 'https://kubernetes.default.svc.cluster.local/api/v1/namespaces', provider: 'Kubernetes API', path: '/api/v1/namespaces' },
  { url: 'https://kubernetes.default.svc.cluster.local/api/v1/secrets', provider: 'Kubernetes Secrets', path: '/api/v1/secrets' },
];

async function testCloudMetadata(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Test if domain responds to SSRF-style metadata requests
  // We test if the server itself is cloud-hosted by checking headers
  try {
    const res = await fetchUrl(`https://${domain}/`, 5000);
    const headers = res.headers;

    // Detect cloud provider from headers
    const isAWS = headers['server']?.includes('AmazonS3') ||
                  headers['x-amz-request-id'] ||
                  headers['x-amz-cf-id'];
    const isAzure = headers['x-powered-by']?.includes('ASP.NET') ||
                    headers['x-azure-ref'];
    const isGCP = headers['server']?.includes('GoogleFrontend') ||
                  headers['x-goog-generation'];

    if (isAWS || isAzure || isGCP) {
      const provider = isAWS ? 'AWS' : isAzure ? 'Azure' : 'GCP';
      findings.push(generateFinding(
        `Cloud Infrastructure Detected (${provider})`,
        `The target is hosted on ${provider}. Cloud metadata endpoints may be accessible via SSRF vulnerabilities.`,
        Severity.INFO,
        'Service Exposure',
        domain,
        `Cloud provider detected: ${provider}\nHeaders: ${JSON.stringify(Object.fromEntries(Object.entries(headers).filter(([k]) => ['server', 'x-powered-by', 'x-amz-', 'x-azure', 'x-goog'].some(p => k.startsWith(p)))))}`,
        `Cloud-hosted applications are susceptible to SSRF attacks that can access instance metadata endpoints, potentially exposing IAM credentials, API keys, and other sensitive configuration.`,
        `Implement IMDSv2 (AWS) or equivalent metadata protection. Use network policies to restrict metadata access. Validate and sanitize all user-supplied URLs.`,
        ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html']
      ));
    }
  } catch {}

  // Test SSRF via the application itself (indirect metadata access)
  try {
    const res = await fetchUrl(`https://${domain}/`, 5000);
    if (res.body.toLowerCase().includes('169.254.169.254') || res.body.toLowerCase().includes('metadata')) {
      findings.push(generateFinding(
        'Metadata Reference Detected in Response',
        'The application response contains references to cloud metadata endpoints, indicating potential SSRF vulnerability.',
        Severity.HIGH,
        'Service Exposure',
        domain,
        'Response body contains metadata endpoint references.',
        'The application may be vulnerable to SSRF attacks that could access cloud metadata.',
        'Validate and sanitize all URLs. Implement URL allowlists. Block requests to internal IP ranges.',
        ['https://cwe.mitre.org/data/definitions/918.html']
      ));
    }
  } catch {}

  return findings;
}

// ─── DEFAULT CREDENTIAL TESTING ──────────────────────────────────────────────
const DEFAULT_CREDENTIALS = [
  { service: 'Redis', port: 6379, payloads: ['PING\r\n', 'INFO server\r\n', 'CONFIG GET requirepass\r\n'] },
  { service: 'MySQL', port: 3306, payloads: [] }, // Banner analysis only
  { service: 'PostgreSQL', port: 5432, payloads: [] },
  { service: 'MongoDB', port: 27017, payloads: [] },
  { service: 'Elasticsearch', port: 9200, payloads: ['/_cat/health', '/_cluster/health', '/_cat/indices'] },
  { service: 'CouchDB', port: 5984, payloads: ['/_all_dbs', '/_users/_all_docs', '/_config'] },
  { service: 'Memcached', port: 11211, payloads: ['stats', 'version', 'get user'] },
];

async function testDefaultCredentials(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ips = await resolveHost(domain);
  if (ips.length === 0) return findings;
  const ip = ips[0];

  for (const svc of DEFAULT_CREDENTIALS) {
    for (const payload of svc.payloads) {
      try {
        const sock = new net.Socket();
        const result = await new Promise<{ success: boolean; response: string }>((resolve) => {
          sock.setTimeout(3000);
          sock.connect(svc.port, ip, () => {
            sock.write(payload);
          });
          sock.on('data', (data) => {
            const resp = data.toString();
            const success = !resp.includes('NOAUTH') && !resp.includes('ERR') && !resp.includes('UNAUTH') && resp.length > 10;
            sock.destroy();
            resolve({ success, response: resp.substring(0, 512) });
          });
          sock.on('error', () => { sock.destroy(); resolve({ success: false, response: '' }); });
          sock.on('timeout', () => { sock.destroy(); resolve({ success: false, response: '' }); });
        });

        if (result.success && result.response) {
          findings.push(generateFinding(
            `${svc.service} Unauthenticated Access`,
            `${svc.service} on ${ip}:${svc.port} responded to unauthenticated command "${payload.trim()}".`,
            Severity.CRITICAL,
            'Service Exposure',
            `${ip}:${svc.port}`,
            `Command: ${payload.trim()}\nResponse:\n${result.response}`,
            `Attacker can ${svc.service === 'Redis' ? 'execute arbitrary commands, read/write data, and potentially achieve RCE' : 'access sensitive data and potentially escalate privileges'}.`,
            `Enable authentication on ${svc.service}. Restrict access to trusted IPs only. Use firewall rules to block public access.`,
            []
          ));
          break; // One finding per service is enough
        }
      } catch {}
    }
  }

  return findings;
}

// ─── MAIL SERVER MISCONFIGURATION ────────────────────────────────────────────
async function testMailSecurity(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Check for open relay indicators
  try {
    const mxRecords = await new Promise<string[]>((resolve) => {
      dns.resolveMx(domain, (err, addresses) => {
        if (err) resolve([]);
        else resolve(addresses.map(a => a.exchange));
      });
    });

    for (const mx of mxRecords.slice(0, 3)) {
      const mxHost = mx.replace(/\.$/, '');

      // Check for STARTTLS support
      try {
        const sock = new net.Socket();
        const result = await new Promise<{ hasTLS: boolean; banner: string }>((resolve) => {
          sock.setTimeout(5000);
          sock.connect(25, mxHost, () => {
            sock.write(`EHLO test.${domain}\r\n`);
          });
          let banner = '';
          let hasTLS = false;
          sock.on('data', (data) => {
            banner += data.toString();
            if (banner.includes('250-STARTTLS') || banner.includes('250 STARTTLS')) {
              hasTLS = true;
            }
            if (banner.includes('250 ') && !banner.includes('250-')) {
              sock.destroy();
              resolve({ hasTLS, banner: banner.substring(0, 512) });
            }
          });
          sock.on('error', () => { sock.destroy(); resolve({ hasTLS: false, banner: '' }); });
          sock.on('timeout', () => { sock.destroy(); resolve({ hasTLS: false, banner: '' }); });
        });

        if (!result.hasTLS && result.banner) {
          findings.push(generateFinding(
            `Mail Server ${mxHost} Missing TLS`,
            `The mail server ${mxHost} does not support STARTTLS. Email transmitted to this server is sent in plaintext.`,
            Severity.HIGH,
            'Service Exposure',
            mxHost,
            `EHLO banner:\n${result.banner}\n\nSTARTTLS not advertised.`,
            'Emails in transit can be intercepted and read by network attackers. Sensitive data in emails (credentials, tokens, PII) is exposed.',
            'Enable STARTTLS on the mail server. Configure TLS certificates. Consider enforcing TLS for all connections.',
            ['https://www.postfix.org/TLS_README.html']
          ));
        }
      } catch {}
    }
  } catch {}

  return findings;
}

// ─── KUBERNETES / CONTAINER EXPOSURE ────────────────────────────────────────
async function testContainerExposure(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const k8sEndpoints = [
    { path: '/api/v1/namespaces', name: 'Kubernetes API' },
    { path: '/apis/apps/v1/deployments', name: 'Kubernetes Deployments' },
    { path: '/api/v1/secrets', name: 'Kubernetes Secrets' },
    { path: '/api/v1/configmaps', name: 'Kubernetes ConfigMaps' },
    { path: '/healthz', name: 'Kubernetes Health Check' },
    { path: '/metrics', name: 'Kubernetes Metrics' },
  ];

  for (const ep of k8sEndpoints) {
    try {
      const res = await fetchUrl(`https://${domain}${ep.path}`, 3000);
      if (res.statusCode === 200 && (res.body.includes('items') || res.body.includes('kind'))) {
        findings.push(generateFinding(
          `${ep.name} Exposed`,
          `${ep.name} endpoint is accessible at ${domain}${ep.path} without authentication.`,
          ep.path.includes('secret') ? Severity.CRITICAL : Severity.HIGH,
          'Service Exposure',
          `${domain}${ep.path}`,
          `HTTP ${res.statusCode}\nResponse (first 500 chars): ${res.body.substring(0, 500)}`,
          ep.path.includes('secret')
            ? 'Kubernetes secrets may contain database credentials, API keys, TLS certificates, and other sensitive data.'
            : 'Exposed Kubernetes endpoints can reveal internal infrastructure, enable unauthorized deployments, or leak sensitive configuration.',
          'Implement RBAC authentication. Restrict API server access to authorized networks. Use NetworkPolicies to limit pod-to-pod communication.',
          ['https://kubernetes.io/docs/concepts/security/overview/']
        ));
      }
    } catch {}
  }

  // Docker daemon detection
  try {
    const res = await fetchUrl(`http://${domain}:2375/version`, 3000);
    if (res.statusCode === 200 && res.body.includes('Version')) {
      findings.push(generateFinding(
        'Docker Daemon Exposed',
        'The Docker daemon API is accessible on port 2375 without TLS. This allows full control over the Docker host.',
        Severity.CRITICAL,
        'Service Exposure',
        `${domain}:2375`,
        `Docker version API response: ${res.body.substring(0, 300)}`,
        'Attacker can create containers, access host filesystem, and achieve full server compromise via Docker API.',
        'Disable remote Docker API access. Use TLS client certificates. Bind Docker daemon to localhost only.',
        ['https://docs.docker.com/engine/security/protect-access/']
      ));
    }
  } catch {}

  return findings;
}

// ─── SERVICE BANNER ANALYSIS ─────────────────────────────────────────────────
const SERVICE_PORTS = [
  { port: 21, name: 'FTP', protocol: 'ftp' },
  { port: 22, name: 'SSH', protocol: 'ssh' },
  { port: 23, name: 'Telnet', protocol: 'telnet' },
  { port: 25, name: 'SMTP', protocol: 'smtp' },
  { port: 53, name: 'DNS', protocol: 'dns' },
  { port: 80, name: 'HTTP', protocol: 'http' },
  { port: 110, name: 'POP3', protocol: 'pop3' },
  { port: 143, name: 'IMAP', protocol: 'imap' },
  { port: 443, name: 'HTTPS', protocol: 'https' },
  { port: 993, name: 'IMAPS', protocol: 'imaps' },
  { port: 995, name: 'POP3S', protocol: 'pop3s' },
  { port: 3389, name: 'RDP', protocol: 'rdp' },
  { port: 5900, name: 'VNC', protocol: 'vnc' },
  { port: 8080, name: 'HTTP-Alt', protocol: 'http' },
  { port: 8443, name: 'HTTPS-Alt', protocol: 'https' },
];

async function testServiceBanners(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ips = await resolveHost(domain);
  if (ips.length === 0) return findings;
  const ip = ips[0];

  const bannerTests = await Promise.all(
    SERVICE_PORTS.map(async (svc) => {
      const result = await measureTcp(ip, svc.port, 3000);
      return { ...svc, ...result };
    })
  );

  for (const svc of bannerTests) {
    if (!svc.open || !svc.banner) continue;

    // Detect version info in banner
    const versionMatch = svc.banner.match(/[\d]+\.[\d]+[\.\d]*/);
    if (versionMatch) {
      findings.push(generateFinding(
        `${svc.name} Version Disclosure`,
        `${svc.name} service on port ${svc.port} reveals version information in its banner.`,
        Severity.LOW,
        'Information Disclosure',
        `${ip}:${svc.port}`,
        `Banner: ${svc.banner}`,
        'Version information helps attackers identify known vulnerabilities for the specific software version.',
        'Suppress version information in service banners where possible.',
        []
      ));
    }

    // Detect dangerous services
    if (svc.protocol === 'telnet') {
      findings.push(generateFinding(
        'Telnet Service Enabled',
        'Telnet service is running on port 23. Telnet transmits all data including credentials in plaintext.',
        Severity.HIGH,
        'Service Exposure',
        `${ip}:${svc.port}`,
        `Banner: ${svc.banner}`,
        'All data including usernames and passwords are transmitted in cleartext, susceptible to network sniffing.',
        'Replace Telnet with SSH for remote access. Disable Telnet service if not required.',
        ['https://cwe.mitre.org/data/definitions/319.html']
      ));
    }

    if (svc.protocol === 'ftp' && svc.banner.toLowerCase().includes('anonymous')) {
      findings.push(generateFinding(
        'FTP Anonymous Access',
        'FTP server allows anonymous login. This may expose sensitive files to unauthorized users.',
        Severity.MEDIUM,
        'Service Exposure',
        `${ip}:${svc.port}`,
        `Banner: ${svc.banner}`,
        'Anonymous FTP access can expose sensitive files, configuration data, or source code.',
        'Disable anonymous FTP access. Use SFTP instead of FTP for file transfers.',
        []
      ));
    }
  }

  return findings;
}

// ─── MAIN EXPORT ─────────────────────────────────────────────────────────────
export async function runServiceAuditScan(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const results = await Promise.allSettled([
    testDatabaseExposure(domain),
    testCloudMetadata(domain),
    testDefaultCredentials(domain),
    testMailSecurity(domain),
    testContainerExposure(domain),
    testServiceBanners(domain),
  ]);

  for (const result of results) {
    if (result.status === 'fulfilled') {
      findings.push(...result.value);
    }
  }

  return findings;
}

import * as net from 'net';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

interface PortResult {
  port: number;
  open: boolean;
  banner: string;
  service: string;
  category: 'web' | 'database' | 'mail' | 'management' | 'file-transfer' | 'messaging' | 'container' | 'other';
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const PORTS_TO_CHECK: Array<{ port: number; service: string; category: PortResult['category']; risk: PortResult['risk'] }> = [
  // File transfer
  { port: 21, service: 'FTP', category: 'file-transfer', risk: 'medium' },
  { port: 69, service: 'TFTP', category: 'file-transfer', risk: 'high' },
  { port: 990, service: 'FTPS', category: 'file-transfer', risk: 'low' },
  { port: 2049, service: 'NFS', category: 'file-transfer', risk: 'high' },
  { port: 9418, service: 'Git', category: 'file-transfer', risk: 'medium' },
  // Management / Remote
  { port: 22, service: 'SSH', category: 'management', risk: 'low' },
  { port: 23, service: 'Telnet', category: 'management', risk: 'critical' },
  { port: 135, service: 'MSRPC', category: 'management', risk: 'high' },
  { port: 139, service: 'NetBIOS', category: 'management', risk: 'high' },
  { port: 445, service: 'SMB', category: 'management', risk: 'high' },
  { port: 3389, service: 'RDP', category: 'management', risk: 'critical' },
  { port: 5900, service: 'VNC', category: 'management', risk: 'critical' },
  { port: 5985, service: 'WinRM', category: 'management', risk: 'high' },
  { port: 5986, service: 'WinRM-SSL', category: 'management', risk: 'high' },
  { port: 2222, service: 'SSH-Alt', category: 'management', risk: 'low' },
  // Mail
  { port: 25, service: 'SMTP', category: 'mail', risk: 'info' },
  { port: 110, service: 'POP3', category: 'mail', risk: 'info' },
  { port: 143, service: 'IMAP', category: 'mail', risk: 'info' },
  { port: 465, service: 'SMTPS', category: 'mail', risk: 'info' },
  { port: 587, service: 'Submission', category: 'mail', risk: 'info' },
  { port: 993, service: 'IMAPS', category: 'mail', risk: 'info' },
  { port: 995, service: 'POP3S', category: 'mail', risk: 'info' },
  // Web (HTTP)
  { port: 80, service: 'HTTP', category: 'web', risk: 'info' },
  { port: 443, service: 'HTTPS', category: 'web', risk: 'info' },
  { port: 8080, service: 'HTTP-Proxy', category: 'web', risk: 'low' },
  { port: 8443, service: 'HTTPS-Alt', category: 'web', risk: 'low' },
  { port: 8888, service: 'HTTP-Alt', category: 'web', risk: 'low' },
  { port: 3000, service: 'HTTP-Dev', category: 'web', risk: 'low' },
  { port: 3001, service: 'HTTP-Dev2', category: 'web', risk: 'low' },
  { port: 4000, service: 'HTTP-Dev', category: 'web', risk: 'low' },
  { port: 5000, service: 'HTTP-Dev', category: 'web', risk: 'low' },
  { port: 5173, service: 'Vite', category: 'web', risk: 'low' },
  { port: 8000, service: 'HTTP-Dev', category: 'web', risk: 'low' },
  { port: 8081, service: 'HTTP-Alt', category: 'web', risk: 'low' },
  { port: 9000, service: 'HTTP-Alt', category: 'web', risk: 'low' },
  { port: 9090, service: 'HTTP-Alt', category: 'web', risk: 'low' },
  { port: 9200, service: 'Elasticsearch', category: 'web', risk: 'medium' },
  { port: 9443, service: 'HTTPS-Alt', category: 'web', risk: 'low' },
  { port: 10443, service: 'HTTPS-Alt', category: 'web', risk: 'low' },
  { port: 2087, service: 'cPanel', category: 'web', risk: 'low' },
  { port: 2083, service: 'cPanel-SSL', category: 'web', risk: 'low' },
  { port: 2096, service: 'Webmail', category: 'web', risk: 'low' },
  { port: 4200, service: 'HTTP-Dev', category: 'web', risk: 'low' },
  { port: 7443, service: 'HTTPS-Alt', category: 'web', risk: 'low' },
  // Databases
  { port: 3306, service: 'MySQL', category: 'database', risk: 'critical' },
  { port: 5432, service: 'PostgreSQL', category: 'database', risk: 'critical' },
  { port: 1433, service: 'MSSQL', category: 'database', risk: 'critical' },
  { port: 1434, service: 'MSSQL-Monitor', category: 'database', risk: 'critical' },
  { port: 1521, service: 'Oracle', category: 'database', risk: 'critical' },
  { port: 6379, service: 'Redis', category: 'database', risk: 'critical' },
  { port: 5984, service: 'CouchDB', category: 'database', risk: 'high' },
  { port: 8529, service: 'ArangoDB', category: 'database', risk: 'high' },
  { port: 9042, service: 'Cassandra', category: 'database', risk: 'high' },
  { port: 9229, service: 'Node-Debug', category: 'database', risk: 'critical' },
  { port: 11211, service: 'Memcached', category: 'database', risk: 'high' },
  { port: 27017, service: 'MongoDB', category: 'database', risk: 'critical' },
  { port: 27018, service: 'MongoDB-Alt', category: 'database', risk: 'critical' },
  { port: 28017, service: 'MongoDB-Web', category: 'database', risk: 'critical' },
  // DNS
  { port: 53, service: 'DNS', category: 'other', risk: 'info' },
  // Messaging
  { port: 5672, service: 'AMQP', category: 'messaging', risk: 'medium' },
  { port: 5671, service: 'AMQPS', category: 'messaging', risk: 'low' },
  { port: 1883, service: 'MQTT', category: 'messaging', risk: 'medium' },
  { port: 8883, service: 'MQTTS', category: 'messaging', risk: 'low' },
  { port: 9092, service: 'Kafka', category: 'messaging', risk: 'medium' },
  // Containers / Orchestrators
  { port: 2375, service: 'Docker', category: 'container', risk: 'critical' },
  { port: 2376, service: 'Docker-SSL', category: 'container', risk: 'critical' },
  { port: 6443, service: 'Kubernetes', category: 'container', risk: 'critical' },
  { port: 10250, service: 'Kubelet', category: 'container', risk: 'critical' },
  { port: 10255, service: 'Kubelet-Read', category: 'container', risk: 'critical' },
  { port: 2379, service: 'etcd', category: 'container', risk: 'critical' },
  { port: 2380, service: 'etcd-peer', category: 'container', risk: 'critical' },
  // Other
  { port: 111, service: 'RPCBind', category: 'management', risk: 'high' },
  { port: 5601, service: 'Kibana', category: 'other', risk: 'medium' },
  { port: 9090, service: 'Prometheus', category: 'other', risk: 'medium' },
  { port: 15672, service: 'RabbitMQ-Mgmt', category: 'other', risk: 'high' },
  { port: 50000, service: 'SAP', category: 'other', risk: 'high' },
];

// Ports that are HTTP-like and should be probed with HEAD request
const HTTP_LIKE_PORTS = new Set([80, 8080, 8888, 3000, 3001, 4000, 5000, 5173, 8000, 8081, 9000, 9090, 4200]);
const HTTPS_LIKE_PORTS = new Set([443, 8443, 9443, 10443, 2083, 2096, 7443]);

// Export for other modules (site crawl, etc.) to consume
export function getHttpLikePorts(): number[] {
  return [...HTTP_LIKE_PORTS, ...HTTPS_LIKE_PORTS];
}

function probePort(host: string, port: number, timeout: number): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;
    let banner = '';

    const done = (result: { open: boolean; banner: string }) => {
      if (!resolved) {
        resolved = true;
        try { socket.destroy(); } catch {}
        resolve(result);
      }
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.setTimeout(2000);
      socket.on('data', (data: Buffer) => {
        banner += data.toString('utf-8').replace(/[\x00-\x1f\x7f-\x9f]/g, '').trim();
      });
      // Probe HTTP-like ports with HEAD request to identify server
      if (HTTP_LIKE_PORTS.has(port)) {
        socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        setTimeout(() => done({ open: true, banner }), 2000);
      } else if (HTTPS_LIKE_PORTS.has(port)) {
        // TLS ports: send ClientHello to trigger server hello, or just report open
        done({ open: true, banner: '' });
      } else {
        // Non-HTTP services: wait briefly for banner
        setTimeout(() => done({ open: true, banner }), 1500);
      }
    });

    socket.on('timeout', () => {
      if (!resolved) {
        // If we got a connect event but timeout waiting for banner, port is still open
        if (banner) {
          done({ open: true, banner });
        } else {
          done({ open: false, banner: '' });
        }
      }
    });

    socket.on('error', () => done({ open: false, banner: '' }));
    socket.connect(port, host);
  });
}

export async function runPortScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const openPorts: PortResult[] = [];

  try {
    // Scan ports in parallel batches of 10
    const BATCH_SIZE = 10;
    const TIMEOUT = 3000;

    for (let i = 0; i < PORTS_TO_CHECK.length; i += BATCH_SIZE) {
      const batch = PORTS_TO_CHECK.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (portDef) => {
          const result = await probePort(domain, portDef.port, TIMEOUT);
          return {
            ...portDef,
            open: result.open,
            banner: result.banner,
          };
        })
      );

      for (const result of results) {
        if (result.open) {
          openPorts.push({
            port: result.port,
            open: true,
            banner: result.banner,
            service: result.service,
            category: result.category,
            risk: result.risk,
          });
        }
      }
    }

    // Generate findings based on open ports
    if (openPorts.length === 0) {
      findings.push(generateFinding(
        'No common ports exposed',
        'No commonly scanned ports were found to be open on the target.',
        Severity.INFO,
        'Port Scan',
        domain,
        `Scanned ${PORTS_TO_CHECK.length} ports, all closed/filtered`,
        'This is a good sign - minimal attack surface',
        'Continue monitoring for unexpected port openings',
        []
      ));
    } else {
      // Group by category for summary
      const byCategory: Record<string, PortResult[]> = {};
      for (const p of openPorts) {
        if (!byCategory[p.category]) byCategory[p.category] = [];
        byCategory[p.category].push(p);
      }

      // Critical database ports
      const dbPorts = openPorts.filter(p => p.category === 'database');
      if (dbPorts.length > 0) {
        const portList = dbPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'Database ports exposed to internet',
          `The following database ports are accessible from the internet: ${portList}. This is a critical security risk.`,
          Severity.CRITICAL,
          'Port Scan',
          domain,
          `Open database ports: ${portList}`,
          'Exposed database ports can lead to unauthorized access, data theft, and ransomware attacks',
          'Restrict database access to internal networks only. Use firewalls, VPNs, or private network interfaces.',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));
      }

      // Management ports (SSH, RDP, etc.)
      const mgmtPorts = openPorts.filter(p => p.category === 'management');
      if (mgmtPorts.length > 0) {
        const portList = mgmtPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'Management ports exposed',
          `The following management/service ports are accessible: ${portList}.`,
          mgmtPorts.some(p => p.port === 23) ? Severity.CRITICAL : Severity.MEDIUM,
          'Port Scan',
          domain,
          `Open management ports: ${portList}`,
          'Exposed management ports can be targeted for brute-force attacks and unauthorized access',
          'Restrict management ports to trusted IP ranges. Use VPN for remote access.',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));

        // Telnet is especially critical
        if (mgmtPorts.some(p => p.port === 23)) {
          findings.push(generateFinding(
            'Telnet service detected (port 23)',
            'Telnet transmits all data including credentials in plaintext.',
            Severity.CRITICAL,
            'Port Scan',
            domain,
            'Port 23 (Telnet) is open',
            'Telnet is completely unencrypted; all credentials and data are visible to network eavesdroppers',
            'Replace Telnet with SSH (port 22) immediately',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
          ));
        }
      }

      // Container orchestration
      const containerPorts = openPorts.filter(p => p.category === 'container');
      if (containerPorts.length > 0) {
        const portList = containerPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'Container orchestration ports exposed',
          `The following container/orchestration ports are accessible: ${portList}.`,
          Severity.CRITICAL,
          'Port Scan',
          domain,
          `Open container ports: ${portList}`,
          'Exposed container orchestration APIs can allow full cluster compromise',
          'Restrict access to cluster management interfaces to internal networks only',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));
      }

      // File transfer
      const ftpPorts = openPorts.filter(p => p.category === 'file-transfer');
      if (ftpPorts.length > 0) {
        const portList = ftpPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'File transfer service exposed',
          `The following file transfer services are accessible: ${portList}.`,
          Severity.MEDIUM,
          'Port Scan',
          domain,
          `Open file transfer ports: ${portList}`,
          'FTP transmits credentials in plaintext; NFS can expose file systems',
          'Use SFTP/SCP instead of FTP. Restrict NFS to internal networks.',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));
      }

      // Alt web ports
      const webPorts = openPorts.filter(p => p.category === 'web' && p.port !== 80 && p.port !== 443);
      if (webPorts.length > 0) {
        const portList = webPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'Alternative web ports open',
          `The following alternative web ports are accessible: ${portList}. These may expose development or administration interfaces.`,
          Severity.LOW,
          'Port Scan',
          domain,
          `Open alternative web ports: ${portList}`,
          'Alternative web ports often host less-secured applications or admin panels',
          'Review and restrict access to alternative web ports',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));
      }

      // Messaging
      const msgPorts = openPorts.filter(p => p.category === 'messaging');
      if (msgPorts.length > 0) {
        const portList = msgPorts.map(p => `${p.port}/${p.service}`).join(', ');
        findings.push(generateFinding(
          'Message queue service exposed',
          `The following messaging services are accessible: ${portList}.`,
          Severity.MEDIUM,
          'Port Scan',
          domain,
          `Open messaging ports: ${portList}`,
          'Exposed message queues can allow message injection or data theft',
          'Restrict messaging services to internal networks and require authentication',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
        ));
      }

      // Banner grabbing results - info findings for interesting banners
      for (const port of openPorts) {
        if (port.banner && port.banner.length > 5) {
          const bannerShort = port.banner.substring(0, 200);
          // Only generate finding if banner reveals version info
          if (/\d+\.\d+/.test(bannerShort)) {
            findings.push(generateFinding(
              'Service version disclosed in banner',
              `Port ${port.port} (${port.service}) reveals version information in its banner.`,
              Severity.LOW,
              'Port Scan',
              domain,
              `Port ${port.port}/${port.service}: ${bannerShort}`,
              'Version information helps attackers identify specific software vulnerabilities',
              'Configure services to suppress version information in banners',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Infrastructure_Configuration_Management_Testing']
            ));
          }
        }
      }

      // Summary of all open ports
      const allPorts = openPorts.map(p => `${p.port}/${p.service} (${p.risk})`).join('; ');
      findings.push(generateFinding(
        'Open port summary',
        `${openPorts.length} ports are open on the target.`,
        Severity.INFO,
        'Port Scan',
        domain,
        allPorts,
        'Open ports increase the attack surface',
        'Close any ports that are not required for production services',
        []
      ));
    }

    const duration = Date.now() - startTime;
    return {
      module: 'portScan',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'portScan',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

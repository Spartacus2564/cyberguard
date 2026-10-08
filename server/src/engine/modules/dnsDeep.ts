import * as dns from 'dns';
import { promisify } from 'util';
import * as net from 'net';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from '../modules/shared';

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveCname = promisify(dns.resolveCname);
const resolveNs = promisify(dns.resolveNs);
const resolveSoa = promisify(dns.resolveSoa);

// DANE/TLSA record type (52)
async function resolveTlsa(domain: string): Promise<string[]> {
  try {
    return await new Promise<string[]>((resolve, reject) => {
      dns.resolve(domain, 'TLSA', (err, records) => {
        if (err) reject(err);
        else resolve(records as string[]);
      });
    });
  } catch {
    return [];
  }
}

// CAA record type (257)
async function resolveCaa(domain: string): Promise<string[]> {
  try {
    return await new Promise<string[]>((resolve, reject) => {
      dns.resolve(domain, 'CAA', (err, records) => {
        if (err) reject(err);
        else resolve(records as unknown as string[]);
      });
    });
  } catch {
    return [];
  }
}

// SRV records
async function resolveSrv(domain: string): Promise<dns.SrvRecord[]> {
  try {
    return await new Promise<dns.SrvRecord[]>((resolve, reject) => {
      dns.resolve(domain, 'SRV', (err, records) => {
        if (err) reject(err);
        else resolve(records as dns.SrvRecord[]);
      });
    });
  } catch {
    return [];
  }
}

// Try zone transfer against each nameserver
async function attemptZoneTransfer(domain: string, nameservers: string[]): Promise<{ success: boolean; server: string; records?: string[] }> {
  for (const ns of nameservers) {
    try {
      const client = new net.Socket();
      const result = await new Promise<{ success: boolean; server: string; records?: string[] }>((resolve) => {
        const timeout = setTimeout(() => {
          client.destroy();
          resolve({ success: false, server: ns });
        }, 5000);

        client.connect(53, ns, () => {
          const query = buildAxfrQuery(domain);
          client.write(query);
        });

        let data = Buffer.alloc(0);
        client.on('data', (chunk: Buffer) => {
          data = Buffer.concat([data, chunk]);
        });

        client.on('end', () => {
          clearTimeout(timeout);
          if (data.length > 512) {
            const records = parseAxfrResponse(data, domain);
            resolve({ success: true, server: ns, records });
          } else {
            resolve({ success: false, server: ns });
          }
        });

        client.on('error', () => {
          clearTimeout(timeout);
          resolve({ success: false, server: ns });
        });
      });

      if (result.success) return result;
    } catch {}
  }
  return { success: false, server: '' };
}

function buildAxfrQuery(domain: string): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0000, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = Buffer.alloc(domain.length + 6);
  const parts = domain.split('.');
  let offset = 0;
  for (const part of parts) {
    question.writeUInt8(part.length, offset);
    offset++;
    question.write(part, offset, 'ascii');
    offset += part.length;
  }
  question.writeUInt8(0, offset);
  question.writeUInt16BE(252, offset + 1);
  question.writeUInt16BE(1, offset + 3);

  return Buffer.concat([header, question]);
}

function parseAxfrResponse(data: Buffer, domain: string): string[] {
  const records: string[] = [];
  const str = data.toString('ascii');
  const recordPatterns = [
    new RegExp(`${domain.replace(/\./g, '\\.')}.*?IN\\s+A\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)`, 'gi'),
    new RegExp(`${domain.replace(/\./g, '\\.')}.*?IN\\s+AAAA\\s+([\\da-f:]+)`, 'gi'),
    new RegExp(`${domain.replace(/\./g, '\\.')}.*?IN\\s+MX\\s+\\d+\\s+(\\S+)`, 'gi'),
    new RegExp(`${domain.replace(/\./g, '\\.')}.*?IN\\s+NS\\s+(\\S+)`, 'gi'),
  ];
  for (const pattern of recordPatterns) {
    let match;
    while ((match = pattern.exec(str)) !== null) {
      records.push(match[0]);
    }
  }
  return records;
}

// Wildcard detection
async function detectWildcard(domain: string): Promise<{ isWildcard: boolean; wildcardIp?: string }> {
  const randomSubdomains = [
    `test${Math.random().toString(36).substring(7)}.${domain}`,
    `nonexistent${Math.random().toString(36).substring(7)}.${domain}`,
    `random${Date.now()}.${domain}`,
  ];

  for (const sub of randomSubdomains) {
    try {
      const ips = await resolve4(sub);
      if (ips.length > 0) {
        const secondTry = await resolve4(randomSubdomains[0]);
        if (secondTry.length > 0 && secondTry[0] === ips[0]) {
          return { isWildcard: true, wildcardIp: ips[0] };
        }
      }
    } catch {}
  }
  return { isWildcard: false };
}

// Reverse DNS / PTR check
async function checkPtrRecords(ips: string[]): Promise<Record<string, string[]>> {
  const results: Record<string, string[]> = {};
  for (const ip of ips) {
    try {
      const names = await new Promise<string[]>((resolve, reject) => {
        dns.reverse(ip, (err, names) => {
          if (err) reject(err);
          else resolve(names);
        });
      });
      results[ip] = names;
    } catch {
      results[ip] = [];
    }
  }
  return results;
}

export async function runDnsDeepScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // === AAAA Records (IPv6) ===
    try {
      const aaaaRecords = await resolve6(domain);
      if (aaaaRecords.length === 0) {
        findings.push(generateFinding(
          'No IPv6 (AAAA) records configured',
          'Domain has no AAAA records for IPv6 connectivity.',
          Severity.INFO, 'DNS Security', domain,
          'No AAAA records found',
          'IPv6 readiness is increasingly important for security and accessibility',
          'Add AAAA records for IPv6 support',
          ['https://www.cloudflare.com/learning/dns/dns-records/']
        ));
      } else {
        findings.push(generateFinding(
          'IPv6 (AAAA) records configured',
          `Domain has ${aaaaRecords.length} IPv6 address(es) configured.`,
          Severity.INFO, 'DNS Security', domain,
          `AAAA records: ${aaaaRecords.join(', ')}`,
          'IPv6 support improves security and future-proofing',
          'Ensure IPv6 is properly configured and monitored',
          []
        ));
      }
    } catch {}

    // === CAA Records (Certificate Authority Authorization) ===
    try {
      const caaRecords = await resolveCaa(domain);
      if (caaRecords.length === 0) {
        findings.push(generateFinding(
          'No CAA records configured',
          'Domain has no Certificate Authority Authorization records.',
          Severity.HIGH, 'DNS Security', domain,
          'No CAA records found',
          'Any Certificate Authority can issue certificates for this domain',
          'Add CAA records to restrict certificate issuance to authorized CAs',
          ['https://letsencrypt.org/docs/caa/']
        ));
      } else {
        const issueRecords = caaRecords.filter(r => String(r).includes('0 issue'));
        if (issueRecords.length > 0) {
          findings.push(generateFinding(
            'CAA records configured',
            `${caaRecords.length} CAA record(s) found restricting certificate issuance.`,
            Severity.INFO, 'DNS Security', domain,
            `CAA records: ${caaRecords.join('; ')}`,
            'CAA records limit which CAs can issue certificates',
            'Review CAA records periodically to ensure they reflect current CA requirements',
            []
          ));
        }
      }
    } catch {}

    // === DNSSEC Deep Validation ===
    try {
      const dnskey = await new Promise<any[]>((resolve, reject) => {
        dns.resolve(domain, 'DNSKEY', (err, records) => {
          if (err) reject(err);
          else resolve(records as any[]);
        });
      });

      if (dnskey && dnskey.length > 0) {
        const hasDsa = dnskey.some((k: any) => k.algorithm === 3 || k.algorithm === 6);

        if (hasDsa) {
          findings.push(generateFinding(
            'Weak DNSSEC algorithm detected',
            'DNSSEC is using deprecated DSA algorithm.',
            Severity.HIGH, 'DNS Security', domain,
            'DNSKEY records contain DSA algorithm',
            'DSA is cryptographically weak and deprecated',
            'Migrate to RSA-2048+ or ECDSA/Ed25519',
            ['https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml']
          ));
        }
      }
    } catch {}

    // === DANE/TLSA Records ===
    try {
      const tlsaRecords = await resolveTlsa(`_25._tcp.${domain}`);
      const httpsTlsa = await resolveTlsa(`_443._tcp.${domain}`);

      if (tlsaRecords.length === 0 && httpsTlsa.length === 0) {
        findings.push(generateFinding(
          'No DANE/TLSA records configured',
          'No DANE TLSA records found for the domain.',
          Severity.INFO, 'DNS Security', domain,
          'No TLSA records found on _25._tcp or _443._tcp',
          'DANE provides an additional layer of TLS certificate validation',
          'Consider implementing DANE/TLSA for email and HTTPS',
          ['https://www.rfc-editor.org/rfc/rfc6698']
        ));
      } else {
        findings.push(generateFinding(
          'DANE/TLSA records configured',
          `Found ${tlsaRecords.length + httpsTlsa.length} TLSA record(s).`,
          Severity.INFO, 'DNS Security', domain,
          `TLSA records found: ${tlsaRecords.length + httpsTlsa.length}`,
          'DANE/TLSA provides certificate pinning via DNS',
          'Ensure TLSA records are kept in sync with certificate rotations',
          []
        ));
      }
    } catch {}

    // === Zone Transfer Test ===
    try {
      const nsRecords = await resolveNs(domain);
      if (nsRecords.length > 0) {
        const zoneTransferResult = await attemptZoneTransfer(domain, nsRecords);

        if (zoneTransferResult.success) {
          findings.push(generateFinding(
            'DNS zone transfer allowed',
            `Zone transfer (AXFR) was successful against nameserver ${zoneTransferResult.server}.`,
            Severity.CRITICAL, 'DNS Security', domain,
            `Zone transfer successful against ${zoneTransferResult.server}\nExposed records: ${zoneTransferResult.records?.length || 0}`,
            'Zone transfers expose the entire DNS zone including all subdomains and internal records',
            'Restrict zone transfers to authorized secondary nameservers only',
            ['https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/']
          ));
        }
      }
    } catch {}

    // === Wildcard DNS Detection ===
    try {
      const wildcardResult = await detectWildcard(domain);
      if (wildcardResult.isWildcard) {
        findings.push(generateFinding(
          'Wildcard DNS record detected',
          `Domain resolves random subdomains to ${wildcardResult.wildcardIp}.`,
          Severity.MEDIUM, 'DNS Security', domain,
          `Wildcard IP: ${wildcardResult.wildcardIp}`,
          'Wildcard DNS can expose unintended subdomains and services',
          'Remove wildcard DNS records and explicitly define subdomains',
          []
        ));
      }
    } catch {}

    // === PTR / Reverse DNS ===
    try {
      const aRecords = await resolve4(domain);
      if (aRecords.length > 0) {
        const ptrResults = await checkPtrRecords(aRecords.slice(0, 3));

        for (const [ip, ptrNames] of Object.entries(ptrResults)) {
          if (ptrNames.length === 0) {
            findings.push(generateFinding(
              `No reverse DNS (PTR) for ${ip}`,
              `IP address ${ip} has no PTR record configured.`,
              Severity.INFO, 'DNS Security', domain,
              `IP: ${ip} - No PTR record`,
              'Missing reverse DNS can affect email deliverability and is a best practice',
              'Configure PTR records through your hosting provider',
              []
            ));
          } else {
            const ptrDomain = ptrNames[0]?.replace(/\.$/, '');
            if (ptrDomain && ptrDomain !== domain) {
              findings.push(generateFinding(
                'Reverse DNS mismatch',
                `PTR record for ${ip} points to ${ptrDomain} but forward DNS resolves to ${domain}.`,
                Severity.LOW, 'DNS Security', domain,
                `IP: ${ip} → PTR: ${ptrNames[0]} (expected: ${domain})`,
                'Mismatched PTR records can indicate misconfiguration',
                'Ensure forward and reverse DNS records are consistent',
                []
              ));
            }
          }
        }
      }
    } catch {}

    // === SRV Records Check ===
    try {
      const commonSrvPrefixes = [
        '_xmpp-server', '_xmpp-client', '_sip', '_sips',
        '_ldap', '_kerberos', '_imap', '_pop3', '_smtp',
      ];
      const foundSrv: string[] = [];

      for (const prefix of commonSrvPrefixes) {
        try {
          const srvRecords = await resolveSrv(`${prefix}._tcp.${domain}`);
          if (srvRecords.length > 0) {
            foundSrv.push(`${prefix}: ${srvRecords.length} record(s)`);
          }
        } catch {}
      }

      if (foundSrv.length > 0) {
        findings.push(generateFinding(
          'SRV records discovered',
          `Found ${foundSrv.length} types of SRV records.`,
          Severity.INFO, 'DNS Security', domain,
          `SRV records: ${foundSrv.join('; ')}`,
          'SRV records reveal available services and their endpoints',
          'Review SRV records to ensure they don\'t expose unnecessary service information',
          []
        ));
      }
    } catch {}

    // === SOA Record Analysis ===
    try {
      const soa = await resolveSoa(domain);
      if (soa) {
        if (soa.refresh < 300) {
          findings.push(generateFinding(
            'SOA refresh interval too low',
            `SOA refresh interval is ${soa.refresh}s (recommended: 300-3600s).`,
            Severity.LOW, 'DNS Security', domain,
            `Refresh: ${soa.refresh}s, Retry: ${soa.retry}s, Expire: ${soa.expire}`,
            'Very low refresh intervals can cause excessive DNS traffic',
            'Set SOA refresh to 300-3600 seconds',
            []
          ));
        }

        if (soa.expire < 604800) {
          findings.push(generateFinding(
            'SOA expire time too low',
            `SOA expire time is ${soa.expire}s (recommended: at least 604800s / 1 week).`,
            Severity.MEDIUM, 'DNS Security', domain,
            `Expire: ${soa.expire}s`,
            'Low expire times can cause DNS failures if primary nameserver is unreachable',
            'Set SOA expire to at least 604800 seconds (1 week)',
            []
          ));
        }

        // Check serial number format
        const serialStr = String(soa.serial);
        if (serialStr.length === 10) {
          const datePart = serialStr.substring(0, 8);
          const year = parseInt(datePart.substring(0, 4));
          const month = parseInt(datePart.substring(4, 6));
          const day = parseInt(datePart.substring(6, 8));
          const serialDate = new Date(year, month - 1, day);
          const daysSinceUpdate = Math.floor((Date.now() - serialDate.getTime()) / (1000 * 60 * 60 * 24));

          if (daysSinceUpdate > 365) {
            findings.push(generateFinding(
              'SOA serial number appears stale',
              `SOA serial date is from ${daysSinceUpdate} days ago.`,
              Severity.INFO, 'DNS Security', domain,
              `Serial: ${soa.serial} (last updated ~${daysSinceUpdate} days ago)`,
              'Stale SOA serial may indicate unmanaged DNS',
              'Update SOA serial when making DNS changes',
              []
            ));
          }
        }
      }
    } catch {}

    // === DNS Entropy / Predictability Check ===
    try {
      const nsRecords = await resolveNs(domain);
      if (nsRecords.length >= 2) {
        const ips: string[] = [];
        for (const ns of nsRecords.slice(0, 5)) {
          try {
            const a = await resolve4(ns);
            ips.push(a[0]);
          } catch {}
        }

        if (ips.length >= 2) {
          const subnets = ips.map(ip => ip.split('.').slice(0, 3).join('.'));
          const uniqueSubnets = new Set(subnets);
          if (uniqueSubnets.size === 1) {
            findings.push(generateFinding(
              'All nameservers on same subnet',
              'All nameservers resolve to IP addresses in the same /24 subnet.',
              Severity.HIGH, 'DNS Security', domain,
              `Nameserver IPs: ${ips.join(', ')} (all in ${subnets[0]}/24)`,
              'If the /24 subnet is compromised, all DNS resolution is compromised',
              'Use nameservers from different network segments for redundancy',
              []
            ));
          }
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return { module: 'dnsDeep', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'dnsDeep', findings, duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

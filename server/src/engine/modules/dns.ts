import * as dns from 'dns';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const resolve4 = promisify(dns.resolve4);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolve = promisify(dns.resolve);
const resolveNs = promisify(dns.resolveNs);
const resolveSrv = promisify(dns.resolveSrv);

// AD service records to enumerate
const AD_SRV_PREFIXES = [
  '_ldap._tcp', '_kerberos._tcp', '_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp',
  '_gc._tcp', '_ldap._tcp.dc._msdcs', '_ldap._tcp.pdc._msdcs',
  '_ldap._tcp.{domain}',
];

export async function runDnsScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    try {
      const aRecords = await resolve4(domain);
      if (aRecords.length > 0) {
        const internalIps = aRecords.filter(ip => {
          const parts = ip.split('.');
          if (parts[0] === '10') return true;
          if (parts[0] === '192' && parts[1] === '168') return true;
          if (parts[0] === '172' && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) return true;
          return false;
        });
        if (internalIps.length > 0) {
          findings.push(generateFinding(
            'Exposed internal IP addresses',
            'DNS A records contain internal/private IP addresses that should not be exposed publicly.',
            Severity.MEDIUM, 'DNS Security', domain,
            `Internal IPs found: ${internalIps.join(', ')}`,
            'Attackers can map internal network topology and target internal services',
            'Review DNS records and remove internal IP addresses from public DNS',
            ['https://www.acunetix.com/blog/articles/dns-enumeration/']
          ));
        }
        if (aRecords.length > 10) {
          findings.push(generateFinding(
            'Excessive DNS A records',
            `Domain has ${aRecords.length} A records, which may indicate load balancing or misconfiguration.`,
            Severity.INFO, 'DNS Security', domain,
            `${aRecords.length} A records: ${aRecords.slice(0, 5).join(', ')}...`,
            'Excessive records may complicate DNS management',
            'Review and consolidate DNS A records if appropriate',
            []
          ));
        }
      }
    } catch (error) {
      errors.push(`A record lookup failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      const mxRecords = await resolveMx(domain);
      if (mxRecords.length === 0) {
        findings.push(generateFinding(
          'No MX records found',
          'No mail exchange records found for the domain.',
          Severity.INFO, 'DNS Security', domain,
          'No MX records', 'Email delivery may be affected',
          'Configure MX records if email is needed for this domain', []
        ));
      } else {
        const hasDuplicatePriority = mxRecords.some((mx, i) =>
          mxRecords.some((other, j) => i !== j && mx.priority === other.priority && mx.exchange === other.exchange)
        );
        if (hasDuplicatePriority) {
          findings.push(generateFinding(
            'Duplicate MX records',
            'Multiple MX records with the same priority and exchange found.',
            Severity.LOW, 'DNS Security', domain,
            `MX records: ${mxRecords.map(m => `${m.priority} ${m.exchange}`).join(', ')}`,
            'Duplicate records may cause unnecessary DNS queries',
            'Remove duplicate MX records', []
          ));
        }
      }
    } catch (error) {
      // MX records not being present is not necessarily an error
    }

    try {
      const txtRecords = await resolveTxt(domain);
      const spfRecords = txtRecords.flat().filter(record => record.startsWith('v=spf1'));

      if (spfRecords.length === 0) {
        findings.push(generateFinding(
          'Missing SPF record',
          'No SPF (Sender Policy Framework) record found. SPF helps prevent email spoofing.',
          Severity.HIGH, 'Email Security', domain,
          'No SPF record in TXT records',
          'Domain is vulnerable to email spoofing attacks',
          'Add an SPF record: v=spf1 -all (or appropriate policy)',
          ['https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/']
        ));
      } else {
        const permissiveSpf = spfRecords.find(spf => spf.includes('+all'));
        if (permissiveSpf) {
          findings.push(generateFinding(
            'SPF record with too permissive policy',
            'SPF record contains "+all" which allows any server to send email on behalf of the domain.',
            Severity.CRITICAL, 'Email Security', domain,
            `SPF record: ${permissiveSpf}`,
            'Domain is fully vulnerable to email spoofing despite having SPF',
            'Replace "+all" with "-all" or "~all" in your SPF record',
            ['https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/']
          ));
        }
        if (spfRecords.length > 1) {
          findings.push(generateFinding(
            'Multiple SPF records',
            'Multiple SPF records found. Only one SPF record is allowed per domain.',
            Severity.HIGH, 'Email Security', domain,
            `Found ${spfRecords.length} SPF records`,
            'Multiple SPF records cause email authentication failures',
            'Consolidate all SPF mechanisms into a single record',
            ['https://www.cloudflare.com/learning/email-security/spf/']
          ));
        }
      }
    } catch (error) {
      errors.push(`TXT record lookup failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
      const dmarcTxt = dmarcRecords.flat().filter(record => record.startsWith('v=DMARC1'));

      if (dmarcTxt.length === 0) {
        findings.push(generateFinding(
          'Missing DMARC record',
          'No DMARC (Domain-based Message Authentication, Reporting & Conformance) record found.',
          Severity.HIGH, 'Email Security', domain,
          `No DMARC record found at _dmarc.${domain}`,
          'Domain is vulnerable to email spoofing and phishing attacks',
          'Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com',
          ['https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/']
        ));
      } else {
        const dmarcRecord = dmarcTxt[0];
        if (dmarcRecord.includes('p=none')) {
          findings.push(generateFinding(
            'DMARC policy set to none',
            'DMARC policy is set to "none" which only monitors but does not enforce.',
            Severity.MEDIUM, 'Email Security', domain,
            `DMARC record: ${dmarcRecord}`,
            'Email spoofing attacks are not being blocked',
            'Change DMARC policy to "quarantine" or "reject" after monitoring period',
            ['https://www.cloudflare.com/learning/email-security/dmarc/']
          ));
        }
        if (!dmarcRecord.includes('rua=')) {
          findings.push(generateFinding(
            'DMARC reporting not configured',
            'DMARC record does not include aggregate reporting (rua).',
            Severity.LOW, 'Email Security', domain,
            `DMARC record: ${dmarcRecord}`,
            'No DMARC reports will be received, making it hard to monitor email auth',
            'Add rua=mailto:dmarc-reports@domain.com to your DMARC record',
            ['https://www.cloudflare.com/learning/email-security/dmarc/']
          ));
        }
      }
    } catch (error) {
      // DMARC record not being present is handled above
    }

    // NS record enumeration + zone transfer attempt
    try {
      const nsRecords = await resolveNs(domain);
      if (nsRecords.length > 0) {
        // Try zone transfer (AXFR) against each nameserver
        const { Resolver } = require('dns').Resolver;
        for (const ns of nsRecords.slice(0, 3)) {
          try {
            const resolver = new Resolver();
            resolver.setServers([ns]);
            const records = await new Promise<any[]>((resolve, reject) => {
              resolver.resolve(domain, 'ANY', (err: any, records: any) => {
                if (err) reject(err);
                else resolve(records || []);
              });
            });
            if (records.length > 0) {
              findings.push(generateFinding(
                'DNS zone transfer successful',
                `The nameserver ${ns} allows unrestricted zone transfer (AXFR) for ${domain}.`,
                Severity.CRITICAL,
                'DNS Security',
                domain,
                `Nameserver: ${ns}\nRecords exposed: ${records.length}`,
                'Zone transfer exposes all DNS records including internal hosts, mail servers, and service records',
                'Restrict zone transfers to authorized secondary nameservers only',
                ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods']
              ));
              break;
            }
          } catch {
            // Zone transfer refused (expected for properly configured servers)
          }
        }
      }
    } catch (error) {
      // NS lookup failure
    }

    // SRV record enumeration (useful for AD, mail, and service discovery)
    try {
      const srvPrefixes = [
        '_sip._tcp', '_sip._udp', '_sipfederationtls._tcp', '_xmpp-server._tcp',
        '_autodiscover._tcp', '_submission._tcp', '_imaps._tcp', '_pop3s._tcp',
        '_smtp._tcp', '_imap._tcp', '_kerberos._tcp', '_ldap._tcp',
      ];
      for (const prefix of srvPrefixes) {
        try {
          const srvRecords = await resolveSrv(`${prefix}.${domain}`);
          if (srvRecords.length > 0) {
            const srvList = srvRecords.map(r => `${r.priority}:${r.weight} ${r.name}:${r.port}`).join(', ');
            findings.push(generateFinding(
              `SRV records discovered: ${prefix}`,
              `Service records found for ${prefix}.${domain}.`,
              Severity.INFO,
              'DNS Security',
              domain,
              `SRV: ${srvList}`,
              'SRV records reveal service endpoints and infrastructure',
              'Ensure discovered services are properly secured',
              []
            ));
            // If we find LDAP/Kerberos SRV records, this is likely Active Directory
            if (prefix.includes('ldap') || prefix.includes('kerberos')) {
              findings.push(generateFinding(
                'Active Directory indicators detected',
                `SRV records for ${prefix} suggest this domain uses Active Directory.`,
                Severity.INFO,
                'DNS Security',
                domain,
                `SRV records: ${srvList}`,
                'AD infrastructure should be audited for Kerberoasting, AS-REP, and GPO attacks',
                'Run Active Directory-specific security assessments',
                ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Identity_Management_Testing/']
              ));
            }
          }
        } catch {
          // SRV record not found
        }
      }
    } catch (error) {
      // SRV enumeration failure
    }

    try {
      await resolve(domain, 'DNSKEY');
    } catch (error) {
      try {
        await resolve(domain, 'DS');
      } catch (error) {
        findings.push(generateFinding(
          'DNSSEC not configured',
          'Domain does not have DNS Security Extensions (DNSSEC) enabled.',
          Severity.INFO, 'DNS Security', domain,
          'No DNSSEC records found',
          'Domain is vulnerable to DNS spoofing and cache poisoning attacks',
          'Enable DNSSEC for the domain through your DNS registrar',
          ['https://www.cloudflare.com/dns/dnssec/']
        ));
      }
    }

    const duration = Date.now() - startTime;
    return { module: 'dns', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'dns', findings, duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

import * as dns from 'dns';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);

const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'mandrill',
  'everlytickey1', 'dkim', 'mail', 's1', 's2', 'smtp', 'protonmail',
  'protonmail2', 'secureserver', 'mxvault', 'mxlogic', '.mimecast',
  'selector', 'selector01', 'selector02', 'postfix', 'exim',
];

function countSpfDnsLookups(spfRecord: string): number {
  let count = 0;
  const mechanisms = spfRecord.split(/\s+/);
  for (const mechanism of mechanisms) {
    const m = mechanism.toLowerCase();
    if (m.startsWith('include:') || m.startsWith('a') || m.startsWith('mx') ||
        m.startsWith('redirect=') || m.startsWith('exists:')) {
      count++;
    }
  }
  return count;
}

function parseSpfMechanisms(spfRecord: string): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  const parts = spfRecord.split(/\s+/);
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (lower.startsWith('include:')) {
      if (!result.includes) result.includes = [];
      result.includes.push(part.substring(8));
    } else if (lower.startsWith('ip4:') || lower.startsWith('ip6:')) {
      if (!result.ip) result.ip = [];
      result.ip.push(part);
    } else if (lower === 'mx' || lower.startsWith('mx:')) {
      if (!result.mx) result.mx = [];
      result.mx.push(part);
    } else if (lower === 'a' || lower.startsWith('a:')) {
      if (!result.a) result.a = [];
      result.a.push(part);
    }
  }
  return result;
}

function parseDmarcTags(dmarc: string): Record<string, string> {
  const tags: Record<string, string> = {};
  const parts = dmarc.split(';').map(s => s.trim());
  for (const part of parts) {
    const [key, ...valueParts] = part.split('=');
    if (key && valueParts.length > 0) {
      tags[key.trim().toLowerCase()] = valueParts.join('=').trim();
    }
  }
  return tags;
}

export async function runEmailSecurityScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // === MX Records ===
    let mxRecords: dns.MxRecord[] = [];
    try {
      mxRecords = await resolveMx(domain);
    } catch (e) {
      findings.push(generateFinding(
        'No MX records found',
        'No MX records were found for the domain, meaning email cannot be delivered.',
        Severity.HIGH,
        'Email Security',
        domain,
        'DNS MX lookup returned no records',
        'Without MX records, email delivery to this domain will fail',
        'Configure MX records pointing to your mail servers',
        ['https://datatracker.ietf.org/doc/html/rfc5321#section-3.4.2']
      ));
    }

    // Check for duplicate MX records
    if (mxRecords.length > 1) {
      const seen = new Set<string>();
      const duplicates: string[] = [];
      for (const mx of mxRecords) {
        const key = `${mx.priority}-${mx.exchange.toLowerCase()}`;
        if (seen.has(key)) {
          duplicates.push(`${mx.priority} ${mx.exchange}`);
        }
        seen.add(key);
      }
      if (duplicates.length > 0) {
        findings.push(generateFinding(
          'Duplicate MX records',
          `Duplicate MX records found: ${duplicates.join(', ')}`,
          Severity.LOW,
          'Email Security',
          domain,
          `Duplicate MX: ${duplicates.join('; ')}`,
          'Duplicate MX records are redundant and may cause confusion',
          'Remove duplicate MX records',
          ['https://datatracker.ietf.org/doc/html/rfc5321#section-3.4.2']
        ));
      }
    }

    // === SPF Record Analysis ===
    let spfRecord = '';
    try {
      const txtRecords = await resolveTxt(domain);
      const flatTxt = txtRecords.flat();
      const spfRecords = flatTxt.filter(r => r.startsWith('v=spf1'));

      if (spfRecords.length === 0) {
        findings.push(generateFinding(
          'No SPF record found',
          'No SPF record was found for the domain.',
          Severity.HIGH,
          'Email Security',
          domain,
          'No v=spf1 TXT record found',
          'Without SPF, anyone can send email claiming to be from your domain',
          'Add an SPF TXT record to authorize legitimate mail servers',
          ['https://datatracker.ietf.org/doc/html/rfc7208']
        ));
      } else if (spfRecords.length > 1) {
        findings.push(generateFinding(
          'Multiple SPF records',
          `${spfRecords.length} SPF records found. Only one is allowed per RFC 7208.`,
          Severity.HIGH,
          'Email Security',
          domain,
          `Found ${spfRecords.length} SPF records: ${spfRecords.join('; ')}`,
          'Multiple SPF records cause unpredictable email authentication results',
          'Combine all SPF mechanisms into a single record',
          ['https://datatracker.ietf.org/doc/html/rfc7208#section-3.2']
        ));
      } else {
        spfRecord = spfRecords[0];

        // Check for +all (explicit permissive)
        if (spfRecord.includes('+all') || spfRecord.includes(' +all')) {
          findings.push(generateFinding(
            'SPF record with +all policy',
            'The SPF record uses +all, which allows any server to send email for this domain.',
            Severity.CRITICAL,
            'Email Security',
            domain,
            `SPF record: ${spfRecord}`,
            'A +all SPF policy provides no protection against email spoofing',
            'Change +all to -all (hard fail) or ~all (soft fail)',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.4']
          ));
        }

        // Check for implicit +all (bare "all" without qualifier)
        const allMechanism = spfRecord.match(/\ball\b/);
        if (allMechanism && !spfRecord.includes('-all') && !spfRecord.includes('~all') && !spfRecord.includes('+all') && !spfRecord.includes('?all')) {
          findings.push(generateFinding(
            'SPF record contains implicit +all',
            'The SPF record contains a bare "all" mechanism without a qualifier, which defaults to +all.',
            Severity.CRITICAL,
            'Email Security',
            domain,
            `SPF record: ${spfRecord}`,
            'Implicit +all provides no protection against email spoofing',
            'Add an explicit qualifier: -all (hard fail) or ~all (soft fail)',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.4']
          ));
        }

        // Check for ~all (softfail)
        if (spfRecord.includes('~all')) {
          findings.push(generateFinding(
            'SPF record uses softfail (~all)',
            'The SPF record uses ~all (softfail), which marks failing emails but does not reject them.',
            Severity.LOW,
            'Email Security',
            domain,
            `SPF record: ${spfRecord}`,
            'Softfail allows spoofed emails to be delivered (marked but not rejected)',
            'Consider upgrading to -all (hard fail) after verifying legitimate senders',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-8.4']
          ));
        }

        // Count DNS lookups (RFC 7208 limit: 10)
        const lookupCount = countSpfDnsLookups(spfRecord);
        if (lookupCount > 10) {
          findings.push(generateFinding(
            'SPF record exceeds 10 DNS lookups',
            `The SPF record requires ${lookupCount} DNS lookups, exceeding the RFC 7208 limit of 10.`,
            Severity.HIGH,
            'Email Security',
            domain,
            `DNS lookup count: ${lookupCount}`,
            'SPF records with more than 10 DNS lookups are ignored by receivers',
            'Flatten the SPF record by replacing includes with IP ranges',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4']
          ));
        } else if (lookupCount > 7) {
          findings.push(generateFinding(
            'SPF record approaching DNS lookup limit',
            `The SPF record requires ${lookupCount} DNS lookups (limit: 10).`,
            Severity.LOW,
            'Email Security',
            domain,
            `DNS lookup count: ${lookupCount}`,
            'Approaching the DNS lookup limit may cause issues with future changes',
            'Consider flattening the SPF record to reduce DNS lookups',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4']
          ));
        }

        // Analyze SPF mechanisms
        const mechanisms = parseSpfMechanisms(spfRecord);
        if (mechanisms.includes && mechanisms.includes.length > 0) {
          findings.push(generateFinding(
            'SPF includes detected',
            `The SPF record contains ${mechanisms.includes.length} include mechanism(s).`,
            Severity.INFO,
            'Email Security',
            domain,
            `Includes: ${mechanisms.includes.join(', ')}`,
            'Each include adds a DNS lookup and extends the authorized sender list',
            'Review included domains to ensure they are authorized to send on your behalf',
            ['https://datatracker.ietf.org/doc/html/rfc7208#section-5.2']
          ));
        }
      }
    } catch (e) {
      errors.push(`SPF analysis failed: ${e instanceof Error ? e.message : String(e)}`);
    }

    // === DMARC Record Analysis ===
    try {
      const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
      const flatDmarc = dmarcRecords.flat();
      const dmarcEntries = flatDmarc.filter(r => r.startsWith('v=DMARC1'));

      if (dmarcEntries.length === 0) {
        findings.push(generateFinding(
          'No DMARC record found',
          'No DMARC record was found for the domain.',
          Severity.HIGH,
          'Email Security',
          domain,
          'No v=DMARC1 TXT record found on _dmarc.' + domain,
          'Without DMARC, email spoofing cannot be detected or blocked',
          'Add a DMARC record starting with p=none to begin monitoring',
          ['https://datatracker.ietf.org/doc/html/rfc7489']
        ));
      } else {
        const dmarc = dmarcEntries[0];
        const tags = parseDmarcTags(dmarc);
        const policy = tags.p || '';

        if (policy === 'none') {
          findings.push(generateFinding(
            'DMARC policy set to none',
            'The DMARC policy is set to none, which only monitors but does not protect against spoofing.',
            Severity.MEDIUM,
            'Email Security',
            domain,
            `DMARC record: ${dmarc}`,
            'p=none allows spoofed emails to be delivered; it only generates reports',
            'Gradually move to p=quarantine and then p=reject after monitoring',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        } else if (policy === 'quarantine') {
          findings.push(generateFinding(
            'DMARC policy set to quarantine',
            'The DMARC policy is set to quarantine, which sends failing emails to spam.',
            Severity.INFO,
            'Email Security',
            domain,
            `DMARC policy: quarantine`,
            'Quarantine is a good step; consider upgrading to reject for maximum protection',
            'After monitoring, upgrade to p=reject for full protection',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        } else if (policy === 'reject') {
          findings.push(generateFinding(
            'DMARC policy set to reject',
            'The DMARC policy is set to reject, providing maximum protection against email spoofing.',
            Severity.INFO,
            'Email Security',
            domain,
            'DMARC policy: reject',
            'This is the recommended DMARC policy for maximum email security',
            'Maintain current configuration',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        }

        // Check subdomain policy
        const subdomainPolicy = tags.sp;
        if (!subdomainPolicy) {
          findings.push(generateFinding(
            'DMARC missing subdomain policy',
            'The DMARC record does not specify a subdomain policy (sp=).',
            Severity.LOW,
            'Email Security',
            domain,
            'sp= tag not found in DMARC record',
            'Without sp=, subdomains inherit the main domain policy, which may not be intended',
            'Add sp= tag to explicitly set subdomain policy',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        }

        // Check for reporting
        if (!tags.rua && !tags.ruf) {
          findings.push(generateFinding(
            'DMARC reporting not configured',
            'The DMARC record does not include rua= or ruf= reporting addresses.',
            Severity.MEDIUM,
            'Email Security',
            domain,
            'No rua= or ruf= tags found in DMARC record',
            'Without reporting, you cannot monitor email authentication failures',
            'Add rua=mailto:reports@yourdomain.com for aggregate reports',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        } else if (!tags.rua) {
          findings.push(generateFinding(
            'DMARC aggregate reporting not configured',
            'The DMARC record has ruf= but no rua= for aggregate reporting.',
            Severity.LOW,
            'Email Security',
            domain,
            'ruf= found but rua= missing',
            'Aggregate reports provide high-level authentication failure statistics',
            'Add rua=mailto:reports@yourdomain.com',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        }

        // Check pct tag
        if (tags.pct && parseInt(tags.pct) < 100) {
          findings.push(generateFinding(
            'DMARC pct tag below 100',
            `The DMARC pct tag is set to ${tags.pct}%, meaning the policy is not fully enforced.`,
            Severity.INFO,
            'Email Security',
            domain,
            `pct=${tags.pct}`,
            'A pct below 100 means only a percentage of failing messages are affected',
            'Gradually increase pct to 100 as you verify legitimate senders',
            ['https://datatracker.ietf.org/doc/html/rfc7489#section-6.3']
          ));
        }
      }
    } catch (e) {
      // DMARC not found
      findings.push(generateFinding(
        'No DMARC record found',
        'No DMARC record was found for the domain.',
        Severity.HIGH,
        'Email Security',
        domain,
        'No v=DMARC1 TXT record found on _dmarc.' + domain,
        'Without DMARC, email spoofing cannot be detected or blocked',
        'Add a DMARC record starting with p=none to begin monitoring',
        ['https://datatracker.ietf.org/doc/html/rfc7489']
      ));
    }

    // === DKIM Selector Probing ===
    let dkimFound = false;
    for (const selector of COMMON_DKIM_SELECTORS) {
      try {
        const dkimRecords = await resolveTxt(`${selector}._domainkey.${domain}`);
        const flatDkim = dkimRecords.flat();
        const dkimRecord = flatDkim.find(r => r.includes('v=DKIM1') || r.includes('p='));

        if (dkimRecord) {
          dkimFound = true;

          // Parse DKIM key
          if (dkimRecord.includes('k=ed25519')) {
            findings.push(generateFinding(
              'DKIM with Ed25519 key found',
              `DKIM record found with Ed25519 key on selector "${selector}".`,
              Severity.INFO,
              'Email Security',
              domain,
              `Selector: ${selector}, Key type: Ed25519`,
              'Ed25519 is a modern, secure key type',
              'Maintain current DKIM configuration',
              ['https://datatracker.ietf.org/doc/html/rfc6376']
            ));
          } else if (dkimRecord.includes('k=rsa')) {
            // Check key size if possible (p= key is base64, we can estimate)
            const pMatch = dkimRecord.match(/p=([A-Za-z0-9+/=]+)/);
            if (pMatch) {
              const keyLength = Buffer.from(pMatch[1], 'base64').length * 8;
              if (keyLength < 2048) {
                findings.push(generateFinding(
                  'Weak DKIM key size',
                  `DKIM key on selector "${selector}" is ${keyLength}-bit, below recommended minimum of 2048 bits.`,
                  Severity.HIGH,
                  'Email Security',
                  domain,
                  `Selector: ${selector}, Key size: ${keyLength} bits`,
                  `A ${keyLength}-bit RSA key can be brute-forced with modern computing resources`,
                  'Generate a new DKIM key with at least 2048 bits',
                  ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.3']
                ));
              }
            }
          }

          // Check for revoked key (p= empty)
          if (dkimRecord.match(/p=\s*$/)) {
            findings.push(generateFinding(
              'DKIM key revoked',
              `The DKIM record on selector "${selector}" has an empty p= value, indicating the key is revoked.`,
              Severity.MEDIUM,
              'Email Security',
              domain,
              `Selector: ${selector}, p= (empty)`,
              'A revoked DKIM key means this selector is no longer valid for signing',
              'If intentional, remove the selector. If not, generate a new key.',
              ['https://datatracker.ietf.org/doc/html/rfc6376#section-3.3.1']
            ));
          }

          break; // Found a valid DKIM record, no need to check more selectors
        }
      } catch {
        // Selector not found, continue
      }
    }

    if (dkimFound) {
      findings.push(generateFinding(
        'DKIM record discovered',
        'A valid DKIM record was found for the domain.',
        Severity.INFO,
        'Email Security',
        domain,
        'DKIM record found via selector probing',
        'DKIM helps verify email authenticity and integrity',
        'Maintain DKIM key rotation schedule',
        ['https://datatracker.ietf.org/doc/html/rfc6376']
      ));
    } else {
      findings.push(generateFinding(
        'No DKIM record discoverable',
        `No DKIM record was found using any of ${COMMON_DKIM_SELECTORS.length} common selectors.`,
        Severity.MEDIUM,
        'Email Security',
        domain,
        `Checked ${COMMON_DKIM_SELECTORS.length} selectors: ${COMMON_DKIM_SELECTORS.slice(0, 8).join(', ')}...`,
        'Without DKIM, email recipients cannot verify that emails were sent by your servers',
        'Set up DKIM signing with a 2048-bit key on a common selector',
        ['https://datatracker.ietf.org/doc/html/rfc6376']
      ));
    }

    // === MTA-STS Check ===
    try {
      const mtaStsRecords = await resolveTxt(`_mta-sts.${domain}`);
      const flatMtaSts = mtaStsRecords.flat();
      const mtaStsEntry = flatMtaSts.find(r => r.startsWith('v=STSv1'));

      if (mtaStsEntry) {
        findings.push(generateFinding(
          'MTA-STS policy found',
          'An MTA-STS policy was found, which enforces TLS for incoming email.',
          Severity.INFO,
          'Email Security',
          domain,
          `MTA-STS record: ${mtaStsEntry}`,
          'MTA-STS protects against SMTP downgrade attacks and expired certificates',
          'Ensure the MTA-STS policy is properly configured at https://mta-sts.{domain}/.well-known/mta-sts.txt',
          ['https://datatracker.ietf.org/doc/html/rfc8461']
        ));
      }
    } catch {
      // MTA-STS not found
    }

    // === DANE/TLSA Check ===
    try {
      const tlsaRecords = await resolveTxt(`_25._tcp.${domain}`);
      // DANE uses TLSA records, not TXT, but we can check via a different approach
      // For now, just note the check
    } catch {
      // TLSA not found via TXT (expected, TLSA is a different record type)
    }

    // === SMTP TLS Reporting (TLSRPT) Check ===
    try {
      const tlsrptRecords = await resolveTxt(`_smtp._tls.${domain}`);
      const flatTlsrpt = tlsrptRecords.flat();
      const tlsrptEntry = flatTlsrpt.find(r => r.startsWith('v=TLSRPTv1'));

      if (tlsrptEntry) {
        findings.push(generateFinding(
          'SMTP TLS reporting configured',
          'SMTP TLS reporting (TLSRPT) is configured for the domain.',
          Severity.INFO,
          'Email Security',
          domain,
          `TLSRPT record: ${tlsrptEntry}`,
          'TLSRPT provides visibility into TLS failures during SMTP delivery',
          'Review TLSRPT reports regularly to detect SMTP security issues',
          ['https://datatracker.ietf.org/doc/html/rfc8460']
        ));
      }
    } catch {
      // TLSRPT not found
    }

    const duration = Date.now() - startTime;
    return {
      module: 'emailSecurity',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'emailSecurity',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

import { Request, Response, NextFunction } from 'express';
import dns from 'dns';
import net from 'net';

const BLOCKED_TLDS = ['.local', '.internal', '.localhost', '.test', '.example'];

const PRIVATE_RANGES_V4 = [
  { start: [10, 0, 0, 0], end: [10, 255, 255, 255] },
  { start: [172, 16, 0, 0], end: [172, 31, 255, 255] },
  { start: [192, 168, 0, 0], end: [192, 168, 255, 255] },
];

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return (parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]) >>> 0;
}

function isPrivateIPv4(ip: string): boolean {
  if (!net.isIPv4(ip)) return false;
  const ipNum = ipToNumber(ip);
  if (ipNum === null) return false;
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '169.254.169.254') return true;
  const lo = ipToNumber('127.0.0.0')!;
  const hi = ipToNumber('127.255.255.255')!;
  if (ipNum >= lo && ipNum <= hi) return true;
  const aLo = ipToNumber('169.254.0.0')!;
  const aHi = ipToNumber('169.254.255.255')!;
  if (ipNum >= aLo && ipNum <= aHi) return true;
  for (const range of PRIVATE_RANGES_V4) {
    const s = ipToNumber(range.start.join('.'))!;
    const e = ipToNumber(range.end.join('.'))!;
    if (ipNum >= s && ipNum <= e) return true;
  }
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
  if (lower.startsWith('fe80:')) return true;
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice(7);
    if (net.isIPv4(v4)) return isPrivateIPv4(v4);
  }
  return false;
}

function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return false;
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) return false;
  if (net.isIP(domain) !== 0) return false;
  for (const tld of BLOCKED_TLDS) {
    if (domain.toLowerCase().endsWith(tld)) return false;
  }
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain);
}

function resolveAndValidate(domain: string): Promise<{ valid: boolean; reason?: string; resolvedIps?: string[] }> {
  return new Promise((resolve) => {
    dns.resolve4(domain, (err4, ipv4) => {
      const ips: string[] = [];
      if (!err4) ips.push(...ipv4);

      dns.resolve6(domain, (err6, ipv6) => {
        if (!err6) ips.push(...ipv6);

        if (ips.length === 0 && err4) {
          resolve({ valid: false, reason: 'DNS resolution failed' });
          return;
        }

        for (const address of ips) {
          if (isPrivateIP(address)) {
            resolve({ valid: false, reason: `Resolved to private/internal IP: ${address}` });
            return;
          }
        }

        resolve({ valid: true, resolvedIps: ips });
      });
    });
  });
}

export async function validateTarget(
  domain: string
): Promise<{ valid: boolean; reason?: string; resolvedIps?: string[] }> {
  if (!domain || typeof domain !== 'string') {
    return { valid: false, reason: 'Target domain is required' };
  }

  const cleanDomain = domain.trim().toLowerCase();

  if (['localhost', '::1', '0.0.0.0', '127.0.0.1', '169.254.169.254'].includes(cleanDomain)) {
    return { valid: false, reason: 'Localhost/internal addresses are not allowed' };
  }

  if (cleanDomain.startsWith('10.') || cleanDomain.startsWith('192.168.') || cleanDomain.startsWith('172.')) {
    return { valid: false, reason: 'Private IP addresses are not allowed' };
  }

  if (!isValidDomain(cleanDomain)) {
    return { valid: false, reason: 'Invalid domain: must be a valid public domain name' };
  }

  return resolveAndValidate(cleanDomain);
}

export const ssrfProtection = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const target = req.body.domain || req.body.target || req.query.target || req.params.domain;

  if (!target) {
    next();
    return;
  }

  const result = await validateTarget(target as string);

  if (!result.valid) {
    res.status(400).json({
      message: 'SSRF protection: target is not safe to scan',
      reason: result.reason,
    });
    return;
  }

  (req as any).resolvedIps = result.resolvedIps;
  next();
};

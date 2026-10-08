// ═══════════════════════════════════════════════════════════════════════════════
// SCOPE ENFORCEMENT MIDDLEWARE — Validates targets against engagement scope
// ═══════════════════════════════════════════════════════════════════════════════
// Applied to scan-triggering endpoints. Ensures every target is authorized
// before any tool is executed. Non-destructive: blocks only, never modifies.
// ═══════════════════════════════════════════════════════════════════════════════

import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── IP Utilities ────────────────────────────────────────────────────────────

function ipToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isInCIDR(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const ipLong = ipToLong(ip);
  const networkLong = ipToLong(network);
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipLong & mask) === (networkLong & mask);
}

// ─── Match Helpers ───────────────────────────────────────────────────────────

function matchesDomain(target: string, rule: string): boolean {
  const lower = target.toLowerCase();
  const ruleLower = rule.toLowerCase();
  return lower === ruleLower || lower.endsWith('.' + ruleLower);
}

function matchesRule(target: string, rule: { targetType: string; value: string }): boolean {
  switch (rule.targetType) {
    case 'domain':
      return matchesDomain(target, rule.value);
    case 'cidr':
      try { return isInCIDR(target, rule.value); } catch { return false; }
    case 'ip':
      return target === rule.value;
    case 'url':
      try {
        const url = new URL(rule.value);
        return target.includes(url.hostname);
      } catch { return false; }
    case 'regex':
      try { return new RegExp(rule.value, 'i').test(target); } catch { return false; }
    default:
      return false;
  }
}

// ─── Middleware Factory ──────────────────────────────────────────────────────

export function requireScopeValidation() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authReq = req as AuthRequest;
    const { organizationId } = authReq;

    // Extract target from body or query
    const target = (req.body?.target || req.query?.target || '') as string;
    const engagementId = req.body?.engagementId as string | undefined;

    // If no engagement ID, fall back to SSRF protection (existing middleware)
    if (!engagementId) {
      next();
      return;
    }

    // Load scope rules from the engagement
    const engagement = await prisma.engagement.findFirst({
      where: { id: engagementId, organizationId },
      include: { scopeRules: true },
    });

    if (!engagement) {
      res.status(404).json({ message: 'Engagement not found' });
      return;
    }

    if (engagement.scopeRules.length === 0) {
      // No scope rules = legacy mode, allow everything (SSRF middleware still runs)
      next();
      return;
    }

    // Check target against scope rules
    const targets = target.split(',').map(t => t.trim()).filter(Boolean);

    for (const t of targets) {
      // Deny rules first
      const denied = engagement.scopeRules
        .filter(r => r.type === 'deny')
        .some(rule => matchesRule(t, rule));

      if (denied) {
        logger.warn(`[Scope] BLOCKED: "${t}" matches deny rule in engagement ${engagementId}`);
        await logScopeViolation(authReq.userId, organizationId, engagementId, t, 'deny_rule_matched');
        res.status(403).json({
          message: `Target "${t}" is not within the engagement scope`,
          target: t,
          engagementId,
        });
        return;
      }

      // Allow rules
      const allowed = engagement.scopeRules
        .filter(r => r.type === 'allow')
        .some(rule => matchesRule(t, rule));

      if (!allowed) {
        logger.warn(`[Scope] BLOCKED: "${t}" has no matching allow rule in engagement ${engagementId}`);
        await logScopeViolation(authReq.userId, organizationId, engagementId, t, 'no_allow_rule');
        res.status(403).json({
          message: `Target "${t}" is not within the engagement scope`,
          target: t,
          engagementId,
        });
        return;
      }
    }

    logger.info(`[Scope] ALLOWED: "${target}" is in scope for engagement ${engagementId}`);
    next();
  };
}

// ─── Audit Logging ───────────────────────────────────────────────────────────

async function logScopeViolation(
  userId: string,
  organizationId: string,
  engagementId: string,
  target: string,
  reason: string,
): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        organizationId,
        action: 'scope.violation',
        resource: 'engagement',
        resourceId: engagementId,
        details: JSON.stringify({ target, reason, timestamp: new Date().toISOString() }),
        ipAddress: 'system',
      },
    });
  } catch (e) {
    logger.warn(`[Scope] Failed to log violation: ${e}`);
  }
}

// ─── Scope Check Utility (for use in other services) ─────────────────────────

export async function isTargetInEngagementScope(
  target: string,
  engagementId: string,
  organizationId: string,
): Promise<{ allowed: boolean; reason?: string }> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId },
    include: { scopeRules: true },
  });

  if (!engagement) return { allowed: false, reason: 'engagement_not_found' };
  if (engagement.scopeRules.length === 0) return { allowed: true, reason: 'no_scope_rules' };

  // Check deny
  for (const rule of engagement.scopeRules.filter(r => r.type === 'deny')) {
    if (matchesRule(target, rule)) {
      return { allowed: false, reason: `deny_rule: ${rule.targetType}=${rule.value}` };
    }
  }

  // Check allow
  for (const rule of engagement.scopeRules.filter(r => r.type === 'allow')) {
    if (matchesRule(target, rule)) {
      return { allowed: true };
    }
  }

  return { allowed: false, reason: 'no_allow_rule_match' };
}

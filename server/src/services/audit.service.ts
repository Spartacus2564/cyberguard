import prisma from '../lib/prisma';
import logger from '../utils/logger';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_OFFSET = 100_000;

export interface AuditLogData {
  userId?: string;
  organizationId?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  details?: string;
  ipAddress?: string;
}

export async function logAudit(data: AuditLogData): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: data.userId || null,
        organizationId: data.organizationId || null,
        action: data.action,
        resource: data.resource || null,
        resourceId: data.resourceId || null,
        details: data.details || null,
        ipAddress: data.ipAddress || null,
      },
    });
  } catch (err) {
    // Don't let audit logging failures break the main flow
    logger.error('Audit log write failed:', { error: String(err) });
  }
}

export async function getAuditLogs(
  organizationId: string,
  options: { limit?: number; offset?: number; action?: string } = {}
) {
  const requestedLimit = options.limit ?? DEFAULT_LIMIT;
  const requestedOffset = options.offset ?? 0;
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(MAX_LIMIT, Math.max(1, Math.trunc(requestedLimit)))
    : DEFAULT_LIMIT;
  const offset = Number.isFinite(requestedOffset)
    ? Math.min(MAX_OFFSET, Math.max(0, Math.trunc(requestedOffset)))
    : 0;
  const action = options.action?.trim();

  const where: any = { organizationId };
  if (action) where.action = action;

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit,
      skip: offset,
    }),
    prisma.auditLog.count({ where }),
  ]);

  return { logs, total, limit, offset };
}

import prisma from '../lib/prisma';
import logger from '../utils/logger';

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
  const { limit = 50, offset = 0, action } = options;

  const where: any = { organizationId };
  if (action) where.action = action;

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    }),
    prisma.auditLog.count({ where }),
  ]);

  return { logs, total, limit, offset };
}

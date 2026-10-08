jest.mock('../src/lib/prisma', () => ({
  __esModule: true,
  default: {
    auditLog: {
      findMany: jest.fn(),
      count: jest.fn(),
      create: jest.fn(),
    },
  },
}));

import prisma from '../src/lib/prisma';
import { getAuditLogs } from '../src/services/audit.service';

const auditLogMock = prisma.auditLog as unknown as {
  findMany: jest.Mock;
  count: jest.Mock;
};

describe('getAuditLogs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    auditLogMock.findMany.mockResolvedValue([]);
    auditLogMock.count.mockResolvedValue(0);
  });

  it('clamps pagination, trims filters, and remains organization-scoped', async () => {
    const result = await getAuditLogs('org-1', {
      limit: 500,
      offset: -10,
      action: '  assessment.created  ',
    });

    expect(auditLogMock.findMany).toHaveBeenCalledWith({
      where: { organizationId: 'org-1', action: 'assessment.created' },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 200,
      skip: 0,
    });
    expect(auditLogMock.count).toHaveBeenCalledWith({
      where: { organizationId: 'org-1', action: 'assessment.created' },
    });
    expect(result).toEqual({ logs: [], total: 0, limit: 200, offset: 0 });
  });

  it('uses bounded defaults for non-finite pagination values', async () => {
    const result = await getAuditLogs('org-1', {
      limit: Number.NaN,
      offset: Number.POSITIVE_INFINITY,
    });

    expect(auditLogMock.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ take: 50, skip: 0 })
    );
    expect(result.limit).toBe(50);
    expect(result.offset).toBe(0);
  });
});
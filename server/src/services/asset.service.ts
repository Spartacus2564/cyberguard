import prisma from '../lib/prisma';

export async function createAsset(domain: string, organizationId: string) {
  const existing = await prisma.asset.findFirst({
    where: { domain, organizationId },
  });

  if (existing) {
    return existing;
  }

  return prisma.asset.create({
    data: { domain, organizationId },
  });
}

export async function getAssetsByOrganization(organizationId: string) {
  return prisma.asset.findMany({
    where: { organizationId },
    orderBy: { createdAt: 'desc' },
  });
}

export async function getAssetById(id: string, organizationId: string) {
  return prisma.asset.findFirst({
    where: { id, organizationId },
  });
}

export async function deleteAsset(id: string, organizationId: string) {
  const asset = await prisma.asset.findFirst({
    where: { id, organizationId },
  });

  if (!asset) {
    throw new Error('Asset not found or access denied');
  }

  return prisma.asset.delete({ where: { id } });
}

export { prisma };

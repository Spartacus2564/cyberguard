import prisma from '../lib/prisma';

export async function getUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
    include: { organization: true },
  });
}

export async function getUserByEmail(email: string) {
  return prisma.user.findUnique({
    where: { email },
  });
}

export async function updateUser(
  id: string,
  data: { firstName?: string; lastName?: string }
) {
  return prisma.user.update({
    where: { id },
    data,
    include: { organization: true },
  });
}

export async function getUsersByOrganization(organizationId: string) {
  return prisma.user.findMany({
    where: { organizationId },
    include: { organization: true },
    orderBy: { createdAt: 'desc' },
  });
}

export { prisma };

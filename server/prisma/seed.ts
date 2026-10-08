import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding CyberGuard database...');

  const org = await prisma.organization.create({
    data: {
      name: 'CyberGuard Demo',
    },
  });
  console.log(`Created organization: ${org.name} (${org.id})`);

  const adminHash = await bcrypt.hash('Admin123!', 12);
  const admin = await prisma.user.create({
    data: {
      email: 'admin@cyberguard.io',
      passwordHash: adminHash,
      firstName: 'Admin',
      lastName: 'User',
      role: 'ADMIN',
      organizationId: org.id,
    },
  });
  console.log(`Created admin: ${admin.email} (${admin.id})`);

  const memberHash = await bcrypt.hash('Member123!', 12);
  const member = await prisma.user.create({
    data: {
      email: 'member@cyberguard.io',
      passwordHash: memberHash,
      firstName: 'Member',
      lastName: 'User',
      role: 'MEMBER',
      organizationId: org.id,
    },
  });
  console.log(`Created member: ${member.email} (${member.id})`);

  console.log('Seeding complete.');
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

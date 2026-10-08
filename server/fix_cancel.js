const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
(async () => {
  // Delete the stuck DRAFT engagement
  const del = await p.engagement.delete({ where: { id: '5f0bc009-cf35-4be4-b9e4-8a731c01ba03' } });
  console.log('Deleted stuck engagement:', del.id, del.status);

  // Also clean up any orphaned engagements with null domain
  const orphans = await p.engagement.deleteMany({ where: { domain: null } });
  console.log('Deleted orphaned engagements (null domain):', orphans.count);

  await p.$disconnect();
})();

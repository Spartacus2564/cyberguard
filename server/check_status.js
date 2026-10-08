const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
(async () => {
  const engagements = await p.engagement.findMany({
    where: { domain: 'tekup-student.educated.tn' },
    select: { id: true, status: true },
    orderBy: { createdAt: 'desc' }
  });
  console.log('Engagements:', JSON.stringify(engagements, null, 2));
  
  const assessments = await p.assessment.findMany({
    where: { domain: 'tekup-student.educated.tn' },
    select: { id: true, status: true, engagementId: true },
    orderBy: { createdAt: 'desc' }
  });
  console.log('Assessments:', JSON.stringify(assessments, null, 2));
  
  await p.$disconnect();
})();

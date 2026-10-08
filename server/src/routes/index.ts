import { Router } from 'express';
import authRoutes from './auth.routes';
import assessmentRoutes from './assessment.routes';
import findingRoutes from './finding.routes';
import reportRoutes from './report.routes';
import userRoutes from './user.routes';
import auditRoutes from './audit.routes';
import engagementRoutes from './engagement.routes';
import knowledgeRoutes from './knowledge.routes';
import dashboardRoutes from './dashboard.routes';

// Register engagement scan queue processor at startup
import '../queue/engagementQueue';

const router = Router();

router.use('/api/auth', authRoutes);
router.use('/api/assessments', assessmentRoutes);
router.use('/api/findings', findingRoutes);
router.use('/api/reports', reportRoutes);
router.use('/api/users', userRoutes);
router.use('/api/audit', auditRoutes);
router.use('/api', dashboardRoutes);
router.use('/api', knowledgeRoutes);
router.use('/api/engagements', engagementRoutes);

export default router;

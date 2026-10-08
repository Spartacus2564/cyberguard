import request from 'supertest';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { config } from '../src/config';
import { authenticate } from '../src/middleware/auth';
import { ssrfProtection } from '../src/middleware/ssrfProtection';
import { errorHandler } from '../src/middleware/errorHandler';
import { validate } from '../src/middleware/validate';
import { body, param } from 'express-validator';
import * as authService from '../src/services/auth.service';
import * as assessmentService from '../src/services/assessment.service';
import * as findingService from '../src/services/finding.service';
import * as reportService from '../src/services/report.service';
import { UserRole } from '../src/types';

// Create test app without listening
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: config.allowedOrigins, credentials: true }));
app.use(express.json());
app.use(morgan('combined'));

// Auth routes
app.post('/api/auth/login',
  validate([body('email').isEmail(), body('password').isString()]),
  async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const result = await authService.login(email, password);
      res.json(result);
    } catch (error: any) {
      res.status(401).json({ message: error.message || 'Login failed' });
    }
  }
);

app.post('/api/auth/register',
  validate([
    body('email').isEmail(),
    body('password').isLength({ min: 12 }),
    body('firstName').isString(),
    body('lastName').isString(),
    body('organizationName').isString(),
  ]),
  async (req, res, next) => {
    try {
      const { email, password, firstName, lastName, organizationName } = req.body;
      const result = await authService.register(email, password, firstName, lastName, organizationName);
      res.status(201).json(result);
    } catch (error: any) {
      res.status(400).json({ message: error.message || 'Registration failed' });
    }
  }
);

// Protected routes
app.get('/api/assessments', authenticate, async (req: any, res) => {
  try {
    const result = await assessmentService.getAssessmentsByOrganization(req.organizationId);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/assessments/stats', authenticate, async (req: any, res) => {
  try {
    const stats = await assessmentService.getAssessmentStats(req.organizationId);
    res.json(stats);
  } catch (error: any) {
    res.status(500).json({ message: 'Failed to fetch assessment stats' });
  }
});

app.post('/api/assessments',
  authenticate,
  ssrfProtection,
  validate([body('domain').isString().isLength({ min: 1, max: 253 })]),
  async (req: any, res) => {
    try {
      const assessment = await assessmentService.createAssessment(
        req.body.domain,
        req.organizationId,
        req.body.assetId
      );
      res.status(201).json(assessment);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  }
);

app.get('/api/assessments/:id',
  authenticate,
  validate([param('id').isUUID()]),
  async (req: any, res) => {
    try {
      const assessment = await assessmentService.getAssessmentById(req.params.id, req.organizationId);
      if (!assessment) return res.status(404).json({ message: 'Assessment not found' });
      res.json(assessment);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  }
);

app.delete('/api/assessments/:id',
  authenticate,
  validate([param('id').isUUID()]),
  async (req: any, res) => {
    try {
      await assessmentService.deleteAssessment(req.params.id, req.organizationId);
      res.json({ message: 'Assessment deleted' });
    } catch (error: any) {
      res.status(400).json({ message: error.message });
    }
  }
);

app.get('/api/assessments/:id/findings',
  authenticate,
  validate([param('id').isUUID()]),
  async (req: any, res) => {
    try {
      const findings = await findingService.getFindingsByAssessment(req.params.id, req.organizationId);
      res.json(findings);
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  }
);

app.use(errorHandler);

const DEMO_EMAIL = 'test@demo.io';
const DEMO_PASSWORD = 'Secure123!';

let authToken: string;
let assessmentId: string;

beforeAll(async () => {
  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: DEMO_EMAIL, password: DEMO_PASSWORD });

  if (loginRes.status === 200 && loginRes.body.token) {
    authToken = loginRes.body.token;
  }
});

describe('Auth API', () => {
  it('should login with valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: DEMO_EMAIL, password: DEMO_PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe(DEMO_EMAIL);
  });

  it('should reject invalid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: DEMO_EMAIL, password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.message).toBeDefined();
  });

  it('should reject missing fields', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: DEMO_EMAIL });
    expect(res.status).toBe(400);
  });

  it('should reject weak password on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        email: `weak-${Date.now()}@example.com`,
        password: 'weak',
        firstName: 'Test',
        lastName: 'User',
        organizationName: 'Test Org',
      });
    expect(res.status).toBe(400);
  });
});

describe('Assessment API', () => {
  it('should create assessment', async () => {
    if (!authToken) return;
    const res = await request(app)
      .post('/api/assessments')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ domain: 'example.com' });
    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.domain).toBe('example.com');
    expect(res.body.status).toBe('PENDING');
    assessmentId = res.body.id;
  });

  it('should get assessment by ID', async () => {
    if (!authToken || !assessmentId) return;
    const res = await request(app)
      .get(`/api/assessments/${assessmentId}`)
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(assessmentId);
  });

  it('should list assessments', async () => {
    if (!authToken) return;
    const res = await request(app)
      .get('/api/assessments')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.assessments)).toBe(true);
  });

  it('should get stats', async () => {
    if (!authToken) return;
    const res = await request(app)
      .get('/api/assessments/stats')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(200);
    expect(res.body.findingsBySeverity).toBeDefined();
  });

  it('should reject unauthenticated requests', async () => {
    const res = await request(app).get('/api/assessments');
    expect(res.status).toBe(401);
  });

  it('should reject invalid UUID', async () => {
    if (!authToken) return;
    const res = await request(app)
      .get('/api/assessments/invalid-uuid')
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(400);
  });

  it('should delete assessment', async () => {
    if (!authToken || !assessmentId) return;
    const res = await request(app)
      .delete(`/api/assessments/${assessmentId}`)
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(200);
  });
});

describe('Finding API', () => {
  it('should return findings for assessment', async () => {
    if (!authToken || !assessmentId) return;
    const res = await request(app)
      .get(`/api/assessments/${assessmentId}/findings`)
      .set('Authorization', `Bearer ${authToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

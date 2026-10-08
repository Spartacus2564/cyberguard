import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import { config } from './config';
import routes from './routes';
import advancedRoutes from './routes/advanced.routes';
import { errorHandler } from './middleware/errorHandler';
import { userRateLimiter } from './middleware/rateLimiter';
import { initializeScheduler } from './services/scheduler.service';
import logger from './utils/logger';
import prisma from './lib/prisma';
import redis from './lib/redis';
import jwt from 'jsonwebtoken';
import { JWTPayload } from './types';

const app = express();

// ═══════════════════════════════════════════════════════════════════════════════
// SSE PROGRESS — standalone endpoint (bypasses router auth middleware)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/engagements/:id/progress', async (req, res) => {
  const queryToken = req.query.token as string;
  // Inline cookie parse (SSE route is registered before the cookie parser middleware)
  let cookieToken: string | undefined;
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    for (const c of cookieHeader.split(';')) {
      const [name, ...parts] = c.trim().split('=');
      if (name?.trim() === 'cyberguard_token') { cookieToken = parts.join('=').trim(); break; }
    }
  }
  const token = queryToken || cookieToken;
  if (!token) {
    res.status(401).json({ message: 'Token required' });
    return;
  }

  let organizationId: string;
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as JWTPayload;
    organizationId = decoded.organizationId;
  } catch {
    res.status(401).json({ message: 'Invalid token' });
    return;
  }

  let engStatus = '';
  try {
    const engagement = await prisma.engagement.findFirst({
      where: { id: req.params.id, organizationId }
    });
    if (!engagement) {
      res.status(404).json({ message: 'Engagement not found' });
      return;
    }
    engStatus = engagement.status;
  } catch {
    res.status(404).json({ message: 'Engagement not found' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  res.write('data: ' + JSON.stringify({ type: 'connected', engagementId: req.params.id }) + '\n\n');

  // If already done, send terminal state immediately
  if (engStatus === 'COMPLETED') {
    res.write('data: ' + JSON.stringify({ progress: 100, status: 'COMPLETED' }) + '\n\n');
  } else if (engStatus === 'FAILED') {
    res.write('data: ' + JSON.stringify({ progress: 0, status: 'FAILED', error: 'Scan failed' }) + '\n\n');
  } else if (engStatus === 'ACTIVE') {
    // Aggressive recovery: check immediately if scan is actually done
    try {
      const engagement = await prisma.engagement.findFirst({ where: { id: req.params.id, organizationId } });
      if (engagement) {
        // Check if assessment is completed
        const assessment = await prisma.assessment.findFirst({
          where: { organizationId, domain: engagement.domain || '' },
          orderBy: { createdAt: 'desc' },
        });
        // Check if findings exist (scan ran and produced results)
        if (assessment) {
          const findingCount = await prisma.finding.count({
            where: { assessmentId: assessment.id },
          });
          if (assessment.status === 'COMPLETED' || findingCount > 0) {
            await prisma.engagement.update({ where: { id: req.params.id }, data: { status: 'COMPLETED', completedAt: new Date() } });
            engStatus = 'COMPLETED';
            res.write('data: ' + JSON.stringify({ progress: 100, status: 'COMPLETED' }) + '\n\n');
          }
        }
      }
    } catch (e) { logger.warn('SSE recovery check failed: ' + e); }
  }

  const progressKey = 'engagement:' + req.params.id + ':progress';
  let recoveryTick = 0;

  const sendProgress = async () => {
    try {
      const data = await redis.get(progressKey);
      if (data) {
        res.write('data: ' + data + '\n\n');
      } else if (engStatus === 'ACTIVE') {
        // Recovery check every 10 seconds (every 5th tick) to reduce DB load
        recoveryTick++;
        if (recoveryTick % 5 === 0) {
          try {
            const engagement = await prisma.engagement.findFirst({ where: { id: req.params.id, organizationId } });
            if (engagement && engagement.status !== 'ACTIVE') {
              engStatus = engagement.status;
              const finalData = engStatus === 'COMPLETED'
                ? { progress: 100, status: 'COMPLETED' }
                : { progress: 0, status: 'FAILED', error: 'Scan failed' };
              res.write('data: ' + JSON.stringify(finalData) + '\n\n');
            } else if (engagement) {
              const assessment = await prisma.assessment.findFirst({
                where: { organizationId, domain: engagement.domain || '' },
                orderBy: { createdAt: 'desc' },
              });
              if (assessment) {
                const findingCount = await prisma.finding.count({ where: { assessmentId: assessment.id } });
                if (findingCount > 0 || assessment.status === 'COMPLETED') {
                  await prisma.engagement.update({ where: { id: req.params.id }, data: { status: 'COMPLETED', completedAt: new Date() } });
                  engStatus = 'COMPLETED';
                  res.write('data: ' + JSON.stringify({ progress: 100, status: 'COMPLETED' }) + '\n\n');
                }
              }
            }
          } catch (e) { logger.warn('SSE recovery poll failed: ' + e); }
        }
      }
    } catch (e) {
      logger.warn('[Server] SSE progress failed: ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  const intervalId = setInterval(sendProgress, 2000);

  const subscriber = redis.duplicate();
  const channel = 'engagement:' + req.params.id + ':events';
  await subscriber.subscribe(channel);
  subscriber.on('message', function(ch: string, message: string) {
    if (ch === channel) {
      res.write('data: ' + message + '\n\n');
    }
  });

  req.on('close', () => {
    clearInterval(intervalId);
    subscriber.unsubscribe(channel);
    subscriber.quit();
  });
});

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: config.allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

app.use(compression());
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// Manual cookie parser (replaces cookie-parser package)
app.use((req, _res, next) => {
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const cookies: Record<string, string> = {};
    cookieHeader.split(';').forEach(c => {
      const [name, ...valueParts] = c.trim().split('=');
      if (name) cookies[name.trim()] = valueParts.join('=').trim();
    });
    (req as any).cookies = cookies;
  }
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Per-user rate limiting (authenticated users get their own bucket)
app.use(userRateLimiter);

app.get('/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    let redisOk = false;
    try {
      const pong = await redis.ping();
      redisOk = pong === 'PONG';
    } catch (e) {
      logger.warn('[Server] Redis health check failed: ' + (e instanceof Error ? e.message : String(e)));
    }
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected',
      redis: redisOk ? 'connected' : 'disconnected',
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
    });
  }
});

app.use(routes);
app.use('/api/advanced', advancedRoutes);
app.use(errorHandler);

const server = app.listen(config.port, async () => {
  logger.info(`CyberGuard server running on port ${config.port} [${config.nodeEnv}]`);
  
  // Initialize scheduler for recurring scans
  try {
    await initializeScheduler();
  } catch (error) {
    logger.error('Failed to initialize scheduler:', { error: String(error) });
  }
});

const shutdown = async (signal: string) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  server.close(async () => {
    await prisma.$disconnect();
    logger.info('Server shut down gracefully');
    process.exit(0);
  });
  setTimeout(() => {
    logger.error('Graceful shutdown timed out. Force exiting.');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { reason: String(reason) });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  shutdown('uncaughtException');
});

export { app, server };

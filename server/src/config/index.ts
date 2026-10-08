import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

// Auto-generate JWT secret for development if not provided
if (!process.env.JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Missing required environment variable: JWT_SECRET');
  }
  process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
  console.warn('[Config] Auto-generated JWT_SECRET for development. Set JWT_SECRET env var for production.');
}

// Warn about weak/default secrets
const weakSecrets = ['cyberguard-dev-secret-2026-change-in-production', 'secret', 'changeme', 'password'];
if (weakSecrets.includes(process.env.JWT_SECRET || '')) {
  console.warn('[Config] WARNING: JWT_SECRET is a weak/default value. Set a strong random secret for production.');
}

const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET'] as const;

if (process.env.NODE_ENV === 'production') {
  const prodRequired = ['DATABASE_URL', 'JWT_SECRET', 'REDIS_URL'] as const;
  for (const envVar of prodRequired) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }
} else {
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }
}

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL!,
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwtSecret: process.env.JWT_SECRET!,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
  allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10),
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '500', 10),
  loginRateLimitMax: parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '5', 10),
  registerRateLimitMax: parseInt(process.env.REGISTER_RATE_LIMIT_MAX || '3', 10),
  aiProvider: process.env.AI_PROVIDER || 'ollama',
  aiApiKey: process.env.AI_API_KEY || '',
  aiBaseUrl: process.env.AI_BASE_URL || '',
  aiModel: process.env.AI_MODEL || 'hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF',
  securityModel: process.env.SECURITY_MODEL || 'hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF',
  generalModel: process.env.GENERAL_MODEL || 'dolphin3:8b',
  reasoningModel: process.env.REASONING_MODEL || 'hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF',
  ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://host.docker.internal:11434',
  ollamaTimeout: parseInt(process.env.OLLAMA_TIMEOUT || '300000', 10),
  portScanEnabled: process.env.PORT_SCAN_ENABLED === 'true',
  reportsDir: process.env.REPORTS_DIR || 'reports',
};

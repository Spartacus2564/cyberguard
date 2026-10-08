import { Router, Request, Response, NextFunction } from 'express';
import { rateLimit, RateLimitRequestHandler } from 'express-rate-limit';
import { config } from '../config';

const ipKeyGenerator = (req: Request) => req.ip || req.socket.remoteAddress || 'unknown';

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please try again in 15 minutes.' },
  keyGenerator: ipKeyGenerator,
});

export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: config.registerRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many registration attempts. Please try again later.' },
  keyGenerator: ipKeyGenerator,
});

export const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many scan requests. Please wait before starting another assessment.' },
});

// Per-user rate limiter — use IP as key (userId extraction from JWT happens after rate limiting)
// This ensures all requests are properly rate-limited regardless of auth state
export const userRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please try again later.' },
  keyGenerator: ipKeyGenerator,
});

// Authenticated rate limiter — use userId from JWT (must be applied AFTER auth middleware)
export const authenticatedRateLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please try again later.' },
  keyGenerator: (req: Request) => {
    const authReq = req as any;
    if (authReq.userId) return `user:${authReq.userId}`;
    return ipKeyGenerator(req);
  },
  skip: (req: Request) => {
    // Skip if no userId (auth not yet applied)
    return !(req as any).userId;
  },
});

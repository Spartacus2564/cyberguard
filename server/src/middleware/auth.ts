import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { AuthRequest, JWTPayload, UserRole } from '../types';
import redis from '../lib/redis';

const REVOKED_TOKENS_KEY = 'cyberguard:revoked_tokens';

export async function revokeToken(token: string): Promise<void> {
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as JWTPayload;
    const ttl = decoded.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 7 * 24 * 60 * 60;
    if (ttl > 0) {
      await redis.setex(`${REVOKED_TOKENS_KEY}:${token}`, ttl, '1');
    }
  } catch {
    // Token invalid or Redis unavailable, ignore
  }
}

export async function isTokenRevoked(token: string): Promise<boolean> {
  try {
    const result = await redis.get(`${REVOKED_TOKENS_KEY}:${token}`);
    return result === '1';
  } catch {
    return false;
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies?.cyberguard_token;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : cookieToken;

  if (!token) {
    res.status(401).json({ message: 'Missing or invalid Authorization header' });
    return;
  }

  try {
    if (await isTokenRevoked(token)) {
      res.status(401).json({ message: 'Token has been revoked' });
      return;
    }

    const decoded = jwt.verify(token, config.jwtSecret) as JWTPayload;
    const authReq = req as AuthRequest;

    authReq.userId = decoded.userId;
    authReq.organizationId = decoded.organizationId;
    authReq.email = decoded.email;
    authReq.role = decoded.role;

    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({ message: 'Token has expired' });
    } else if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({ message: 'Invalid token' });
    } else {
      res.status(401).json({ message: 'Authentication failed' });
    }
  }
};

export const requireRole = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthRequest;
    if (!authReq.role || !roles.includes(authReq.role)) {
      res.status(403).json({ message: 'Insufficient permissions' });
      return;
    }
    next();
  };
};

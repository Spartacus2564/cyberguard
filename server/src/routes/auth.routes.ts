import { Router, Request, Response } from 'express';
import { body } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate, revokeToken } from '../middleware/auth';
import { AuthRequest, JWTPayload } from '../types';
import * as authService from '../services/auth.service';
import { loginLimiter, registerLimiter } from '../middleware/rateLimiter';
import prisma from '../lib/prisma';
import jwt from 'jsonwebtoken';
import { config } from '../config';

const router = Router();

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: false, // Set to true in production with HTTPS
  sameSite: 'lax' as const,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/',
  domain: 'localhost', // Allow cookie to be sent to proxy
};

const passwordValidation = body('password')
  .isLength({ min: 12 }).withMessage('Password must be at least 12 characters')
  .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
  .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
  .matches(/[0-9]/).withMessage('Password must contain a number')
  .matches(/[^a-zA-Z0-9]/).withMessage('Password must contain a special character');

router.post(
  '/register',
  registerLimiter,
  validate([
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    passwordValidation,
    body('firstName').trim().notEmpty().withMessage('First name is required'),
    body('lastName').trim().notEmpty().withMessage('Last name is required'),
    body('organizationName').trim().notEmpty().isLength({ max: 100 }).withMessage('Organization name is required'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const { email, password, firstName, lastName, organizationName } = req.body;
      const result = await authService.register(email, password, firstName, lastName, organizationName);
      res.cookie('cyberguard_token', result.token, COOKIE_OPTIONS);
      res.status(201).json(result);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      if (message === 'Email already registered') {
        res.status(409).json({ message });
      } else {
        res.status(500).json({ message: 'Registration failed' });
      }
    }
  }
);

router.post(
  '/login',
  loginLimiter,
  validate([
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      const result = await authService.login(email, password);
      res.cookie('cyberguard_token', result.token, COOKIE_OPTIONS);
      res.json(result);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Login failed';
      if (message === 'Invalid credentials') {
        res.status(401).json({ message: 'Invalid email or password' });
      } else {
        res.status(500).json({ message: 'Login failed' });
      }
    }
  }
);

router.get('/me', authenticate, async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const user = await prisma.user.findUnique({
      where: { id: authReq.userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        organizationId: true,
        createdAt: true,
        organization: { select: { id: true, name: true } },
      },
    });

    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch user' });
  }
});

router.post(
  '/change-password',
  authenticate,
  validate([
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    passwordValidation,
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { currentPassword, newPassword } = req.body;
      const result = await authService.changePassword(authReq.userId, currentPassword, newPassword);

      // Revoke the current token so the user must re-login with new password
      const authHeader = req.headers.authorization;
      const cookieToken = req.cookies?.cyberguard_token;
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : cookieToken;
      if (token) {
        await revokeToken(token);
      }

      res.json({ message: result.message });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Password change failed';
      if (message === 'Current password is incorrect') {
        res.status(400).json({ message });
      } else {
        res.status(500).json({ message: 'Password change failed' });
      }
    }
  }
);

router.post('/logout', (req: Request, res: Response) => {
  res.clearCookie('cyberguard_token', { path: '/' });
  res.json({ message: 'Logged out' });
});

export default router;

import { Router, Request, Response } from 'express';
import { body } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate, requireRole } from '../middleware/auth';
import { AuthRequest, UserRole } from '../types';
import * as userService from '../services/user.service';

const router = Router();

router.use(authenticate);

router.get('/me', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const user = await userService.getUserById(authReq.userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch user profile' });
  }
});

router.put(
  '/me',
  validate([
    body('firstName').optional().notEmpty().withMessage('First name cannot be empty'),
    body('lastName').optional().notEmpty().withMessage('Last name cannot be empty'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { firstName, lastName } = req.body;
      const user = await userService.updateUser(authReq.userId, { firstName, lastName });
      res.json({ user });
    } catch (error) {
      res.status(500).json({ message: 'Failed to update user profile' });
    }
  }
);

router.get('/', requireRole(UserRole.ADMIN), async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const users = await userService.getUsersByOrganization(authReq.organizationId);
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

export default router;

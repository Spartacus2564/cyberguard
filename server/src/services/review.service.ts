import { Finding, Severity } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Review Status Enum ───

export enum ReviewStatus {
  PENDING = 'PENDING',
  IN_REVIEW = 'IN_REVIEW',
  APPROVED = 'APPROVED',
  ESCALATED = 'ESCALATED',
  DISMISSED = 'DISMISSED',
  FIXED = 'FIXED',
}

// ─── Types ───

export interface Review {
  id: string;
  findingId: string;
  assessmentId: string;
  status: ReviewStatus;
  reviewerId?: string;
  reviewerName?: string;
  comments: ReviewComment[];
  createdAt: Date;
  updatedAt: Date;
  statusHistory: StatusTransition[];
}

export interface ReviewComment {
  id: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: Date;
}

export interface StatusTransition {
  from: ReviewStatus;
  to: ReviewStatus;
  by: string;
  at: Date;
  reason?: string;
}

export interface ReviewStats {
  total: number;
  byStatus: Record<ReviewStatus, number>;
  bySeverity: Record<Severity, number>;
  avgTimeToReview: number;
  avgTimeToResolution: number;
  topReviewers: Array<{ name: string; count: number }>;
}

// ─── Status Transition Rules ───

const VALID_TRANSITIONS: Record<ReviewStatus, ReviewStatus[]> = {
  [ReviewStatus.PENDING]: [ReviewStatus.IN_REVIEW, ReviewStatus.DISMISSED],
  [ReviewStatus.IN_REVIEW]: [ReviewStatus.APPROVED, ReviewStatus.ESCALATED, ReviewStatus.DISMISSED, ReviewStatus.FIXED],
  [ReviewStatus.APPROVED]: [ReviewStatus.FIXED, ReviewStatus.ESCALATED],
  [ReviewStatus.ESCALATED]: [ReviewStatus.APPROVED, ReviewStatus.FIXED, ReviewStatus.DISMISSED],
  [ReviewStatus.DISMISSED]: [],
  [ReviewStatus.FIXED]: [],
};

function isValidTransition(from: ReviewStatus, to: ReviewStatus): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

// ─── Review Data Store ───
// In production, this would be a Prisma model. Using in-memory for now
// with DB-backed persistence via prisma.review (if model exists) or JSON fields.

const reviewStore = new Map<string, Review>();

function generateId(): string {
  return crypto.randomUUID();
}

// ─── Core Functions ───

export async function createReview(
  findingId: string,
  assessmentId: string,
  reviewerId?: string,
  reviewerName?: string,
): Promise<Review> {
  const finding = await prisma.finding.findUnique({ where: { id: findingId } });
  if (!finding) {
    throw new Error('Finding not found');
  }
  if (finding.assessmentId !== assessmentId) {
    throw new Error('Finding does not belong to this assessment');
  }

  const existingReview = Array.from(reviewStore.values()).find(
    (r) => r.findingId === findingId && r.assessmentId === assessmentId,
  );
  if (existingReview) {
    throw new Error('Review already exists for this finding');
  }

  const review: Review = {
    id: generateId(),
    findingId,
    assessmentId,
    status: ReviewStatus.PENDING,
    reviewerId,
    reviewerName,
    comments: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    statusHistory: [
      {
        from: null as any,
        to: ReviewStatus.PENDING,
        by: reviewerName || 'system',
        at: new Date(),
        reason: 'Review created',
      },
    ],
  };

  reviewStore.set(review.id, review);
  logger.info(`[Review] Created review ${review.id} for finding ${findingId}`);
  return review;
}

export async function addComment(
  reviewId: string,
  authorId: string,
  authorName: string,
  content: string,
): Promise<ReviewComment> {
  const review = reviewStore.get(reviewId);
  if (!review) {
    throw new Error('Review not found');
  }

  if (review.status === ReviewStatus.DISMISSED || review.status === ReviewStatus.FIXED) {
    throw new Error(`Cannot add comments to a ${review.status} review`);
  }

  const comment: ReviewComment = {
    id: generateId(),
    authorId,
    authorName,
    content,
    createdAt: new Date(),
  };

  review.comments.push(comment);
  review.updatedAt = new Date();
  reviewStore.set(reviewId, review);

  logger.info(`[Review] Added comment to review ${reviewId} by ${authorName}`);
  return comment;
}

export async function updateStatus(
  reviewId: string,
  newStatus: ReviewStatus,
  userId: string,
  userName: string,
  reason?: string,
): Promise<Review> {
  const review = reviewStore.get(reviewId);
  if (!review) {
    throw new Error('Review not found');
  }

  if (!isValidTransition(review.status, newStatus)) {
    throw new Error(
      `Invalid status transition: ${review.status} → ${newStatus}. ` +
      `Valid transitions from ${review.status}: ${VALID_TRANSITIONS[review.status].join(', ') || 'none'}`,
    );
  }

  const transition: StatusTransition = {
    from: review.status,
    to: newStatus,
    by: userName,
    at: new Date(),
    reason,
  };

  review.status = newStatus;
  review.statusHistory.push(transition);
  review.updatedAt = new Date();

  if (newStatus === ReviewStatus.APPROVED || newStatus === ReviewStatus.FIXED || newStatus === ReviewStatus.DISMISSED) {
    review.reviewerId = review.reviewerId || userId;
    review.reviewerName = review.reviewerName || userName;
  }

  reviewStore.set(reviewId, review);
  logger.info(`[Review] Updated review ${reviewId}: ${transition.from} → ${newStatus} by ${userName}`);
  return review;
}

export async function getPendingReviews(
  assessmentId: string,
  page: number = 1,
  limit: number = 20,
): Promise<{ reviews: Review[]; total: number; page: number; totalPages: number }> {
  const allReviews = Array.from(reviewStore.values()).filter(
    (r) => r.assessmentId === assessmentId,
  );

  const pending = allReviews.filter((r) => r.status === ReviewStatus.PENDING || r.status === ReviewStatus.IN_REVIEW);
  pending.sort((a, b) => {
    const severityOrder: Record<string, number> = {
      CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
    };
    return (severityOrder[(a as any).severity] ?? 5) - (severityOrder[(b as any).severity] ?? 5);
  });

  const total = pending.length;
  const start = (page - 1) * limit;
  const reviews = pending.slice(start, start + limit);

  return {
    reviews,
    total,
    page,
    totalPages: Math.ceil(total / limit),
  };
}

export async function getReviewStats(assessmentId: string): Promise<ReviewStats> {
  const allReviews = Array.from(reviewStore.values()).filter(
    (r) => r.assessmentId === assessmentId,
  );

  const byStatus: Record<ReviewStatus, number> = {
    [ReviewStatus.PENDING]: 0,
    [ReviewStatus.IN_REVIEW]: 0,
    [ReviewStatus.APPROVED]: 0,
    [ReviewStatus.ESCALATED]: 0,
    [ReviewStatus.DISMISSED]: 0,
    [ReviewStatus.FIXED]: 0,
  };

  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const reviewerCounts = new Map<string, number>();
  let totalReviewTime = 0;
  let totalResolutionTime = 0;
  let reviewCount = 0;
  let resolutionCount = 0;

  for (const review of allReviews) {
    byStatus[review.status]++;

    // Get finding severity
    const finding = await prisma.finding.findUnique({ where: { id: review.findingId } });
    if (finding) {
      bySeverity[finding.severity as Severity]++;
    }

    // Track reviewers
    if (review.reviewerName) {
      reviewerCounts.set(review.reviewerName, (reviewerCounts.get(review.reviewerName) || 0) + 1);
    }

    // Calculate timing
    const firstReview = review.statusHistory.find((h) => h.to === ReviewStatus.IN_REVIEW);
    if (firstReview) {
      totalReviewTime += firstReview.at.getTime() - review.createdAt.getTime();
      reviewCount++;
    }

    if (review.status === ReviewStatus.FIXED || review.status === ReviewStatus.APPROVED || review.status === ReviewStatus.DISMISSED) {
      const lastTransition = review.statusHistory[review.statusHistory.length - 1];
      totalResolutionTime += lastTransition.at.getTime() - review.createdAt.getTime();
      resolutionCount++;
    }
  }

  const topReviewers = Array.from(reviewerCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return {
    total: allReviews.length,
    byStatus,
    bySeverity,
    avgTimeToReview: reviewCount > 0 ? totalReviewTime / reviewCount : 0,
    avgTimeToResolution: resolutionCount > 0 ? totalResolutionTime / resolutionCount : 0,
    topReviewers,
  };
}

export async function getReviewById(reviewId: string): Promise<Review | null> {
  return reviewStore.get(reviewId) || null;
}

export async function getReviewsByAssessment(assessmentId: string): Promise<Review[]> {
  return Array.from(reviewStore.values())
    .filter((r) => r.assessmentId === assessmentId)
    .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
}

export async function getReviewsByFinding(findingId: string): Promise<Review[]> {
  return Array.from(reviewStore.values())
    .filter((r) => r.findingId === findingId)
    .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
}



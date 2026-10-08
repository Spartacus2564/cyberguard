// ═══════════════════════════════════════════════════════════════════════════════
// ASSET INVENTORY SERVICE — Discovery, tracking, and classification of assets
// ═══════════════════════════════════════════════════════════════════════════════

import { AssetType, ValidationStatus } from '@prisma/client';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DiscoveredAssetInput {
  engagementId: string;
  type: AssetType;
  value: string;             // Domain, IP, CIDR, URL, or path
  metadata?: Record<string, unknown>;
}

export interface DiscoveredAssetWithServices {
  id: string;
  engagementId: string;
  type: AssetType;
  value: string;
  metadata: string | null;
  discoveredAt: Date;
  lastSeenAt: Date;
  services: {
    id: string;
    port: number;
    protocol: string;
    service: string;
    version: string | null;
    banner: string | null;
    state: string;
  }[];
}

// ─── Asset CRUD ──────────────────────────────────────────────────────────────

export async function upsertAsset(input: DiscoveredAssetInput): Promise<void> {
  try {
    // Use findFirst + upsert pattern since unique constraint is on (engagementId, type, value)
    const existing = await prisma.discoveredAsset.findFirst({
      where: {
        engagementId: input.engagementId,
        type: input.type,
        value: input.value,
      },
    });

    if (existing) {
      await prisma.discoveredAsset.update({
        where: { id: existing.id },
        data: {
          metadata: input.metadata ? JSON.stringify(input.metadata) : undefined,
          lastSeenAt: new Date(),
        },
      });
    } else {
      await prisma.discoveredAsset.create({
        data: {
          engagementId: input.engagementId,
          type: input.type,
          value: input.value,
          metadata: input.metadata ? JSON.stringify(input.metadata) : null,
        },
      });
    }
  } catch (e) {
    logger.warn(`[Asset] Failed to upsert asset ${input.value}: ${e}`);
  }
}

export async function upsertService(
  assetId: string,
  engagementId: string,
  service: {
    port: number;
    protocol: string;
    service: string;
    version?: string;
    banner?: string;
  },
): Promise<void> {
  try {
    const existing = await prisma.discoveredService.findFirst({
      where: {
        assetId,
        port: service.port,
        protocol: service.protocol,
      },
    });

    if (existing) {
      await prisma.discoveredService.update({
        where: { id: existing.id },
        data: {
          service: service.service,
          version: service.version || null,
          banner: service.banner || null,
        },
      });
    } else {
      await prisma.discoveredService.create({
        data: {
          assetId,
          engagementId,
          port: service.port,
          protocol: service.protocol,
          service: service.service,
          version: service.version || null,
          banner: service.banner || null,
        },
      });
    }
  } catch (e) {
    logger.warn(`[Asset] Failed to upsert service on asset ${assetId}: ${e}`);
  }
}

export async function getAssetsByEngagement(
  engagementId: string,
): Promise<DiscoveredAssetWithServices[]> {
  return prisma.discoveredAsset.findMany({
    where: { engagementId },
    include: { services: true },
    orderBy: { discoveredAt: 'desc' },
  }) as Promise<DiscoveredAssetWithServices[]>;
}

export async function getAssetSummary(engagementId: string) {
  const assets = await prisma.discoveredAsset.groupBy({
    by: ['type'],
    where: { engagementId },
    _count: true,
  });

  const services = await prisma.discoveredService.count({
    where: { engagementId },
  });

  return {
    assetsByType: assets.map(a => ({ type: a.type, count: a._count })),
    totalAssets: assets.reduce((sum, a) => sum + a._count, 0),
    totalServices: services,
  };
}

// ─── Bulk Import ─────────────────────────────────────────────────────────────

export async function importFromScanResults(
  engagementId: string,
  results: {
    assets?: { type: AssetType; value: string; metadata?: Record<string, unknown> }[];
    services?: { assetValue: string; assetType: AssetType; port: number; protocol: string; service: string; version?: string }[];
  },
): Promise<{ assetsImported: number; servicesImported: number }> {
  let assetsImported = 0;
  let servicesImported = 0;

  if (results.assets) {
    for (const asset of results.assets) {
      await upsertAsset({
        engagementId,
        type: asset.type,
        value: asset.value,
        metadata: asset.metadata,
      });
      assetsImported++;
    }
  }

  if (results.services) {
    for (const svc of results.services) {
      const asset = await prisma.discoveredAsset.findFirst({
        where: { engagementId, type: svc.assetType, value: svc.assetValue },
      });

      if (asset) {
        await upsertService(asset.id, engagementId, {
          port: svc.port,
          protocol: svc.protocol,
          service: svc.service,
          version: svc.version,
        });
        servicesImported++;
      }
    }
  }

  logger.info(`[Asset] Imported ${assetsImported} assets, ${servicesImported} services for engagement ${engagementId}`);
  return { assetsImported, servicesImported };
}

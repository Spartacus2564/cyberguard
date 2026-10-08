// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK GRAPH ENGINE — Build and analyze attack paths from findings
// ═══════════════════════════════════════════════════════════════════════════════
// Constructs a directed graph of attack paths:
//   Asset → Vulnerability → Access → Asset → ...
// Each node/edge is persisted. Paths are scored and ranked.
// ═══════════════════════════════════════════════════════════════════════════════

import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackNode {
  id?: string;
  attackPathId: string;
  nodeType: string;
  label: string;
  description?: string;
  assetValue?: string;
  vulnerability?: string;
  evidence?: string;
  metadata?: Record<string, unknown>;
}

export interface AttackEdge {
  sourceNodeId: string;
  targetNodeId: string;
  edgeType: string;
  label: string;
  evidence?: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

// ─── Path Creation ───────────────────────────────────────────────────────────

export async function createAttackPath(
  engagementId: string,
  title: string,
  description: string,
  entryPoint: string,
  impactPoint: string,
  impactLevel: string,
  riskScore: number,
  confidence: number,
): Promise<string> {
  const path = await prisma.attackPath.create({
    data: {
      engagementId,
      title,
      description,
      entryPoint,
      impactPoint,
      impactLevel,
      riskScore,
      confidence,
      pathLength: 0,
    },
  });
  return path.id;
}

export async function addNodeToPath(
  pathId: string,
  node: AttackNode,
): Promise<string> {
  const created = await prisma.attackPathNode.create({
    data: {
      attackPathId: pathId,
      nodeType: node.nodeType,
      label: node.label,
      assetValue: node.assetValue || null,
      vulnerability: node.vulnerability || null,
      evidence: node.evidence || null,
      metadata: node.metadata ? JSON.stringify(node.metadata) : null,
    },
  });
  return created.id;
}

export async function addEdgeToPath(
  pathId: string,
  edge: AttackEdge,
): Promise<void> {
  await prisma.attackPathEdge.create({
    data: {
      attackPathId: pathId,
      sourceNodeId: edge.sourceNodeId,
      targetNodeId: edge.targetNodeId,
      edgeType: edge.edgeType,
      label: edge.label,
      evidence: edge.evidence || null,
      confidence: edge.confidence,
      metadata: edge.metadata ? JSON.stringify(edge.metadata) : null,
    },
  });
}

// ─── Path Building from Scan Results ─────────────────────────────────────────

export async function buildAttackPaths(
  engagementId: string,
): Promise<{ pathId: string; title: string; riskScore: number; nodeCount: number }[]> {
  logger.info(`[AttackGraph] Building attack paths for engagement ${engagementId}`);

  // Gather assets and services
  const [assets, services] = await Promise.all([
    prisma.discoveredAsset.findMany({
      where: { engagementId },
      include: { services: true },
    }),
    prisma.discoveredService.findMany({
      where: { engagementId },
    }),
  ]);

  const createdPaths: { pathId: string; title: string; riskScore: number; nodeCount: number }[] = [];

  // For each service, create a path showing the attack surface
  for (const svc of services) {
    const asset = assets.find(a => a.id === svc.assetId);
    if (!asset) continue;

    const riskScore = calculateServiceRiskScore(svc);
    const impactLevel = riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW';

    const pathId = await createAttackPath(
      engagementId,
      `${svc.service} exposed on ${asset.value}:${svc.port}`,
      `Attack surface: ${svc.service} service accessible on ${asset.value}`,
      asset.value,
      `${svc.service} (port ${svc.port}/${svc.protocol})`,
      impactLevel,
      riskScore,
      0.9,
    );

    // Add asset node
    const assetNodeId = await addNodeToPath(pathId, {
      attackPathId: pathId,
      nodeType: 'asset',
      label: asset.value,
      assetValue: asset.value,
      metadata: { type: asset.type },
    });

    // Add service/vulnerability node
    const svcNodeId = await addNodeToPath(pathId, {
      attackPathId: pathId,
      nodeType: 'service',
      label: `${svc.service} on port ${svc.port}/${svc.protocol}`,
      assetValue: `${svc.service}:${svc.port}`,
      vulnerability: svc.version ? `${svc.service} ${svc.version}` : svc.service,
    });

    // Add edge connecting them
    await addEdgeToPath(pathId, {
      sourceNodeId: assetNodeId,
      targetNodeId: svcNodeId,
      edgeType: 'leads_to',
      label: `Exposes ${svc.service}`,
      confidence: 0.9,
    });

    // Update path length
    await prisma.attackPath.update({
      where: { id: pathId },
      data: { pathLength: 2 },
    });

    createdPaths.push({ pathId, title: `${svc.service} exposed on ${asset.value}:${svc.port}`, riskScore, nodeCount: 2 });
  }

  logger.info(`[AttackGraph] Built ${createdPaths.length} attack paths for engagement ${engagementId}`);
  return createdPaths;
}

// ─── Risk Scoring ────────────────────────────────────────────────────────────

function calculateServiceRiskScore(svc: { service: string; port: number }): number {
  const highRisk = ['ssh', 'smb', 'rdp', 'winrm', 'telnet', 'ftp', 'vnc', 'rlogin'];
  const mediumRisk = ['http', 'https', 'mysql', 'postgresql', 'mssql', 'oracle', 'ldap', 'dns'];
  const serviceLower = (svc.service || '').toLowerCase();

  if (highRisk.includes(serviceLower)) return 70;
  if (mediumRisk.includes(serviceLower)) return 45;
  return 30;
}

// ─── Graph Query ─────────────────────────────────────────────────────────────

export async function getGraphData(engagementId: string) {
  const [nodes, edges, paths] = await Promise.all([
    prisma.attackPathNode.findMany({
      where: { attackPath: { engagementId } },
    }),
    prisma.attackPathEdge.findMany({
      where: { attackPath: { engagementId } },
    }),
    prisma.attackPath.findMany({
      where: { engagementId },
      orderBy: { riskScore: 'desc' },
    }),
  ]);

  return {
    nodes: nodes.map(n => ({
      id: n.id,
      type: n.nodeType,
      label: n.label,
      assetValue: n.assetValue,
      vulnerability: n.vulnerability,
      evidence: n.evidence,
      metadata: n.metadata ? JSON.parse(n.metadata) : null,
    })),
    edges: edges.map(e => ({
      id: e.id,
      source: e.sourceNodeId,
      target: e.targetNodeId,
      type: e.edgeType,
      label: e.label,
      confidence: e.confidence,
      evidence: e.evidence,
      metadata: e.metadata ? JSON.parse(e.metadata) : null,
    })),
    paths: paths.map(p => ({
      id: p.id,
      title: p.title,
      riskScore: p.riskScore,
      impactLevel: p.impactLevel,
      pathLength: p.pathLength,
      description: p.description,
      entryPoint: p.entryPoint,
      impactPoint: p.impactPoint,
      confidence: p.confidence,
      validated: p.validated,
    })),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTONOMOUS ORCHESTRATOR — End-to-end autonomous pentest controller
// ═══════════════════════════════════════════════════════════════════════════════
// Ties together:
//   - Engagement scope management
//   - Existing scan engine (recon + classification + targeted attacks)
//   - Hypothesis Engine (AI reasoning loop)
//   - Attack Graph construction
//   - Evidence collection
//   - Asset inventory
//
// Flow:
//   1. Validate scope → 2. Recon → 3. Classify → 4. Targeted scans →
//   5. Hypothesis loop → 6. Build attack graph → 7. Generate report
// ═══════════════════════════════════════════════════════════════════════════════

import { EngagementStatus } from '@prisma/client';
import { runAssessment, ScanLogEntry } from '../engine';
import { classifyTarget, TargetClassification } from '../engine/targetClassifier';
import { runReasoningLoop, ReasoningResult } from '../engine/hypothesisEngine';
import { buildAttackPaths } from '../engine/attackGraph';
import { updateEngagementStatus } from '../services/engagement.service';
import { importFromScanResults, upsertAsset, upsertService } from '../services/assetInventory.service';
import { createEvidence } from '../services/evidence.service';
import { ScanModule } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import redis from '../lib/redis';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OrchestratorConfig {
  engagementId: string;
  organizationId: string;
  domain: string;
  maxCycles?: number;
  enableHypothesisLoop?: boolean;
  enableAttackGraph?: boolean;
}

export interface OrchestratorProgress {
  phase: string;
  message: string;
  progress: number;
  cycleNumber?: number;
  findingsCount?: number;
}

export interface OrchestratorResult {
  engagementId: string;
  domain: string;
  classification?: TargetClassification;
  findingsCount: number;
  assetsDiscovered: number;
  servicesDiscovered: number;
  attackPathsBuilt: number;
  reasoningResult?: ReasoningResult;
  duration: number;
  success: boolean;
  error?: string;
}

// ─── Asset Extraction ────────────────────────────────────────────────────────

async function persistScanResults(
  engagementId: string,
  domain: string,
  classification: TargetClassification | undefined,
  scanResults: any[],
): Promise<{ assetsCount: number; servicesCount: number }> {
  const allFindings = scanResults.flatMap(r => r.findings);

  // Build assets from classification + findings
  const assets: { type: any; value: string; metadata?: Record<string, unknown> }[] = [];
  const services: { assetValue: string; assetType: any; port: number; protocol: string; service: string; version?: string }[] = [];
  const seenAssets = new Set<string>();
  const seenServices = new Set<string>();

  // Primary domain
  assets.push({ type: 'DOMAIN', value: domain, metadata: { primary: true, classification: classification?.primary } });
  seenAssets.add(domain);

  // Extract from findings
  for (const f of allFindings) {
    const asset = f.affectedAsset || '';

    // Domains
    const domainMatch = asset.match(/^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$/);
    if (domainMatch && !seenAssets.has(domainMatch[0])) {
      seenAssets.add(domainMatch[0]);
      assets.push({ type: 'DOMAIN', value: domainMatch[0] });
    }

    // IPs
    const ipMatch = asset.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipMatch && !seenAssets.has(ipMatch[1])) {
      seenAssets.add(ipMatch[1]);
      assets.push({ type: 'IP', value: ipMatch[1] });
    }

    // Services from port-based findings
    const portMatch = asset.match(/:(\d+)/);
    if (portMatch) {
      const port = parseInt(portMatch[1]);
      const host = asset.replace(/:\d+$/, '').replace(/^(https?:\/\/)/, '');
      const svcKey = `${host}:${port}`;
      if (!seenServices.has(svcKey)) {
        seenServices.add(svcKey);
        const title = (f.title || '').toLowerCase();
        let serviceName = 'unknown';
        if (title.includes('http')) serviceName = 'http';
        else if (title.includes('ssh')) serviceName = 'ssh';
        else if (title.includes('smb') || title.includes('netbios')) serviceName = 'smb';
        else if (title.includes('rdp')) serviceName = 'rdp';
        else if (title.includes('mysql')) serviceName = 'mysql';
        else if (title.includes('postgresql')) serviceName = 'postgresql';
        else if (title.includes('ftp')) serviceName = 'ftp';
        else if (title.includes('smtp')) serviceName = 'smtp';
        else if (title.includes('dns')) serviceName = 'dns';
        else if (title.includes('ldap')) serviceName = 'ldap';
        else if (title.includes('redis')) serviceName = 'redis';
        else if (title.includes('mongo')) serviceName = 'mongodb';

        services.push({
          assetValue: host,
          assetType: 'DOMAIN',
          port,
          protocol: 'tcp',
          service: serviceName,
        });
      }
    }
  }

  // Add services from classification
  if (classification && classification.services) {
    for (const svc of classification.services) {
      const svcName = typeof svc === 'string' ? svc : String(svc);
      const svcLower = svcName.toLowerCase();
      if (svcLower.includes('http') && !seenServices.has(domain + ':443')) {
        seenServices.add(domain + ':443');
        services.push({ assetValue: domain, assetType: 'DOMAIN' as any, port: 443, protocol: 'tcp', service: 'https' });
      }
      if (svcLower.includes('ssh') && !seenServices.has(domain + ':22')) {
        seenServices.add(domain + ':22');
        services.push({ assetValue: domain, assetType: 'DOMAIN' as any, port: 22, protocol: 'tcp', service: 'ssh' });
      }
    }
  }

  // Persist
  await importFromScanResults(engagementId, {
    assets: assets.map(a => ({ type: a.type as any, value: a.value, metadata: a.metadata })),
    services,
  });

  return { assetsCount: assets.length, servicesCount: services.length };
}

// ─── Evidence Capture ────────────────────────────────────────────────────────

async function captureOrchestratorEvidence(
  assessmentId: string,
  phase: string,
  data: Record<string, unknown>,
): Promise<void> {
  try {
    await createEvidence({
      assessmentId,
      type: 'tool_output',
      title: `Orchestrator: ${phase}`,
      content: JSON.stringify(data, null, 2).substring(0, 50000),
      contentType: 'application/json',
      metadata: { phase, timestamp: new Date().toISOString() },
    });
  } catch (e) {
    logger.warn(`[Orchestrator] Failed to capture evidence for ${phase}: ${e}`);
  }
}

// ─── Main Orchestrator ───────────────────────────────────────────────────────

export async function runAutonomousScan(
  config: OrchestratorConfig,
  onProgress?: (progress: OrchestratorProgress) => void,
): Promise<OrchestratorResult> {
  const startTime = Date.now();
  const { engagementId, organizationId, domain } = config;

  logger.info(`[Orchestrator] Starting autonomous scan for ${domain} (engagement: ${engagementId})`);
  onProgress?.({ phase: 'init', message: 'Starting autonomous scan...', progress: 0 });

  try {
    // Mark engagement as active
    await updateEngagementStatus(engagementId, organizationId, EngagementStatus.ACTIVE);

    // Create assessment for this scan
    const assessment = await prisma.assessment.create({
      data: {
        domain,
        organizationId,
        status: 'RUNNING',
      },
    });

    // ── PHASE 1: RECONNAISSANCE ──
    onProgress?.({ phase: 'recon', message: 'Running reconnaissance...', progress: 10 });
    logger.info(`[Orchestrator] Phase 1: Reconnaissance for ${domain}`);

    const reconModules: ScanModule[] = [
      'dns', 'tls', 'headers', 'webConfig', 'technology', 'portScan',
      'osFingerprint', 'dnsDeep', 'emailSecurity',
    ];

    const reconResults = await runAssessment(domain, reconModules);

    // Capture evidence
    await captureOrchestratorEvidence(assessment.id, 'reconnaissance', {
      modulesRun: reconModules,
      findingsCount: reconResults.results.flatMap(r => r.findings).length,
    });

    // ── PHASE 2: CLASSIFICATION ──
    onProgress?.({ phase: 'classify', message: 'Classifying target type...', progress: 25 });
    logger.info(`[Orchestrator] Phase 2: Classification`);

    const classification = classifyTarget(
      domain,
      reconResults.results,
      reconResults.results.find(r => r.module === 'portScan'),
    );

    onProgress?.({
      phase: 'classify',
      message: `Target: ${classification.primary} (${(classification.confidence * 100).toFixed(0)}% confidence)`,
      progress: 30,
    });

    // ── PHASE 3: TARGETED ATTACKS ──
    onProgress?.({ phase: 'attack', message: `Running targeted scans (${classification.primary})...`, progress: 35 });
    logger.info(`[Orchestrator] Phase 3: Targeted attacks (${classification.primary})`);

    const attackModules = classification.recommendedModules;
    const attackResults = await runAssessment(domain, attackModules);

    // Capture evidence
    await captureOrchestratorEvidence(assessment.id, 'targeted_attacks', {
      classification: classification.primary,
      modulesRun: attackModules,
      findingsCount: attackResults.results.flatMap(r => r.findings).length,
    });

    // ── PHASE 4: PERSIST ASSETS ──
    onProgress?.({ phase: 'assets', message: 'Building asset inventory...', progress: 55 });
    logger.info(`[Orchestrator] Phase 4: Persisting assets`);

    const allScanResults = [...reconResults.results, ...attackResults.results];
    const { assetsCount, servicesCount } = await persistScanResults(
      engagementId,
      domain,
      classification,
      allScanResults,
    );

    onProgress?.({
      phase: 'assets',
      message: `Discovered ${assetsCount} assets, ${servicesCount} services`,
      progress: 60,
    });

    // ── PHASE 5: HYPOTHESIS REASONING LOOP ──
    let reasoningResult: ReasoningResult | undefined;
    if (config.enableHypothesisLoop !== false) {
      onProgress?.({ phase: 'reasoning', message: 'Starting AI reasoning loop...', progress: 65 });
      logger.info(`[Orchestrator] Phase 5: Hypothesis reasoning loop`);

      const initialFindings = allScanResults.flatMap(r => r.findings);
      reasoningResult = await runReasoningLoop(
        engagementId,
        domain,
        initialFindings,
        (cycle) => {
          onProgress?.({
            phase: 'reasoning',
            message: `Cycle ${cycle.cycleNumber}: ${cycle.hypothesesConfirmed} confirmed, ${cycle.findingsDiscovered} new findings`,
            progress: 65 + (cycle.cycleNumber * 5),
            cycleNumber: cycle.cycleNumber,
            findingsCount: cycle.findingsDiscovered,
          });
        },
      );
    }

    // ── PHASE 6: ATTACK GRAPH ──
    let attackPathsBuilt = 0;
    if (config.enableAttackGraph !== false) {
      onProgress?.({ phase: 'graph', message: 'Building attack graph...', progress: 85 });
      logger.info(`[Orchestrator] Phase 6: Building attack graph`);

      const paths = await buildAttackPaths(engagementId);
      attackPathsBuilt = paths.length;

      onProgress?.({
        phase: 'graph',
        message: `Built ${attackPathsBuilt} attack paths`,
        progress: 90,
      });
    }

    // ── PHASE 7: FINALIZE ──
    onProgress?.({ phase: 'finalize', message: 'Finalizing engagement...', progress: 95 });

    const allFindings = allScanResults.flatMap(r => r.findings);
    const totalFindings = reasoningResult
      ? reasoningResult.totalFindings
      : allFindings.length;

    await updateEngagementStatus(engagementId, organizationId, EngagementStatus.COMPLETED);

    const duration = Date.now() - startTime;
    onProgress?.({ phase: 'complete', message: `Scan complete in ${(duration / 1000).toFixed(1)}s`, progress: 100 });

    logger.info(`[Orchestrator] Autonomous scan complete for ${domain}: ${totalFindings} findings, ${assetsCount} assets, ${attackPathsBuilt} attack paths (${(duration / 1000).toFixed(1)}s)`);

    return {
      engagementId,
      domain,
      classification,
      findingsCount: totalFindings,
      assetsDiscovered: assetsCount,
      servicesDiscovered: servicesCount,
      attackPathsBuilt,
      reasoningResult,
      duration,
      success: true,
    };
  } catch (error: any) {
    const duration = Date.now() - startTime;
    logger.error(`[Orchestrator] Autonomous scan failed for ${domain}: ${error.message}`);

    try {
      await updateEngagementStatus(engagementId, organizationId, EngagementStatus.FAILED);
    } catch {}

    onProgress?.({ phase: 'error', message: `Scan failed: ${error.message}`, progress: 100 });

    return {
      engagementId,
      domain,
      findingsCount: 0,
      assetsDiscovered: 0,
      servicesDiscovered: 0,
      attackPathsBuilt: 0,
      duration,
      success: false,
      error: error.message,
    };
  }
}

import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, statSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join, basename, extname } from 'path';
import { IRModuleResult, Evidence, EvidenceType, EvidenceStatus, CustodyEntry, IRScanContext, Finding, Severity } from '../../../types';
import { logInfo, logDone } from '../../scanLogger';
import { generateFinding } from '../../modules/shared';

const MODULE_NAME = 'evidenceCollector';

interface CollectionTarget {
  type: EvidenceType;
  source: string;
  path: string;
  recursive?: boolean;
  filters?: string[];
}

async function hashFile(filePath: string): Promise<{ md5: string; sha1: string; sha256: string }> {
  const buffer = readFileSync(filePath);
  return {
    md5: createHash('md5').update(buffer).digest('hex'),
    sha1: createHash('sha1').update(buffer).digest('hex'),
    sha256: createHash('sha256').update(buffer).digest('hex'),
  };
}

async function collectFile(target: CollectionTarget, caseId: string, collector: string): Promise<Evidence> {
  const stats = statSync(target.path);
  const hashes = await hashFile(target.path);
  const now = Date.now();

  const evidence: Evidence = {
    id: `ev-${caseId}-${createHash('sha1').update(target.path + now).digest('hex').slice(0, 8)}`,
    caseId,
    type: target.type,
    source: target.source,
    path: target.path,
    hash: hashes,
    size: stats.size,
    collectedAt: now,
    collectedBy: collector,
    status: 'collected',
    chainOfCustody: [{
      timestamp: now,
      action: 'collected',
      actor: collector,
      location: target.path,
      hashVerified: true,
    }],
    metadata: {
      originalPath: target.path,
      fileName: basename(target.path),
      extension: extname(target.path),
      permissions: stats.mode.toString(8),
      modifiedAt: stats.mtimeMs,
      accessedAt: stats.atimeMs,
    },
  };

  return evidence;
}

async function collectDirectory(target: CollectionTarget, caseId: string, collector: string): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const files = readdirSync(target.path, { withFileTypes: true, recursive: target.recursive ?? true });

  for (const file of files) {
    if (file.isFile()) {
      const fullPath = join(target.path, file.name);
      if (target.filters && target.filters.length > 0) {
        const matches = target.filters.some(f => file.name.endsWith(f) || file.name.includes(f));
        if (!matches) continue;
      }
      try {
        const evidence = await collectFile({ ...target, path: fullPath }, caseId, collector);
        evidenceList.push(evidence);
      } catch (e) {
        // Skip unreadable files
      }
    }
  }

  return evidenceList;
}

async function runVolatilityMemoryDump(caseId: string, outputDir: string): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const timestamp = Date.now();
  const dumpPath = join(outputDir, `memory-${caseId}-${timestamp}.raw`);

  try {
    logInfo(MODULE_NAME, 'Running memory acquisition via WinPMEM/LiME...');
    const platform = process.platform;
    
    if (platform === 'win32') {
      execFileSync('winpmem_mini_x64_rc2.exe', ['-o', dumpPath], { timeout: 300000 });
    } else {
      execFileSync('lime', ['-o', dumpPath, 'path=/dev/mem', 'format=raw'], { timeout: 300000 });
    }

    const evidence = await collectFile({
      type: 'memory-dump',
      source: 'live-memory',
      path: dumpPath,
    }, caseId, 'volatility-acquisition');

    evidence.metadata = {
      ...evidence.metadata,
      acquisitionTool: platform === 'win32' ? 'WinPMEM' : 'LiME',
      platform,
      volatilityVersion: '3',
    };

    evidenceList.push(evidence);
    logDone(MODULE_NAME, `Memory dump acquired: ${dumpPath}`);
  } catch (e) {
    logInfo(MODULE_NAME, `Memory acquisition failed: ${e}`);
  }

  return evidenceList;
}

async function collectWindowsEventLogs(caseId: string, outputDir: string): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const logNames = ['System', 'Security', 'Application', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational'];
  const timestamp = Date.now();

  for (const logName of logNames) {
    try {
      const safeName = logName.replace(/\//g, '-');
      const outPath = join(outputDir, `evtx-${safeName}-${caseId}-${timestamp}.evtx`);
      
      execFileSync('wevtutil', ['epl', logName, outPath], { timeout: 60000 });
      
      const evidence = await collectFile({
        type: 'log-files',
        source: `windows-eventlog:${logName}`,
        path: outPath,
      }, caseId, 'wevtutil');

      evidence.metadata = {
        ...evidence.metadata,
        logName,
        format: 'evtx',
      };
      
      evidenceList.push(evidence);
    } catch (e) {
      logInfo(MODULE_NAME, `Failed to export ${logName}: ${e}`);
    }
  }

  return evidenceList;
}

async function collectLinuxLogs(caseId: string, outputDir: string): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const logPaths = [
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/log/messages',
    '/var/log/secure',
    '/var/log/audit/audit.log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
  ];
  const timestamp = Date.now();

  for (const logPath of logPaths) {
    if (!existsSync(logPath)) continue;
    
    try {
      const outPath = join(outputDir, `log-${basename(logPath)}-${caseId}-${timestamp}.log`);
      const content = readFileSync(logPath, 'utf8');
      writeFileSync(outPath, content);

      const evidence = await collectFile({
        type: 'log-files',
        source: `linux-log:${logPath}`,
        path: outPath,
      }, caseId, 'log-copy');

      evidence.metadata = {
        ...evidence.metadata,
        originalPath: logPath,
        format: 'text',
      };
      
      evidenceList.push(evidence);
    } catch (e) {
      logInfo(MODULE_NAME, `Failed to collect ${logPath}: ${e}`);
    }
  }

  return evidenceList;
}

async function collectNetworkCapture(caseId: string, outputDir: string, durationSec: number = 60): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const timestamp = Date.now();
  const pcapPath = join(outputDir, `pcap-${caseId}-${timestamp}.pcap`);

  try {
    logInfo(MODULE_NAME, `Capturing network traffic for ${durationSec}s...`);
    execFileSync('tshark', ['-a', `duration:${durationSec}`, '-w', pcapPath], { timeout: (durationSec + 30) * 1000 });

    const evidence = await collectFile({
      type: 'pcap',
      source: 'live-capture',
      path: pcapPath,
    }, caseId, 'tshark');

    evidence.metadata = {
      ...evidence.metadata,
      duration: durationSec,
      tool: 'tshark',
    };
    
    evidenceList.push(evidence);
    logDone(MODULE_NAME, `PCAP captured: ${pcapPath}`);
  } catch (e) {
    logInfo(MODULE_NAME, `Network capture failed: ${e}`);
  }

  return evidenceList;
}

async function collectRegistryHives(caseId: string, outputDir: string): Promise<Evidence[]> {
  const evidenceList: Evidence[] = [];
  const hives = ['SYSTEM', 'SOFTWARE', 'SECURITY', 'SAM', 'DEFAULT'];
  const timestamp = Date.now();

  for (const hive of hives) {
    try {
      const outPath = join(outputDir, `registry-${hive}-${caseId}-${timestamp}.reg`);
      execFileSync('reg', ['save', `HKLM\\${hive}`, outPath, '/y'], { timeout: 30000 });

      const evidence = await collectFile({
        type: 'registry',
        source: `registry-hive:HKLM\\${hive}`,
        path: outPath,
      }, caseId, 'reg-save');

      evidence.metadata = {
        ...evidence.metadata,
        hive,
        format: 'reg',
      };
      
      evidenceList.push(evidence);
    } catch (e) {
      logInfo(MODULE_NAME, `Failed to save ${hive} hive: ${e}`);
    }
  }

  return evidenceList;
}

export async function runEvidenceCollection(context: IRScanContext): Promise<IRModuleResult> {
  const startTime = Date.now();
  const result: IRModuleResult = {
    evidence: [],
    errors: [],
  };

  logInfo(MODULE_NAME, `Starting evidence collection for case ${context.caseId}`);

  const outputDir = join(process.cwd(), 'evidence', context.caseId);
  mkdirSync(outputDir, { recursive: true });

  const collector = 'cyberguard-ir';

  try {
    // Collect from evidencePaths in context
    for (const path of context.evidencePaths) {
      if (!existsSync(path)) {
        result.errors.push(`Path not found: ${path}`);
        continue;
      }

      const stats = statSync(path);
      if (stats.isFile()) {
        const evidence = await collectFile({
          type: inferEvidenceType(path),
          source: 'user-specified',
          path,
        }, context.caseId, collector);
        result.evidence!.push(evidence);
      } else if (stats.isDirectory()) {
        const dirEvidence = await collectDirectory({
          type: 'file-system',
          source: 'user-specified',
          path,
          recursive: true,
        }, context.caseId, collector);
        result.evidence!.push(...dirEvidence);
      }
    }

    // Auto-collect volatile data based on platform
    const platform = process.platform;
    
    if (platform === 'win32') {
      result.evidence!.push(...await collectWindowsEventLogs(context.caseId, outputDir));
      result.evidence!.push(...await collectRegistryHives(context.caseId, outputDir));
    } else {
      result.evidence!.push(...await collectLinuxLogs(context.caseId, outputDir));
    }

    // Memory dump (optional, requires admin/root)
    if (context.riskTolerance !== 'low') {
      result.evidence!.push(...await runVolatilityMemoryDump(context.caseId, outputDir));
    }

    // Network capture
    result.evidence!.push(...await collectNetworkCapture(context.caseId, outputDir, 30));

    // Write evidence manifest
    const manifestPath = join(outputDir, 'evidence-manifest.json');
    writeFileSync(manifestPath, JSON.stringify(result.evidence, null, 2));

    // Add custody entries for preservation
    const now = Date.now();
    for (const ev of result.evidence!) {
      ev.chainOfCustody.push({
        timestamp: now,
        action: 'preserved',
        actor: collector,
        location: outputDir,
        hashVerified: true,
      });
      ev.status = 'preserved';
    }

    logDone(MODULE_NAME, `Collected ${result.evidence!.length} evidence items in ${Date.now() - startTime}ms`);
  } catch (e) {
    result.errors.push(`Evidence collection failed: ${e}`);
    logInfo(MODULE_NAME, `Evidence collection error: ${e}`);
  }

  return result;
}

function inferEvidenceType(path: string): EvidenceType {
  const ext = extname(path).toLowerCase();
  if (['.evtx', '.log', '.txt'].includes(ext)) return 'log-files';
  if (['.pcap', '.pcapng', '.cap'].includes(ext)) return 'pcap';
  if (['.raw', '.mem', '.dmp', '.vmem'].includes(ext)) return 'memory-dump';
  if (['.reg', '.hiv'].includes(ext)) return 'registry';
  return 'file-system';
}

export interface EvidenceCollectorModule {
  run: typeof runEvidenceCollection;
}

export const evidenceCollector: EvidenceCollectorModule = {
  run: runEvidenceCollection,
};


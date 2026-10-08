// ═══════════════════════════════════════════════════════════════════════════════
// TOOL REGISTRY — Central catalog of all available security tools
// ═══════════════════════════════════════════════════════════════════════════════

import { exec } from 'child_process';
import { promisify } from 'util';
import { ToolDefinition } from './types';
import logger from '../utils/logger';

const execAsync = promisify(exec);

// ─── Tool Definitions ────────────────────────────────────────────────────────

const TOOL_DEFINITIONS: Omit<ToolDefinition, 'installed' | 'version'>[] = [
  {
    name: 'nmap',
    displayName: 'Nmap',
    category: 'port_scan',
    description: 'Network port scanner with service detection, OS fingerprinting, and NSE vulnerability scripts',
    capabilities: ['host_discovery', 'port_scanning', 'service_detection', 'os_fingerprint', 'vulnerability_detection', 'nmap_scripting', 'banner_grabbing'],
    binary: 'nmap',
    versionCommand: 'nmap --version',
    defaultArgs: ['-sV', '-sC', '-T4', '--open'],
    timeout: 300000,
    maxConcurrent: 3,
    requiresRoot: false,
  },
  {
    name: 'nuclei',
    displayName: 'Nuclei',
    category: 'vuln_scan',
    description: 'Template-based vulnerability scanner with 9000+ community templates',
    capabilities: ['vulnerability_detection', 'nuclei_templates'],
    binary: 'nuclei',
    versionCommand: 'nuclei -version',
    defaultArgs: ['-severity', 'critical,high,medium', '-silent', '-timeout', '8', '-retries', '2', '-rl', '30', '-c', '5'],
    timeout: 300000,
    maxConcurrent: 2,
    requiresRoot: false,
  },
  {
    name: 'nikto',
    displayName: 'Nikto',
    category: 'web_scan',
    description: 'Web server scanner checking for dangerous files, outdated software, and misconfigurations',
    capabilities: ['vulnerability_detection', 'directory_bruteforce'],
    binary: 'nikto',
    versionCommand: 'nikto -Version',
    defaultArgs: ['-Tuning', '1234567890abc', '-timeout', '5', '-maxtime', '90s'],
    timeout: 120000,
    maxConcurrent: 2,
    requiresRoot: false,
  },
  {
    name: 'whatweb',
    displayName: 'WhatWeb',
    category: 'web_scan',
    description: 'Web technology fingerprinter identifying CMS, frameworks, libraries, and server software',
    capabilities: ['banner_grabbing', 'header_analysis'],
    binary: 'whatweb',
    versionCommand: 'whatweb --version',
    defaultArgs: ['-a', '3', '--color=never'],
    timeout: 60000,
    maxConcurrent: 3,
    requiresRoot: false,
  },
  {
    name: 'dirb',
    displayName: 'DIRB',
    category: 'web_scan',
    description: 'Web content scanner that brute-forces directories and files',
    capabilities: ['directory_bruteforce'],
    binary: 'dirb',
    versionCommand: 'dirb',
    defaultArgs: ['-r', '-z', '100', '-S'],
    timeout: 120000,
    maxConcurrent: 2,
    requiresRoot: false,
  },
  {
    name: 'dig',
    displayName: 'dig',
    category: 'recon',
    description: 'DNS lookup utility for DNS enumeration and zone transfer testing',
    capabilities: ['dns_enumeration'],
    binary: 'dig',
    versionCommand: 'dig -v',
    defaultArgs: [],
    timeout: 30000,
    maxConcurrent: 5,
    requiresRoot: false,
  },
  {
    name: 'curl',
    displayName: 'curl',
    category: 'recon',
    description: 'HTTP client for banner grabbing, header analysis, and web requests',
    capabilities: ['banner_grabbing', 'header_analysis'],
    binary: 'curl',
    versionCommand: 'curl --version',
    defaultArgs: ['-sI', '-k', '--max-time', '10'],
    timeout: 15000,
    maxConcurrent: 10,
    requiresRoot: false,
  },
  {
    name: 'hydra',
    displayName: 'Hydra',
    category: 'credential',
    description: 'Online password brute-force tool supporting 50+ protocols',
    capabilities: ['credential_testing'],
    binary: 'hydra',
    versionCommand: 'hydra -h',
    defaultArgs: ['-f', '-V'],
    timeout: 300000,
    maxConcurrent: 1,
    requiresRoot: false,
  },
  {
    name: 'smbclient',
    displayName: 'smbclient',
    category: 'enumeration',
    description: 'SMB/CIFS client for share enumeration and file access',
    capabilities: ['smb_enumeration'],
    binary: 'smbclient',
    defaultArgs: ['-L', '-N'],
    timeout: 30000,
    maxConcurrent: 2,
    requiresRoot: false,
  },
  {
    name: 'enum4linux-ng',
    displayName: 'enum4linux-ng',
    category: 'enumeration',
    description: 'Next-gen SMB/NetBIOS enumeration tool',
    capabilities: ['smb_enumeration', 'ldap_enumeration'],
    binary: 'enum4linux-ng',
    defaultArgs: ['-A'],
    timeout: 120000,
    maxConcurrent: 2,
    requiresRoot: false,
  },
];

// ─── Registry Class ──────────────────────────────────────────────────────────

class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();
  private initialized = false;

  async initialize(): Promise<void> {
    if (this.initialized) return;

    logger.info('[ToolRegistry] Initializing — checking tool availability...');

    const checks = TOOL_DEFINITIONS.map(async (def) => {
      const installed = await this.checkInstalled(def.binary);
      let version: string | undefined;

      if (installed && def.versionCommand) {
        version = await this.getVersion(def.versionCommand);
      }

      const tool: ToolDefinition = { ...def, installed, version };
      this.tools.set(def.name, tool);

      if (installed) {
        logger.info(`[ToolRegistry] ${def.displayName} v${version || 'unknown'} — available`);
      } else {
        logger.warn(`[ToolRegistry] ${def.displayName} — NOT installed`);
      }
    });

    await Promise.all(checks);
    this.initialized = true;

    const available = [...this.tools.values()].filter(t => t.installed).length;
    const total = this.tools.size;
    logger.info(`[ToolRegistry] Initialization complete: ${available}/${total} tools available`);
  }

  private async checkInstalled(binary: string): Promise<boolean> {
    try {
      await execAsync(`which ${binary}`, { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  private async getVersion(command: string): Promise<string | undefined> {
    try {
      const { stdout } = await execAsync(command, { timeout: 5000 });
      // Extract version-like string from output
      const match = stdout.match(/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)/);
      return match ? match[1] : stdout.split('\n')[0]?.trim();
    } catch {
      return undefined;
    }
  }

  getTool(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  getToolsByCategory(category: string): ToolDefinition[] {
    return [...this.tools.values()].filter(t => t.category === category && t.installed);
  }

  getToolsByCapability(capability: string): ToolDefinition[] {
    return [...this.tools.values()].filter(t => t.capabilities.includes(capability as any) && t.installed);
  }

  getAvailableTools(): ToolDefinition[] {
    return [...this.tools.values()].filter(t => t.installed);
  }

  getAllTools(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  isInstalled(name: string): boolean {
    return this.tools.get(name)?.installed ?? false;
  }

  getToolInfo(): { name: string; installed: boolean; version?: string; category: string }[] {
    return [...this.tools.values()].map(t => ({
      name: t.name,
      installed: t.installed,
      version: t.version,
      category: t.category,
    }));
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────────

let _registry: ToolRegistry | null = null;

export async function getToolRegistry(): Promise<ToolRegistry> {
  if (!_registry) {
    _registry = new ToolRegistry();
    await _registry.initialize();
  }
  return _registry;
}

export { ToolRegistry };

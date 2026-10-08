// ═══════════════════════════════════════════════════════════════════════════════
// TOOL ABSTRACTION LAYER — Types
// ═══════════════════════════════════════════════════════════════════════════════
// Every security tool is registered with a structured definition.
// The rest of the application consumes normalized findings, not raw output.
// ═══════════════════════════════════════════════════════════════════════════════

import { Severity } from '../types';

export type ToolCategory =
  | 'recon'
  | 'port_scan'
  | 'vuln_scan'
  | 'web_scan'
  | 'enumeration'
  | 'exploitation'
  | 'credential'
  | 'ad_analysis'
  | 'cloud'
  | 'reporting';

export type ToolCapability =
  | 'host_discovery'
  | 'port_scanning'
  | 'service_detection'
  | 'os_fingerprint'
  | 'vulnerability_detection'
  | 'web_crawling'
  | 'directory_bruteforce'
  | 'subdomain_enumeration'
  | 'dns_enumeration'
  | 'ssl_analysis'
  | 'header_analysis'
  | 'credential_testing'
  | 'smb_enumeration'
  | 'ldap_enumeration'
  | 'kerberos_testing'
  | 'nmap_scripting'
  | 'nuclei_templates'
  | 'screenshot'
  | 'banner_grabbing';

export interface ToolDefinition {
  name: string;
  displayName: string;
  category: ToolCategory;
  description: string;
  capabilities: ToolCapability[];
  binary: string;                // Binary name to execute
  versionCommand?: string;       // Command to get version
  defaultArgs: string[];         // Default arguments
  timeout: number;               // Default timeout in ms
  maxConcurrent: number;         // Max concurrent executions
  requiresRoot: boolean;         // Needs root/sudo
  installed: boolean;            // Detected at startup
  version?: string;              // Detected version string
}

export interface ToolInput {
  target: string;                // Target domain, IP, CIDR, or URL
  args?: string[];               // Additional arguments
  env?: Record<string, string>;  // Environment variables
  timeout?: number;              // Override timeout
  scopeCheck?: (target: string) => boolean;  // Scope validation callback
}

export interface ToolOutput {
  tool: string;
  target: string;
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  duration: number;
  findings: NormalizedFinding[];
  rawFindings: unknown[];        // Tool-specific parsed structures
  evidence: ToolEvidence[];
  error?: string;
}

export interface NormalizedFinding {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cvssScore?: number;
  affectedAsset: string;
  evidence: string;
  impact: string;
  remediation: string;
  references: string[];
  toolName: string;
  toolOutput?: string;
  validationStatus: 'DISCOVERED' | 'VALIDATED' | 'CONFIRMED_IMPACT' | 'FALSE_POSITIVE';
  confidence: number;           // 0.0 - 1.0
}

export interface ToolEvidence {
  type: 'command_output' | 'http_request' | 'http_response' | 'certificate' | 'dns_record' | 'screenshot' | 'raw';
  title: string;
  content: string;
  contentType?: string;
  metadata?: Record<string, unknown>;
}

export interface ToolExecutionRecord {
  id: string;
  toolName: string;
  category: ToolCategory;
  command: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled';
  exitCode?: number;
  stdout?: string;
  stderr?: string;
  findingsCount: number;
  durationMs: number;
  startedAt: Date;
  completedAt?: Date;
  error?: string;
}

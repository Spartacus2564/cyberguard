import { parse } from 'csv-parse/sync';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, basename } from 'path';
import { IRModuleResult, TimelineEvent, Evidence, Severity, IRScanContext, Finding } from '../../../types';
import { logInfo, logDone } from '../../scanLogger';
import { generateFinding } from '../../modules/shared';

const MODULE_NAME = 'logTimeline';

interface ParsedLogEntry {
  timestamp: number;
  source: string;
  eventType: string;
  message: string;
  raw: Record<string, unknown>;
}

const EVENT_PATTERNS: Record<string, { pattern: RegExp; type: string; severity: Severity; mitre: string[] }[]> = {
  windows: [
    { pattern: /Event ID:?\s*4624/, type: 'Logon', severity: Severity.INFO, mitre: ['T1078'] },
    { pattern: /Event ID:?\s*4625/, type: 'Failed Logon', severity: Severity.MEDIUM, mitre: ['T1110'] },
    { pattern: /Event ID:?\s*4688/, type: 'Process Creation', severity: Severity.INFO, mitre: ['T1059'] },
    { pattern: /Event ID:?\s*4689/, type: 'Process Termination', severity: Severity.INFO, mitre: [] },
    { pattern: /Event ID:?\s*4698/, type: 'Scheduled Task Created', severity: Severity.MEDIUM, mitre: ['T1053'] },
    { pattern: /Event ID:?\s*4703/, type: 'Scheduled Task Deleted', severity: Severity.MEDIUM, mitre: ['T1053'] },
    { pattern: /Event ID:?\s*5140/, type: 'Network Share Accessed', severity: Severity.INFO, mitre: ['T1021.002'] },
    { pattern: /Event ID:?\s*4624.*Logon Type:?\s*10/, type: 'RDP Logon', severity: Severity.MEDIUM, mitre: ['T1021.001'] },
    { pattern: /Event ID:?\s*4672/, type: 'Special Privileges Assigned', severity: Severity.MEDIUM, mitre: ['T1068'] },
    { pattern: /Event ID:?\s*1102/, type: 'Audit Log Cleared', severity: Severity.HIGH, mitre: ['T1070.001'] },
    { pattern: /Event ID:?\s*7045/, type: 'Service Installed', severity: Severity.MEDIUM, mitre: ['T1543.003'] },
    { pattern: /Event ID:?\s*4657/, type: 'Registry Value Modified', severity: Severity.LOW, mitre: ['T1112'] },
    { pattern: /Event ID:?\s*5156/, type: 'Filtering Platform Connection', severity: Severity.INFO, mitre: ['T1043'] },
  ],
  linux: [
    { pattern: /Failed password for/, type: 'Failed SSH Login', severity: Severity.MEDIUM, mitre: ['T1110'] },
    { pattern: /Accepted password for/, type: 'Successful SSH Login', severity: Severity.INFO, mitre: ['T1078'] },
    { pattern: /sudo:.*COMMAND=/, type: 'Sudo Command', severity: Severity.MEDIUM, mitre: ['T1548.003'] },
    { pattern: /systemd.*Started/, type: 'Service Started', severity: Severity.INFO, mitre: ['T1543.002'] },
    { pattern: /cron.*CMD/, type: 'Cron Job', severity: Severity.LOW, mitre: ['T1053.003'] },
    { pattern: /kernel.*TCP.*SYN.*FLOOD/, type: 'Possible SYN Flood', severity: Severity.HIGH, mitre: ['T1499'] },
    { pattern: /apparmor.*DENIED/, type: 'AppArmor Denial', severity: Severity.LOW, mitre: ['T1027'] },
  ],
  sysmon: [
    { pattern: /Event ID:?\s*1/, type: 'Process Create', severity: Severity.INFO, mitre: ['T1059'] },
    { pattern: /Event ID:?\s*3/, type: 'Network Connection', severity: Severity.INFO, mitre: ['T1043'] },
    { pattern: /Event ID:?\s*7/, type: 'Image Load', severity: Severity.INFO, mitre: ['T1574.001'] },
    { pattern: /Event ID:?\s*8/, type: 'CreateRemoteThread', severity: Severity.HIGH, mitre: ['T1055'] },
    { pattern: /Event ID:?\s*10/, type: 'Process Access', severity: Severity.MEDIUM, mitre: ['T1050'] },
    { pattern: /Event ID:?\s*11/, type: 'File Create', severity: Severity.INFO, mitre: ['T1547'] },
    { pattern: /Event ID:?\s*13/, type: 'Registry SetValue', severity: Severity.MEDIUM, mitre: ['T1112'] },
    { pattern: /Event ID:?\s*22/, type: 'DNS Query', severity: Severity.INFO, mitre: ['T1071.004'] },
  ],
  network: [
    { pattern: /\[Alert\].*ET MALWARE/, type: 'Suricata Malware Alert', severity: Severity.HIGH, mitre: ['T1071'] },
    { pattern: /\[Alert\].*ET SCAN/, type: 'Suricata Scan Alert', severity: Severity.MEDIUM, mitre: ['T1595'] },
    { pattern: /\[Alert\].*ET EXPLOIT/, type: 'Suricata Exploit Alert', severity: Severity.HIGH, mitre: ['T1190'] },
    { pattern: /\[Alert\].*ET C2/, type: 'Suricata C2 Alert', severity: Severity.HIGH, mitre: ['T1071.001'] },
  ],
};

function parseEVTX(content: string): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  try {
    const lines = content.split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      const tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})/);
      const timestamp = tsMatch ? new Date(tsMatch[1]).getTime() : Date.now();
      
      for (const rule of EVENT_PATTERNS.windows) {
        if (rule.pattern.test(line)) {
          entries.push({
            timestamp,
            source: 'windows-eventlog',
            eventType: rule.type,
            message: line.slice(0, 500),
            raw: { originalLine: line },
          });
        }
      }
    }
  } catch {}
  return entries;
}

function parseSysmonXML(content: string): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  try {
    const eventRegex = /<Event[^>]*>[\s\S]*?<\/Event>/g;
    const events = content.match(eventRegex) || [];
    
    for (const event of events) {
      const tsMatch = event.match(/<TimeCreated SystemTime="([^"]+)"/);
      const timestamp = tsMatch ? new Date(tsMatch[1]).getTime() : Date.now();
      
      const eidMatch = event.match(/<EventID>(\d+)<\/EventID>/);
      const eventId = eidMatch ? eidMatch[1] : 'unknown';
      
      for (const rule of EVENT_PATTERNS.sysmon) {
        if (rule.pattern.test(`Event ID: ${eventId}`)) {
          entries.push({
            timestamp,
            source: 'sysmon',
            eventType: rule.type,
            message: event.slice(0, 500),
            raw: { eventId, xml: event },
          });
        }
      }
    }
  } catch {}
  return entries;
}

function parseLinuxLog(content: string, source: string): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    if (!line.trim()) continue;
    const tsMatch = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    const timestamp = tsMatch ? new Date(`${new Date().getFullYear()} ${tsMatch[1]}`).getTime() : Date.now();
    
    for (const rule of EVENT_PATTERNS.linux) {
      if (rule.pattern.test(line)) {
        entries.push({
          timestamp,
          source,
          eventType: rule.type,
          message: line.slice(0, 500),
          raw: { originalLine: line },
        });
      }
    }
  }
  return entries;
}

function parsePCAPSummary(pcapPath: string): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  try {
    const { execFileSync } = require('child_process');
    const output = execFileSync('tshark', ['-r', pcapPath, '-q', '-z', 'conv,tcp', '-z', 'io,phs'], { timeout: 60000 }).toString();
    
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('TCP') || line.includes('UDP')) {
        entries.push({
          timestamp: Date.now(),
          source: 'pcap',
          eventType: 'Network Conversation',
          message: line.trim(),
          raw: { summary: line },
        });
      }
    }
  } catch {}
  return entries;
}

function parseZeekLogs(zeekDir: string): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  if (!existsSync(zeekDir)) return entries;
  
  const logFiles = ['conn.log', 'http.log', 'dns.log', 'ssl.log', 'notice.log'];
  
  for (const logFile of logFiles) {
    const filePath = join(zeekDir, logFile);
    if (!existsSync(filePath)) continue;
    
    try {
      const content = readFileSync(filePath, 'utf8');
      const lines = content.split('\n').filter(l => l && !l.startsWith('#'));
      
      for (const line of lines) {
        const fields = line.split('\t');
        if (fields.length < 2) continue;
        
        const timestamp = parseFloat(fields[0]) * 1000 || Date.now();
        
        entries.push({
          timestamp,
          source: 'zeek',
          eventType: logFile.replace('.log', '').toUpperCase(),
          message: line.slice(0, 500),
          raw: { fields },
        });
      }
    } catch {}
  }
  return entries;
}

function classifyEvent(entry: ParsedLogEntry, allEntries: ParsedLogEntry[]): { severity: Severity; mitre: string[] } {
  let maxSeverity: Severity = 'info';
  const mitreSet = new Set<string>();
  
  for (const platform of Object.values(EVENT_PATTERNS)) {
    for (const rule of platform) {
      if (rule.pattern.test(entry.message)) {
        if (severityWeight(rule.severity) > severityWeight(maxSeverity)) {
          maxSeverity = rule.severity;
        }
        rule.mitre.forEach(t => mitreSet.add(t));
      }
    }
  }
  
  return { severity: maxSeverity, mitre: Array.from(mitreSet) };
}

function severityWeight(s: Severity): number {
  const weights = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return weights[s] || 1;
}

function buildTimeline(events: ParsedLogEntry[], caseId: string, evidenceMap: Map<string, string>): TimelineEvent[] {
  const timeline: TimelineEvent[] = [];
  const sortedEvents = [...events].sort((a, b) => a.timestamp - b.timestamp);
  
  for (const entry of sortedEvents) {
    const { severity, mitre } = classifyEvent(entry, sortedEvents);
    
    const relatedEvidence: string[] = [];
    for (const [evId, evPath] of evidenceMap.entries()) {
      if (entry.raw.originalLine && entry.raw.originalLine.includes(basename(evPath))) {
        relatedEvidence.push(evId);
      }
    }
    
    timeline.push({
      id: `tl-${caseId}-${createHash('sha1').update(entry.message + entry.timestamp).digest('hex').slice(0, 8)}`,
      caseId,
      timestamp: entry.timestamp,
      source: entry.source,
      eventType: entry.eventType,
      description: entry.message.slice(0, 200),
      severity,
      mitreTechniques: mitre,
      relatedEvidence,
      rawData: entry.raw,
    });
  }
  
  return timeline;
}

function createHash(algorithm: string) {
  return require('crypto').createHash(algorithm);
}

export async function runLogTimeline(context: IRScanContext): Promise<IRModuleResult> {
  const startTime = Date.now();
  const result: IRModuleResult = {
    timelineEvents: [],
    evidence: [],
    errors: [],
  };

  logInfo(MODULE_NAME, `Building timeline for case ${context.caseId}`);

  const evidenceDir = join(process.cwd(), 'evidence', context.caseId);
  if (!existsSync(evidenceDir)) {
    result.errors.push('Evidence directory not found. Run evidenceCollector first.');
    return result;
  }

  const evidenceFiles = require('fs').readdirSync(evidenceDir).filter((f: string) => f !== 'evidence-manifest.json');
  const allEntries: ParsedLogEntry[] = [];
  const evidenceMap = new Map<string, string>();

  for (const file of evidenceFiles) {
    const filePath = join(evidenceDir, file);
    
    try {
      const content = readFileSync(filePath, 'utf8');
      let entries: ParsedLogEntry[] = [];
      
      if (file.endsWith('.evtx') || file.includes('eventlog')) {
        entries = parseEVTX(content);
      } else if (file.includes('sysmon')) {
        entries = parseSysmonXML(content);
      } else if (file.endsWith('.log') || file.endsWith('.txt')) {
        if (file.includes('auth') || file.includes('syslog') || file.includes('messages')) {
          entries = parseLinuxLog(content, `linux:${basename(file)}`);
        } else {
          entries = parseEVTX(content);
        }
      } else if (file.endsWith('.pcap') || file.endsWith('.pcapng')) {
        entries = parsePCAPSummary(filePath);
      }
      
      allEntries.push(...entries);
      evidenceMap.set(file, filePath);
    } catch (e) {
      result.errors.push(`Failed to parse ${file}: ${e}`);
    }
  }

  // Parse Zeek if available
  const zeekDir = join(process.cwd(), 'zeek-logs');
  if (existsSync(zeekDir)) {
    allEntries.push(...parseZeekLogs(zeekDir));
  }

  if (allEntries.length === 0) {
    result.errors.push('No log entries parsed from evidence');
    return result;
  }

  const timeline = buildTimeline(allEntries, context.caseId, evidenceMap);
  result.timelineEvents = timeline;

  // Generate findings for high-severity events
  const highSeverityEvents = timeline.filter(e => ['high', 'critical'].includes(e.severity));
  for (const event of highSeverityEvents.slice(0, 20)) {
    result.findings!.push(generateFinding({
      title: `Suspicious Activity: ${event.eventType}`,
      description: event.description,
      severity: event.severity,
      category: 'incident-response',
      target: context.targetScope[0] || 'unknown',
      evidence: { timelineEvent: event.id, source: event.source, mitre: event.mitreTechniques },
      references: event.mitreTechniques.map(t => `https://attack.mitre.org/techniques/${t}/`),
    }));
  }

  // Write timeline output
  const outputDir = join(process.cwd(), 'ir-output', context.caseId);
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(join(outputDir, 'timeline.json'), JSON.stringify(timeline, null, 2));

  logDone(MODULE_NAME, `Timeline built: ${timeline.length} events, ${highSeverityEvents.length} high-severity in ${Date.now() - startTime}ms`);
  return result;
}

export interface LogTimelineModule {
  run: typeof runLogTimeline;
}

export const logTimeline: LogTimelineModule = {
  run: runLogTimeline,
};


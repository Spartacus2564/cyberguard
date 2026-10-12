import { IRModuleResult, ContainmentAction, IRScanContext, Evidence, IOC, TimelineEvent, Severity, Finding } from '../../../types';
import { logInfo, logDone } from '../../scanLogger';
import { generateFinding } from '../../modules/shared';

const MODULE_NAME = 'containmentPlanner';

const CONTAINMENT_PLAYBOOKS: Record<string, {
  name: string;
  description: string;
  actions: Omit<ContainmentAction, 'id' | 'caseId' | 'status' | 'executedAt' | 'executedBy' | 'result' | 'rollbackInfo'>[];
  prerequisites: string[];
  severity: Severity;
}> = {
  'malware-execution': {
    name: 'Malware Execution Containment',
    description: 'Isolate host and kill malicious processes when malware execution is detected',
    severity: Severity.HIGH,
    prerequisites: ['malware sample analyzed', 'process identified'],
    actions: [
      { type: 'host-isolate', target: '{hostname}', parameters: { method: 'network-quarantine', vlan: 'quarantine' } },
      { type: 'process-kill', target: '{process_name}', parameters: { signal: 'SIGKILL' } },
      { type: 'file-quarantine', target: '{file_path}', parameters: { quarantineDir: '/quarantine' } },
      { type: 'network-block', target: '{c2_ips}', parameters: { direction: 'both', protocol: 'tcp' } },
    ],
  },
  'credential-theft': {
    name: 'Credential Theft Response',
    description: 'Disable compromised accounts and rotate credentials',
    severity: Severity.CRITICAL,
    prerequisites: ['compromised accounts identified'],
    actions: [
      { type: 'account-disable', target: '{username}', parameters: { domain: '{domain}' } },
      { type: 'account-disable', target: '{service_account}', parameters: { domain: '{domain}' } },
      { type: 'custom', target: 'password-rotation', parameters: { accounts: ['{username}', '{service_account}'], forceLogout: true } },
    ],
  },
  'lateral-movement': {
    name: 'Lateral Movement Containment',
    description: 'Block lateral movement paths and isolate affected network segments',
    severity: Severity.HIGH,
    prerequisites: ['lateral movement detected', 'compromised hosts identified'],
    actions: [
      { type: 'network-block', target: '{source_subnet}', parameters: { destination: '{dest_subnet}', protocol: 'tcp', ports: [445, 135, 139, 3389, 5985] } },
      { type: 'host-isolate', target: '{compromised_host}', parameters: { method: 'network-quarantine' } },
      { type: 'custom', target: 'disable-smb-signing', parameters: { hosts: '{affected_hosts}' } },
    ],
  },
  'data-exfiltration': {
    name: 'Data Exfiltration Containment',
    description: 'Block exfiltration channels and preserve evidence',
    severity: Severity.CRITICAL,
    prerequisites: ['exfiltration detected', 'channels identified'],
    actions: [
      { type: 'network-block', target: '{exfil_destination_ips}', parameters: { direction: 'outbound', protocol: 'all' } },
      { type: 'network-block', target: '{exfil_destination_domains}', parameters: { direction: 'outbound', protocol: 'tcp', ports: [80, 443, 53, 21, 22] } },
      { type: 'custom', target: 'enable-dlp', parameters: { rules: 'strict' } },
      { type: 'custom', target: 'preserve-evidence', parameters: { hosts: '{source_hosts}' } },
    ],
  },
  'ransomware': {
    name: 'Ransomware Containment',
    description: 'Immediate isolation to prevent spread and encryption',
    severity: Severity.CRITICAL,
    prerequisites: ['ransomware detected'],
    actions: [
      { type: 'host-isolate', target: '{infected_hosts}', parameters: { method: 'full-isolation', preserveMemory: true } },
      { type: 'network-block', target: '{infected_subnets}', parameters: { direction: 'both', protocol: 'all' } },
      { type: 'process-kill', target: '{ransomware_process}', parameters: { signal: 'SIGKILL' } },
      { type: 'file-quarantine', target: '{encrypted_files}', parameters: { quarantineDir: '/quarantine/ransomware' } },
      { type: 'custom', target: 'snapshot-volumes', parameters: { hosts: '{infected_hosts}' } },
    ],
  },
  'web-shell': {
    name: 'Web Shell Containment',
    description: 'Remove web shell and block attacker access',
    severity: Severity.HIGH,
    prerequisites: ['web shell identified'],
    actions: [
      { type: 'file-quarantine', target: '{web_shell_path}', parameters: { quarantineDir: '/quarantine/webshells' } },
      { type: 'network-block', target: '{attacker_ips}', parameters: { direction: 'inbound', protocol: 'tcp', ports: [80, 443] } },
      { type: 'custom', target: 'reset-web-app', parameters: { appPool: '{app_pool}', restoreBackup: true } },
      { type: 'custom', target: 'rotate-app-keys', parameters: { application: '{web_app}' } },
    ],
  },
  'persistence-mechanism': {
    name: 'Persistence Mechanism Removal',
    description: 'Remove persistence artifacts and prevent re-infection',
    severity: Severity.HIGH,
    prerequisites: ['persistence mechanism identified'],
    actions: [
      { type: 'registry-delete', target: '{registry_key}', parameters: { backup: true } },
      { type: 'file-quarantine', target: '{startup_file}', parameters: { quarantineDir: '/quarantine/persistence' } },
      { type: 'custom', target: 'remove-scheduled-task', parameters: { taskName: '{task_name}' } },
      { type: 'custom', target: 'remove-service', parameters: { serviceName: '{service_name}' } },
    ],
  },
};

function matchPlaybooks(iocs: IOC[], timeline: TimelineEvent[], findings: Finding[]): string[] {
  const matched: string[] = [];
  const mitreSet = new Set<string>();
  const iocTypes = new Set<string>();
  
  for (const ioc of iocs) {
    iocTypes.add(ioc.type);
    mitreSet.add(...ioc.mitreTechniques);
  }
  
  for (const event of timeline) {
    mitreSet.add(...event.mitreTechniques);
  }
  
  for (const finding of findings) {
    if (finding.category === 'malware-analysis' || finding.category === 'incident-response') {
      mitreSet.add(...(finding.evidence?.mitre || []));
    }
  }
  
  const techniques = Array.from(mitreSet);
  
  if (techniques.some(t => ['T1486', 'T1490'].includes(t))) matched.push('ransomware');
  if (techniques.some(t => ['T1059', 'T1059.001', 'T1059.003', 'T1059.005'].includes(t)) && iocTypes.has('file-path')) matched.push('malware-execution');
  if (techniques.some(t => ['T1003', 'T1003.001', 'T1555', 'T1556'].includes(t))) matched.push('credential-theft');
  if (techniques.some(t => ['T1021', 'T1021.001', 'T1021.002', 'T1021.003', 'T1021.004', 'T1021.005', 'T1021.006'].includes(t))) matched.push('lateral-movement');
  if (techniques.some(t => ['T1041', 'T1048', 'T1567', 'T1537'].includes(t))) matched.push('data-exfiltration');
  if (techniques.some(t => ['T1505', 'T1505.003', 'T1505.004'].includes(t)) || iocTypes.has('file-path')) matched.push('web-shell');
  if (techniques.some(t => ['T1547', 'T1053', 'T1543', 'T1137', 'T1505'].includes(t))) matched.push('persistence-mechanism');
  
  return [...new Set(matched)];
}

function generateActions(playbookNames: string[], context: IRScanContext, iocs: IOC[], timeline: TimelineEvent[]): ContainmentAction[] {
  const actions: ContainmentAction[] = [];
  const now = Date.now();
  
  for (const playbookName of playbookNames) {
    const playbook = CONTAINMENT_PLAYBOOKS[playbookName];
    if (!playbook) continue;
    
    const iocValues: Record<string, string[]> = {};
    for (const ioc of iocs) {
      if (!iocValues[ioc.type]) iocValues[ioc.type] = [];
      iocValues[ioc.type].push(ioc.value);
    }
    
    for (const actionTmpl of playbook.actions) {
      let target = actionTmpl.target;
      let parameters = { ...actionTmpl.parameters };
      
      target = target
        .replace('{hostname}', context.targetScope[0] || 'unknown-host')
        .replace('{domain}', context.targetScope[0]?.split('.').slice(1).join('.') || 'unknown')
        .replace('{c2_ips}', iocValues.ip?.join(',') || 'unknown')
        .replace('{exfil_destination_ips}', iocValues.ip?.join(',') || 'unknown')
        .replace('{exfil_destination_domains}', iocValues.domain?.join(',') || 'unknown')
        .replace('{attacker_ips}', iocValues.ip?.join(',') || 'unknown')
        .replace('{infected_hosts}', context.targetScope.join(','))
        .replace('{infected_subnets}', context.targetScope.join(','))
        .replace('{compromised_host}', context.targetScope[0] || 'unknown-host')
        .replace('{source_subnet}', context.targetScope[0] || 'unknown')
        .replace('{dest_subnet}', context.targetScope[1] || 'unknown')
        .replace('{affected_hosts}', context.targetScope.join(','))
        .replace('{ransomware_process}', 'unknown.exe')
        .replace('{encrypted_files}', 'unknown')
        .replace('{web_shell_path}', 'unknown')
        .replace('{web_app}', 'unknown')
        .replace('{app_pool}', 'unknown')
        .replace('{process_name}', 'unknown.exe')
        .replace('{file_path}', 'unknown')
        .replace('{username}', 'unknown')
        .replace('{service_account}', 'unknown')
        .replace('{registry_key}', 'unknown')
        .replace('{startup_file}', 'unknown')
        .replace('{task_name}', 'unknown')
        .replace('{service_name}', 'unknown');
      
      for (const [key, value] of Object.entries(parameters)) {
        if (typeof value === 'string') {
          (parameters as Record<string, any>)[key] = value
            .replace('{hostname}', context.targetScope[0] || 'unknown-host')
            .replace('{domain}', context.targetScope[0]?.split('.').slice(1).join('.') || 'unknown');
        }
      }
      
      actions.push({
        id: `ca-${context.caseId}-${createHash('sha1').update(playbookName + actionTmpl.type + target).digest('hex').slice(0, 8)}`,
        caseId: context.caseId,
        type: actionTmpl.type,
        target,
        parameters,
        status: 'pending',
      });
    }
  }
  
  return actions;
}

function createHash(algorithm: string) {
  return require('crypto').createHash(algorithm);
}

export async function runContainmentPlanner(context: IRScanContext): Promise<IRModuleResult> {
  const startTime = Date.now();
  const result: IRModuleResult = {
    containmentActions: [],
    findings: [],
    errors: [],
  };

  logInfo(MODULE_NAME, `Planning containment for case ${context.caseId}`);

  const outputDir = join(process.cwd(), 'ir-output', context.caseId);
  const iocsPath = join(outputDir, 'iocs.json');
  const timelinePath = join(outputDir, 'timeline.json');

  let iocs: IOC[] = [];
  let timeline: TimelineEvent[] = [];

  if (existsSync(iocsPath)) {
    iocs = JSON.parse(require('fs').readFileSync(iocsPath, 'utf8'));
  }
  if (existsSync(timelinePath)) {
    timeline = JSON.parse(require('fs').readFileSync(timelinePath, 'utf8'));
  }

  if (iocs.length === 0 && timeline.length === 0) {
    result.errors.push('No IOCs or timeline data available. Run iocExtractor and logTimeline first.');
    return result;
  }

  const matchedPlaybooks = matchPlaybooks(iocs, timeline, []);
  
  if (matchedPlaybooks.length === 0) {
    matchedPlaybooks.push('malware-execution');
  }

  const actions = generateActions(matchedPlaybooks, context, iocs, timeline);
  result.containmentActions = actions;

  for (const action of actions) {
    result.findings!.push(generateFinding({
      title: `Containment Action Planned: ${action.type}`,
      description: `Target: ${action.target} - ${JSON.stringify(action.parameters)}`,
      severity: Severity.INFO,
      category: 'containment-planning',
      target: context.targetScope[0] || 'unknown',
      evidence: { actionId: action.id, playbooks: matchedPlaybooks },
    }));
  }

  const outputDirFinal = join(outputDir, 'containment');
  require('fs').mkdirSync(outputDirFinal, { recursive: true });
  require('fs').writeFileSync(join(outputDirFinal, 'actions.json'), JSON.stringify(actions, null, 2));
  require('fs').writeFileSync(join(outputDirFinal, 'playbooks-matched.json'), JSON.stringify(matchedPlaybooks, null, 2));

  logDone(MODULE_NAME, `Containment plan generated: ${matchedPlaybooks.length} playbooks, ${actions.length} actions in ${Date.now() - startTime}ms`);
  return result;
}

function existsSync(path: string): boolean {
  return require('fs').existsSync(path);
}

function join(...paths: string[]): string {
  return require('path').join(...paths);
}

export interface ContainmentPlannerModule {
  run: typeof runContainmentPlanner;
}

export const containmentPlanner: ContainmentPlannerModule = {
  run: runContainmentPlanner,
};


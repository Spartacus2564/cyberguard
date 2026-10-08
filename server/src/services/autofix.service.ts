import { Finding, Severity } from '../types';
import { config } from '../config';
import logger from '../utils/logger';

export interface FixPR {
  id: string;
  title: string;
  description: string;
  branch: string;
  findings: Finding[];
  changes: FileChange[];
  createdAt: Date;
  status: 'pending' | 'applied' | 'rejected';
}

export interface FileChange {
  file: string;
  action: 'add' | 'modify' | 'delete';
  content: string;
  description: string;
}

export interface RemediationTemplate {
  category: string;
  severity: Severity;
  template: (finding: Finding) => FileChange[];
}

const REMEDIATION_TEMPLATES: RemediationTemplate[] = [
  {
    category: 'Security Headers',
    severity: Severity.HIGH,
    template: (finding) => {
      if (finding.title.includes('Content-Security-Policy')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Add to server block\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';" always;`,
          description: 'Add Content-Security-Policy header to nginx configuration',
        }];
      }
      if (finding.title.includes('X-Frame-Options')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Add to server block\nadd_header X-Frame-Options "DENY" always;`,
          description: 'Add X-Frame-Options header to prevent clickjacking',
        }];
      }
      if (finding.title.includes('Strict-Transport-Security')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Add to server block\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
          description: 'Add HSTS header to enforce HTTPS',
        }];
      }
      return [{
        file: 'nginx.conf',
        action: 'modify',
        content: `# Add missing security headers\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-XSS-Protection "1; mode=block" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        description: 'Add missing security headers to nginx configuration',
      }];
    },
  },
  {
    category: 'TLS/HTTPS',
    severity: Severity.HIGH,
    template: (finding) => {
      if (finding.title.includes('TLS 1.0') || finding.title.includes('TLS 1.1')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Disable old TLS versions\nssl_protocols TLSv1.2 TLSv1.3;`,
          description: 'Disable TLS 1.0 and 1.1, use only TLS 1.2+',
        }];
      }
      if (finding.title.includes('weak cipher')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Use strong cipher suites\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;`,
          description: 'Configure strong TLS cipher suites',
        }];
      }
      return [{
        file: 'nginx.conf',
        action: 'modify',
        content: `# Update TLS configuration\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;`,
        description: 'Update TLS configuration for security',
      }];
    },
  },
  {
    category: 'DNS Security',
    severity: Severity.MEDIUM,
    template: (finding) => {
      if (finding.title.includes('DMARC')) {
        return [{
          file: 'dns-record.txt',
          action: 'add',
          content: `_dmarc.${finding.affectedAsset}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${finding.affectedAsset}; ruf=mailto:dmarc-forensics@${finding.affectedAsset}; fo=1"`,
          description: 'Add DMARC record with quarantine policy',
        }];
      }
      if (finding.title.includes('SPF')) {
        return [{
          file: 'dns-record.txt',
          action: 'add',
          content: `@ IN TXT "v=spf1 include:_spf.google.com ~all"`,
          description: 'Add SPF record for email authentication',
        }];
      }
      if (finding.title.includes('CAA')) {
        return [{
          file: 'dns-record.txt',
          action: 'add',
          content: `@ IN CAA 0 issue "letsencrypt.org"\n@ IN CAA 0 issuewild "letsencrypt.org"`,
          description: 'Add CAA records to restrict certificate issuance',
        }];
      }
      return [];
    },
  },
  {
    category: 'Information Disclosure',
    severity: Severity.LOW,
    template: (finding) => {
      if (finding.title.includes('Server header')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Hide server version\nserver_tokens off;`,
          description: 'Hide server version information',
        }];
      }
      if (finding.title.includes('X-Powered-By')) {
        return [{
          file: 'nginx.conf',
          action: 'modify',
          content: `# Remove X-Powered-By header\nproxy_hide_header X-Powered-By;`,
          description: 'Remove X-Powered-By header',
        }];
      }
      return [];
    },
  },
];

export function generateFixPR(findings: Finding[], domain: string): FixPR {
  const changes: FileChange[] = [];
  const matchedFindings: Finding[] = [];

  for (const finding of findings) {
    for (const template of REMEDIATION_TEMPLATES) {
      if (
        finding.category === template.category &&
        (finding.severity === template.severity || 
         (template.severity === Severity.HIGH && finding.severity === Severity.CRITICAL))
      ) {
        const fileChanges = template.template(finding);
        if (fileChanges.length > 0) {
          changes.push(...fileChanges);
          matchedFindings.push(finding);
        }
      }
    }
  }

  // Deduplicate changes by file
  const uniqueChanges = changes.reduce((acc, change) => {
    const existing = acc.find(c => c.file === change.file);
    if (existing) {
      existing.content += '\n\n' + change.content;
      existing.description += '\n' + change.description;
    } else {
      acc.push(change);
    }
    return acc;
  }, [] as FileChange[]);

  const prId = `fix-${Date.now()}`;
  const branch = `security-fix/${domain}-${Date.now()}`;

  return {
    id: prId,
    title: `Security fixes for ${domain} (${matchedFindings.length} findings)`,
    description: generatePRDescription(findings, matchedFindings, domain),
    branch,
    findings: matchedFindings,
    changes: uniqueChanges,
    createdAt: new Date(),
    status: 'pending',
  };
}

function generatePRDescription(allFindings: Finding[], fixedFindings: Finding[], domain: string): string {
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  fixedFindings.forEach(f => {
    if (f.severity in severityCounts) severityCounts[f.severity as keyof typeof severityCounts]++;
  });

  let description = `## Security Remediation for ${domain}\n\n`;
  description += `This PR addresses ${fixedFindings.length} security findings out of ${allFindings.length} total.\n\n`;
  description += `### Severity Breakdown\n`;
  description += `- Critical: ${severityCounts.CRITICAL}\n`;
  description += `- High: ${severityCounts.HIGH}\n`;
  description += `- Medium: ${severityCounts.MEDIUM}\n`;
  description += `- Low: ${severityCounts.LOW}\n\n`;
  description += `### Changes\n\n`;

  for (const change of fixedFindings) {
    description += `#### ${change.title}\n`;
    description += `- **Severity**: ${change.severity}\n`;
    description += `- **Category**: ${change.category}\n`;
    description += `- **Impact**: ${change.impact}\n`;
    description += `- **Remediation**: ${change.remediation}\n\n`;
  }

  description += `### Files Changed\n\n`;
  description += `| File | Action | Description |\n`;
  description += `|------|--------|-------------|\n`;

  return description;
}

export function generateFixDiff(changes: FileChange[]): string {
  let diff = '';
  
  for (const change of changes) {
    diff += `--- a/${change.file}\n`;
    diff += `+++ b/${change.file}\n`;
    diff += `@@ -0,0 +1,${change.content.split('\n').length} @@\n`;
    diff += change.content.split('\n').map(line => `+${line}`).join('\n');
    diff += '\n\n';
  }
  
  return diff;
}

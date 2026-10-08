import { Finding } from '../types';
import logger from '../utils/logger';

// ─── GitHub Actions Workflow ───

export function generateGitHubActionsWorkflow(config: {
  domain: string;
  apiUrl: string;
  schedule?: string;
}): string {
  const { domain, apiUrl, schedule } = config;
  const cronSchedule = schedule || '0 6 * * 1';

  return `name: CyberGuard Security Scan

on:
  schedule:
    - cron: '${cronSchedule}'
  workflow_dispatch:
    inputs:
      domain:
        description: 'Target domain to scan'
        required: false
        default: '${domain}'
      modules:
        description: 'Comma-separated scan modules (leave empty for all)'
        required: false

env:
  CYBERGUARD_API_URL: ${apiUrl}
  CYBERGUARD_DOMAIN: \${{ github.event.inputs.domain || '${domain}' }}

jobs:
  security-scan:
    name: Security Assessment
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Run CyberGuard scan
        id: scan
        run: |
          MODULES=\${{ github.event.inputs.modules }}
          if [ -z "$MODULES" ]; then
            MODULES="dns,tls,headers,webConfig,technology,portScan,cveCorrelation,siteCrawl,apiSecurity"
          fi

          RESPONSE=$(curl -s -X POST "\${CYBERGUARD_API_URL}/api/assessments" \\
            -H "Authorization: Bearer \${{ secrets.CYBERGUARD_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{
              "domain": "'"$CYBERGUARD_DOMAIN"'",
              "modules": "'"$MODULES"'"
            }')

          ASSESSMENT_ID=$(echo $RESPONSE | jq -r '.id')
          echo "assessment_id=$ASSESSMENT_ID" >> $GITHUB_OUTPUT
          echo "Assessment started: $ASSESSMENT_ID"

      - name: Wait for scan completion
        run: |
          ASSESSMENT_ID=\${{ steps.scan.outputs.assessment_id }}
          MAX_WAIT=1800
          INTERVAL=30
          ELAPSED=0

          while [ $ELAPSED -lt $MAX_WAIT ]; do
            STATUS=$(curl -s "\${CYBERGUARD_API_URL}/api/assessments/$ASSESSMENT_ID" \\
              -H "Authorization: Bearer \${{ secrets.CYBERGUARD_API_KEY }}" | jq -r '.status')

            if [ "$STATUS" = "COMPLETED" ]; then
              echo "Scan completed successfully"
              break
            elif [ "$STATUS" = "FAILED" ]; then
              echo "Scan failed"
              exit 1
            fi

            sleep $INTERVAL
            ELAPSED=$((ELAPSED + INTERVAL))
          done

          if [ $ELAPSED -ge $MAX_WAIT ]; then
            echo "Scan timed out"
            exit 1
          fi

      - name: Fetch scan results
        id: results
        run: |
          ASSESSMENT_ID=\${{ steps.scan.outputs.assessment_id }}
          RESPONSE=$(curl -s "\${CYBERGUARD_API_URL}/api/assessments/$ASSESSMENT_ID/findings" \\
            -H "Authorization: Bearer \${{ secrets.CYBERGUARD_API_KEY }}")

          CRITICAL=$(echo $RESPONSE | jq '[.findings[] | select(.severity == "CRITICAL")] | length')
          HIGH=$(echo $RESPONSE | jq '[.findings[] | select(.severity == "HIGH")] | length')
          MEDIUM=$(echo $RESPONSE | jq '[.findings[] | select(.severity == "MEDIUM")] | length')
          LOW=$(echo $RESPONSE | jq '[.findings[] | select(.severity == "LOW")] | length')
          TOTAL=$(echo $RESPONSE | jq '.findings | length')

          echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
          echo "high=$HIGH" >> $GITHUB_OUTPUT
          echo "medium=$MEDIUM" >> $GITHUB_OUTPUT
          echo "low=$LOW" >> $GITHUB_OUTPUT
          echo "total=$TOTAL" >> $GITHUB_OUTPUT

      - name: Security Summary
        run: |
          echo "## Security Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Severity | Count |" >> $GITHUB_STEP_SUMMARY
          echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
          echo "| Critical | \${{ steps.results.outputs.critical }} |" >> $GITHUB_STEP_SUMMARY
          echo "| High | \${{ steps.results.outputs.high }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Medium | \${{ steps.results.outputs.medium }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Low | \${{ steps.results.outputs.low }} |" >> $GITHUB_STEP_SUMMARY
          echo "| **Total** | **\${{ steps.results.outputs.total }}** |" >> $GITHUB_STEP_SUMMARY

      - name: Fail on critical findings
        if: steps.results.outputs.critical > 0
        run: |
          echo "::error::\${{ steps.results.outputs.critical }} critical security findings detected"
          exit 1

      - name: Notify on completion
        if: always()
        run: |
          curl -s -X POST "\${CYBERGUARD_API_URL}/api/webhooks/notify" \\
            -H "Content-Type: application/json" \\
            -d '{
              "event": "scan_complete",
              "domain": "'"$CYBERGUARD_DOMAIN"'",
              "assessmentId": "'"\${{ steps.scan.outputs.assessment_id }}"'",
              "criticalCount": "\${{ steps.results.outputs.critical }}",
              "highCount": "\${{ steps.results.outputs.high }}",
              "totalFindings": "\${{ steps.results.outputs.total }}"
            }' || true
`;
}

// ─── GitLab CI/CD Template ───

export function generateGitLabCI(config: {
  domain: string;
  apiUrl: string;
  schedule?: string;
}): string {
  const { domain, apiUrl, schedule } = config;
  const cronSchedule = schedule || '0 6 * * 1';

  return `# CyberGuard Security Scan - GitLab CI/CD Template
# Add CYBERGUARD_API_KEY to your CI/CD variables

variables:
  CYBERGUARD_API_URL: "${apiUrl}"
  CYBERGUARD_DOMAIN: "${domain}"

stages:
  - security-scan
  - notify

security-scan:
  stage: security-scan
  image: curlimages/curl:latest
  timeout: 30m
  before_script:
    - apk add --no-cache jq
  script:
    - |
      echo "Starting CyberGuard security scan for $CYBERGUARD_DOMAIN"
      
      RESPONSE=$(curl -s -X POST "\${CYBERGUARD_API_URL}/api/assessments" \\
        -H "Authorization: Bearer \${CYBERGUARD_API_KEY}" \\
        -H "Content-Type: application/json" \\
        -d "{
          \"domain\": \"$CYBERGUARD_DOMAIN\",
          \"modules\": \"dns,tls,headers,webConfig,technology,portScan,cveCorrelation,siteCrawl,apiSecurity\"
        }")
      
      ASSESSMENT_ID=$(echo $RESPONSE | jq -r '.id')
      echo "Assessment ID: $ASSESSMENT_ID"
      
      # Poll for completion
      MAX_WAIT=1800
      INTERVAL=30
      ELAPSED=0
      
      while [ $ELAPSED -lt $MAX_WAIT ]; do
        STATUS=$(curl -s "\${CYBERGUARD_API_URL}/api/assessments/$ASSESSMENT_ID" \\
          -H "Authorization: Bearer \${CYBERGUARD_API_KEY}" | jq -r '.status')
        
        if [ "$STATUS" = "COMPLETED" ]; then
          echo "Scan completed"
          break
        elif [ "$STATUS" = "FAILED" ]; then
          echo "Scan failed"
          exit 1
        fi
        
        sleep $INTERVAL
        ELAPSED=$((ELAPSED + INTERVAL))
      done
      
      # Fetch results
      FINDINGS=$(curl -s "\${CYBERGUARD_API_URL}/api/assessments/$ASSESSMENT_ID/findings" \\
        -H "Authorization: Bearer \${CYBERGUARD_API_KEY}")
      
      CRITICAL=$(echo $FINDINGS | jq '[.findings[] | select(.severity == "CRITICAL")] | length')
      HIGH=$(echo $FINDINGS | jq '[.findings[] | select(.severity == "HIGH")] | length')
      TOTAL=$(echo $FINDINGS | jq '.findings | length')
      
      echo "Critical: $CRITICAL"
      echo "High: $HIGH"
      echo "Total: $TOTAL"
      
      if [ "$CRITICAL" -gt 0 ]; then
        echo "::error::$CRITICAL critical security findings"
        exit 1
      fi
  artifacts:
    paths:
      - scan-results.json
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_PIPELINE_SOURCE == "web"'
    - if: '$CI_PIPELINE_SOURCE == "api"'

notify:
  stage: notify
  image: curlimages/curl:latest
  when: always
  script:
    - |
      curl -s -X POST "\${CYBERGUARD_API_URL}/api/webhooks/notify" \\
        -H "Content-Type: application/json" \\
        -d "{
          \"event\": \"gitlab_scan_complete\",
          \"domain\": \"$CYBERGUARD_DOMAIN\",
          \"pipelineUrl\": \"$CI_PIPELINE_URL\",
          \"status\": \"$CI_JOB_STATUS\"
        }" || true
  dependencies:
    - security-scan
`;
}

// ─── Webhook Payload Generator ───

export interface WebhookPayload {
  event: string;
  timestamp: string;
  domain: string;
  assessmentId: string;
  status: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    remediation: string;
  }>;
  metadata: Record<string, unknown>;
}

export function generateWebhookPayload(assessment: {
  id: string;
  domain: string;
  status: string;
  findings?: Finding[];
  completedAt?: Date;
  riskScore?: number;
  [key: string]: unknown;
}): WebhookPayload {
  const findings = assessment.findings || [];
  const summary = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'CRITICAL').length,
    high: findings.filter((f) => f.severity === 'HIGH').length,
    medium: findings.filter((f) => f.severity === 'MEDIUM').length,
    low: findings.filter((f) => f.severity === 'LOW').length,
    info: findings.filter((f) => f.severity === 'INFO').length,
  };

  const criticalFindings = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 10)
    .map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      remediation: f.remediation,
    }));

  return {
    event: `assessment.${assessment.status.toLowerCase()}`,
    timestamp: new Date().toISOString(),
    domain: assessment.domain,
    assessmentId: assessment.id,
    status: assessment.status,
    summary,
    findings: criticalFindings,
    metadata: {
      riskScore: assessment.riskScore,
      completedAt: assessment.completedAt?.toISOString(),
    },
  };
}

// ─── Slack / Teams Notification Format ───

export function formatSlackNotification(payload: WebhookPayload): object {
  const color =
    payload.summary.critical > 0 ? '#dc3545' :
    payload.summary.high > 0 ? '#fd7e14' :
    '#28a745';

  return {
    attachments: [
      {
        color,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: `CyberGuard Scan: ${payload.domain}`,
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Status:* ${payload.status}` },
              { type: 'mrkdwn', text: `*Total Findings:* ${payload.summary.total}` },
              { type: 'mrkdwn', text: `*Critical:* ${payload.summary.critical}` },
              { type: 'mrkdwn', text: `*High:* ${payload.summary.high}` },
            ],
          },
          ...(payload.findings.length > 0
            ? [
                {
                  type: 'section',
                  text: {
                    type: 'mrkdwn',
                    text: `*Top Findings:*\n${payload.findings.slice(0, 5).map((f) => `• ${f.severity}: ${f.title}`).join('\n')}`,
                  },
                },
              ]
            : []),
        ],
      },
    ],
  };
}

export function formatTeamsNotification(payload: WebhookPayload): object {
  const themeColor =
    payload.summary.critical > 0 ? 'FF0000' :
    payload.summary.high > 0 ? 'FFA500' :
    '00FF00';

  return {
    '@type': 'MessageCard',
    themeColor,
    summary: `Security scan for ${payload.domain} completed`,
    sections: [
      {
        activityTitle: `CyberGuard Security Scan: ${payload.domain}`,
        facts: [
          { name: 'Status', value: payload.status },
          { name: 'Total Findings', value: payload.summary.total.toString() },
          { name: 'Critical', value: payload.summary.critical.toString() },
          { name: 'High', value: payload.summary.high.toString() },
          { name: 'Medium', value: payload.summary.medium.toString() },
        ],
      },
      ...(payload.findings.length > 0
        ? [
            {
              text: `**Top Findings:**\n${payload.findings.slice(0, 5).map((f) => `• ${f.severity}: ${f.title}`).join('\n')}`,
            },
          ]
        : []),
    ],
  };
}

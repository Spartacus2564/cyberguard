import { Finding, Severity } from '../types';
import logger from '../utils/logger';

export interface NotificationConfig {
  enabled: boolean;
  webhookUrl?: string;
  slackWebhookUrl?: string;
  emailRecipients?: string[];
  notifyOnCritical: boolean;
  notifyOnHigh: boolean;
}

function getNotificationConfig(): NotificationConfig {
  return {
    enabled: process.env.NOTIFICATIONS_ENABLED === 'true',
    webhookUrl: process.env.NOTIFICATION_WEBHOOK_URL || undefined,
    slackWebhookUrl: process.env.NOTIFICATION_SLACK_WEBHOOK_URL || undefined,
    emailRecipients: process.env.NOTIFICATION_EMAIL_RECIPIENTS
      ? process.env.NOTIFICATION_EMAIL_RECIPIENTS.split(',').map(e => e.trim())
      : undefined,
    notifyOnCritical: process.env.NOTIFY_ON_CRITICAL !== 'false',
    notifyOnHigh: process.env.NOTIFY_ON_HIGH !== 'false',
  };
}

export async function sendFindingsNotifications(
  organizationId: string,
  domain: string,
  findings: Finding[],
  assessmentId: string
): Promise<void> {
  try {
    const notifConfig = getNotificationConfig();

    if (!notifConfig.enabled) return;

    const criticalFindings = findings.filter(f => f.severity === Severity.CRITICAL);
    const highFindings = findings.filter(f => f.severity === Severity.HIGH);

    const shouldNotify =
      (notifConfig.notifyOnCritical && criticalFindings.length > 0) ||
      (notifConfig.notifyOnHigh && highFindings.length > 0);

    if (!shouldNotify) return;

    const message = buildNotificationMessage(domain, findings, criticalFindings, highFindings, assessmentId);

    if (notifConfig.webhookUrl) {
      await sendWebhook(notifConfig.webhookUrl, message);
    }

    if (notifConfig.slackWebhookUrl) {
      await sendSlackNotification(notifConfig.slackWebhookUrl, message);
    }

    logger.info(`[Notifications] Sent for ${domain}: ${criticalFindings.length} critical, ${highFindings.length} high`);
  } catch (e) {
    logger.warn(`[Notifications] Failed: ${e}`);
  }
}

function buildNotificationMessage(
  domain: string,
  allFindings: Finding[],
  critical: Finding[],
  high: Finding[],
  assessmentId: string
): { title: string; body: string; severity: string; findings: Finding[] } {
  const total = allFindings.length;
  const title = `Security Scan Alert: ${domain}`;
  const body = [
    `Scan completed for ${domain}.`,
    `Total findings: ${total}`,
    critical.length > 0 ? `CRITICAL: ${critical.length} finding(s) - ${critical.map(f => f.title).join(', ')}` : '',
    high.length > 0 ? `HIGH: ${high.length} finding(s) - ${high.slice(0, 5).map(f => f.title).join(', ')}` : '',
    `View report: /dashboard/engagement/${assessmentId}`,
  ].filter(Boolean).join('\n');

  return {
    title,
    body,
    severity: critical.length > 0 ? 'CRITICAL' : 'HIGH',
    findings: [...critical, ...high],
  };
}

async function sendWebhook(url: string, message: { title: string; body: string; severity: string }): Promise<void> {
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: message.body,
        severity: message.severity,
        title: message.title,
        source: 'CyberGuard',
        timestamp: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (e) {
    logger.warn(`[Notifications] Webhook failed: ${e}`);
  }
}

async function sendSlackNotification(url: string, message: { title: string; body: string; severity: string }): Promise<void> {
  try {
    const color = message.severity === 'CRITICAL' ? '#ff0000' : '#ff8800';
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attachments: [{
          color,
          title: message.title,
          text: message.body,
          footer: 'CyberGuard Security Scanner',
          ts: Math.floor(Date.now() / 1000),
        }],
      }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (e) {
    logger.warn(`[Notifications] Slack failed: ${e}`);
  }
}

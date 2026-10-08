import redis from '../lib/redis';
import logger from '../utils/logger';

// ─── GLOBAL SCAN LOGGER ─────────────────────────────────────────────────────
// Modules import `scanLog` and call it to emit exploitation-level log entries.
// Each entry goes to Redis `scan:{assessmentId}:logs` as a list.
// The assessment ID is set once per scan job via `setScanContext()`.

let _assessmentId: string | null = null;

export function setScanContext(assessmentId: string) {
  _assessmentId = assessmentId;
}

export function clearScanContext() {
  _assessmentId = null;
}

export interface ScanLogEntry {
  ts: string;
  level: 'info' | 'warn' | 'error' | 'done' | 'exploit' | 'probe' | 'vuln';
  module: string;
  message: string;
  duration?: number;
  findings?: number;
  errors?: string[];
}

const LOGS_KEY_PREFIX = 'scan:';
const LOGS_KEY_SUFFIX = ':logs';
const MAX_LOGS = 200;
const TTL = 900; // 15 minutes

/**
 * Emit a log entry for the current scan.
 * Writes directly to Redis — fire-and-forget, never blocks the caller.
 * PROBE entries are skipped from the main log to prevent flooding.
 */
export function scanLog(entry: Omit<ScanLogEntry, 'ts'>) {
  if (!_assessmentId) return;
  // PROBE entries are too noisy — each HTTP request generates 2 entries.
  // Skip them from the main log to keep exploit/vuln/done visible.
  if (entry.level === 'probe') return;
  const full: ScanLogEntry = { ...entry, ts: new Date().toISOString() };
  const key = `${LOGS_KEY_PREFIX}${_assessmentId}${LOGS_KEY_SUFFIX}`;
  redis.rpush(key, JSON.stringify(full)).catch(() => {});
  redis.ltrim(key, -MAX_LOGS, -1).catch(() => {});
  redis.expire(key, TTL).catch(() => {});
}

/**
 * Log an HTTP request being made by a module.
 */
export function logRequest(module: string, method: string, url: string, opts?: { payload?: string; note?: string }) {
  const msg = `${method} ${url}` + (opts?.payload ? ` ← ${opts.payload.substring(0, 120)}` : '') + (opts?.note ? ` (${opts.note})` : '');
  scanLog({ level: 'probe', module, message: msg });
}

/**
 * Log an HTTP response received.
 */
export function logResponse(module: string, url: string, status: number, opts?: { bodySnippet?: string; duration?: number }) {
  const snippet = opts?.bodySnippet ? ` → ${status} [${opts.bodySnippet.substring(0, 100)}]` : ` → ${status}`;
  scanLog({ level: 'info', module, message: `${url}${snippet}`, duration: opts?.duration });
}

/**
 * Log an exploitation attempt.
 */
export function logExploit(module: string, technique: string, target: string, payload?: string) {
  const msg = `[${technique}] ${target}` + (payload ? ` | payload: ${payload.substring(0, 150)}` : '');
  scanLog({ level: 'exploit', module, message: msg });
}

/**
 * Log a vulnerability discovery.
 */
export function logVuln(module: string, title: string, severity: string, evidence?: string) {
  const msg = `FOUND ${severity} — ${title}` + (evidence ? ` | ${evidence.substring(0, 150)}` : '');
  scanLog({ level: 'vuln', module, message: msg });
}

/**
 * Log a module phase/info message.
 */
export function logInfo(module: string, message: string) {
  scanLog({ level: 'info', module, message });
}

/**
 * Log a module completion.
 */
export function logDone(module: string, message: string, duration?: number, findings?: number) {
  scanLog({ level: 'done', module, message, duration, findings });
}

/**
 * Log a warning.
 */
export function logWarn(module: string, message: string) {
  scanLog({ level: 'warn', module, message });
}

/**
 * Log an error.
 */
export function logError(module: string, message: string) {
  scanLog({ level: 'error', module, message });
}

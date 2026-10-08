import * as fs from 'fs';
import * as path from 'path';
import logger from '../../utils/logger';

// SecLists base path inside the container
const SECLISTS_BASE = process.env.SECLISTS_PATH || '/opt/SecLists';

// Cache for loaded wordlists to avoid re-reading files
const wordlistCache = new Map<string, string[]>();

/**
 * Load a SecLists wordlist file and return lines as an array.
 * Caches results in memory for repeated access.
 */
export function loadWordlist(relativePath: string, maxLines?: number): string[] {
  const cacheKey = `${relativePath}:${maxLines || 'all'}`;
  if (wordlistCache.has(cacheKey)) {
    return wordlistCache.get(cacheKey)!;
  }

  const fullPath = path.join(SECLISTS_BASE, relativePath);
  try {
    const content = fs.readFileSync(fullPath, 'utf-8');
    let lines = content.split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));

    if (maxLines && lines.length > maxLines) {
      lines = lines.slice(0, maxLines);
    }

    wordlistCache.set(cacheKey, lines);
    logger.info(`[SecLists] Loaded ${lines.length} entries from ${relativePath}`);
    return lines;
  } catch (e) {
    logger.warn(`[SecLists] Failed to load ${relativePath}: ${e}`);
    return [];
  }
}

// ─── SUBDOMAIN ENUMERATION ───────────────────────────────────────────────────

/** Top 20k subdomains for brute-force */
export function getSubdomainWordlist(): string[] {
  return loadWordlist('Discovery/DNS/subdomains-top1million-20000.txt');
}

/** Smaller list for quick scans */
export function getSubdomainWordlistSmall(): string[] {
  return loadWordlist('Discovery/DNS/subdomains-top1million-5000.txt');
}

// ─── DIRECTORY & FILE DISCOVERY ──────────────────────────────────────────────

/** Common web paths (small, fast) */
export function getCommonPaths(): string[] {
  return loadWordlist('Discovery/Web-Content/common.txt');
}

/** Medium raft directories */
export function getRaftMediumDirectories(): string[] {
  return loadWordlist('Discovery/Web-Content/raft-medium-directories.txt');
}

/** Medium raft files */
export function getRaftMediumFiles(): string[] {
  return loadWordlist('Discovery/Web-Content/raft-medium-files.txt');
}

/** Medium raft extensions */
export function getRaftMediumExtensions(): string[] {
  return loadWordlist('Discovery/Web-Content/raft-medium-extensions.txt');
}

/** Large directories (for thorough scans) */
export function getRaftLargeDirectories(): string[] {
  return loadWordlist('Discovery/Web-Content/raft-large-directories.txt', 10000);
}

/** Robots.txt common paths */
export function getRobotsPaths(): string[] {
  return loadWordlist('Discovery/Web-Content/raft-medium-directories.txt', 5000);
}

// ─── CREDENTIAL TESTING ──────────────────────────────────────────────────────

/** Top usernames */
export function getUsernameWordlist(): string[] {
  return loadWordlist('Usernames/top-usernames-shortlist.txt');
}

/** Common passwords */
export function getPasswordWordlist(): string[] {
  return loadWordlist('Passwords/Common-Credentials/10k-most-common.txt', 5000);
}

/** Default credentials */
export function getDefaultCredentials(): Array<{ username: string; password: string }> {
  const lines = loadWordlist('Passwords/Common-Credentials/best1050.txt', 500);
  return lines.map(line => {
    const parts = line.split(':');
    return { username: parts[0] || '', password: parts[1] || '' };
  }).filter(c => c.username.length > 0);
}

// ─── INJECTION PAYLOADS ──────────────────────────────────────────────────────

/** XSS payloads */
export function getXssPayloads(): string[] {
  return loadWordlist('Fuzzing/XSS/XSS-RSNAKE.txt', 200);
}

/** SQL injection payloads */
export function getSqlInjectionPayloads(): string[] {
  return loadWordlist('Fuzzing/SQL/sql-injection-bypasses.txt', 100);
}

/** SSTI payloads */
export function getSstiPayloads(): string[] {
  return loadWordlist('Fuzzing/SSTI/ssti-payloads.txt', 50);
}

/** Command injection payloads */
export function getCommandInjectionPayloads(): string[] {
  return loadWordlist('Fuzzing/OS-Injection/command-injection-unix.txt', 50);
}

/** Special chars for fuzzing */
export function getSpecialChars(): string[] {
  return loadWordlist('Fuzzing/special-chars.txt');
}

// ─── COMMON SECRETS & SENSITIVE PATHS ────────────────────────────────────────

/** Sensitive file paths */
export function getSensitivePaths(): string[] {
  return loadWordlist('Discovery/Web-Content/common.txt', 2000);
}

/** API endpoints */
export function getApiPaths(): string[] {
  const paths = loadWordlist('Discovery/Web-Content/common.txt', 2000);
  return paths.filter(p => p.startsWith('/api') || p.startsWith('/v1') || p.startsWith('/v2') || p.includes('graphql'));
}

/** Backup file extensions */
export function getBackupExtensions(): string[] {
  return ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.copy', '.temp'];
}

export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export function formatDateTime(dateStr: string): string {
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function computeScore(findings: { severity: string }[]): number {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach((f) => {
    counts[f.severity as keyof typeof counts]++;
  });
  return Math.max(
    0,
    100 -
      (counts.CRITICAL * 25 +
        counts.HIGH * 15 +
        counts.MEDIUM * 8 +
        counts.LOW * 3 +
        counts.INFO * 1)
  );
}

export function getGrade(score: number): { label: string; color: string } {
  if (score >= 90) return { label: 'A', color: 'bg-green-500 text-white' };
  if (score >= 80) return { label: 'B', color: 'bg-blue-500 text-white' };
  if (score >= 70) return { label: 'C', color: 'bg-yellow-500 text-black' };
  if (score >= 60) return { label: 'D', color: 'bg-orange-500 text-white' };
  return { label: 'F', color: 'bg-red-500 text-white' };
}

export function getScoreColor(score: number): string {
  if (score >= 90) return '#22c55e';
  if (score >= 80) return '#3b82f6';
  if (score >= 70) return '#eab308';
  if (score >= 60) return '#f97316';
  return '#ef4444';
}

export const statusColors: Record<string, string> = {
  PENDING: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/20',
  RUNNING: 'bg-blue-500/15 text-blue-400 border border-blue-500/20',
  COMPLETED: 'bg-green-500/15 text-green-400 border border-green-500/20',
  FAILED: 'bg-red-500/15 text-red-400 border border-red-500/20',
};

export const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/20',
  HIGH: 'bg-orange-500/15 text-orange-400 border border-orange-500/20',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/20',
  LOW: 'bg-blue-500/15 text-blue-400 border border-blue-500/20',
  INFO: 'bg-gray-500/15 text-gray-400 border border-gray-500/20',
};

export const severityBadge: Record<string, string> = {
  CRITICAL: 'bg-red-500 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-white',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

export const severityHex: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
};

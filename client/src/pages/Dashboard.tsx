import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';

interface Stats {
  securityScore: number;
  totalAssets: number;
  activeAssessments: number;
  criticalFindings: number;
  totalEngagements: number;
  findingsBySeverity: { severity: string; count: number }[];
  recentAssessments: { id: string; domain: string; status: string; score: number | null; findingsCount: number; createdAt: string }[];
}

interface ActiveScan {
  id: string;
  name: string;
  status: string;
  description?: string;
  createdAt: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [activeScans, setActiveScans] = useState<ActiveScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [domain, setDomain] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    loadStats();
    loadActiveScans();
    const interval = setInterval(loadActiveScans, 10000);
    return () => clearInterval(interval);
  }, []);

  function loadStats() {
    api.get('/dashboard/stats').then(r => setStats(r.data)).catch(console.error).finally(() => setLoading(false));
  }

  function loadActiveScans() {
    api.get('/engagements').then(r => {
      const all = r.data.engagements || r.data.data || [];
      setActiveScans(all.filter((e: ActiveScan) => e.status === 'ACTIVE' || e.status === 'DRAFT'));
    }).catch(console.error);
  }

  const startScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) navigate('/scan', { state: { domain: domain.trim() } });
  };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" /></div>;

  const severityColor: Record<string, string> = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280' };
  const totalFindings = stats?.findingsBySeverity.reduce((s, f) => s + f.count, 0) || 0;

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="hero-gradient text-center py-10">
        <h1 className="text-4xl font-bold text-white mb-3 tracking-tight">
          Go hack yourself.
        </h1>
        <p className="text-gray-500 text-base mb-10 max-w-md mx-auto">
          Before they do. Enter a target to start autonomous security validation.
        </p>
        <form onSubmit={startScan} className="max-w-xl mx-auto flex gap-3">
          <input
            className="input flex-1 text-center font-mono text-lg py-3.5"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
          />
          <button type="submit" className="btn-primary px-10 py-3.5 text-base font-semibold">
            Scan
          </button>
        </form>
      </div>

      {/* Active Scans */}
      {activeScans.length > 0 && (
        <div className="card-glow p-4 border-cyber-500/20 bg-cyber-500/[0.03]">
          <div className="flex items-center gap-2.5 mb-3">
            <div className="w-2 h-2 rounded-full bg-cyber-500 animate-pulse" />
            <h3 className="text-xs font-semibold text-cyber-400 uppercase tracking-wider">{activeScans.length} Active Assessment{activeScans.length > 1 ? 's' : ''}</h3>
          </div>
          <div className="space-y-1.5">
            {activeScans.map(scan => (
              <button key={scan.id} onClick={() => navigate('/scan/' + scan.id)}
                className="w-full flex items-center justify-between p-3 rounded-lg bg-dark-900/60 hover:bg-dark-800/60 transition-all text-left group border border-white/[0.03]">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-2 h-2 rounded-full bg-cyber-500 animate-pulse flex-shrink-0" />
                  <div className="min-w-0">
                    <span className="text-sm font-medium text-white group-hover:text-cyber-400 transition-colors">{scan.name}</span>
                    <span className="text-xs text-gray-600 ml-2">{scan.description || 'Scanning...'}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="badge-info text-[10px] animate-pulse">RUNNING</span>
                  <svg className="w-4 h-4 text-gray-700 group-hover:text-cyber-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="glow-line" />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Security Score', value: stats?.securityScore || 0, suffix: '/100', color: (stats?.securityScore || 0) >= 70 ? 'text-emerald-400' : (stats?.securityScore || 0) >= 40 ? 'text-yellow-400' : 'text-red-400' },
          { label: 'Discovered Assets', value: stats?.totalAssets || 0, color: 'text-cyber-400' },
          { label: 'Critical + High', value: stats?.criticalFindings || 0, color: 'text-red-400' },
          { label: 'Assessments', value: stats?.totalEngagements || 0, color: 'text-white' },
        ].map((m) => (
          <div key={m.label} className="metric-card text-center">
            <p className={`text-3xl font-bold ${m.color}`}>
              {m.value}
              {m.suffix && <span className="text-lg text-gray-600">{m.suffix}</span>}
            </p>
            <p className="text-[11px] text-gray-500 mt-1.5 uppercase tracking-wider font-medium">{m.label}</p>
          </div>
        ))}
      </div>

      {/* Severity + Recent */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card p-5">
          <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-4">Findings by Severity</h3>
          <div className="space-y-3">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => {
              const count = stats?.findingsBySeverity.find(f => f.severity === sev)?.count || 0;
              const pct = totalFindings > 0 ? (count / totalFindings) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="text-[11px] font-medium text-gray-500 w-14 text-right uppercase">{sev.toLowerCase()}</span>
                  <div className="flex-1 h-1.5 bg-dark-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700" style={{ width: pct + '%', backgroundColor: severityColor[sev] }} />
                  </div>
                  <span className="text-xs font-semibold text-white w-6 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-4">Recent Assessments</h3>
          <div className="space-y-0.5">
            {(!stats?.recentAssessments || stats.recentAssessments.length === 0) ? (
              <p className="text-gray-600 text-sm text-center py-6">No assessments yet. Enter a domain above to get started.</p>
            ) : stats.recentAssessments.map((a) => (
              <button key={a.id} onClick={() => navigate('/scan/' + a.id)}
                className="w-full flex items-center justify-between p-2.5 rounded-lg hover:bg-dark-800/60 transition-all text-left group">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${a.status === 'COMPLETED' ? 'bg-emerald-500' : a.status === 'RUNNING' ? 'bg-cyber-500 animate-pulse' : a.status === 'FAILED' ? 'bg-red-500' : 'bg-gray-600'}`} />
                  <span className="text-sm text-gray-300 truncate group-hover:text-white transition-colors font-mono">{a.domain}</span>
                </div>
                <div className="flex items-center gap-4 text-xs text-gray-600 flex-shrink-0">
                  {a.score != null && <span className={a.score >= 70 ? 'text-emerald-400' : a.score >= 40 ? 'text-yellow-400' : 'text-red-400'}>{a.score}</span>}
                  <span>{a.findingsCount} findings</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

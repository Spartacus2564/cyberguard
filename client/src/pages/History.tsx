import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';

interface Engagement {
  id: string;
  name: string;
  status: string;
  description?: string;
  createdAt: string;
  _count?: { discoveredAssets: number; hypotheses: number; attackPaths: number };
}

export default function History() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'running' | 'completed' | 'failed'>('all');
  const navigate = useNavigate();

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  function load() {
    api.get('/engagements').then(r => setEngagements(r.data.engagements || r.data.data || [])).catch(console.error).finally(() => setLoading(false));
  }

  const filtered = engagements.filter(e => {
    if (filter === 'running') return e.status === 'ACTIVE' || e.status === 'DRAFT';
    if (filter === 'completed') return e.status === 'COMPLETED';
    if (filter === 'failed') return e.status === 'FAILED';
    return true;
  });

  const running = engagements.filter(e => e.status === 'ACTIVE' || e.status === 'DRAFT');
  const completed = engagements.filter(e => e.status === 'COMPLETED');
  const failed = engagements.filter(e => e.status === 'FAILED');

  const statusStyles: Record<string, { dot: string; text: string; badge: string }> = {
    DRAFT: { dot: 'bg-gray-600', text: 'text-gray-500', badge: 'badge-info' },
    ACTIVE: { dot: 'bg-cyber-500', text: 'text-cyber-400', badge: 'badge-info' },
    COMPLETED: { dot: 'bg-emerald-500', text: 'text-emerald-400', badge: 'badge-success' },
    FAILED: { dot: 'bg-red-500', text: 'text-red-400', badge: 'badge-critical' },
    CANCELLED: { dot: 'bg-gray-600', text: 'text-gray-500', badge: 'badge-info' },
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Engagements</h1>
          <p className="text-gray-500 text-sm mt-1">All security assessments</p>
        </div>
        <button onClick={() => navigate('/scan')} className="btn-primary">New Scan</button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-1 border-b border-white/5">
        {([
          { key: 'all' as const, label: 'All', count: engagements.length },
          { key: 'running' as const, label: 'Running', count: running.length },
          { key: 'completed' as const, label: 'Completed', count: completed.length },
          { key: 'failed' as const, label: 'Failed', count: failed.length },
        ]).map(f => (
          <button key={f.key} onClick={() => setFilter(f.key)}
            className={`px-4 py-3 text-[12px] font-semibold uppercase tracking-wider border-b-2 transition-all ${filter === f.key ? 'border-cyber-500 text-cyber-400' : 'border-transparent text-gray-600 hover:text-gray-400'}`}>
            {f.label}
            {f.count > 0 && <span className="ml-1.5 text-[10px] text-gray-600">({f.count})</span>}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center h-40"><div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" /></div>
      ) : filtered.length === 0 ? (
        <div className="card p-16 text-center">
          <p className="text-gray-500 mb-4">No assessments found</p>
          <button onClick={() => navigate('/scan')} className="btn-primary">Start Your First Scan</button>
        </div>
      ) : (
        <div className="space-y-1.5">
          {filtered.map(eng => {
            const s = statusStyles[eng.status] || statusStyles.DRAFT;
            const isActive = eng.status === 'ACTIVE' || eng.status === 'DRAFT';
            return (
              <button key={eng.id} onClick={() => navigate('/scan/' + eng.id)}
                className={`w-full p-4 flex items-center justify-between transition-all text-left group rounded-xl border ${isActive ? 'card-glow border-cyber-500/10 bg-cyber-500/[0.02]' : 'card border-white/[0.03]'}`}>
                <div className="flex items-center gap-4 min-w-0">
                  <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${s.dot} ${isActive ? 'animate-pulse' : ''}`} />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-white group-hover:text-cyber-400 transition-colors truncate">{eng.name}</p>
                    <p className="text-xs text-gray-600 truncate">{eng.description || 'No description'}</p>
                  </div>
                </div>
                <div className="flex items-center gap-5 text-xs text-gray-500 flex-shrink-0 ml-4">
                  {isActive && <span className="badge-info animate-pulse">RUNNING</span>}
                  {!isActive && <span className={s.badge}>{eng.status}</span>}
                  <span className="text-gray-600">{eng._count?.discoveredAssets || 0} assets</span>
                  <span className="text-gray-600">{eng._count?.hypotheses || 0} hypotheses</span>
                  <span className="text-gray-600 hidden md:inline">{new Date(eng.createdAt).toLocaleDateString()}</span>
                  <svg className="w-4 h-4 text-gray-700 group-hover:text-gray-500 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

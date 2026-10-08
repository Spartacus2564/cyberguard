import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../lib/api';

interface Engagement {
  id: string;
  name: string;
  status: string;
  target: string;
  createdAt: string;
  _count?: { assets: number; evidence: number };
}

export default function Engagements() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', target: '', description: '' });
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => { load(); }, []);

  async function load() {
    try {
      const res = await api.get('/engagements');
      setEngagements(res.data.data || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.post('/engagements', form);
      setShowCreate(false);
      setForm({ name: '', target: '', description: '' });
      load();
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  }

  const statusColors: Record<string, string> = {
    DRAFT: 'text-gray-500',
    ACTIVE: 'text-cyber-400',
    PAUSED: 'text-yellow-400',
    COMPLETED: 'text-emerald-400',
    CANCELLED: 'text-red-400',
  };

  const statusDots: Record<string, string> = {
    DRAFT: 'bg-gray-600',
    ACTIVE: 'bg-cyber-500 animate-pulse',
    PAUSED: 'bg-yellow-500',
    COMPLETED: 'bg-emerald-500',
    CANCELLED: 'bg-red-500',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Engagements</h1>
          <p className="text-gray-500 text-sm mt-1">Manage penetration testing engagements</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary text-sm">
          + New Engagement
        </button>
      </div>

      <div className="glow-line" />

      {loading ? (
        <div className="flex items-center justify-center h-40">
          <div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
        </div>
      ) : engagements.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-dark-800 flex items-center justify-center">
            <svg className="w-8 h-8 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"/>
            </svg>
          </div>
          <p className="text-gray-400 font-medium mb-1">No engagements yet</p>
          <p className="text-gray-600 text-sm mb-4">Create your first engagement to start autonomous testing</p>
          <button onClick={() => setShowCreate(true)} className="btn-primary text-sm">Create Engagement</button>
        </div>
      ) : (
        <div className="grid gap-3">
          {engagements.map((eng) => (
            <Link
              key={eng.id}
              to={'/engagements/' + eng.id}
              className="card-glow p-5 flex items-center justify-between hover:border-dark-600 transition-all group"
            >
              <div className="flex items-center gap-4 min-w-0">
                <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${statusDots[eng.status] || 'bg-gray-600'}`} />
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-white group-hover:text-cyber-400 transition-colors truncate">{eng.name}</h3>
                  <p className="text-xs text-gray-600 truncate mt-0.5">{eng.target}</p>
                </div>
              </div>
              <div className="flex items-center gap-6 text-xs text-gray-500 flex-shrink-0 ml-4">
                <span className={statusColors[eng.status] || 'text-gray-500'}>{eng.status}</span>
                <span>{eng._count?.assets || 0} assets</span>
                <span>{new Date(eng.createdAt).toLocaleDateString()}</span>
                <svg className="w-4 h-4 text-gray-700 group-hover:text-gray-500 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5"/>
                </svg>
              </div>
            </Link>
          ))}
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setShowCreate(false)}>
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-white mb-4">New Engagement</h2>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1.5">Engagement Name</label>
                <input className="input" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} placeholder="e.g. Q1 External Pentest" required />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1.5">Target Domain</label>
                <input className="input" value={form.target} onChange={(e) => setForm({...form, target: e.target.value})} placeholder="e.g. example.com" required />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-1.5">Description</label>
                <textarea className="input" rows={3} value={form.description} onChange={(e) => setForm({...form, description: e.target.value})} placeholder="Scope and objectives..." />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="btn-secondary flex-1 text-sm">Cancel</button>
                <button type="submit" disabled={submitting} className="btn-primary flex-1 text-sm">{submitting ? 'Creating...' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

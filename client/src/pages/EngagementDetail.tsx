import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../lib/api';

interface Engagement {
  id: string;
  name: string;
  status: string;
  target: string;
  description?: string;
  createdAt: string;
  _count?: { assets: number; evidence: number; attackPaths: number; hypotheses: number; knowledge: number };
}

interface Asset {
  id: string;
  hostname: string;
  ipAddress?: string;
  type: string;
  services?: string;
}

interface AttackPath {
  id: string;
  title: string;
  riskScore: number;
  chainJson?: string;
}

interface Evidence {
  id: string;
  type: string;
  title: string;
  severity: string;
  source?: string;
  createdAt: string;
}

interface ToolExecution {
  id: string;
  toolName: string;
  status: string;
  startedAt: string;
  completedAt?: string;
}

interface KnowledgeEntry {
  id: string;
  category: string;
  key: string;
  value: string;
  confidence: number;
  source?: string;
  createdAt: string;
}

interface HypothesisEntry {
  id: string;
  hypothesis: string;
  reasoning: string;
  confidence: number;
  status: string;
  testAction?: string;
  testResult?: string;
  evidence?: string;
  createdAt: string;
}

const tabs = ['Overview', 'Assets', 'Attack Graph', 'Knowledge', 'Hypotheses', 'Evidence', 'Scans'] as const;

export default function EngagementDetail() {
  const { id } = useParams();
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [activeTab, setActiveTab] = useState<string>('Overview');
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  const [assets, setAssets] = useState<Asset[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [toolExecutions, setToolExecutions] = useState<ToolExecution[]>([]);
  const [knowledge, setKnowledge] = useState<KnowledgeEntry[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisEntry[]>([]);
  const [knowledgeStats, setKnowledgeStats] = useState<any>(null);
  const [hypothesisStats, setHypothesisStats] = useState<any>(null);

  useEffect(() => { loadEngagement(); }, [id]);
  useEffect(() => {
    if (activeTab === 'Assets') loadAssets();
    if (activeTab === 'Attack Graph') loadAttackPaths();
    if (activeTab === 'Evidence') loadEvidence();
    if (activeTab === 'Scans') loadToolExecutions();
    if (activeTab === 'Knowledge') { loadKnowledge(); loadKnowledgeStats(); }
    if (activeTab === 'Hypotheses') { loadHypotheses(); loadHypothesisStats(); }
  }, [activeTab]);

  async function loadEngagement() {
    try { const res = await api.get('/engagements/' + id); setEngagement(res.data); } catch (e) { console.error(e); } finally { setLoading(false); }
  }
  async function loadAssets() { try { const res = await api.get('/engagements/' + id + '/assets'); setAssets(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadAttackPaths() { try { const res = await api.get('/engagements/' + id + '/attack-paths'); setAttackPaths(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadEvidence() { try { const res = await api.get('/engagements/' + id + '/evidence'); setEvidence(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadToolExecutions() { try { const res = await api.get('/engagements/' + id + '/tool-executions'); setToolExecutions(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadKnowledge() { try { const res = await api.get('/engagements/' + id + '/knowledge'); setKnowledge(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadKnowledgeStats() { try { const res = await api.get('/engagements/' + id + '/knowledge/stats'); setKnowledgeStats(res.data); } catch (e) { console.error(e); } }
  async function loadHypotheses() { try { const res = await api.get('/engagements/' + id + '/hypotheses'); setHypotheses(res.data.data || []); } catch (e) { console.error(e); } }
  async function loadHypothesisStats() { try { const res = await api.get('/engagements/' + id + '/hypotheses/stats'); setHypothesisStats(res.data); } catch (e) { console.error(e); } }

  async function triggerScan() {
    setScanning(true);
    try { await api.post('/engagements/' + id + '/scan'); loadEngagement(); } catch (e) { console.error(e); } finally { setScanning(false); }
  }

  if (loading) return <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" /></div>;
  if (!engagement) return <div className="text-center py-16"><p className="text-gray-500">Engagement not found</p><Link to="/engagements" className="text-cyber-500 text-sm mt-2 inline-block">Back to engagements</Link></div>;

  const statusColor: Record<string, string> = {
    DRAFT: 'text-gray-500 bg-gray-500/10 border-gray-500/20',
    ACTIVE: 'text-cyber-400 bg-cyber-500/10 border-cyber-500/20',
    PAUSED: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    COMPLETED: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    CANCELLED: 'text-red-400 bg-red-500/10 border-red-500/20',
  };

  const hypStatusColors: Record<string, string> = {
    PROPOSED: 'badge-info',
    TESTING: 'badge-medium',
    CONFIRMED: 'badge-success',
    REFUTED: 'badge-critical',
    ABANDONED: 'badge-info',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <Link to="/engagements" className="text-xs text-gray-600 hover:text-gray-400 transition-colors mb-2 inline-flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5"/></svg>
            Engagements
          </Link>
          <h1 className="text-2xl font-bold text-white tracking-tight mt-1">{engagement.name}</h1>
          <p className="text-gray-500 text-sm mt-1">{engagement.target}</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={'text-xs font-semibold px-3 py-1 rounded-full border ' + (statusColor[engagement.status] || '')}>{engagement.status}</span>
          <button onClick={triggerScan} disabled={scanning || engagement.status === 'ACTIVE'} className="btn-primary text-sm">
            {scanning ? <span className="flex items-center gap-2"><span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />Scanning...</span> : 'Run Scan'}
          </button>
        </div>
      </div>
      <div className="glow-line" />

      <div className="flex gap-1 border-b border-dark-700/50 overflow-x-auto">
        {tabs.map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={'px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ' + (activeTab === tab ? 'text-cyber-400 border-cyber-500' : 'text-gray-500 border-transparent hover:text-gray-300')}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'Overview' && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[
            { label: 'Assets', value: engagement._count?.assets || 0, color: 'text-cyber-400' },
            { label: 'Attack Paths', value: engagement._count?.attackPaths || 0, color: 'text-orange-400' },
            { label: 'Knowledge', value: engagement._count?.knowledge || 0, color: 'text-emerald-400' },
            { label: 'Hypotheses', value: engagement._count?.hypotheses || 0, color: 'text-purple-400' },
            { label: 'Evidence', value: engagement._count?.evidence || 0, color: 'text-yellow-400' },
          ].map((m) => (
            <div key={m.label} className="metric-card text-center">
              <p className={'text-3xl font-bold ' + m.color}>{m.value}</p>
              <p className="text-xs text-gray-500 mt-1">{m.label}</p>
            </div>
          ))}
          {engagement.description && (
            <div className="col-span-full card p-5">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Description</p>
              <p className="text-sm text-gray-300 leading-relaxed">{engagement.description}</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'Assets' && (
        <div className="space-y-3">
          {assets.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No assets discovered yet.</p></div> : (
            <div className="card overflow-hidden">
              <table className="w-full">
                <thead><tr className="border-b border-dark-700/50">
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Hostname</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">IP</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Type</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Services</th>
                </tr></thead>
                <tbody className="divide-y divide-dark-700/30">
                  {assets.map((a) => (
                    <tr key={a.id} className="hover:bg-dark-800/50 transition-colors">
                      <td className="px-5 py-3 text-sm font-medium text-white">{a.hostname}</td>
                      <td className="px-5 py-3 text-sm text-gray-400 font-mono">{a.ipAddress || '-'}</td>
                      <td className="px-5 py-3"><span className="badge-info">{a.type}</span></td>
                      <td className="px-5 py-3 text-sm text-gray-500">{a.services ? JSON.parse(a.services).length + ' services' : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'Attack Graph' && (
        <div className="space-y-3">
          {attackPaths.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No attack paths constructed yet.</p></div> : (
            <div className="grid gap-3">
              {attackPaths.map((p) => (
                <div key={p.id} className="card p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-white">{p.title}</h4>
                      <p className="text-xs text-gray-600 mt-1">Path ID: {p.id.slice(0, 8)}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-wider">Risk Score</p>
                      <p className={'text-xl font-bold ' + (p.riskScore >= 70 ? 'text-red-400' : p.riskScore >= 40 ? 'text-yellow-400' : 'text-emerald-400')}>{p.riskScore}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'Knowledge' && (
        <div className="space-y-4">
          {knowledgeStats && (
            <div className="grid grid-cols-3 gap-4">
              <div className="metric-card text-center"><p className="text-2xl font-bold text-white">{knowledgeStats.totalEntries}</p><p className="text-xs text-gray-500">Entries</p></div>
              <div className="metric-card text-center"><p className="text-2xl font-bold text-white">{knowledgeStats.categories}</p><p className="text-xs text-gray-500">Categories</p></div>
              <div className="metric-card text-center"><p className="text-2xl font-bold text-emerald-400">{(knowledgeStats.avgConfidence * 100).toFixed(0)}%</p><p className="text-xs text-gray-500">Avg Confidence</p></div>
            </div>
          )}
          {knowledge.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No knowledge entries yet.</p></div> : (
            <div className="card overflow-hidden">
              <table className="w-full">
                <thead><tr className="border-b border-dark-700/50">
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Category</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Key</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Confidence</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Source</th>
                </tr></thead>
                <tbody className="divide-y divide-dark-700/30">
                  {knowledge.map((k) => (
                    <tr key={k.id} className="hover:bg-dark-800/50 transition-colors">
                      <td className="px-5 py-3"><span className="badge-info">{k.category}</span></td>
                      <td className="px-5 py-3 text-sm text-white font-mono">{k.key}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-dark-800 rounded-full overflow-hidden"><div className="h-full bg-cyber-500 rounded-full" style={{ width: (k.confidence * 100) + '%' }} /></div>
                          <span className="text-xs text-gray-400">{(k.confidence * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-sm text-gray-500">{k.source || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'Hypotheses' && (
        <div className="space-y-4">
          {hypothesisStats && (
            <div className="grid grid-cols-4 gap-4">
              <div className="metric-card text-center"><p className="text-2xl font-bold text-white">{hypothesisStats.total}</p><p className="text-xs text-gray-500">Total</p></div>
              <div className="metric-card text-center"><p className="text-2xl font-bold text-cyber-400">{hypothesisStats.testing}</p><p className="text-xs text-gray-500">Testing</p></div>
              <div className="metric-card text-center"><p className="text-2xl font-bold text-emerald-400">{hypothesisStats.confirmed}</p><p className="text-xs text-gray-500">Confirmed</p></div>
              <div className="metric-card text-center"><p className="text-2xl font-bold text-emerald-400">{(hypothesisStats.avgConfidence * 100).toFixed(0)}%</p><p className="text-xs text-gray-500">Avg Confidence</p></div>
            </div>
          )}
          {hypotheses.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No hypotheses generated yet.</p></div> : (
            <div className="space-y-3">
              {hypotheses.map((h) => (
                <div key={h.id} className="card p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className={hypStatusColors[h.status] || 'badge-info'}>{h.status}</span>
                      <h4 className="text-sm font-medium text-white">{h.hypothesis}</h4>
                    </div>
                    <div className="text-right flex-shrink-0 ml-4">
                      <p className="text-lg font-bold text-white">{(h.confidence * 100).toFixed(0)}%</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">{h.reasoning}</p>
                  {h.testResult && (
                    <div className="bg-dark-800 rounded-lg p-3 mt-2">
                      <p className="text-xs font-semibold text-gray-400 mb-1">Test Result</p>
                      <p className="text-xs text-gray-300">{h.testResult}</p>
                    </div>
                  )}
                  {h.evidence && (
                    <div className="bg-dark-800 rounded-lg p-3 mt-2">
                      <p className="text-xs font-semibold text-gray-400 mb-1">Evidence</p>
                      <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">{h.evidence}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'Evidence' && (
        <div className="space-y-3">
          {evidence.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No evidence collected yet.</p></div> : (
            <div className="grid gap-3">
              {evidence.map((ev) => (
                <div key={ev.id} className="card p-5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={'badge-' + (ev.severity === 'CRITICAL' ? 'critical' : ev.severity === 'HIGH' ? 'high' : ev.severity === 'MEDIUM' ? 'medium' : ev.severity === 'LOW' ? 'low' : 'info')}>{ev.severity}</span>
                      <div>
                        <h4 className="text-sm font-medium text-white">{ev.title}</h4>
                        <p className="text-xs text-gray-600 mt-0.5">{ev.type} {ev.source ? '- ' + ev.source : ''}</p>
                      </div>
                    </div>
                    <span className="text-xs text-gray-600">{new Date(ev.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'Scans' && (
        <div className="space-y-3">
          {toolExecutions.length === 0 ? <div className="card p-10 text-center"><p className="text-gray-500 text-sm">No tool executions recorded yet.</p></div> : (
            <div className="card overflow-hidden">
              <table className="w-full">
                <thead><tr className="border-b border-dark-700/50">
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Tool</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Status</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Started</th>
                  <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Completed</th>
                </tr></thead>
                <tbody className="divide-y divide-dark-700/30">
                  {toolExecutions.map((tx) => (
                    <tr key={tx.id} className="hover:bg-dark-800/50 transition-colors">
                      <td className="px-5 py-3 text-sm font-medium text-white">{tx.toolName}</td>
                      <td className="px-5 py-3"><span className={tx.status === 'completed' ? 'badge-success' : tx.status === 'running' ? 'badge-info' : 'badge-medium'}>{tx.status}</span></td>
                      <td className="px-5 py-3 text-sm text-gray-500">{new Date(tx.startedAt).toLocaleString()}</td>
                      <td className="px-5 py-3 text-sm text-gray-500">{tx.completedAt ? new Date(tx.completedAt).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

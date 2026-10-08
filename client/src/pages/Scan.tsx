import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import api from '../lib/api';

type Phase = 'idle' | 'creating' | 'scanning' | 'complete' | 'error';

interface LogEntry { time: string; msg: string; type: 'info' | 'success' | 'error' | 'warn'; }
interface Finding { id: string; title: string; severity: string; description: string; evidence?: string; remediation?: string; references?: string | string[]; category?: string; }
interface Asset { id: string; value: string; type: string; metadata?: Record<string, unknown>; }
interface HypothesisEntry { id: string; hypothesis: string; reasoning: string; confidence: number; status: string; testResult?: string; evidence?: string; }
interface AttackPathNode { id: string; type: string; label: string; evidence?: string; vulnerability?: string; metadata?: Record<string, unknown>; }
interface AttackPathEdge { id: string; source: string; target: string; type: string; label: string; confidence?: number; evidence?: string; metadata?: Record<string, unknown>; }
interface AttackPathEntry { id: string; title: string; riskScore: number; impactLevel?: string; description?: string; entryPoint?: string; impactPoint?: string; confidence?: number; nodes?: AttackPathNode[]; edges?: AttackPathEdge[]; }

const SCAN_PHASES = [
  { key: 'recon', label: 'Recon', desc: 'Discovering assets and services' },
  { key: 'scan', label: 'Vuln Scan', desc: 'Running security modules' },
  { key: 'analyze', label: 'AI Analysis', desc: 'Reasoning about attack paths' },
  { key: 'report', label: 'Report', desc: 'Generating findings' },
];

function getScanPhase(progress: number): number {
  if (progress < 10) return 0;
  if (progress < 60) return 1;
  if (progress < 90) return 2;
  return 3;
}

export default function Scan() {
  const { id: urlId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const inputDomain = (location.state as any)?.domain || '';

  const [domain, setDomain] = useState(inputDomain);
  const [phase, setPhase] = useState<Phase>(urlId ? 'scanning' : 'idle');
  const [engagementId, setEngagementId] = useState(urlId || '');
  const [progress, setProgress] = useState(0);
  const [currentModule, setCurrentModule] = useState('');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisEntry[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPathEntry[]>([]);
  const [error, setError] = useState('');
  const [scanDuration, setScanDuration] = useState(0);
  const [activeTab, setActiveTab] = useState<'findings' | 'assets' | 'hypotheses' | 'attack-paths' | 'logs' | 'chat' | 'report'>('findings');
  const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'ai'; content: string }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [reportId, setReportId] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [latestInsight, setLatestInsight] = useState<{ title: string; type: string } | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'severity' | 'title'>('severity');
  const [findingPage, setFindingPage] = useState(1);
  const FINDINGS_PER_PAGE = 10;
  const chatEndRef = useRef<HTMLDivElement>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const mountedRef = useRef(false);

  const addLog = (msg: string, type: LogEntry['type'] = 'info') => {
    let finalType = type;
    if (type === 'info' && msg.startsWith('[AI]')) finalType = 'info';
    if (type === 'info' && msg.startsWith('[Done]')) finalType = 'success';
    setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg, type: finalType }]);
  };

  useEffect(() => {
    if (logsEndRef.current) {
      const container = logsEndRef.current.closest('.overflow-y-auto');
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    }
  }, [logs]);

  useEffect(() => {
    if (phase === 'scanning') {
      timerRef.current = setInterval(() => setScanDuration(d => d + 1), 1000);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [phase]);

  // Cleanup SSE on unmount
  useEffect(() => {
    return () => { if (sseRef.current) { sseRef.current.close(); sseRef.current = null; } };
  }, []);

  // On mount with urlId: load engagement data, reconnect SSE
  useEffect(() => {
    if (urlId && !mountedRef.current) {
      mountedRef.current = true;
      loadEngagement(urlId);
    }
  }, [urlId]);

  // If navigated with domain (from Dashboard), auto-create and scan — ONCE
  useEffect(() => {
    if (inputDomain && !urlId && !mountedRef.current) {
      mountedRef.current = true;
      startScan(inputDomain);
    }
  }, []); // Empty deps — only on mount

  async function loadEngagement(eid: string) {
    try {
      const engRes = await api.get('/engagements/' + eid);
      const eng = engRes.data;
      setDomain(eng.domain || eng.name || eid);
      setEngagementId(eid);

      if (eng.status === 'COMPLETED') {
        setPhase('complete');
        setProgress(100);
        addLog('Scan completed', 'success');
        loadResults(eid);
        loadLogs(eid);
        loadReport(eid, eng.domain);
      } else if (eng.status === 'FAILED') {
        setPhase('error');
        setError('Scan failed');
        addLog('Scan previously failed', 'error');
        loadLogs(eid);
      } else {
        setPhase('scanning');
        // Restore timer from startedAt
        if (eng.startedAt) {
          const elapsed = Math.floor((Date.now() - new Date(eng.startedAt).getTime()) / 1000);
          if (elapsed > 0) setScanDuration(elapsed);
        }
        setupSSE(eid);
        loadResults(eid);
      }
    } catch (e) {
      setPhase('error');
      setError('Failed to load engagement');
    }
  }

  async function loadLogs(eid: string) {
    try {
      const res = await api.get('/engagements/' + eid + '/logs');
      const rawLogs = res.data.logs || [];
      if (rawLogs.length > 0) {
        const parsed: LogEntry[] = rawLogs
          .filter((l: any) => l.message)
          .map((l: any) => {
            const ts = l.ts ? new Date(l.ts).toLocaleTimeString() : '';
            let type: LogEntry['type'] = 'info';
            if (l.level === 'done') type = 'success';
            else if (l.level === 'error') type = 'error';
            else if (l.level === 'warn') type = 'warn';
            else if (l.level === 'vuln' || l.level === 'exploit') type = 'error';
            return { time: ts, msg: l.message, type };
          });
        setLogs(parsed);
      }
    } catch {}
  }

  async function loadReport(eid: string, domain?: string) {
    try {
      const res = await api.get('/reports');
      const reports = res.data.reports || res.data.data || (Array.isArray(res.data) ? res.data : []);
      const match = reports.find((r: any) => r.assessment?.domain === domain || r.title?.includes(domain || ''));
      if (match) setReportId(match.id);
    } catch {}
  }

  async function downloadReport() {
    if (!reportId || !domain) return;
    setReportLoading(true);
    try {
      const res = await api.get('/reports/' + reportId + '/download', { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyberguard-report-${domain}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Failed to download report');
    } finally {
      setReportLoading(false);
    }
  }

  async function loadResults(eid: string) {
    try {
      const [findingsRes, assetsRes, hypRes, apRes] = await Promise.all([
        api.get('/engagements/' + eid + '/findings').catch(() => ({ data: { data: [] } })),
        api.get('/engagements/' + eid + '/assets').catch(() => ({ data: { data: [] } })),
        api.get('/engagements/' + eid + '/hypotheses').catch(() => ({ data: { data: [] } })),
        api.get('/engagements/' + eid + '/attack-graph').catch(() => ({ data: { paths: [], nodes: [], edges: [] } })),
      ]);
      setFindings(findingsRes.data.data || []);
      setAssets(assetsRes.data.assets || assetsRes.data.data || []);
      setHypotheses(hypRes.data.data || []);

      // Merge nodes and edges into paths
      const graphNodes: AttackPathNode[] = apRes.data.nodes || [];
      const graphEdges: AttackPathEdge[] = apRes.data.edges || [];
      const rawPaths = apRes.data.paths || apRes.data.data || [];
      const enrichedPaths = rawPaths.map((p: AttackPathEntry) => {
        const pathNodes = graphNodes.filter((n: AttackPathNode) => {
          return graphEdges.some((e: AttackPathEdge) => e.source === n.id || e.target === n.id);
        });
        const pathEdges = graphEdges;
        return { ...p, nodes: pathNodes.length > 0 ? pathNodes : graphNodes, edges: pathEdges };
      });
      setAttackPaths(enrichedPaths.length > 0 ? enrichedPaths : rawPaths);
    } catch (e) { console.error(e); }
  }

  function setupSSE(eid: string) {
    if (sseRef.current) { sseRef.current.close(); }
    const es = new EventSource(`/api/engagements/${eid}/progress`);
    sseRef.current = es;

    // Periodically refresh results during scanning so tabs show live data
    const refreshInterval = setInterval(() => {
      if (phase === 'scanning') loadResults(eid);
    }, 15000); // every 15s

    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.progress != null) setProgress(Math.min(100, data.progress));
        if (data.currentModule) {
          setCurrentModule(data.currentModule);
          if (data.aiActivity) {
            addLog(`[AI] ${data.aiActivity}`);
          } else {
            addLog(`Running: ${data.currentModule}`);
          }
        }
        if (data.type === 'ai_activity' && data.message) {
          addLog(`[AI] ${data.message}`);
        }
        if (data.type === 'module_complete' && data.message) {
          addLog(`[Done] ${data.message}`);
          // Refresh results after each module completes
          loadResults(eid);
        }
        if (data.type === 'ai_insight' && data.insight) {
          const insight = data.insight;
          const label = `[AI Insight] [${insight.type}] ${insight.title}`;
          addLog(label);
          setLatestInsight({ title: insight.title, type: insight.type });
        }
        if (data.status === 'COMPLETED') {
          clearInterval(refreshInterval);
          setPhase('complete');
          setProgress(100);
          addLog('Scan completed successfully', 'success');
          loadResults(eid);
          loadLogs(eid);
          loadReport(eid, domain);
          es.close();
          sseRef.current = null;
        }
        if (data.status === 'FAILED') {
          clearInterval(refreshInterval);
          setPhase('error');
          setError(data.error || 'Scan failed');
          addLog('Scan failed: ' + (data.error || 'Unknown error'), 'error');
          es.close();
          sseRef.current = null;
        }
      } catch {}
    };
    es.onerror = () => {
      clearInterval(refreshInterval);
      // Retry after 3 seconds if still scanning
      setTimeout(() => {
        if (phase === 'scanning' && sseRef.current === es) {
          es.close();
          setupSSE(eid);
        }
      }, 3000);
    };
  }

  async function startScan(targetDomain: string) {
    const d = targetDomain || domain;
    if (!d.trim()) return;
    if (phase === 'creating' || phase === 'scanning') return;
    setDomain(d.trim());
    setPhase('creating');
    setProgress(0);
    setLogs([]);
    setFindings([]);
    setAssets([]);
    setHypotheses([]);
    setAttackPaths([]);
    setScanDuration(0);
    setError('');
    addLog(`Target: ${d.trim()}`);

    try {
      addLog('Creating engagement...');
      const engRes = await api.post('/engagements', { name: d.trim(), target: d.trim() });
      const eid = engRes.data.id;
      setEngagementId(eid);
      navigate('/scan/' + eid, { replace: true });

      addLog('Starting scan...');
      setPhase('scanning');
      await api.post(`/engagements/${eid}/scan`);
      addLog('Scan queued. Processing modules...', 'info');
      setupSSE(eid);
    } catch (e: any) {
      setPhase('error');
      const msg = e.response?.data?.message || e.response?.data?.error || 'Failed to start scan';
      setError(msg);
      addLog(msg, 'error');
    }
  }

  async function sendChat() {
    if (!chatInput.trim() || chatLoading || !engagementId) return;
    const msg = chatInput.trim();
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: msg }]);
    setChatLoading(true);
    try {
      const res = await api.post(`/engagements/${engagementId}/chat`, { message: msg });
      setChatMessages(prev => [...prev, { role: 'ai', content: res.data.response }]);
    } catch (e: any) {
      setChatMessages(prev => [...prev, { role: 'ai', content: 'Error: ' + (e.response?.data?.message || 'Failed to get response') }]);
    } finally {
      setChatLoading(false);
    }
  }

  const formatTime = (s: number) => `${Math.floor(s / 60)}:${(s % 60).toString().padStart(2, '0')}`;
  const sevBadge = (s: string) => s === 'CRITICAL' ? 'badge-critical' : s === 'HIGH' ? 'badge-high' : s === 'MEDIUM' ? 'badge-medium' : s === 'LOW' ? 'badge-low' : 'badge-info';
  const currentPhaseIdx = phase === 'scanning' ? getScanPhase(progress) : phase === 'complete' ? 3 : 0;

  async function cancelScanHandler() {
    if (!window.confirm('Are you sure you want to cancel this scan?')) return;
    if (!engagementId) return;
    setCancelling(true);
    try {
      await api.post(`/engagements/${engagementId}/cancel`);
      if (sseRef.current) {
        sseRef.current.close();
        sseRef.current = null;
      }
      setPhase('error');
      setError('Scan cancelled');
      addLog('Scan cancelled by user', 'warn');
    } catch (e) {
      console.error('Failed to cancel scan:', e);
      addLog('Failed to cancel scan', 'error');
    } finally {
      setCancelling(false);
    }
  }

  // ─── IDLE ────────────────────────────────────────────────────────────────
  if (phase === 'idle') {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="w-full max-w-lg text-center">
          <div className="hero-gradient mb-8">
            <div className="w-20 h-20 mx-auto mb-6 rounded-2xl bg-cyber-500/10 border border-cyber-500/20 flex items-center justify-center">
              <svg className="w-10 h-10 text-cyber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-white mb-2">New Security Assessment</h2>
            <p className="text-gray-500 text-sm mb-8">Enter a target domain to begin autonomous pentesting</p>
          </div>
          <form onSubmit={(e) => { e.preventDefault(); startScan(domain); }} className="flex gap-3">
            <input className="input flex-1 text-center font-mono text-lg py-3.5" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" autoFocus />
            <button type="submit" className="btn-primary px-10 py-3.5 text-base font-semibold">Start</button>
          </form>
        </div>
      </div>
    );
  }

  // ─── SCANNING / COMPLETE / ERROR ────────────────────────────────────────
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-[10px] font-bold uppercase tracking-wider ${phase === 'complete' ? 'text-emerald-400' : phase === 'error' ? 'text-red-400' : 'text-cyber-400'}`}>
              {phase === 'creating' ? 'Initializing' : phase === 'scanning' ? 'Scanning' : phase === 'complete' ? 'Complete' : 'Failed'}
            </span>
            {(phase === 'scanning' || phase === 'creating') && (
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-pulse" />
            )}
          </div>
          <h1 className="text-2xl font-bold text-white font-mono tracking-tight">{domain}</h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className="text-[10px] text-gray-600 uppercase tracking-wider">Elapsed</p>
            <p className="text-lg font-mono font-bold text-white">{formatTime(scanDuration)}</p>
          </div>
          {(phase === 'scanning' || phase === 'creating') && (
            <div className="w-10 h-10 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
          )}
          {phase === 'complete' && (
            <div className="w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
              </svg>
            </div>
          )}
        </div>
      </div>

      {(phase === 'scanning' || phase === 'creating') && (
        <div className="card p-5">
          <div className="flex items-center justify-between">
            {SCAN_PHASES.map((p, i) => (
              <div key={p.key} className="flex items-center gap-3">
                <div className="flex flex-col items-center gap-2">
                  <div className={`phase-dot ${i < currentPhaseIdx ? 'phase-dot-done' : i === currentPhaseIdx ? 'phase-dot-active' : 'phase-dot-pending'}`} />
                  <div className="text-center">
                    <p className={`text-[11px] font-semibold ${i <= currentPhaseIdx ? 'text-white' : 'text-gray-600'}`}>{p.label}</p>
                    <p className="text-[10px] text-gray-600 hidden md:block">{p.desc}</p>
                  </div>
                </div>
                {i < SCAN_PHASES.length - 1 && (
                  <div className={`w-12 md:w-20 h-px ${i < currentPhaseIdx ? 'bg-emerald-500/40' : 'bg-dark-700'}`} />
                )}
              </div>
            ))}
          </div>
          <div className="mt-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">
                {currentModule ? (
                  <span className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-400 animate-pulse" />
                    Module: {currentModule}
                  </span>
                ) : 'Preparing scan...'}
              </span>
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold text-cyber-400">{progress}%</span>
                <button
                  onClick={cancelScanHandler}
                  disabled={cancelling}
                  className="px-3 py-1.5 text-[11px] font-semibold bg-red-600/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-600/30 transition-all disabled:opacity-50"
                >
                  {cancelling ? 'Cancelling...' : 'Cancel Scan'}
                </button>
              </div>
            </div>
            <div className="w-full h-1.5 bg-dark-800 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyber-600 to-cyber-400 rounded-full transition-all duration-500 ease-out" style={{ width: progress + '%' }} />
            </div>
            {currentModule && (
              <p className="text-[10px] text-gray-600 mt-2">
                {progress < 10 ? 'Initializing scan engine...' :
                 progress < 25 ? 'Enumerating target surface...' :
                 progress < 50 ? 'Running vulnerability modules...' :
                 progress < 70 ? 'Analyzing security posture...' :
                 progress < 90 ? 'Generating AI analysis...' : 'Finalizing report...'}
              </p>
            )}
            {latestInsight && (
              <div className="mt-2 px-3 py-2 rounded-md bg-cyan-500/5 border border-cyan-500/15">
                <p className="text-[10px] text-cyan-400 font-semibold uppercase tracking-wider">AI Insight: {latestInsight.type.replace(/_/g, ' ')}</p>
                <p className="text-[11px] text-cyan-300/80 mt-0.5">{latestInsight.title}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg">{error}</div>
      )}

      {/* LIVE ACTIVITY PANEL — visible during scanning */}
      {(phase === 'scanning' || phase === 'creating') && (
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyber-400 animate-pulse" />
              <h3 className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Live Activity</h3>
            </div>
            <span className="text-[10px] text-gray-600">{logs.length} events</span>
          </div>
          <div className="bg-dark-950 rounded-lg p-3 h-72 overflow-y-auto font-mono text-xs space-y-0.5">
            {logs.length === 0 && (
              <div className="text-gray-600 text-center py-8">
                <div className="w-6 h-6 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin mx-auto mb-3" />
                <p>Initializing scan...</p>
              </div>
            )}
            {logs.map((l, i) => {
              const isAI = l.msg.startsWith('[AI]');
              const isInsight = l.msg.startsWith('[AI Insight]');
              const isDone = l.msg.startsWith('[Done]');
              const isError = l.type === 'error';
              return (
                <div key={i} className={`flex gap-2 ${isError ? 'text-red-400' : isDone ? 'text-emerald-400' : isInsight ? 'text-cyan-400 font-medium' : isAI ? 'text-cyber-400' : 'text-gray-500'}`}>
                  <span className="text-gray-700 flex-shrink-0 w-16">{l.time}</span>
                  <span>{l.msg}</span>
                </div>
              );
            })}
            <div ref={logsEndRef} />
          </div>
        </div>
      )}

      {/* RESULTS — tabs visible when scanning (for live data) or after completion */}
      {(phase === 'scanning' || phase === 'complete' || findings.length > 0 || assets.length > 0 || hypotheses.length > 0 || attackPaths.length > 0) && (
        <>
          <div className="glow-line" />
          <div className="flex items-center gap-1 border-b border-white/5">
            {([
              { key: 'findings' as const, label: 'Findings', count: findings.length },
              { key: 'assets' as const, label: 'Assets', count: assets.length },
              { key: 'hypotheses' as const, label: 'AI Hypotheses', count: hypotheses.length },
              { key: 'attack-paths' as const, label: 'Attack Paths', count: attackPaths.length },
              { key: 'logs' as const, label: 'Logs', count: logs.length },
              { key: 'chat' as const, label: 'AI Chat', count: chatMessages.length },
              { key: 'report' as const, label: 'Report', count: reportId ? 1 : 0 },
            ]).map(tab => (
              <button key={tab.key} onClick={() => setActiveTab(tab.key)}
                className={`px-4 py-3 text-[12px] font-semibold uppercase tracking-wider border-b-2 transition-all ${activeTab === tab.key ? 'border-cyber-500 text-cyber-400' : 'border-transparent text-gray-600 hover:text-gray-400'}`}>
                {tab.label}
                {tab.count > 0 && <span className="ml-1.5 text-[10px] text-gray-600">({tab.count})</span>}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="metric-card text-center py-4"><p className="text-2xl font-bold text-cyber-400">{assets.length}</p><p className="text-[11px] text-gray-500 uppercase tracking-wider mt-1">Assets</p></div>
            <div className="metric-card text-center py-4"><p className="text-2xl font-bold text-purple-400">{hypotheses.length}</p><p className="text-[11px] text-gray-500 uppercase tracking-wider mt-1">Hypotheses</p></div>
            <div className="metric-card text-center py-4"><p className="text-2xl font-bold text-orange-400">{attackPaths.length}</p><p className="text-[11px] text-gray-500 uppercase tracking-wider mt-1">Attack Paths</p></div>
            <div className="metric-card text-center py-4"><p className="text-2xl font-bold text-emerald-400">{hypotheses.filter(h => h.status === 'CONFIRMED').length}</p><p className="text-[11px] text-gray-500 uppercase tracking-wider mt-1">Confirmed</p></div>
          </div>

          {activeTab === 'findings' && (() => {
            const findingItems = findings;
            const filteredFindings = findingItems
              .filter((f: Finding) => severityFilter === 'ALL' || f.severity === severityFilter)
              .filter((f: Finding) => categoryFilter === 'ALL' || (f as any).category === categoryFilter)
              .sort((a: Finding, b: Finding) => {
                if (sortBy === 'severity') {
                  const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
                  return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
                }
                return (a.title || '').localeCompare(b.title || '');
              });
            const paginatedFindings = filteredFindings.slice(
              (findingPage - 1) * FINDINGS_PER_PAGE,
              findingPage * FINDINGS_PER_PAGE
            );
            const totalPages = Math.ceil(filteredFindings.length / FINDINGS_PER_PAGE);
            return (
              <div className="card p-5">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium text-gray-300">
                    {filteredFindings.length} finding{filteredFindings.length !== 1 ? 's' : ''}
                    {severityFilter !== 'ALL' && ` (${severityFilter})`}
                    {categoryFilter !== 'ALL' && ` in ${categoryFilter}`}
                  </h3>
                </div>
                <div className="flex flex-wrap gap-3 mb-4">
                  <select
                    value={severityFilter}
                    onChange={(e) => { setSeverityFilter(e.target.value); setFindingPage(1); }}
                    className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>

                  <select
                    value={categoryFilter}
                    onChange={(e) => { setCategoryFilter(e.target.value); setFindingPage(1); }}
                    className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm"
                  >
                    <option value="ALL">All Categories</option>
                    {[...new Set(findingItems.map((f: any) => f.category).filter(Boolean))].map((cat: string) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>

                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as 'severity' | 'title')}
                    className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm"
                  >
                    <option value="severity">Sort by Severity</option>
                    <option value="title">Sort by Title</option>
                  </select>
                </div>

                {filteredFindings.length === 0 ? (
                  <p className="text-gray-600 text-sm text-center py-6">No findings match your filters</p>
                ) : (
                  <div className="space-y-2">
                    {paginatedFindings.map((f: Finding) => {
                      const cvssMatch = f.description?.match(/CVSS[:\s]+(\d+\.?\d*)/i) || f.evidence?.match(/CVSS[:\s]+(\d+\.?\d*)/i);
                      const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : null;
                      const cveIdMatch = f.title?.match(/(CVE-\d{4}-\d+)/) || f.evidence?.match(/(CVE-\d{4}-\d+)/);
                      const cveId = cveIdMatch ? cveIdMatch[1] : null;
                      return (
                        <div key={f.id} className="p-4 rounded-lg bg-dark-800/50 border border-white/[0.03]">
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-white">{f.title}</span>
                              {cvss !== null && (
                                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${cvss >= 9.0 ? 'bg-red-500/20 text-red-400' : cvss >= 7.0 ? 'bg-orange-500/20 text-orange-400' : cvss >= 4.0 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-500/20 text-gray-400'}`}>
                                  CVSS {cvss}
                                </span>
                              )}
                            </div>
                            <span className={sevBadge(f.severity)}>{f.severity}</span>
                          </div>
                          <p className="text-xs text-gray-500 whitespace-pre-line">{f.description}</p>
                          {f.evidence && (() => {
                            const ev = f.evidence;
                            const isHttpProof = ev.includes('>> REQUEST') || ev.includes('PROOF OF VULNERABILITY');
                            const isCommandProof = ev.includes('COMMAND:') || ev.includes('=== PAYLOAD ===');
                            const isChainProof = ev.includes('=== CHAIN STEP');
                            const isUnverified = ev.includes('UNTESTED') || ev.includes('NOT TESTED') || ev.includes('NOT VERIFIED');
                            return (
                              <details className="mt-2" open={f.severity === 'CRITICAL' || f.severity === 'HIGH'}>
                                <summary className={`text-[10px] cursor-pointer hover:text-gray-400 ${isUnverified ? 'text-yellow-600' : 'text-gray-600'}`}>
                                  {isUnverified ? 'Show evidence (unverified)' : isHttpProof ? 'Show HTTP proof' : isCommandProof ? 'Show command proof' : isChainProof ? 'Show chain evidence' : 'Show evidence'}
                                </summary>
                                <div className={`text-[10px] p-2 rounded mt-1 overflow-x-auto font-mono max-h-64 overflow-y-auto ${isUnverified ? 'text-yellow-500 bg-yellow-500/5 border border-yellow-500/20' : 'text-gray-500 bg-dark-900/50'}`}>
                                  {ev.split('\n').map((line, i) => {
                                    if (line.startsWith('>> REQUEST') || line.startsWith('<< RESPONSE') || line.startsWith('=== PROOF') || line.startsWith('=== END')) {
                                      return <div key={i} className="text-cyber-400 font-bold mt-1">{line}</div>;
                                    }
                                    if (line.startsWith('COMMAND:') || line.startsWith('PAYLOAD:') || line.startsWith('=== PAYLOAD')) {
                                      return <div key={i} className="text-red-400">{line}</div>;
                                    }
                                    if (line.startsWith('EXIT CODE:') || line.startsWith('RESULT:') || line.startsWith('STATUS:')) {
                                      return <div key={i} className="text-yellow-400">{line}</div>;
                                    }
                                    if (line.startsWith('=== CHAIN STEP')) {
                                      return <div key={i} className="text-orange-400 font-bold mt-1">{line}</div>;
                                    }
                                    if (line.startsWith('GET ') || line.startsWith('POST ')) {
                                      return <div key={i} className="text-blue-400">{line}</div>;
                                    }
                                    if (line.match(/^\d{3}\s/) || line.includes('HTTP/')) {
                                      return <div key={i} className="text-green-400">{line}</div>;
                                    }
                                    return <div key={i}>{line}</div>;
                                  })}
                                </div>
                              </details>
                            );
                          })()}
                          {(() => {
                            let refs: string[] = [];
                            try {
                              if (f.references) {
                                refs = Array.isArray(f.references) ? f.references : typeof f.references === 'string' ? JSON.parse(f.references) : [];
                              }
                            } catch { refs = []; }
                            return refs.length > 0 ? (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {refs.slice(0, 3).map((ref, i) => (
                                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-[10px] text-cyber-400 hover:text-cyber-300 bg-cyber-500/10 px-1.5 py-0.5 rounded">
                                    {ref.includes('nvd.nist.gov') ? 'NVD' : ref.includes('vulners.com') ? 'Vulners' : ref.includes('attack.mitre.org') ? 'MITRE' : `Ref ${i+1}`}
                                  </a>
                                ))}
                              </div>
                            ) : null;
                          })()}
                          {f.remediation && <p className="text-xs text-cyber-400 mt-2">Remediation: {f.remediation}</p>}
                        </div>
                      );
                    })}
                  </div>
                )}

                {totalPages > 1 && (
                  <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-700/50">
                    <span className="text-xs text-gray-400">
                      Showing {((findingPage - 1) * FINDINGS_PER_PAGE) + 1}-{Math.min(findingPage * FINDINGS_PER_PAGE, filteredFindings.length)} of {filteredFindings.length}
                    </span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setFindingPage(p => Math.max(1, p - 1))}
                        disabled={findingPage === 1}
                        className="px-3 py-1 bg-gray-700/50 rounded text-xs disabled:opacity-30"
                      >
                        Prev
                      </button>
                      <span className="text-xs text-gray-400 px-2">{findingPage}/{totalPages}</span>
                      <button
                        onClick={() => setFindingPage(p => Math.min(totalPages, p + 1))}
                        disabled={findingPage === totalPages}
                        className="px-3 py-1 bg-gray-700/50 rounded text-xs disabled:opacity-30"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {activeTab === 'assets' && (
            <div className="card p-5">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Discovered Assets</h3>
              <div className="space-y-1.5">
                {assets.length === 0 && <p className="text-gray-600 text-sm text-center py-6">No assets discovered</p>}
                {assets.slice(0, 30).map(a => (
                  <div key={a.id} className="flex items-center justify-between py-2 px-3 rounded-lg bg-dark-800/50">
                    <div className="flex items-center gap-3">
                      <span className="badge-info text-[10px]">{a.type}</span>
                      <span className="text-sm font-mono text-white">{a.value}</span>
                    </div>
                    {a.metadata && typeof a.metadata === 'object' && (
                      <span className="text-xs text-gray-600 font-mono">
                        {Object.entries(a.metadata).filter(([k]) => k !== 'primary').slice(0, 2).map(([k, v]) => `${k}: ${String(v)}`).join(' | ')}
                      </span>
                    )}
                  </div>
                ))}
                {assets.length > 30 && <p className="text-xs text-gray-600 text-center pt-2">+{assets.length - 30} more</p>}
              </div>
            </div>
          )}

          {activeTab === 'attack-paths' && (
            <div className="card p-5">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Attack Paths</h3>
              {attackPaths.length === 0 ? <p className="text-gray-600 text-sm text-center py-6">No attack paths discovered</p> : (
                <div className="space-y-4">
                  {attackPaths.map(p => {
                    const pct = Math.min(100, (p.riskScore || 0) * 10);
                    const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#eab308' : '#22c55e';
                    const textColor = pct >= 70 ? 'text-red-400' : pct >= 40 ? 'text-yellow-400' : 'text-emerald-400';
                    const nodes = p.nodes || [];
                    const edges = p.edges || [];
                    return (
                      <div key={p.id} className="p-4 rounded-lg bg-dark-800/50 border border-white/[0.03]">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-white">{p.title}</span>
                          <span className={`text-sm font-bold ${textColor}`}>{p.riskScore}/10</span>
                        </div>
                        <div className="flex flex-wrap gap-2 mb-2">
                          {p.impactLevel && (
                            <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded ${p.impactLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : p.impactLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                              {p.impactLevel}
                            </span>
                          )}
                          {p.entryPoint && <span className="text-[10px] text-gray-500">Entry: {p.entryPoint}</span>}
                          {p.impactPoint && <span className="text-[10px] text-gray-500">Impact: {p.impactPoint}</span>}
                          {p.confidence && <span className="text-[10px] text-cyber-400">Confidence: {(p.confidence * 100).toFixed(0)}%</span>}
                        </div>
                        {p.description && <p className="text-xs text-gray-500 mb-3">{p.description}</p>}

                        {/* Attack Chain Visualization */}
                        {nodes.length > 0 && (
                          <div className="mt-3 space-y-1">
                            <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-2">Attack Chain</p>
                            <div className="flex flex-wrap items-center gap-1">
                              {nodes.map((node: AttackPathNode, idx: number) => {
                                const nodeColor = node.type === 'asset' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                                  : node.type === 'vulnerability' ? 'bg-red-500/20 text-red-400 border-red-500/30'
                                  : node.type === 'credential' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                                  : node.type === 'impact' ? 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                                  : 'bg-gray-500/20 text-gray-400 border-gray-500/30';
                                const mitre = node.metadata?.mitreTechnique;
                                return (
                                  <div key={node.id} className="flex items-center gap-1">
                                    <div className={`px-2 py-1 rounded border text-[10px] font-medium ${nodeColor}`}>
                                      <span className="uppercase opacity-60">{node.type}: </span>
                                      {node.label?.slice(0, 60)}
                                      {!!mitre && <span className="ml-1 text-cyber-400">[{String(mitre)}]</span>}
                                    </div>
                                    {idx < nodes.length - 1 && <span className="text-gray-600 text-xs">{'\u2192'}</span>}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {/* Node Details */}
                        {nodes.some((n: AttackPathNode) => n.evidence) && (
                          <div className="mt-3 space-y-1">
                            <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">Step Details</p>
                            {nodes.filter((n: AttackPathNode) => n.evidence).map((node: AttackPathNode) => (
                              <div key={node.id} className="bg-dark-950 rounded p-2">
                                <span className="text-[10px] font-semibold text-gray-400">{node.type.toUpperCase()}: {node.label?.slice(0, 50)}</span>
                                <p className="text-[11px] text-gray-500 mt-1 whitespace-pre-wrap">{node.evidence?.slice(0, 300)}</p>
                                {!!node.metadata?.findingSeverity && <span className={`text-[10px] ml-2 ${String(node.metadata.findingSeverity) === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'}`}>{String(node.metadata.findingSeverity)}</span>}
                              </div>
                            ))}
                          </div>
                        )}

                        <div className="w-full h-1.5 bg-dark-700 rounded-full overflow-hidden mt-3">
                          <div className="h-full rounded-full" style={{ width: pct + '%', backgroundColor: color }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'hypotheses' && (
            <div className="card p-5">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">AI Hypotheses</h3>
              <div className="space-y-3">
                {hypotheses.map(h => (
                  <div key={h.id} className="p-4 rounded-lg bg-dark-800/50 border border-white/[0.03]">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={sevBadge(h.status) || 'badge-info'}>{h.status}</span>
                        <span className="text-sm text-white">{h.hypothesis}</span>
                      </div>
                      <span className="text-xs font-bold text-cyber-400">{(h.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <p className="text-xs text-gray-500 mb-2">{h.reasoning}</p>
                    {h.testResult && <div className="bg-dark-950 rounded p-2 mt-2"><p className="text-[10px] text-gray-600 uppercase mb-1">Result</p><p className="text-xs text-gray-300">{h.testResult}</p></div>}
                    {h.evidence && <pre className="text-[11px] text-gray-400 font-mono bg-dark-950 rounded p-2 mt-2 whitespace-pre-wrap">{h.evidence}</pre>}
                  </div>
                ))}
                {hypotheses.length === 0 && <p className="text-gray-600 text-sm text-center py-6">No hypotheses generated</p>}
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="card p-4">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">Live Output</h3>
              <div className="bg-dark-950 rounded-lg p-3 h-64 overflow-y-auto font-mono text-xs space-y-0.5">
                {logs.map((l, i) => {
                  const isAI = l.msg.startsWith('[AI]');
                  const isInsight = l.msg.startsWith('[AI Insight]');
                  const isDone = l.msg.startsWith('[Done]');
                  return (
                    <div key={i} className={`flex gap-2 ${l.type === 'error' ? 'text-red-400' : l.type === 'success' || isDone ? 'text-emerald-400' : isInsight ? 'text-cyan-400 font-medium' : isAI ? 'text-cyber-400' : 'text-gray-500'}`}>
                      <span className="text-gray-700 flex-shrink-0">{l.time}</span>
                      <span>{l.msg}</span>
                    </div>
                  );
                })}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}

          {activeTab === 'chat' && (
            <div className="card p-4">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-3">AI Pentest Assistant</h3>
              <p className="text-xs text-gray-600 mb-4">Ask the AI about findings, attack paths, remediation, or to investigate deeper.</p>
              <div className="bg-dark-950 rounded-lg p-3 h-80 overflow-y-auto space-y-3 mb-3">
                {chatMessages.length === 0 && (
                  <div className="text-center py-10">
                    <p className="text-gray-600 text-sm">Ask anything about this assessment</p>
                    <div className="flex flex-wrap gap-2 justify-center mt-4">
                      {['Explain the top 3 critical findings', 'What attack paths are most dangerous?', 'How should I remediate these issues?'].map(q => (
                        <button key={q} onClick={() => { setChatInput(q); }}
                          className="text-[11px] text-cyber-400 border border-cyber-500/20 rounded-full px-3 py-1.5 hover:bg-cyber-500/10 transition-colors">
                          {q}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {chatMessages.map((m, i) => (
                  <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[80%] rounded-lg px-4 py-2.5 text-sm ${m.role === 'user' ? 'bg-cyber-500/10 border border-cyber-500/20 text-white' : 'bg-dark-800 border border-white/5 text-gray-300'}`}>
                      <pre className="whitespace-pre-wrap font-sans text-[13px] leading-relaxed">{m.content}</pre>
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-dark-800 border border-white/5 rounded-lg px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                        <div className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                        <div className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>
              <form onSubmit={(e) => { e.preventDefault(); sendChat(); }} className="flex gap-2">
                <input className="input flex-1" value={chatInput} onChange={e => setChatInput(e.target.value)}
                  placeholder="Ask about findings, attack paths, remediation..." disabled={chatLoading} />
                <button type="submit" className="btn-primary px-6" disabled={chatLoading || !chatInput.trim()}>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
                  </svg>
                </button>
              </form>
            </div>
          )}

          {activeTab === 'report' && (
            <div className="card p-6">
              <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-4">Security Report</h3>
              {reportId ? (
                <div className="space-y-4">
                  <div className="bg-dark-800/50 rounded-lg p-5 border border-white/[0.03]">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                        <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                        </svg>
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-white">PDF Report Ready</p>
                        <p className="text-xs text-gray-500">Full security assessment with executive summary, findings, and remediation plan</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-3 mb-4">
                      <div className="text-center"><p className="text-lg font-bold text-red-400">{findings.filter(f => f.severity === 'CRITICAL').length}</p><p className="text-[10px] text-gray-500">Critical</p></div>
                      <div className="text-center"><p className="text-lg font-bold text-orange-400">{findings.filter(f => f.severity === 'HIGH').length}</p><p className="text-[10px] text-gray-500">High</p></div>
                      <div className="text-center"><p className="text-lg font-bold text-yellow-400">{findings.filter(f => f.severity === 'MEDIUM').length}</p><p className="text-[10px] text-gray-500">Medium</p></div>
                    </div>
                    <button onClick={downloadReport} disabled={reportLoading} className="btn-primary w-full flex items-center justify-center gap-2 py-3">
                      {reportLoading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : (
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                        </svg>
                      )}
                      Download PDF Report
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-dark-800 border border-white/5 flex items-center justify-center">
                    <svg className="w-6 h-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                    </svg>
                  </div>
                  <p className="text-gray-500 text-sm mb-4">
                    {phase === 'scanning' ? 'Report will be generated when the scan completes' : 'No report available yet'}
                  </p>
                  {phase === 'scanning' && (
                    <div className="flex items-center justify-center gap-2 text-xs text-gray-600">
                      <div className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-pulse" />
                      Scan in progress...
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {phase === 'complete' && (
            <div className="flex gap-3 pt-2">
              {reportId && (
                <button onClick={downloadReport} disabled={reportLoading} className="btn-secondary flex-1 flex items-center justify-center gap-2">
                  {reportLoading ? <div className="w-4 h-4 border-2 border-gray-500/30 border-t-gray-500 rounded-full animate-spin" /> : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                    </svg>
                  )}
                  Download Report
                </button>
              )}
              <button onClick={() => navigate('/dashboard')} className="btn-secondary flex-1">Dashboard</button>
              <button onClick={() => { setPhase('idle'); setDomain(''); navigate('/scan', { replace: true }); }} className="btn-primary flex-1">New Scan</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

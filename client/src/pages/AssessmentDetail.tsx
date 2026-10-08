import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../lib/api';

interface Finding {
  id: string;
  title: string;
  severity: string;
  description: string;
  evidence?: string;
  remediation?: string;
}

interface Assessment {
  id: string;
  domain: string;
  status: string;
  score: number | null;
  findingsCount: number;
  createdAt: string;
  findings?: Finding[];
}

const severityColors: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  INFO: 'badge-info',
};

export default function AssessmentDetail() {
  const { id } = useParams();
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => { load(); }, [id]);

  async function load() {
    try {
      const res = await api.get('/assessments/' + id);
      setAssessment(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
      </div>
    );
  }

  if (!assessment) {
    return (
      <div className="text-center py-16">
        <p className="text-gray-500">Assessment not found</p>
        <Link to="/dashboard" className="text-cyber-500 text-sm mt-2 inline-block">Back to dashboard</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <Link to="/dashboard" className="text-xs text-gray-600 hover:text-gray-400 transition-colors mb-2 inline-flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5"/></svg>
            Dashboard
          </Link>
          <h1 className="text-2xl font-bold text-white tracking-tight mt-1">{assessment.domain}</h1>
          <p className="text-gray-500 text-sm mt-1">{new Date(assessment.createdAt).toLocaleDateString()}</p>
        </div>
        <div className="flex items-center gap-4">
          {assessment.score != null && (
            <div className="metric-card px-5 py-3 text-center">
              <p className="text-3xl font-bold text-white">{assessment.score}</p>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Score</p>
            </div>
          )}
          <span className={'text-xs font-semibold px-3 py-1 rounded-full border ' + (
            assessment.status === 'COMPLETED' ? 'badge-success' :
            assessment.status === 'RUNNING' ? 'badge-info' :
            assessment.status === 'FAILED' ? 'badge-critical' :
            'badge-medium'
          )}>
            {assessment.status}
          </span>
        </div>
      </div>
      <div className="glow-line" />

      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Findings ({assessment.findingsCount})</h2>
        {!assessment.findings || assessment.findings.length === 0 ? (
          <div className="card p-10 text-center">
            <p className="text-gray-500 text-sm">No findings yet</p>
          </div>
        ) : (
          <div className="space-y-2">
            {assessment.findings.map((f) => (
              <div key={f.id} className="card p-4 cursor-pointer hover:border-dark-600 transition-all" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={severityColors[f.severity] || 'badge-info'}>{f.severity}</span>
                    <span className="text-sm font-medium text-white truncate">{f.title}</span>
                  </div>
                  <svg className={'w-4 h-4 text-gray-600 transition-transform ' + (expanded === f.id ? 'rotate-180' : '')} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5"/>
                  </svg>
                </div>
                {expanded === f.id && (
                  <div className="mt-3 pt-3 border-t border-dark-700/50 space-y-3">
                    <p className="text-sm text-gray-400 leading-relaxed">{f.description}</p>
                    {f.evidence && (
                      <div>
                        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Evidence</p>
                        <div className="text-xs text-gray-400 bg-dark-800 p-3 rounded-lg overflow-x-auto font-mono max-h-64 overflow-y-auto">
                          {f.evidence.split('\n').map((line, i) => {
                            if (line.startsWith('>> REQUEST') || line.startsWith('<< RESPONSE') || line.startsWith('=== PROOF') || line.startsWith('=== END')) {
                              return <div key={i} className="text-cyber-400 font-bold mt-1">{line}</div>;
                            }
                            if (line.startsWith('COMMAND:') || line.startsWith('PAYLOAD:') || line.startsWith('=== PAYLOAD')) {
                              return <div key={i} className="text-red-400">{line}</div>;
                            }
                            if (line.startsWith('EXIT CODE:') || line.startsWith('RESULT:') || line.startsWith('STATUS:')) {
                              return <div key={i} className="text-yellow-400">{line}</div>;
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
                      </div>
                    )}
                    {f.remediation && (
                      <div>
                        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Remediation</p>
                        <p className="text-sm text-gray-400">{f.remediation}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

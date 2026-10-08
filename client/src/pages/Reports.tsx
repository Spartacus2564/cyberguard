import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';

interface Report {
  id: string;
  title: string;
  format: string;
  status: string;
  createdAt: string;
  assessment: { id: string; domain: string; status: string };
}

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => { load(); }, []);

  function load() {
    api.get('/reports').then(r => {
      const data = r.data;
      const list = data.reports || data.data || (Array.isArray(data) ? data : []);
      list.sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      setReports(list);
    }).catch(() => setReports([])).finally(() => setLoading(false));
  }

  async function generateReport(assessmentId: string) {
    setGenerating(assessmentId);
    try {
      await api.post('/reports/generate/' + assessmentId);
      load();
    } catch (e: any) {
      alert(e.response?.data?.message || 'Failed to generate report');
    } finally {
      setGenerating(null);
    }
  }

  async function downloadReport(reportId: string, domain: string) {
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
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Reports</h1>
        <p className="text-gray-500 text-sm mt-1">Export assessment findings as PDF reports</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-40"><div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" /></div>
      ) : reports.length === 0 ? (
        <div className="card p-16 text-center">
          <svg className="w-12 h-12 text-gray-700 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1">
            <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
          </svg>
          <p className="text-gray-500 mb-4">No reports yet. Complete a scan to generate a report.</p>
          <button onClick={() => navigate('/scan')} className="btn-primary">Start a Scan</button>
        </div>
      ) : (
        <div className="space-y-1.5">
          {reports.map(r => (
            <div key={r.id} className="card p-4 flex items-center justify-between">
              <div className="flex items-center gap-4 min-w-0">
                <div className="w-10 h-10 rounded-lg bg-dark-800 flex items-center justify-center flex-shrink-0">
                  <svg className="w-5 h-5 text-cyber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                  </svg>
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white truncate">{r.title || r.assessment?.domain || 'Report'}</p>
                  <p className="text-xs text-gray-600">{r.assessment?.domain} | {(r.format || 'pdf').toUpperCase()} | {new Date(r.createdAt).toLocaleDateString()}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <span className="badge-success">{r.status}</span>
                <button onClick={() => downloadReport(r.id, r.assessment?.domain || 'report')}
                  className="btn-ghost text-xs flex items-center gap-1.5">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                  </svg>
                  Download
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

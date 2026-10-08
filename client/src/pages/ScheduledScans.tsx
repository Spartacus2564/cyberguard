import { useState, useEffect } from 'react';
import api from '../lib/api';

interface Schedule {
  id: string;
  domain: string;
  cronExpression: string;
  enabled: boolean;
  nextRun?: string;
  lastRun?: string;
}

export default function ScheduledScans() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { load(); }, []);

  async function load() {
    try {
      const res = await api.get('/scheduled-scans');
      setSchedules(res.data.schedules || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Schedules</h1>
          <p className="text-gray-500 text-sm mt-1">Automated scan schedules</p>
        </div>
        <button className="btn-primary text-sm">+ New Schedule</button>
      </div>
      <div className="glow-line" />

      {loading ? (
        <div className="flex items-center justify-center h-40">
          <div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
        </div>
      ) : schedules.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-gray-500">No scheduled scans configured</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-700/50">
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Domain</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Schedule</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Status</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Next Run</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/30">
              {schedules.map((s) => (
                <tr key={s.id} className="hover:bg-dark-800/50 transition-colors">
                  <td className="px-5 py-3 text-sm font-medium text-white">{s.domain}</td>
                  <td className="px-5 py-3 text-sm text-gray-400 font-mono">{s.cronExpression}</td>
                  <td className="px-5 py-3">{s.enabled ? <span className="badge-success">Enabled</span> : <span className="badge-medium">Disabled</span>}</td>
                  <td className="px-5 py-3 text-sm text-gray-500">{s.nextRun ? new Date(s.nextRun).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

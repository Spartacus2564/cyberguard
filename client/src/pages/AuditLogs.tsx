import { useState, useEffect } from 'react';
import api from '../lib/api';

interface AuditEntry {
  id: string;
  action: string;
  resource: string;
  details?: string;
  createdAt: string;
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { load(); }, []);

  async function load() {
    try {
      const res = await api.get('/audit-logs');
      setLogs(res.data.logs || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Audit Log</h1>
        <p className="text-gray-500 text-sm mt-1">Activity and event history</p>
      </div>
      <div className="glow-line" />

      {loading ? (
        <div className="flex items-center justify-center h-40">
          <div className="w-8 h-8 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
        </div>
      ) : logs.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-gray-500">No audit logs yet</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-700/50">
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Action</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Resource</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Details</th>
                <th className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-5 py-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/30">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-dark-800/50 transition-colors">
                  <td className="px-5 py-3"><span className="badge-info">{log.action}</span></td>
                  <td className="px-5 py-3 text-sm text-white font-mono">{log.resource}</td>
                  <td className="px-5 py-3 text-sm text-gray-500 truncate max-w-xs">{log.details || '-'}</td>
                  <td className="px-5 py-3 text-sm text-gray-500">{new Date(log.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

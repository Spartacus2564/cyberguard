import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';

export default function NewAssessment() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await api.post('/assessments', { domain: domain.trim() });
      navigate('/assessments/' + res.data.id);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create assessment');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-lg mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">New Scan</h1>
        <p className="text-gray-500 text-sm mt-1">Start a security assessment against a target domain</p>
      </div>
      <div className="glow-line" />

      <form onSubmit={handleSubmit} className="card-glow p-6 space-y-5">
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-2.5 rounded-lg">{error}</div>
        )}
        <div>
          <label className="block text-xs font-semibold text-gray-400 mb-1.5">Target Domain</label>
          <input
            className="input font-mono"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            required
          />
          <p className="text-xs text-gray-600 mt-2">Enter the root domain to assess. All scans are non-destructive and passive by default.</p>
        </div>
        <button type="submit" disabled={loading} className="btn-primary w-full text-sm">
          {loading ? 'Creating...' : 'Start Assessment'}
        </button>
      </form>
    </div>
  );
}

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth';

export default function Register() {
  const [form, setForm] = useState({ firstName: '', lastName: '', email: '', password: '', confirmPassword: '', organizationName: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setLoading(true);
    try {
      await register(form);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-950 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyber-500/10 border border-cyber-500/20 mb-4">
            <svg className="w-7 h-7 text-cyber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Create Account</h1>
          <p className="text-gray-600 text-sm mt-1">Join CyberGuard to secure your assets</p>
        </div>

        <form onSubmit={handleSubmit} className="card-glow p-6 space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-2.5 rounded-lg">
              {error}
            </div>
          )}
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1.5">Organization</label>
            <input className="input" value={form.organizationName} onChange={(e) => setForm({...form, organizationName: e.target.value})} placeholder="Acme Corp" required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1.5">First Name</label>
              <input className="input" value={form.firstName} onChange={(e) => setForm({...form, firstName: e.target.value})} required />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-400 mb-1.5">Last Name</label>
              <input className="input" value={form.lastName} onChange={(e) => setForm({...form, lastName: e.target.value})} required />
            </div>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1.5">Email</label>
            <input type="email" className="input" value={form.email} onChange={(e) => setForm({...form, email: e.target.value})} required />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1.5">Password</label>
            <input type="password" className="input" value={form.password} onChange={(e) => setForm({...form, password: e.target.value})} required />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1.5">Confirm Password</label>
            <input type="password" className="input" value={form.confirmPassword} onChange={(e) => setForm({...form, confirmPassword: e.target.value})} required />
          </div>
          <button type="submit" disabled={loading} className="btn-primary w-full text-sm">
            {loading ? 'Creating...' : 'Create Account'}
          </button>
          <p className="text-center text-xs text-gray-600">
            Already have an account? <Link to="/login" className="text-cyber-500 hover:text-cyber-400">Sign in</Link>
          </p>
        </form>
      </div>
    </div>
  );
}

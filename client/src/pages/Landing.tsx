import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="min-h-screen bg-dark-950">
      {/* Nav */}
      <nav className="border-b border-dark-700/50 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <svg className="w-6 h-6 text-cyber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            <span className="text-base font-bold text-white tracking-tight">CyberGuard</span>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/login" className="btn-ghost text-sm">Sign in</Link>
            <Link to="/register" className="btn-primary text-sm">Get Started</Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-6 pt-24 pb-20 text-center">
        <div className="inline-flex items-center gap-2 bg-cyber-500/10 border border-cyber-500/20 text-cyber-400 text-xs font-semibold px-4 py-1.5 rounded-full mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-500 animate-pulse" />
          Autonomous Security Validation
        </div>
        <h1 className="text-5xl md:text-6xl font-bold text-white tracking-tight leading-[1.1] mb-6">
          Find vulnerabilities<br />
          <span className="text-gradient">before attackers do</span>
        </h1>
        <p className="text-lg text-gray-500 max-w-xl mx-auto mb-10 leading-relaxed">
          CyberGuard autonomously discovers, validates, and reports security weaknesses across your entire attack surface using AI-driven reasoning.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link to="/register" className="btn-primary text-base px-8 py-3">Start Free Trial</Link>
          <Link to="/login" className="btn-secondary text-base px-8 py-3">Sign in</Link>
        </div>
      </section>

      <div className="glow-line" />

      {/* Features */}
      <section className="max-w-6xl mx-auto px-6 py-20">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            { title: 'Autonomous Discovery', desc: 'Automated reconnaissance and asset enumeration across your entire infrastructure.' },
            { title: 'AI Reasoning Engine', desc: 'Multi-cycle hypothesis testing that chains vulnerabilities into full attack paths.' },
            { title: 'Evidence & Reporting', desc: 'Every finding includes proof, severity, and remediation guidance with PDF exports.' },
          ].map((f) => (
            <div key={f.title} className="card-glow p-6">
              <h3 className="text-sm font-semibold text-white mb-2">{f.title}</h3>
              <p className="text-sm text-gray-500 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <div className="glow-line" />

      {/* Footer */}
      <footer className="max-w-6xl mx-auto px-6 py-8 text-center text-xs text-gray-600">
        CyberGuard - Autonomous Security Validation Platform
      </footer>
    </div>
  );
}

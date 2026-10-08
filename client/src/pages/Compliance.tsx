export default function Compliance() {
  const frameworks = [
    { name: 'OWASP Top 10', status: 'partial', findings: 7 },
    { name: 'NIST 800-53', status: 'not-started', findings: 0 },
    { name: 'PCI DSS', status: 'partial', findings: 4 },
    { name: 'SOC 2', status: 'not-started', findings: 0 },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Compliance</h1>
        <p className="text-gray-500 text-sm mt-1">Framework compliance tracking</p>
      </div>
      <div className="glow-line" />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {frameworks.map((fw) => (
          <div key={fw.name} className="card-glow p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white">{fw.name}</h3>
              <span className={fw.status === 'partial' ? 'badge-medium' : 'badge-info'}>
                {fw.status === 'partial' ? 'Partial' : 'Not Started'}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>{fw.findings} findings mapped</span>
              <span className="text-cyber-500 cursor-pointer hover:text-cyber-400">View details</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function CICD() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">CI/CD Integration</h1>
        <p className="text-gray-500 text-sm mt-1">Integrate CyberGuard into your pipeline</p>
      </div>
      <div className="glow-line" />

      <div className="card-glow p-6 space-y-4">
        <h3 className="text-sm font-semibold text-white">Quick Start</h3>
        <p className="text-sm text-gray-400 leading-relaxed">
          Use the CyberGuard CLI or API to trigger scans from your CI/CD pipeline. All scans are non-destructive and safe for production environments.
        </p>
        <div className="bg-dark-800 rounded-lg p-4 font-mono text-xs text-gray-400 overflow-x-auto">
          <p className="text-gray-600"># Example: trigger scan via API</p>
          <p className="text-cyber-400">curl -X POST https://api.cyberguard.dev/v1/assessments \</p>
          <p className="ml-4">-H "Authorization: Bearer $TOKEN" \</p>
          <p className="ml-4">-H "Content-Type: application/json" \</p>
          <p className="ml-4">-d {'{ "domain": "your-app.com" }'}</p>
        </div>
      </div>
    </div>
  );
}

const http = require('http');

const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0OTE1ZGQ2ZS1iNjBmLTRiOTQtYjRmMy03M2RhOTNlOTg3NTUiLCJlbWFpbCI6InRlc3RAZGVtby5pbyIsIm9yZ2FuaXphdGlvbklkIjoiNGJhZDY5MGMtNTY3MS00MzI2LTllZDEtZTIyZTA5M2JiYTQ2Iiwicm9sZSI6IkFETUlOIiwiaWF0IjoxNzg5NDk3NTk3LCJleHAiOjE3OTAxMDIzOTd9.tOW6Y68-SWirCyRldn_pCixlTPXWLP1cPte36Pt_6SA';

function api(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: 'localhost', port: 3001, path, method,
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  // Create fresh engagement
  console.log('Creating engagement...');
  const eng = await api('POST', '/api/engagements', {
    name: 'Tekup Student Scan v2',
    target: 'tekup-student.educated.tn',
    scopeRules: [{ type: 'allow', targetType: 'domain', value: 'tekup-student.educated.tn' }]
  });
  console.log('Engagement:', eng.id, eng.name);
  
  if (eng.id) {
    // Start scan with specific modules to test our fixes
    console.log('\nStarting scan...');
    const scan = await api('POST', `/api/engagements/${eng.id}/scan`, {
      modules: ['dns', 'tls', 'headers', 'webConfig', 'technology', 'portScan', 'osFingerprint', 'siteCrawl', 'smarterRecon', 'exploitation', 'activeVuln']
    });
    console.log('Scan:', JSON.stringify(scan));
    
    const assessmentId = scan.assessmentId;
    
    // Poll status
    console.log('\nPolling status...');
    for (let i = 0; i < 120; i++) {
      await new Promise(r => setTimeout(r, 10000));
      try {
        // Check assessment
        const assessResp = await api('GET', `/api/assessments/${assessmentId}`);
        const status = assessResp.status;
        const progress = assessResp.progress || 0;
        
        // Get recent logs
        const logsResp = await api('GET', `/api/engagements/${eng.id}/logs?limit=10`);
        const logList = Array.isArray(logsResp) ? logsResp : logsResp.logs || [];
        const lastLogs = logList.slice(-5);
        
        const now = new Date().toLocaleTimeString();
        console.log(`[${now}] Status: ${status} | Progress: ${progress}%`);
        for (const l of lastLogs) {
          console.log(`  [${l.level}] ${l.module}: ${(l.message || '').substring(0, 150)}`);
        }
        
        if (status === 'COMPLETED' || status === 'FAILED') {
          // Get findings via the scan results endpoint
          console.log('\n=== SCAN RESULTS ===');
          console.log('Status:', status);
          console.log('Progress:', progress);
          
          // Get all logs to see findings
          const allLogs = await api('GET', `/api/engagements/${eng.id}/logs?limit=200`);
          const allLogList = Array.isArray(allLogs) ? allLogs : allLogs.logs || [];
          const findLogs = allLogList.filter(l => l.level === 'vuln' || l.level === 'exploit');
          console.log('\nFindings from logs:', findLogs.length);
          for (const l of findLogs) {
            console.log(`  [${l.level}] ${l.module}: ${(l.message || '').substring(0, 300)}`);
          }
          
          // Count by module
          const byModule = {};
          for (const l of allLogList) {
            const m = l.module || 'unknown';
            if (!byModule[m]) byModule[m] = { info: 0, warn: 0, error: 0, done: 0, vuln: 0, exploit: 0 };
            byModule[m][l.level] = (byModule[m][l.level] || 0) + 1;
          }
          console.log('\n=== MODULE ACTIVITY ===');
          for (const [mod, counts] of Object.entries(byModule)) {
            console.log(`  ${mod}: info=${counts.info} done=${counts.done} vuln=${counts.vuln} exploit=${counts.exploit} error=${counts.error}`);
          }
          break;
        }
      } catch (e) {
        console.log(`Poll error: ${e.message}`);
      }
    }
  }
})();

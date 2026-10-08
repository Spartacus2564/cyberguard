import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl, fetchUrlFollowRedirects, buildProof, formatProofAsText, isLoginPage, isGenericPage, isHtmlContent } from './shared';
import { getAI } from '../../services/ai.service';

async function checkStatusCodeOnly(url: string, timeout = 5000): Promise<number> {
  try {
    const result = await fetchUrl(url, timeout);
    return result.statusCode;
  } catch {
    return 0;
  }
}

async function checkPathWithRedirect(url: string, timeout = 5000) {
  const rr = await fetchUrlFollowRedirects(url, timeout, 3);
  return { status: rr.finalStatus, body: rr.finalBody, headers: rr.finalHeaders, redirected: rr.isRedirect, chain: rr.chain, metaRedirect: rr.metaRedirect, isLogin: rr.isLogin, isGeneric: rr.isGeneric };
}

async function checkPath(url: string, timeout = 5000): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  try {
    const result = await fetchUrl(url, timeout);
    return { status: result.statusCode, body: result.body, headers: result.headers };
  } catch {
    return { status: 0, body: '', headers: {} };
  }
}

export async function runWebConfigScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let headers: http.IncomingHttpHeaders = {};
    let body = '';
    let statusCode = 0;

    try {
      const result = await fetchUrl(`https://${domain}`, 10000);
      headers = result.headers;
      body = result.body;
      statusCode = result.statusCode;
    } catch (e) {
      try {
        const result = await fetchUrl(`http://${domain}`, 10000);
        headers = result.headers;
        body = result.body;
        statusCode = result.statusCode;
      } catch (e2) {
        errors.push(`Could not fetch ${domain}: ${e2 instanceof Error ? e2.message : String(e2)}`);
      }
    }

    // === Sensitive File Exposure ===
    const sensitiveFiles = [
      { path: '/.env', name: '.env file', severity: Severity.CRITICAL, desc: 'Environment variables including secrets and API keys' },
      { path: '/.git/HEAD', name: 'Git repository', severity: Severity.CRITICAL, desc: 'Git repository exposed, may contain source code and secrets' },
      { path: '/.git/config', name: 'Git config', severity: Severity.CRITICAL, desc: 'Git configuration exposed' },
      { path: '/.gitignore', name: '.gitignore', severity: Severity.MEDIUM, desc: 'Git ignore rules exposed, may reveal hidden paths' },
      { path: '/wp-config.php.bak', name: 'WordPress config backup', severity: Severity.CRITICAL, desc: 'WordPress configuration backup may contain database credentials' },
      { path: '/composer.json', name: 'Composer config', severity: Severity.MEDIUM, desc: 'PHP dependency manager config may reveal dependencies' },
      { path: '/composer.lock', name: 'Composer lock', severity: Severity.LOW, desc: 'Exact dependency versions may help identify vulnerable packages' },
      { path: '/package.json', name: 'Node.js config', severity: Severity.MEDIUM, desc: 'Node.js package config may reveal dependencies and scripts' },
      { path: '/package-lock.json', name: 'Node.js lock', severity: Severity.LOW, desc: 'Exact dependency versions may help identify vulnerable packages' },
      { path: '/.htaccess', name: '.htaccess', severity: Severity.HIGH, desc: 'Apache configuration file may reveal access rules' },
      { path: '/web.config', name: 'IIS config', severity: Severity.HIGH, desc: 'IIS configuration may reveal server settings' },
      { path: '/config.php', name: 'PHP config', severity: Severity.CRITICAL, desc: 'PHP configuration may contain credentials' },
      { path: '/backup.sql', name: 'Database backup', severity: Severity.CRITICAL, desc: 'Database backup file exposed' },
      { path: '/dump.sql', name: 'Database dump', severity: Severity.CRITICAL, desc: 'Database dump file exposed' },
      { path: '/debug.log', name: 'Debug log', severity: Severity.HIGH, desc: 'Debug log may contain sensitive information' },
      { path: '/error_log', name: 'Error log', severity: Severity.HIGH, desc: 'Error log may contain sensitive information' },
      { path: '/phpinfo.php', name: 'PHP info', severity: Severity.HIGH, desc: 'PHP info page exposes server configuration' },
      { path: '/server-status', name: 'Apache status', severity: Severity.HIGH, desc: 'Apache server-status page exposed' },
      { path: '/server-info', name: 'Apache info', severity: Severity.HIGH, desc: 'Apache server-info page exposed' },
      { path: '/.DS_Store', name: 'macOS directory', severity: Severity.LOW, desc: 'macOS .DS_Store file may reveal directory structure' },
      { path: '/Thumbs.db', name: 'Windows thumbnail', severity: Severity.LOW, desc: 'Windows thumbnail cache may reveal file structure' },
      { path: '/crossdomain.xml', name: 'Flash crossdomain', severity: Severity.MEDIUM, desc: 'Flash crossdomain policy may be overly permissive' },
      { path: '/clientaccesspolicy.xml', name: 'Silverlight policy', severity: Severity.MEDIUM, desc: 'Silverlight cross-domain policy may be overly permissive' },
    ];

    const baseUrl = `https://${domain}`;
    for (const file of sensitiveFiles) {
      const result = await checkPathWithRedirect(`${baseUrl}${file.path}`, 5000);
      if (result.status === 200 && result.body.length > 0) {
        // If it redirected and the final destination is a login/generic page, skip (false positive)
        if (result.redirected && (result.isLogin || result.isGeneric)) continue;

        // Skip if response is HTML (likely a 404 page or login page)
        if (isHtmlContent(result.headers, result.body)) {
          if (isLoginPage(result.body) || isGenericPage(result.body)) continue;
          // If redirected to HTML, the original path likely doesn't exist
          if (result.redirected) continue;
          // For non-config files, HTML response = false positive
          const configPaths = ['/.env', '/.git/HEAD', '/.git/config', '/config.php', '/backup.sql', '/dump.sql'];
          if (!configPaths.includes(file.path)) continue;
        }

        // Additional verification for .git/HEAD
        if (file.path === '/.git/HEAD' && !result.body.includes('ref:')) continue;
        // Additional verification for .env
        if (file.path === '/.env' && !result.body.includes('=')) continue;
        // Additional verification for .git/config
        if (file.path === '/.git/config' && !result.body.includes('[core]') && !result.body.includes('[remote')) continue;
        // Additional verification for SQL dumps
        if ((file.path === '/backup.sql' || file.path === '/dump.sql') && !result.body.toLowerCase().includes('create table') && !result.body.toLowerCase().includes('insert into') && !result.body.toLowerCase().includes('drop table')) continue;
        // Additional verification for .htaccess
        if (file.path === '/.htaccess' && !result.body.toLowerCase().includes('rewrite') && !result.body.toLowerCase().includes('redirect') && !result.body.toLowerCase().includes('deny from')) continue;
        // Additional verification for web.config
        if (file.path === '/web.config' && !result.body.includes('<configuration') && !result.body.includes('<system.')) continue;

        const proof = buildProof('GET', `${baseUrl}${file.path}`, undefined, undefined, result.status, result.headers, result.body, result.chain, result.metaRedirect);
        findings.push(generateFinding(
          `${file.name} exposed`,
          `${file.name} was found accessible at ${file.path}. ${file.desc}.`,
          file.severity,
          'Web Configuration',
          domain,
          formatProofAsText(proof),
          `${file.desc}. This can leak sensitive information or credentials.`,
          `Remove or restrict access to ${file.path}`,
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
    }

    // === security.txt ===
    const secResult = await checkPath(`${baseUrl}/.well-known/security.txt`, 5000);
    if (secResult.status === 200) {
      findings.push(generateFinding(
        'security.txt present',
        'A security.txt file was found at the well-known location.',
        Severity.INFO,
        'Web Configuration',
        domain,
        '/.well-known/security.txt returned 200',
        'Positive: responsible disclosure policy is documented',
        'Ensure the security.txt contains valid contact and policy information',
        ['https://securitytxt.org/']
      ));
    }

    // === robots.txt Analysis ===
    const robotsResult = await checkPath(`${baseUrl}/robots.txt`, 5000);
    if (robotsResult.status === 200 && robotsResult.body.length > 0) {
      const disallowedPaths = robotsResult.body.match(/Disallow:\s*(.+)/gi);
      if (disallowedPaths && disallowedPaths.length > 0) {
        const paths = disallowedPaths.map(p => p.replace(/Disallow:\s*/i, '').trim()).filter(p => p);
        if (paths.length > 0) {
          findings.push(generateFinding(
            'robots.txt reveals hidden paths',
            `robots.txt contains ${paths.length} Disallow entries that may reveal sensitive paths.`,
            Severity.INFO,
            'Web Configuration',
            domain,
            `Disallowed paths: ${paths.slice(0, 10).join(', ')}${paths.length > 10 ? '...' : ''}`,
            'robots.txt is publicly readable and reveals paths the site owner wants hidden',
            'Consider that robots.txt does not provide security; sensitive paths should be access-controlled',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
          ));
        }
      }
    }

    // === Error Page Analysis ===
    try {
      const notFoundResult = await fetchUrl(`https://${domain}/cyberguard-test-404-${Date.now()}`, 5000);
      const errorBody = notFoundResult.body;
      const errorIndicators = [
        { pattern: /Apache\/[\d.]+/i, name: 'Apache version' },
        { pattern: /nginx\/[\d.]+/i, name: 'Nginx version' },
        { pattern: /Microsoft-IIS\/[\d.]+/i, name: 'IIS version' },
        { pattern: /PHP[\s\/][\d.]+/i, name: 'PHP version' },
        { pattern: /X-Powered-By:\s*[\w.]+/i, name: 'Technology header' },
        { pattern: /Server at [\w.]+ Port \d+/i, name: 'Apache default error' },
        { pattern: /<pre class="exception_value">/i, name: 'Python Django error' },
        { pattern: /Traceback \(most recent call last\)/i, name: 'Python traceback' },
        { pattern: /at line \d+/i, name: 'Stack trace line reference' },
        { pattern: /Fatal error:/i, name: 'PHP fatal error' },
        { pattern: /Warning:/i, name: 'PHP warning' },
      ];

      for (const indicator of errorIndicators) {
        if (indicator.pattern.test(errorBody)) {
          const proof = buildProof('GET', `https://${domain}/cyberguard-test-404`, undefined, undefined, notFoundResult.statusCode, notFoundResult.headers, errorBody);
          findings.push(generateFinding(
            'Error page reveals server information',
            `The 404 error page contains ${indicator.name} information.`,
            Severity.MEDIUM,
            'Web Configuration',
            domain,
            formatProofAsText(proof),
            'Error pages that reveal server information help attackers identify vulnerabilities',
            'Configure custom error pages that do not reveal server details',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
          ));
          break;
        }
      }
    } catch {}

    // === Technology Information in HTML Comments ===
    const commentPatterns = [
      /<!--[\s\S]*?(?:php|asp|jsp|powered by|framework|version|TODO|FIXME|HACK|XXX)[\s\S]*?-->/gi,
      /<!--\s*\$Id:/i,
      /<!--\s*(?:debug|todo|fixme|hack)/i,
    ];
    const exposedComments = body.match(/<!--[\s\S]*?-->/g) || [];
    const techComments = exposedComments.filter(c =>
      commentPatterns.some(p => p.test(c))
    );
    if (techComments.length > 0) {
      findings.push(generateFinding(
        'Technology information in HTML comments',
        'HTML comments contain server-side technology information.',
        Severity.INFO,
        'Web Configuration',
        domain,
        `Found ${techComments.length} comment(s) with technology hints`,
        'Attackers can identify the technology stack and look for specific vulnerabilities',
        'Remove technology-related information from HTML comments in production',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
      ));
    }

    // === Mixed Content Detection ===
    if (body.includes('http://') && body.includes('https://')) {
      const httpMatches = body.match(/src=["']http:\/\/[^"']+["']/gi) || [];
      const cssMatches = body.match(/href=["']http:\/\/[^"']+["']/gi) || [];
      if (httpMatches.length > 0 || cssMatches.length > 0) {
        findings.push(generateFinding(
          'Mixed content detected',
          `The HTTPS page contains ${httpMatches.length + cssMatches.length} HTTP resource reference(s).`,
          Severity.MEDIUM,
          'Web Configuration',
          domain,
          `HTTP resources: ${httpMatches.length} scripts, ${cssMatches.length} stylesheets`,
          'Mixed content allows man-in-the-middle attacks on HTTPS pages',
          'Update all resource references to use HTTPS',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    }

    // AI-enhanced config analysis
    try {
      const ai = getAI();
      const configs = sensitiveFiles.filter((f: any) => f.status === 200).map((f: any) => ({
        path: f.path,
        status: 200,
        contentType: 'application/octet-stream',
        snippet: f.desc || '',
      }));
      if (configs.length > 0) {
        const aiResult = await ai.analyzeWebConfig(configs, domain);
        if (aiResult.findings?.length) {
          for (const af of aiResult.findings) {
            findings.push(generateFinding(
              af.title || 'AI Config Finding',
              af.description || '',
              (af.severity || 'INFO') as Severity,
              'AI Analysis',
              domain,
              af.remediation || '',
              af.impact || '',
              af.remediation || '',
              [],
            ));
          }
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return {
      module: 'webConfig',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'webConfig',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

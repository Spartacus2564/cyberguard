import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl } from './shared';

export async function runTechnologyScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let headers: http.IncomingHttpHeaders = {};
    let body = '';

    try {
      const result = await fetchUrl(`https://${domain}`, 10000);
      headers = result.headers;
      body = result.body;
    } catch (e) {
      try {
        const result = await fetchUrl(`http://${domain}`, 10000);
        headers = result.headers;
        body = result.body;
      } catch (e2) {
        errors.push(`Could not fetch ${domain}: ${e2 instanceof Error ? e2.message : String(e2)}`);
      }
    }

    const detected: string[] = [];

    // Web server from Server header
    const rawServer = headers['server'];
    const server = Array.isArray(rawServer) ? rawServer[0] : rawServer;
    if (server) {
      detected.push(`Web server: ${server}`);
      // Check for version in server string
      if (/\d+\.\d+/.test(server)) {
        findings.push(
          generateFinding(
            'Technology version disclosure',
            'The web server header reveals a specific software version.',
            Severity.LOW,
            'Technology Detection',
            domain,
            `Server header: ${server}`,
            'Attackers can identify and target specific server version vulnerabilities',
            'Remove version information from the Server header',
            []
          )
        );
      }
    }

    // X-Powered-By
    const rawPoweredBy = headers['x-powered-by'];
    const poweredBy = Array.isArray(rawPoweredBy) ? rawPoweredBy[0] : rawPoweredBy;
    if (poweredBy) {
      detected.push(`Powered by: ${poweredBy}`);
      if (/\d+\.\d+/.test(poweredBy)) {
        findings.push(
          generateFinding(
            'Technology version disclosure',
            'The X-Powered-By header reveals specific technology and version.',
            Severity.LOW,
            'Technology Detection',
            domain,
            `X-Powered-By: ${poweredBy}`,
            'Attackers can identify and target specific version vulnerabilities',
            'Remove the X-Powered-By header',
            []
          )
        );
      }
    }

    // CDN detection
    const cdnIndicators: Record<string, string[]> = {
      'Cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
      'Akamai': ['x-akamai-transformed', 'akamai'],
      'Fastly': ['x-fastly-request-id', 'fastly'],
      'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
      'Incapsula': ['x-iinfo', 'incap_ses'],
    };
    for (const [cdn, indicators] of Object.entries(cdnIndicators)) {
      const allHeaders = Object.keys(headers).join(' ').toLowerCase();
      const headerValues = Object.values(headers).map(v => String(v)).join(' ').toLowerCase();
      if (indicators.some(ind => allHeaders.includes(ind) || headerValues.includes(ind))) {
        detected.push(`CDN: ${cdn}`);
      }
    }

    if (detected.length > 0) {
      findings.push(
        generateFinding(
          'Detected technologies',
          `The following technologies were detected from publicly visible indicators.`,
          Severity.INFO,
          'Technology Detection',
          domain,
          detected.join('; '),
          'Information for awareness; this is not a vulnerability',
          'Review whether exposed technology information should be reduced',
          []
        )
      );
    }

    // Meta generator tag
    const generatorMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    if (generatorMatch) {
      const generator = generatorMatch[1];
      findings.push(
        generateFinding(
          'Meta generator tag present',
          'The HTML contains a meta generator tag identifying the CMS or framework.',
          Severity.INFO,
          'Technology Detection',
          domain,
          `Generator: ${generator}`,
          'Identifies the CMS or framework used',
          'Remove the generator meta tag from production pages',
          []
        )
      );
    }

    // Framework signatures in HTML
    const frameworkPatterns: Array<{ name: string; pattern: RegExp }> = [
      { name: 'React', pattern: /__react|__NEXT_DATA__|react-root|react-app/i },
      { name: 'Next.js', pattern: /__next|_next\/static/i },
      { name: 'Nuxt.js', pattern: /__nuxt|_nuxt\/|nuxt\./i },
      { name: 'Vue.js', pattern: /__vue__|vue\.min\.js|v-cloak|vue-app/i },
      { name: 'Angular', pattern: /ng-version|angular\.min\.js|ng-app|ng-controller/i },
      { name: 'jQuery', pattern: /jquery\.min\.js|jquery-\d+\.\d+/i },
      { name: 'WordPress', pattern: /wp-content|wp-includes|wp-json/i },
      { name: 'Drupal', pattern: /drupal\.js|sites\/default\/files|drupal\.settings/i },
      { name: 'Joomla', pattern: /joomla!|media\/joomla/i },
      { name: 'Laravel', pattern: /laravel|csrf-token/i },
      { name: 'Rails', pattern: /_rails|csrf-param.*rails|authenticity_token/i },
      { name: 'Django', pattern: /csrfmiddlewaretoken|django/i },
      { name: 'PHP', pattern: /\.php[\s?"/]|php\.ini/i },
      { name: 'ASP.NET', pattern: /aspxerrorpath|__VIEWSTATE|asp\.net/i },
      { name: 'Ruby on Rails', pattern: /ruby|rails/i },
      { name: 'Bootstrap', pattern: /bootstrap\.min\.css|bootstrap\.min\.js/i },
      { name: 'Tailwind CSS', pattern: /tailwindcss|tailwind\.min\.css/i },
    ];

    const foundFrameworks: string[] = [];
    for (const { name, pattern } of frameworkPatterns) {
      if (pattern.test(body)) {
        foundFrameworks.push(name);
      }
    }
    if (foundFrameworks.length > 0) {
      findings.push(
        generateFinding(
          'Detected frontend frameworks/libraries',
          'The HTML response contains indicators of the following frameworks or libraries.',
          Severity.INFO,
          'Technology Detection',
          domain,
          foundFrameworks.join(', '),
          'Information for awareness; not a direct vulnerability',
          'Ensure all detected frameworks are kept up to date',
          []
        )
      );
    }

    // Script tags for JS frameworks
    const scriptSrcPattern = /<script[^>]+src=["']([^"']+)["']/gi;
    const scriptSrcs: string[] = [];
    let match;
    while ((match = scriptSrcPattern.exec(body)) !== null) {
      scriptSrcs.push(match[1]);
    }

    const cdnScriptIndicators: Record<string, string[]> = {
      'React CDN': ['unpkg.com/react', 'cdnjs.cloudflare.com/react'],
      'Vue CDN': ['unpkg.com/vue', 'cdnjs.cloudflare.com/vue'],
      'Angular CDN': ['unpkg.com/angular', 'cdnjs.cloudflare.com/angular'],
      'jQuery CDN': ['code.jquery.com/jquery', 'cdnjs.cloudflare.com/ajax/libs/jquery'],
      'Bootstrap CDN': ['cdnjs.cloudflare.com/ajax/libs/bootstrap', 'stackpath.bootstrapcdn.com/bootstrap'],
      'Font Awesome CDN': ['cdnjs.cloudflare.com/ajax/libs/font-awesome', 'use.fontawesome.com'],
    };

    const foundCdnLibs: string[] = [];
    for (const [lib, patterns] of Object.entries(cdnScriptIndicators)) {
      if (patterns.some(p => scriptSrcs.some(s => s.includes(p)))) {
        foundCdnLibs.push(lib);
      }
    }
    if (foundCdnLibs.length > 0) {
      findings.push(
        generateFinding(
          'Detected CDN-hosted libraries',
          'The following JavaScript libraries are loaded from CDNs.',
          Severity.INFO,
          'Technology Detection',
          domain,
          foundCdnLibs.join(', '),
          'Information for awareness; CDN libraries should be pinned with SRI',
          'Add Subresource Integrity (SRI) hashes to CDN script tags',
          []
        )
      );

      const scriptTagRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
      let sriMatch;
      const scriptsWithoutSri: string[] = [];
      const scriptsWithSri: string[] = [];
      while ((sriMatch = scriptTagRegex.exec(body)) !== null) {
        const fullTag = sriMatch[0];
        const src = sriMatch[1];
        if (src.includes('cdn') || src.includes('jsdelivr') || src.includes('unpkg') || src.includes('cdnjs') || src.includes('cloudflare') || src.includes('googleapis')) {
          if (fullTag.includes('integrity=')) {
            scriptsWithSri.push(src);
          } else {
            scriptsWithoutSri.push(src);
          }
        }
      }

      if (scriptsWithoutSri.length > 0 && scriptsWithSri.length === 0) {
        findings.push(
          generateFinding(
            'Missing Subresource Integrity (SRI)',
            `${scriptsWithoutSri.length} CDN script(s) lack SRI hashes, making them vulnerable to tampering.`,
            Severity.HIGH,
            'Technology Detection',
            domain,
            scriptsWithoutSri.join('\n'),
            'If a CDN is compromised, tampered scripts could execute malicious code',
            'Add integrity="sha384-..." attributes to all CDN script tags',
            ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity']
          )
        );
      } else if (scriptsWithoutSri.length > 0) {
        findings.push(
          generateFinding(
            'Some CDN scripts missing SRI',
            `${scriptsWithoutSri.length} CDN script(s) lack SRI hashes while ${scriptsWithSri.length} have them.`,
            Severity.MEDIUM,
            'Technology Detection',
            domain,
            scriptsWithoutSri.join('\n'),
            'Inconsistent SRI coverage leaves some scripts vulnerable to CDN tampering',
            'Add SRI hashes to all CDN-hosted script tags',
            ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity']
          )
        );
      }
    }

    const duration = Date.now() - startTime;
    return {
      module: 'technology',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'technology',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

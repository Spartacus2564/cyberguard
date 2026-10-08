export interface CveEntry {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  title: string;
  description: string;
  affectedSoftware: string[];
  versionRange: string;
  remediation: string;
  references: string[];
  publishedDate: string;
}

export interface TechnologyFingerprint {
  name: string;
  version?: string;
  source: 'header' | 'html' | 'meta' | 'banner' | 'cookie' | 'script' | 'dns';
  confidence: 'high' | 'medium' | 'low';
}

// Comprehensive CVE database for common web technologies
export const CVE_DATABASE: CveEntry[] = [
  // === Apache ===
  {
    id: 'CVE-2021-44790',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'Apache httpd buffer overflow in mod_lua',
    description: 'A buffer overflow flaw was found in Apache httpd mod_lua where it reads request body data.',
    affectedSoftware: ['apache'],
    versionRange: '<2.4.52',
    remediation: 'Upgrade to Apache httpd 2.4.52 or later',
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html'],
    publishedDate: '2021-12-20',
  },
  {
    id: 'CVE-2021-40438',
    severity: 'CRITICAL',
    cvss: 9.0,
    title: 'Apache httpd SSRF via mod_proxy',
    description: 'A SSRF flaw was found in Apache httpd mod_proxy. A request may be sent to the backend server which could be used to bypass access controls.',
    affectedSoftware: ['apache'],
    versionRange: '<2.4.49',
    remediation: 'Upgrade to Apache httpd 2.4.49 or later',
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html'],
    publishedDate: '2021-09-16',
  },
  {
    id: 'CVE-2021-39275',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'Apache httpd out-of-bounds write in ap_escape_quotes',
    description: 'A carefully crafted request could cause a buffer overflow in ap_escape_quotes.',
    affectedSoftware: ['apache'],
    versionRange: '<2.4.49',
    remediation: 'Upgrade to Apache httpd 2.4.49 or later',
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html'],
    publishedDate: '2021-09-16',
  },

  // === Nginx ===
  {
    id: 'CVE-2021-23017',
    severity: 'HIGH',
    cvss: 7.7,
    title: 'Nginx DNS resolver vulnerability',
    description: 'A security issue in nginx resolver was discovered, allowing DNS response packet to be crafted to cause resolver worker process crash.',
    affectedSoftware: ['nginx'],
    versionRange: '<1.21.1',
    remediation: 'Upgrade to Nginx 1.21.1 or later',
    references: ['https://nginx.org/en/security_advisories.html'],
    publishedDate: '2021-05-25',
  },
  {
    id: 'CVE-2019-9511',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'HTTP/2 Data Dribble vulnerability in Nginx',
    description: 'Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service.',
    affectedSoftware: ['nginx'],
    versionRange: '<1.17.3',
    remediation: 'Upgrade to Nginx 1.17.3 or later',
    references: ['https://nginx.org/en/security_advisories.html'],
    publishedDate: '2019-08-13',
  },
  {
    id: 'CVE-2022-41741',
    severity: 'HIGH',
    cvss: 7.8,
    title: 'Nginx mp4 module memory corruption',
    description: 'Nginx mp4 module buffer overflow vulnerability could allow a local attacker to gain code execution privileges.',
    affectedSoftware: ['nginx'],
    versionRange: '<1.23.2',
    remediation: 'Upgrade to Nginx 1.23.2 or later',
    references: ['https://nginx.org/en/security_advisories.html'],
    publishedDate: '2022-11-16',
  },

  // === OpenSSL ===
  {
    id: 'CVE-2023-5678',
    severity: 'MEDIUM',
    cvss: 5.3,
    title: 'OpenSSL excessive time checking DH q parameter',
    description: 'Issuing certificates with certain parameters could cause excessive time in DH key generation.',
    affectedSoftware: ['openssl'],
    versionRange: '<3.0.13',
    remediation: 'Upgrade to OpenSSL 3.0.13 or later',
    references: ['https://www.openssl.org/news/secadv/20231106.txt'],
    publishedDate: '2023-11-06',
  },
  {
    id: 'CVE-2023-0286',
    severity: 'HIGH',
    cvss: 7.4,
    title: 'OpenSSL X.400 address type confusion',
    description: 'There is a type confusion vulnerability relating to X.400 address processing inside the X.509 GeneralName.',
    affectedSoftware: ['openssl'],
    versionRange: '<3.0.8',
    remediation: 'Upgrade to OpenSSL 3.0.8 or later',
    references: ['https://www.openssl.org/news/secadv/20230207.txt'],
    publishedDate: '2023-02-07',
  },

  // === PHP ===
  {
    id: 'CVE-2024-4577',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'PHP CGI argument injection',
    description: 'PHP CGI argument injection vulnerability allows remote code execution on Windows systems.',
    affectedSoftware: ['php'],
    versionRange: '<8.1.29',
    remediation: 'Upgrade to PHP 8.1.29, 8.2.20, or 8.3.7',
    references: ['https://www.php.net/ChangeLog-8.php'],
    publishedDate: '2024-06-06',
  },
  {
    id: 'CVE-2024-2961',
    severity: 'CRITICAL',
    cvss: 8.8,
    title: 'PHP iconv buffer overflow',
    description: 'Buffer overflow in PHP iconv extension on 64-bit systems.',
    affectedSoftware: ['php'],
    versionRange: '<8.1.29',
    remediation: 'Upgrade to PHP 8.1.29, 8.2.20, or 8.3.7',
    references: ['https://www.php.net/ChangeLog-8.php'],
    publishedDate: '2024-04-01',
  },
  {
    id: 'CVE-2023-3824',
    severity: 'HIGH',
    cvss: 8.1,
    title: 'PHP buffer overflow in phar_compress',
    description: 'Buffer overflow vulnerability in PHP phar_compress function.',
    affectedSoftware: ['php'],
    versionRange: '<8.1.23',
    remediation: 'Upgrade to PHP 8.1.23 or later',
    references: ['https://www.php.net/ChangeLog-8.php'],
    publishedDate: '2023-08-17',
  },

  // === Python/Django ===
  {
    id: 'CVE-2024-24680',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'Django integer overflow in intcomma template filter',
    description: 'An issue was found in Django where the intcomma template filter was vulnerable to a potential DoS.',
    affectedSoftware: ['django'],
    versionRange: '<4.2.9',
    remediation: 'Upgrade to Django 4.2.9 or later',
    references: ['https://www.djangoproject.com/weblog/2024/jan/02/security-releases/'],
    publishedDate: '2024-01-02',
  },
  {
    id: 'CVE-2023-43665',
    severity: 'MEDIUM',
    cvss: 6.1,
    title: 'Django Truncator and strip_tags DoS',
    description: 'An issue was found in Django where validating URLs and extracting links could lead to DoS.',
    affectedSoftware: ['django'],
    versionRange: '<4.2.6',
    remediation: 'Upgrade to Django 4.2.6 or later',
    references: ['https://www.djangoproject.com/weblog/2023/oct/04/security-releases/'],
    publishedDate: '2023-10-04',
  },

  // === Ruby on Rails ===
  {
    id: 'CVE-2023-44487',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'Rails HTTP/2 Rapid Reset Attack',
    description: 'The HTTP/2 protocol allows a denial of service (server resource consumption) through reset attacks.',
    affectedSoftware: ['rails'],
    versionRange: '<7.0.8',
    remediation: 'Upgrade Rails and update rack dependency',
    references: ['https://rubyonrails.org/2023/10/10/Rails-7-0-8-and-6-1-7-7-have-been-released'],
    publishedDate: '2023-10-10',
  },

  // === Bootstrap ===
  {
    id: 'CVE-2019-8331',
    severity: 'MEDIUM',
    cvss: 6.1,
    title: 'Bootstrap XSS vulnerability',
    description: 'In affected versions, Tooltip is initialized with title option that can lead to XSS.',
    affectedSoftware: ['bootstrap'],
    versionRange: '<4.3.1',
    remediation: 'Upgrade to Bootstrap 4.3.1 or later',
    references: ['https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/'],
    publishedDate: '2019-02-13',
  },

  // === WordPress ===
  {
    id: 'CVE-2024-2899',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'WordPress HTTP Response Splitting',
    description: 'WordPress is vulnerable to HTTP response splitting due to insufficient input validation.',
    affectedSoftware: ['wordpress'],
    versionRange: '<6.4.4',
    remediation: 'Upgrade to WordPress 6.4.4 or later',
    references: ['https://wordpress.org/news/category/security/'],
    publishedDate: '2024-02-01',
  },
  {
    id: 'CVE-2023-5618',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'WordPress RCE via wp_email()',
    description: 'A remote code execution vulnerability was discovered in WordPress wp_email() function.',
    affectedSoftware: ['wordpress'],
    versionRange: '<6.4.1',
    remediation: 'Upgrade to WordPress 6.4.1 or later',
    references: ['https://wordpress.org/news/category/security/'],
    publishedDate: '2023-11-01',
  },

  // === Laravel ===
  {
    id: 'CVE-2024-13918',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'Laravel deserialization vulnerability',
    description: 'Deserialization of untrusted data in Laravel could lead to remote code execution.',
    affectedSoftware: ['laravel'],
    versionRange: '<11.3.1',
    remediation: 'Upgrade to Laravel 11.3.1 or later',
    references: ['https://laravel.com/docs/releases'],
    publishedDate: '2024-10-15',
  },

  // === Node.js/Express ===
  {
    id: 'CVE-2024-29041',
    severity: 'MEDIUM',
    cvss: 6.1,
    title: 'Express.js open redirect',
    description: 'Versions of Express.js prior to 4.19.2 are vulnerable to open redirect via URL parsing.',
    affectedSoftware: ['express'],
    versionRange: '<4.19.2',
    remediation: 'Upgrade to Express.js 4.19.2 or later',
    references: ['https://github.com/expressjs/express/releases'],
    publishedDate: '2024-03-25',
  },

  // === Spring Framework ===
  {
    id: 'CVE-2024-22234',
    severity: 'HIGH',
    cvss: 8.1,
    title: 'Spring Security authorization bypass',
    description: 'An authorization bypass vulnerability was found in Spring Security.',
    affectedSoftware: ['spring'],
    versionRange: '<6.2.3',
    remediation: 'Upgrade to Spring Security 6.2.3 or later',
    references: ['https://spring.io/security/cve'],
    publishedDate: '2024-03-18',
  },

  // === IIS ===
  {
    id: 'CVE-2021-31166',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'IIS HTTP Protocol Stack remote code execution',
    description: 'A remote code execution vulnerability exists when HTTP.sys processes specially crafted HTTP requests.',
    affectedSoftware: ['iis'],
    versionRange: '<10.0.20348.1',
    remediation: 'Apply Windows security update KB5001389',
    references: ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31166'],
    publishedDate: '2021-05-11',
  },

  // === OpenSSH ===
  {
    id: 'CVE-2023-51385',
    severity: 'HIGH',
    cvss: 6.5,
    title: 'OpenSSH command injection via ProxyCommand',
    description: 'A command injection vulnerability was discovered in OpenSSH. When using ProxyCommand or ProxyJump with an untrusted hostname or PATH environment variable, an attacker could inject arbitrary commands. The vulnerability exists because OpenSSH does not properly validate hostnames passed to ProxyCommand.',
    affectedSoftware: ['openssh'],
    versionRange: '<9.3p2',
    remediation: 'Upgrade to OpenSSH 9.3p2 or later. Avoid using untrusted hostnames in ProxyCommand.',
    references: ['https://www.openssh.com/security.html', 'https://nvd.nist.gov/vuln/detail/CVE-2023-51385'],
    publishedDate: '2023-06-23',
  },
  {
    id: 'CVE-2023-48795',
    severity: 'MEDIUM',
    cvss: 5.9,
    title: 'Terrapin attack on SSH Binary Packet Protocol',
    description: 'A prefix truncation attack (Terrapin) was discovered in the SSH Binary Packet Protocol. By manipulating sequence numbers during the handshake, an attacker can strip security-related protocol messages, potentially weakening the encryption. This affects the ChaCha20-Poly1305 and CBC cipher suites.',
    affectedSoftware: ['openssh'],
    versionRange: '<9.6p1',
    remediation: 'Upgrade to OpenSSH 9.6p1 or later. Disable ChaCha20-Poly1305 and CBC ciphers if upgrade is not possible.',
    references: ['https://www.terrapin-attack.com/', 'https://nvd.nist.gov/vuln/detail/CVE-2023-48795'],
    publishedDate: '2023-12-18',
  },
  {
    id: 'CVE-2023-38408',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'OpenSSH agent forwarding RCE',
    description: 'A remote code execution vulnerability was found in OpenSSH. When ssh-agent is forwarding a connection to a malicious server, the attacker could exploit this to execute arbitrary commands on the client system. This affects OpenSSH versions before 9.3p2 when AgentForwarding is enabled.',
    affectedSoftware: ['openssh'],
    versionRange: '<9.3p2',
    remediation: 'Upgrade to OpenSSH 9.3p2 or later. Disable AgentForwarding if not needed.',
    references: ['https://www.openssh.com/security.html', 'https://nvd.nist.gov/vuln/detail/CVE-2023-38408'],
    publishedDate: '2023-07-19',
  },
  {
    id: 'CVE-2021-41617',
    severity: 'HIGH',
    cvss: 7.0,
    title: 'OpenSSH privilege escalation via AuthorizedKeysCommand',
    description: 'A privilege escalation vulnerability was discovered in OpenSSH. When AuthorizedPrincipals or AuthorizedKeysCommand is used with a PKRN token, an attacker could bypass intended restrictions and gain elevated privileges. This affects OpenSSH before 8.5p1.',
    affectedSoftware: ['openssh'],
    versionRange: '<8.5p1',
    remediation: 'Upgrade to OpenSSH 8.5p1 or later.',
    references: ['https://www.openssh.com/security.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41617'],
    publishedDate: '2021-01-01',
  },

  // === OpenSSL ===
  {
    id: 'CVE-2024-5535',
    severity: 'HIGH',
    cvss: 9.1,
    title: 'OpenSSL SSL_select_next_proto buffer overread',
    description: 'A buffer overread vulnerability was discovered in OpenSSL. Calling SSL_select_next_proto with an empty supported client protocols list may result in a crash or reading up to 255 bytes of memory. This can be exploited to cause denial of service or information disclosure.',
    affectedSoftware: ['openssl'],
    versionRange: '<3.3.2',
    remediation: 'Upgrade to OpenSSL 3.3.2 or later.',
    references: ['https://www.openssl.org/news/secadv/20240903.txt', 'https://nvd.nist.gov/vuln/detail/CVE-2024-5535'],
    publishedDate: '2024-09-03',
  },
  {
    id: 'CVE-2024-0727',
    severity: 'MEDIUM',
    cvss: 5.5,
    title: 'OpenSSL PKCS12 NULL dereference',
    description: 'A NULL pointer dereference vulnerability was found in OpenSSL. Processing a malformed PKCS12 file can cause a crash, potentially leading to denial of service. This affects OpenSSL versions before 3.2.1.',
    affectedSoftware: ['openssl'],
    versionRange: '<3.2.1',
    remediation: 'Upgrade to OpenSSL 3.2.1 or later.',
    references: ['https://www.openssl.org/news/secadv/20240125.txt', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0727'],
    publishedDate: '2024-01-25',
  },

  // === Node.js ===
  {
    id: 'CVE-2024-22025',
    severity: 'HIGH',
    cvss: 7.5,
    title: 'Node.js Denial of Service via resource consumption',
    description: 'A denial of service vulnerability was found in Node.js. By using a specially crafted fetch request, an attacker can cause the application to consume excessive resources, leading to service degradation or crash.',
    affectedSoftware: ['node.js'],
    versionRange: '<20.11.1',
    remediation: 'Upgrade to Node.js 20.11.1 or later.',
    references: ['https://nodejs.org/en/blog/vulnerability/january-2024-security-releases', 'https://nvd.nist.gov/vuln/detail/CVE-2024-22025'],
    publishedDate: '2024-02-13',
  },

  // === jQuery ===
  {
    id: 'CVE-2020-11022',
    severity: 'MEDIUM',
    cvss: 6.1,
    title: 'jQuery XSS vulnerability in htmlPrefilter',
    description: 'A cross-site scripting vulnerability was discovered in jQuery. Passing HTML containing untrusted elements from untrusted sources to jQuery DOM manipulation methods can execute scripts. This affects jQuery versions from 1.2 to 3.5.0.',
    affectedSoftware: ['jquery'],
    versionRange: '>=1.2 <3.5.1',
    remediation: 'Upgrade to jQuery 3.5.1 or later.',
    references: ['https://blog.jquery.com/2020/04/10/jquery-3.5.0-released/', 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022'],
    publishedDate: '2020-04-10',
  },
  {
    id: 'CVE-2019-11358',
    severity: 'MEDIUM',
    cvss: 6.1,
    title: 'jQuery prototype pollution vulnerability',
    description: 'A prototype pollution vulnerability was discovered in jQuery. When extending an object with a user-provided constructor, an attacker can inject properties into Object.prototype, potentially leading to denial of service or code execution.',
    affectedSoftware: ['jquery'],
    versionRange: '<3.4.0',
    remediation: 'Upgrade to jQuery 3.4.0 or later.',
    references: ['https://blog.jquery.com/2019/05/01/jquery-3.4.1-released/', 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358'],
    publishedDate: '2019-04-10',
  },

  // === Laravel ===
  {
    id: 'CVE-2021-3129',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'Laravel Ignition RCE via file_get_contents/file_put_contents',
    description: 'A remote code execution vulnerability was discovered in Laravel Ignition. The vulnerability allows an attacker to execute arbitrary code by exploiting unsafe deserialization in the Ignition component. This affects Ignition before 2.5.2 when APP_DEBUG is enabled.',
    affectedSoftware: ['laravel', 'ignition'],
    versionRange: '<2.5.2',
    remediation: 'Update Ignition to version 2.5.2 or later. Disable APP_DEBUG in production.',
    references: ['https://www.ambionics.io/blog/laravel-debug-rce', 'https://nvd.nist.gov/vuln/detail/CVE-2021-3129'],
    publishedDate: '2021-01-15',
  },

  // === Spring ===
  {
    id: 'CVE-2022-22965',
    severity: 'CRITICAL',
    cvss: 9.8,
    title: 'Spring4Shell - Spring Framework RCE via data binding',
    description: 'A remote code execution vulnerability was found in Spring Framework (Spring4Shell). By manipulating class loader access through the Tomcat JDBC LogValve, an attacker can execute arbitrary code on the server. This affects Spring Framework versions before 5.3.18 and 5.2.20 when running on JDK 9+.',
    affectedSoftware: ['spring'],
    versionRange: '<5.3.18',
    remediation: 'Upgrade to Spring Framework 5.3.18 or 5.2.20. Use JDK 8 if upgrade is not immediately possible.',
    references: ['https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement', 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    publishedDate: '2022-04-01',
  },
];

// Technology detection patterns with version extraction
export const TECH_DETECTION_PATTERNS: Record<string, Array<{ pattern: RegExp; name: string; versionGroup?: number }>> = {
  'Server Header': [
    { pattern: /Apache\/([\d.]+)/i, name: 'Apache', versionGroup: 1 },
    { pattern: /nginx\/([\d.]+)/i, name: 'Nginx', versionGroup: 1 },
    { pattern: /Microsoft-IIS\/([\d.]+)/i, name: 'IIS', versionGroup: 1 },
    { pattern: /LiteSpeed\/([\d.]+)/i, name: 'LiteSpeed', versionGroup: 1 },
    { pattern: /Caddy/i, name: 'Caddy' },
    { pattern: /OpenSSH[_\/]([\d.]+)/i, name: 'OpenSSH', versionGroup: 1 },
  ],
  'X-Powered-By': [
    { pattern: /PHP\/([\d.]+)/i, name: 'PHP', versionGroup: 1 },
    { pattern: /ASP\.NET/i, name: 'ASP.NET' },
    { pattern: /Express/i, name: 'Express' },
    { pattern: /Next\.js/i, name: 'Next.js' },
    { pattern: /Phusion Passenger/i, name: 'Passenger' },
  ],
  'HTML Body': [
    { pattern: /WordPress ([\d.]+)/i, name: 'WordPress', versionGroup: 1 },
    { pattern: /Drupal ([\d.]+)/i, name: 'Drupal', versionGroup: 1 },
    { pattern: /Joomla!?\s*([\d.]+)/i, name: 'Joomla', versionGroup: 1 },
    { pattern: /Magento[\s\/]?([\d.]+)/i, name: 'Magento', versionGroup: 1 },
    { pattern: /Shopify/i, name: 'Shopify' },
    { pattern: /Wix\.com/i, name: 'Wix' },
    { pattern: /Squarespace/i, name: 'Squarespace' },
    { pattern: /Webflow/i, name: 'Webflow' },
    { pattern: /Contentful/i, name: 'Contentful' },
    { pattern: /Strapi/i, name: 'Strapi' },
    { pattern: /Ghost ([\d.]+)/i, name: 'Ghost', versionGroup: 1 },
    { pattern: /Typo3\/([\d.]+)/i, name: 'TYPO3', versionGroup: 1 },
  ],
  'Script Tags': [
    { pattern: /react[\/\s]([\d.]+)/i, name: 'React', versionGroup: 1 },
    { pattern: /vue[\/\s]([\d.]+)/i, name: 'Vue.js', versionGroup: 1 },
    { pattern: /angular[\/\s]([\d.]+)/i, name: 'Angular', versionGroup: 1 },
    { pattern: /jquery[\/\-]([\d.]+)/i, name: 'jQuery', versionGroup: 1 },
    { pattern: /bootstrap[\/\-]([\d.]+)/i, name: 'Bootstrap', versionGroup: 1 },
    { pattern: /lodash[\/\s]([\d.]+)/i, name: 'Lodash', versionGroup: 1 },
    { pattern: /moment[\/\s]([\d.]+)/i, name: 'Moment.js', versionGroup: 1 },
    { pattern: /axios[\/\s]([\d.]+)/i, name: 'Axios', versionGroup: 1 },
    { pattern: /webpack[\/\s]([\d.]+)/i, name: 'Webpack', versionGroup: 1 },
    { pattern: /vite[\/\s]([\d.]+)/i, name: 'Vite', versionGroup: 1 },
  ],
  'Meta Tags': [
    { pattern: /generator.*WordPress/i, name: 'WordPress' },
    { pattern: /generator.*Drupal/i, name: 'Drupal' },
    { pattern: /generator.*Joomla/i, name: 'Joomla' },
    { pattern: /generator.*Hugo/i, name: 'Hugo' },
    { pattern: /generator.*Jekyll/i, name: 'Jekyll' },
    { pattern: /generator.*Gatsby/i, name: 'Gatsby' },
    { pattern: /generator.*Next\.js/i, name: 'Next.js' },
    { pattern: /generator.*Nuxt/i, name: 'Nuxt.js' },
  ],
  'DNS Records': [
    { pattern: /google-site-verification/i, name: 'Google' },
    { pattern: /facebook-domain-verification/i, name: 'Facebook' },
    { pattern: /MSValidation/i, name: 'Microsoft' },
    { pattern: /SendGrid/i, name: 'SendGrid' },
    { pattern: /Mailgun/i, name: 'Mailgun' },
    { pattern: /SPF.*include:_spf\.google\.com/i, name: 'Google Workspace' },
    { pattern: /SPF.*include:spf\.protection\.outlook\.com/i, name: 'Microsoft 365' },
  ],
  'Cookie Names': [
    { pattern: /laravel_session/i, name: 'Laravel' },
    { pattern: /PHPSESSID/i, name: 'PHP' },
    { pattern: /JSESSIONID/i, name: 'Java' },
    { pattern: /connect\.sid/i, name: 'Express' },
    { pattern: /csrftoken/i, name: 'Django' },
    { pattern: /_rails_session/i, name: 'Rails' },
    { pattern: /wordpress_logged_in/i, name: 'WordPress' },
    { pattern: /drupal_visitor/i, name: 'Drupal' },
    { pattern: /PHPSESSID/i, name: 'PHP' },
    { pattern: /asp\.net_sessionid/i, name: 'ASP.NET' },
  ],
};

export function findCvesForTechnology(techName: string, version?: string): CveEntry[] {
  const nameLower = techName.toLowerCase();
  return CVE_DATABASE.filter(cve => {
    const matchesSoftware = cve.affectedSoftware.some(s => nameLower.includes(s));
    if (!matchesSoftware) return false;
    // Simple version comparison (can be enhanced)
    if (version && cve.versionRange) {
      const match = cve.versionRange.match(/<([\d.]+)/);
      if (match) {
        const maxVersion = match[1];
        return compareVersions(version, maxVersion) < 0;
      }
    }
    return true;
  });
}

export function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }
  return 0;
}

export function extractTechnologies(
  headers: Record<string, string | string[] | undefined>,
  body: string,
  cookies: string[],
  txtRecords: string[]
): TechnologyFingerprint[] {
  const techs: TechnologyFingerprint[] = [];
  const seen = new Set<string>();

  // Check Server header
  const server = Array.isArray(headers['server']) ? headers['server'][0] : headers['server'];
  if (server) {
    for (const { pattern, name, versionGroup } of TECH_DETECTION_PATTERNS['Server Header']) {
      const match = server.match(pattern);
      if (match && !seen.has(name)) {
        techs.push({
          name,
          version: versionGroup ? match[versionGroup] : undefined,
          source: 'header',
          confidence: 'high',
        });
        seen.add(name);
      }
    }
  }

  // Check X-Powered-By
  const poweredBy = Array.isArray(headers['x-powered-by']) ? headers['x-powered-by'][0] : headers['x-powered-by'];
  if (poweredBy) {
    for (const { pattern, name, versionGroup } of TECH_DETECTION_PATTERNS['X-Powered-By']) {
      const match = poweredBy.match(pattern);
      if (match && !seen.has(name)) {
        techs.push({
          name,
          version: versionGroup ? match[versionGroup] : undefined,
          source: 'header',
          confidence: 'high',
        });
        seen.add(name);
      }
    }
  }

  // Check HTML body
  for (const { pattern, name, versionGroup } of TECH_DETECTION_PATTERNS['HTML Body']) {
    const match = body.match(pattern);
    if (match && !seen.has(name)) {
      techs.push({
        name,
        version: versionGroup ? match[versionGroup] : undefined,
        source: 'html',
        confidence: 'medium',
      });
      seen.add(name);
    }
  }

  // Check Script tags
  for (const { pattern, name, versionGroup } of TECH_DETECTION_PATTERNS['Script Tags']) {
    const match = body.match(pattern);
    if (match && !seen.has(name)) {
      techs.push({
        name,
        version: versionGroup ? match[versionGroup] : undefined,
        source: 'script',
        confidence: 'medium',
      });
      seen.add(name);
    }
  }

  // Check Meta tags
  for (const { pattern, name } of TECH_DETECTION_PATTERNS['Meta Tags']) {
    if (pattern.test(body) && !seen.has(name)) {
      techs.push({
        name,
        source: 'meta',
        confidence: 'low',
      });
      seen.add(name);
    }
  }

  // Check Cookie names
  for (const { pattern, name } of TECH_DETECTION_PATTERNS['Cookie Names']) {
    for (const cookie of cookies) {
      if (pattern.test(cookie) && !seen.has(name)) {
        techs.push({
          name,
          source: 'cookie',
          confidence: 'medium',
        });
        seen.add(name);
        break;
      }
    }
  }

  // Check TXT records
  for (const { pattern, name } of TECH_DETECTION_PATTERNS['DNS Records']) {
    for (const txt of txtRecords) {
      if (pattern.test(txt) && !seen.has(name)) {
        techs.push({
          name,
          source: 'dns',
          confidence: 'low',
        });
        seen.add(name);
        break;
      }
    }
  }

  return techs;
}

import http from 'http';
import https from 'https';
import { URL } from 'url';
import logger from '../../utils/logger';

export interface AuthSession {
  cookies: Record<string, string>;
  headers: Record<string, string>;
  authenticated: boolean;
  lastVerified: Date;
}

export interface CredentialConfig {
  type: 'basic' | 'form' | 'cookie' | 'header';
  username?: string;
  password?: string;
  cookies?: string;
  headers?: Record<string, string>;
  loginUrl?: string;
  loginSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  successIndicator?: string;
}

export class AuthenticatedClient {
  private session: AuthSession = {
    cookies: {},
    headers: {},
    authenticated: false,
    lastVerified: new Date(0),
  };

  constructor(
    private baseUrl: string,
    private credentials?: CredentialConfig
  ) {
    if (credentials?.cookies) {
      this.parseCookieHeader(credentials.cookies);
    }
    if (credentials?.headers) {
      this.session.headers = { ...credentials.headers };
    }
  }

  private parseCookieHeader(cookieStr: string): void {
    cookieStr.split(';').forEach((c) => {
      const [name, ...valueParts] = c.trim().split('=');
      if (name) this.session.cookies[name.trim()] = valueParts.join('=').trim();
    });
  }

  private getCookieHeader(): string {
    return Object.entries(this.session.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  async authenticate(): Promise<boolean> {
    if (!this.credentials) return false;

    if (
      this.credentials.type === 'basic' &&
      this.credentials.username &&
      this.credentials.password
    ) {
      const authHeader =
        'Basic ' +
        Buffer.from(
          `${this.credentials.username}:${this.credentials.password}`
        ).toString('base64');
      this.session.headers['Authorization'] = authHeader;
      this.session.authenticated = true;
      logger.info(
        '[AuthClient] Basic auth configured for ' + this.baseUrl
      );
      return true;
    }

    if (this.credentials.type === 'form' && this.credentials.loginUrl) {
      return await this.formLogin();
    }

    if (this.credentials.type === 'cookie') {
      this.session.authenticated = true;
      return true;
    }

    return false;
  }

  private async formLogin(): Promise<boolean> {
    try {
      const loginPageResult = await this.rawRequest(
        this.credentials!.loginUrl!,
        'GET'
      );
      const csrfToken = this.extractCsrfToken(loginPageResult.body);

      const formData = new URLSearchParams();
      if (this.credentials!.loginSelector) {
        const usernameField = this.extractFieldName(
          this.credentials!.loginSelector
        );
        const passwordField = this.credentials!.passwordSelector
          ? this.extractFieldName(this.credentials!.passwordSelector)
          : 'password';
        formData.set(usernameField, this.credentials!.username || '');
        formData.set(passwordField, this.credentials!.password || '');
        if (csrfToken) formData.set('csrf_token', csrfToken);
      }

      const postResult = await this.rawRequest(
        this.credentials!.loginUrl!,
        'POST',
        formData.toString(),
        { 'Content-Type': 'application/x-www-form-urlencoded' }
      );

      if (this.credentials!.successIndicator) {
        this.session.authenticated = postResult.body.includes(
          this.credentials!.successIndicator
        );
      } else {
        this.session.authenticated =
          postResult.statusCode >= 200 && postResult.statusCode < 400;
      }

      if (this.session.authenticated) {
        logger.info(
          '[AuthClient] Form login successful for ' + this.baseUrl
        );
      } else {
        logger.warn(
          '[AuthClient] Form login may have failed for ' +
            this.baseUrl +
            ' (status: ' +
            postResult.statusCode +
            ')'
        );
      }

      return this.session.authenticated;
    } catch (e) {
      logger.warn('[AuthClient] Form login failed: ' + e);
      return false;
    }
  }

  private extractCsrfToken(html: string): string | null {
    const match =
      html.match(/name="csrf_token"[^>]*value="([^"]+)"/i) ||
      html.match(/name="_csrf"[^>]*value="([^"]+)"/i) ||
      html.match(/name="authenticity_token"[^>]*value="([^"]+)"/i);
    return match ? match[1] : null;
  }

  private extractFieldName(selector: string): string {
    const nameMatch = selector.match(/name="([^"]+)"/);
    if (nameMatch) return nameMatch[1];
    const idMatch = selector.match(/#([^.\s]+)/);
    if (idMatch) return idMatch[1];
    return selector.replace(/[#.\[\]"]/g, '').split(/[\s>]/).pop() || 'field';
  }

  async request(
    path: string,
    method: string = 'GET',
    body?: string,
    extraHeaders?: Record<string, string>
  ): Promise<{
    statusCode: number;
    headers: http.IncomingHttpHeaders;
    body: string;
  }> {
    if (
      this.credentials &&
      Date.now() - this.session.lastVerified.getTime() > 3600000
    ) {
      await this.authenticate();
    }

    const url = path.startsWith('http') ? path : this.baseUrl + path;
    const headers: Record<string, string> = {
      ...this.session.headers,
      ...extraHeaders,
    };

    const cookieHeader = this.getCookieHeader();
    if (cookieHeader) headers['Cookie'] = cookieHeader;

    const result = await this.rawRequest(url, method, body, headers);

    const setCookies = result.headers['set-cookie'];
    if (setCookies) {
      const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
      for (const c of cookies) {
        const [nameValue] = c.split(';');
        const [name, ...valueParts] = nameValue.split('=');
        if (name)
          this.session.cookies[name.trim()] = valueParts.join('=').trim();
      }
    }

    this.session.lastVerified = new Date();
    return result;
  }

  private rawRequest(
    url: string,
    method: string,
    body?: string,
    headers?: Record<string, string>
  ): Promise<{
    statusCode: number;
    headers: http.IncomingHttpHeaders;
    body: string;
  }> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const mod = parsedUrl.protocol === 'https:' ? https : http;

      const reqHeaders: Record<string, string> = {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ...headers,
      };

      if (body && method !== 'GET') {
        reqHeaders['Content-Length'] = Buffer.byteLength(body).toString();
      }

      const req = mod.request(
        url,
        {
          method,
          headers: reqHeaders,
          timeout: 10000,
          rejectUnauthorized: false,
        },
        (res) => {
          let responseBody = '';
          res.on('data', (chunk: Buffer) => {
            responseBody += chunk.toString();
          });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers,
              body: responseBody,
            });
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (body && method !== 'GET') {
        req.write(body);
      }
      req.end();
    });
  }

  getSession(): AuthSession {
    return { ...this.session };
  }
}

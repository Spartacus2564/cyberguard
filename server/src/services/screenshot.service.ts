import puppeteer from 'puppeteer';
import path from 'path';
import fs from 'fs';
import { config } from '../config';
import logger from '../utils/logger';

export interface ScreenshotResult {
  url: string;
  screenshotPath: string;
  timestamp: Date;
  title: string;
  statusCode: number;
  headers: Record<string, string>;
  cookies: { name: string; value: string; domain: string }[];
  consoleLogs: string[];
  networkRequests: { url: string; method: string; status: number }[];
  performanceMetrics: {
    loadTime: number;
    domContentLoaded: number;
    firstPaint: number;
  };
  securityHeaders: Record<string, string>;
  technologies: string[];
  forms: { action: string; method: string; inputs: { name: string; type: string }[] }[];
  links: { href: string; text: string; rel: string }[];
}

export async function captureWebsite(url: string, domain: string): Promise<ScreenshotResult> {
  const screenshotsDir = path.join(config.reportsDir, 'screenshots');
  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  const filename = `${domain}-${Date.now()}.png`;
  const screenshotPath = path.join(screenshotsDir, filename);

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
      ],
    });

    const page = await browser.newPage();

    // Set viewport
    await page.setViewport({ width: 1920, height: 1080 });

    // Set user agent
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Collect console logs
    const consoleLogs: string[] = [];
    page.on('console', msg => {
      consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
    });

    // Collect network requests
    const networkRequests: { url: string; method: string; status: number }[] = [];
    page.on('response', response => {
      networkRequests.push({
        url: response.url(),
        method: response.request().method(),
        status: response.status(),
      });
    });

    // Navigate to URL
    const startTime = Date.now();
    const response = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: 30000,
    });

    const statusCode = response?.status() || 0;
    const headers = response?.headers() || {};

    // Wait for page to fully load
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Take screenshot
    await page.screenshot({
      path: screenshotPath,
      fullPage: true,
    });

    // Get page title
    const title = await page.title();

    // Get cookies
    const cookies = await page.cookies();

    // Get performance metrics
    const performanceMetrics = await page.evaluate(() => {
      const perf = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        loadTime: perf ? perf.loadEventEnd - perf.startTime : 0,
        domContentLoaded: perf ? perf.domContentLoadedEventEnd - perf.startTime : 0,
        firstPaint: perf ? perf.responseStart - perf.startTime : 0,
      };
    });

    // Get security headers
    const securityHeaders: Record<string, string> = {};
    const securityHeaderNames = [
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'strict-transport-security',
      'x-xss-protection',
      'referrer-policy',
      'permissions-policy',
    ];
    for (const name of securityHeaderNames) {
      if (headers[name]) {
        securityHeaders[name] = headers[name];
      }
    }

    // Detect technologies
    const technologies = await page.evaluate(() => {
      const techs: string[] = [];
      
      // Check for common frameworks
      if ((window as any).jQuery) techs.push('jQuery');
      if ((window as any).React) techs.push('React');
      if ((window as any).Vue) techs.push('Vue.js');
      if ((window as any).Angular) techs.push('Angular');
      if ((window as any).__NEXT_DATA__) techs.push('Next.js');
      if ((window as any).__NUXT__) techs.push('Nuxt.js');
      if ((window as any).WebpackJsonp) techs.push('Webpack');
      
      // Check meta tags
      const generator = document.querySelector('meta[name="generator"]');
      if (generator) techs.push(generator.getAttribute('content') || '');
      
      // Check scripts
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      for (const script of scripts) {
        const src = script.getAttribute('src') || '';
        if (src.includes('react')) techs.push('React');
        if (src.includes('vue')) techs.push('Vue.js');
        if (src.includes('angular')) techs.push('Angular');
        if (src.includes('jquery')) techs.push('jQuery');
      }
      
      return [...new Set(techs)];
    });

    // Get forms
    const forms = await page.evaluate(() => {
      const forms = Array.from(document.querySelectorAll('form'));
      return forms.map(form => ({
        action: form.getAttribute('action') || '',
        method: form.getAttribute('method') || 'GET',
        inputs: Array.from(form.querySelectorAll('input')).map(input => ({
          name: input.getAttribute('name') || '',
          type: input.getAttribute('type') || 'text',
        })),
      }));
    });

    // Get links
    const links = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('a[href]'));
      return links.slice(0, 100).map(link => ({
        href: link.getAttribute('href') || '',
        text: link.textContent?.trim() || '',
        rel: link.getAttribute('rel') || '',
      }));
    });

    logger.info(`[Screenshot] Captured ${url} - ${screenshotPath}`);

    return {
      url,
      screenshotPath,
      timestamp: new Date(),
      title,
      statusCode,
      headers,
      cookies: cookies.map(c => ({ name: c.name, value: c.value, domain: c.domain })),
      consoleLogs,
      networkRequests,
      performanceMetrics,
      securityHeaders,
      technologies,
      forms,
      links,
    };
  } catch (error) {
    logger.error(`[Screenshot] Failed to capture ${url}: ${error}`);
    throw error;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

export async function captureMultiplePages(urls: string[], domain: string): Promise<ScreenshotResult[]> {
  const results: ScreenshotResult[] = [];
  
  for (const url of urls) {
    try {
      const result = await captureWebsite(url, domain);
      results.push(result);
    } catch (error) {
      logger.error(`[Screenshot] Failed to capture ${url}: ${error}`);
    }
  }
  
  return results;
}

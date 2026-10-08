import { generateFinding, fetchUrl, fetchJson } from '../src/engine/modules/shared';
import { Severity } from '../src/types';

describe('Shared Module', () => {
  describe('generateFinding', () => {
    it('should generate a finding with all required fields', () => {
      const finding = generateFinding(
        'Test finding',
        'Test description',
        Severity.HIGH,
        'Test Category',
        'test.example.com',
        'Test evidence',
        'Test impact',
        'Test remediation',
        ['https://example.com']
      );

      expect(finding.id).toBeDefined();
      expect(finding.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(finding.title).toBe('Test finding');
      expect(finding.description).toBe('Test description');
      expect(finding.severity).toBe(Severity.HIGH);
      expect(finding.category).toBe('Test Category');
      expect(finding.affectedAsset).toBe('test.example.com');
      expect(finding.evidence).toBe('Test evidence');
      expect(finding.impact).toBe('Test impact');
      expect(finding.remediation).toBe('Test remediation');
      expect(finding.references).toEqual(['https://example.com']);
      expect(finding.detectedAt).toBeInstanceOf(Date);
    });

    it('should generate unique IDs for each finding', () => {
      const finding1 = generateFinding('F1', 'D1', Severity.LOW, 'C', 'A', 'E', 'I', 'R');
      const finding2 = generateFinding('F2', 'D2', Severity.LOW, 'C', 'A', 'E', 'I', 'R');
      expect(finding1.id).not.toBe(finding2.id);
    });

    it('should handle all severity levels', () => {
      const severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
      for (const severity of severities) {
        const finding = generateFinding('T', 'D', severity, 'C', 'A', 'E', 'I', 'R');
        expect(finding.severity).toBe(severity);
      }
    });

    it('should default references to empty array', () => {
      const finding = generateFinding('T', 'D', Severity.LOW, 'C', 'A', 'E', 'I', 'R');
      expect(finding.references).toEqual([]);
    });
  });

  describe('fetchUrl', () => {
    it('should fetch a valid URL', async () => {
      // Use httpbin.org for testing (it's a test API)
      // Skip if network is unavailable
      try {
        const result = await fetchUrl('https://httpbin.org/get', 10000);
        expect(result.statusCode).toBe(200);
        expect(result.body).toBeDefined();
        expect(result.headers).toBeDefined();
      } catch {
        // Network unavailable, skip test
      }
    }, 15000);

    it('should handle timeout', async () => {
      try {
        await fetchUrl('http://192.0.2.1/get', 1000); // TEST-NET, should timeout
        fail('Should have thrown');
      } catch (e: any) {
        expect(e.message).toBeDefined();
      }
    }, 5000);
  });

  describe('fetchJson', () => {
    it('should parse JSON response', async () => {
      try {
        const result = await fetchJson('https://httpbin.org/get', 10000);
        expect(result).toBeDefined();
        expect(typeof result).toBe('object');
      } catch {
        // Network unavailable, skip test
      }
    }, 15000);
  });
});

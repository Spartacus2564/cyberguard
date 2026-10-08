import { validateTarget } from '../src/middleware/ssrfProtection';

describe('SSRF Protection - Extended', () => {
  describe('validateTarget', () => {
    it('should reject localhost', async () => {
      const result = await validateTarget('localhost');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Localhost');
    });

    it('should reject 127.0.0.1', async () => {
      const result = await validateTarget('127.0.0.1');
      expect(result.valid).toBe(false);
    });

    it('should reject private IPs', async () => {
      const privateIPs = ['10.0.0.1', '192.168.1.1', '172.16.0.1'];
      for (const ip of privateIPs) {
        const result = await validateTarget(ip);
        expect(result.valid).toBe(false);
      }
    });

    it('should reject cloud metadata IP', async () => {
      const result = await validateTarget('169.254.169.254');
      expect(result.valid).toBe(false);
    });

    it('should reject blocked TLDs', async () => {
      const blockedDomains = ['test.local', 'foo.internal', 'bar.localhost'];
      for (const domain of blockedDomains) {
        const result = await validateTarget(domain);
        expect(result.valid).toBe(false);
      }
    });

    it('should accept valid public domains', async () => {
      const result = await validateTarget('example.com');
      expect(result.valid).toBe(true);
    });

    it('should reject empty input', async () => {
      const result = await validateTarget('');
      expect(result.valid).toBe(false);
    });

    it('should reject invalid domain format', async () => {
      const result = await validateTarget('not a domain');
      expect(result.valid).toBe(false);
    });
  });
});

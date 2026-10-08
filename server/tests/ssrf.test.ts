import { validateTarget } from '../src/middleware/ssrfProtection';

describe('SSRF Protection', () => {
  describe('validateTarget', () => {
    it('should allow valid public domains', async () => {
      const result = await validateTarget('example.com');
      expect(result.valid).toBe(true);
    });

    it('should block localhost', async () => {
      const result = await validateTarget('localhost');
      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it('should block 127.x.x.x addresses', async () => {
      const result = await validateTarget('127.0.0.1');
      expect(result.valid).toBe(false);
    });

    it('should block private IP ranges', async () => {
      const result = await validateTarget('192.168.1.1');
      expect(result.valid).toBe(false);
    });

    it('should block 10.x.x.x ranges', async () => {
      const result = await validateTarget('10.0.0.1');
      expect(result.valid).toBe(false);
    });

    it('should block cloud metadata endpoint', async () => {
      const result = await validateTarget('169.254.169.254');
      expect(result.valid).toBe(false);
    });

    it('should block .local domains', async () => {
      const result = await validateTarget('myhost.local');
      expect(result.valid).toBe(false);
    });

    it('should block .internal domains', async () => {
      const result = await validateTarget('service.internal');
      expect(result.valid).toBe(false);
    });

    it('should reject empty input', async () => {
      const result = await validateTarget('');
      expect(result.valid).toBe(false);
    });
  });
});

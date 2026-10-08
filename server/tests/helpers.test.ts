import { isValidDomain, sanitizeString, maskEmail } from '../src/utils/helpers';

describe('Helper Utilities', () => {
  describe('isValidDomain', () => {
    it('should accept valid domains', () => {
      expect(isValidDomain('example.com')).toBe(true);
      expect(isValidDomain('sub.example.com')).toBe(true);
      expect(isValidDomain('my-site.org')).toBe(true);
    });

    it('should reject invalid domains', () => {
      expect(isValidDomain('')).toBe(false);
      expect(isValidDomain('http://example.com')).toBe(false);
      expect(isValidDomain('example')).toBe(false);
      expect(isValidDomain('example com')).toBe(false);
      expect(isValidDomain('192.168.1.1')).toBe(false);
    });
  });

  describe('sanitizeString', () => {
    it('should trim whitespace', () => {
      expect(sanitizeString('  hello  ')).toBe('hello');
    });

    it('should handle empty strings', () => {
      expect(sanitizeString('')).toBe('');
    });
  });

  describe('maskEmail', () => {
    it('should mask email properly', () => {
      const masked = maskEmail('john@example.com');
      expect(masked).toContain('@example.com');
      expect(masked).not.toBe('john@example.com');
    });
  });
});

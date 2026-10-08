import { calculateSecurityScore, getGrade, getGradeLabel, getRiskLevel, calculateCvssLikeScore } from '../src/engine/riskScoring';
import { Finding, Severity } from '../src/types';

describe('Risk Scoring Engine', () => {
  describe('getGrade', () => {
    it('should return A+ for 95+', () => {
      expect(getGrade(95)).toBe('A+');
      expect(getGrade(100)).toBe('A+');
    });

    it('should return A for 90-94', () => {
      expect(getGrade(90)).toBe('A');
      expect(getGrade(94)).toBe('A');
    });

    it('should return A- for 85-89', () => {
      expect(getGrade(85)).toBe('A-');
      expect(getGrade(89)).toBe('A-');
    });

    it('should return B+ for 80-84', () => {
      expect(getGrade(80)).toBe('B+');
      expect(getGrade(84)).toBe('B+');
    });

    it('should return B for 75-79', () => {
      expect(getGrade(75)).toBe('B');
      expect(getGrade(79)).toBe('B');
    });

    it('should return B- for 70-74', () => {
      expect(getGrade(70)).toBe('B-');
      expect(getGrade(74)).toBe('B-');
    });

    it('should return C+ for 65-69', () => {
      expect(getGrade(65)).toBe('C+');
      expect(getGrade(69)).toBe('C+');
    });

    it('should return C for 60-64', () => {
      expect(getGrade(60)).toBe('C');
      expect(getGrade(64)).toBe('C');
    });

    it('should return F for 0-29', () => {
      expect(getGrade(20)).toBe('F');
      expect(getGrade(0)).toBe('F');
    });
  });

  describe('getGradeLabel', () => {
    it('should return correct labels', () => {
      expect(getGradeLabel(95)).toBe('Excellent');
      expect(getGradeLabel(80)).toBe('Good');
      expect(getGradeLabel(60)).toBe('Average');
      expect(getGradeLabel(40)).toBe('Poor');
      expect(getGradeLabel(20)).toBe('Critical');
    });
  });

  describe('getRiskLevel', () => {
    it('should return correct risk levels', () => {
      expect(getRiskLevel(95)).toBe('Minimal Risk');
      expect(getRiskLevel(85)).toBe('Low Risk');
      expect(getRiskLevel(75)).toBe('Moderate Risk');
      expect(getRiskLevel(65)).toBe('Elevated Risk');
      expect(getRiskLevel(55)).toBe('High Risk');
      expect(getRiskLevel(35)).toBe('Severe Risk');
      expect(getRiskLevel(15)).toBe('Critical Risk');
    });
  });

  describe('calculateSecurityScore', () => {
    it('should return 100 for no findings', () => {
      const result = calculateSecurityScore([]);
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A+');
    });

    it('should reduce score for findings', () => {
      const findings: Finding[] = [
        {
          id: '1', title: 'Test', description: 'Test', severity: Severity.HIGH,
          category: 'Security Headers', affectedAsset: 'test.com', evidence: '', impact: '',
          remediation: '', references: [], detectedAt: new Date(),
        },
      ];
      const result = calculateSecurityScore(findings);
      expect(result.score).toBeLessThan(100);
      expect(result.score).toBeGreaterThan(0);
    });

    it('should reduce score more for critical findings', () => {
      const criticalFindings: Finding[] = [
        {
          id: '1', title: 'Critical', description: 'Test', severity: Severity.CRITICAL,
          category: 'TLS/HTTPS', affectedAsset: 'test.com', evidence: '', impact: '',
          remediation: '', references: [], detectedAt: new Date(),
        },
      ];
      const lowFindings: Finding[] = [
        {
          id: '2', title: 'Low', description: 'Test', severity: Severity.LOW,
          category: 'Technology Detection', affectedAsset: 'test.com', evidence: '', impact: '',
          remediation: '', references: [], detectedAt: new Date(),
        },
      ];
      const criticalResult = calculateSecurityScore(criticalFindings);
      const lowResult = calculateSecurityScore(lowFindings);
      expect(criticalResult.score).toBeLessThan(lowResult.score);
    });

    it('should clamp score between 0 and 100', () => {
      const manyFindings: Finding[] = Array(20).fill(null).map((_, i) => ({
        id: String(i), title: 'Test', description: 'Test', severity: Severity.CRITICAL,
        category: 'TLS/HTTPS', affectedAsset: 'test.com', evidence: '', impact: '',
        remediation: '', references: [], detectedAt: new Date(),
      }));
      const result = calculateSecurityScore(manyFindings);
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });

    it('should return breakdown counts', () => {
      const findings: Finding[] = [
        { id: '1', title: 'C1', description: '', severity: Severity.CRITICAL, category: '', affectedAsset: '', evidence: '', impact: '', remediation: '', references: [], detectedAt: new Date() },
        { id: '2', title: 'H1', description: '', severity: Severity.HIGH, category: '', affectedAsset: '', evidence: '', impact: '', remediation: '', references: [], detectedAt: new Date() },
        { id: '3', title: 'M1', description: '', severity: Severity.MEDIUM, category: '', affectedAsset: '', evidence: '', impact: '', remediation: '', references: [], detectedAt: new Date() },
        { id: '4', title: 'L1', description: '', severity: Severity.LOW, category: '', affectedAsset: '', evidence: '', impact: '', remediation: '', references: [], detectedAt: new Date() },
        { id: '5', title: 'I1', description: '', severity: Severity.INFO, category: '', affectedAsset: '', evidence: '', impact: '', remediation: '', references: [], detectedAt: new Date() },
      ];
      const result = calculateSecurityScore(findings);
      expect(result.breakdown.critical).toBe(1);
      expect(result.breakdown.high).toBe(1);
      expect(result.breakdown.medium).toBe(1);
      expect(result.breakdown.low).toBe(1);
      expect(result.breakdown.info).toBe(1);
    });
  });

  describe('calculateCvssLikeScore', () => {
    it('should return 9.0-10.0 for CRITICAL', () => {
      const score = calculateCvssLikeScore(Severity.CRITICAL, 'TLS/HTTPS');
      expect(score).toBeGreaterThanOrEqual(9.0);
      expect(score).toBeLessThanOrEqual(10.0);
    });

    it('should return 7.0-8.9 for HIGH', () => {
      const score = calculateCvssLikeScore(Severity.HIGH, 'Security Headers');
      expect(score).toBeGreaterThanOrEqual(7.0);
      expect(score).toBeLessThanOrEqual(8.9);
    });

    it('should return 0.0 for INFO', () => {
      const score = calculateCvssLikeScore(Severity.INFO, 'Technology Detection');
      expect(score).toBe(0.0);
    });
  });
});

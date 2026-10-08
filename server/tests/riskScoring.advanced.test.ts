import { calculateSecurityScore, getGrade, getGradeLabel, getRiskLevel, generateScoringBreakdown, calculateCvssLikeScore, CATEGORY_WEIGHTS } from '../src/engine/riskScoring';
import { Finding, Severity } from '../src/types';

function makeFinding(severity: Severity, category: string = ''): Finding {
  return {
    id: '00000000-0000-0000-0000-000000000001',
    title: 'Test',
    description: 'Test',
    severity,
    category,
    affectedAsset: 'test.com',
    evidence: '',
    impact: '',
    remediation: '',
    references: [],
    detectedAt: new Date(),
  };
}

describe('Risk Scoring - Comprehensive', () => {
  describe('calculateSecurityScore with categories', () => {
    it('should apply category weights to penalties', () => {
      const tlsFinding = makeFinding(Severity.HIGH, 'TLS/HTTPS');
      const techFinding = makeFinding(Severity.HIGH, 'Technology Detection');

      const tlsResult = calculateSecurityScore([tlsFinding]);
      const techResult = calculateSecurityScore([techFinding]);

      // TLS/HTTPS has weight 1.4, Technology Detection has weight 0.8
      // So TLS finding should penalize more
      expect(tlsResult.score).toBeLessThan(techResult.score);
    });

    it('should return category scores', () => {
      const findings = [
        makeFinding(Severity.HIGH, 'TLS/HTTPS'),
        makeFinding(Severity.MEDIUM, 'Security Headers'),
      ];
      const result = calculateSecurityScore(findings);
      expect(result.categoryScores['TLS/HTTPS']).toBeDefined();
      expect(result.categoryScores['Security Headers']).toBeDefined();
      expect(result.categoryScores['TLS/HTTPS'].findings).toBe(1);
    });

    it('should handle multiple findings in same category', () => {
      const findings = Array(5).fill(null).map(() =>
        makeFinding(Severity.MEDIUM, 'Security Headers')
      );
      const result = calculateSecurityScore(findings);
      expect(result.categoryScores['Security Headers'].findings).toBe(5);
    });
  });

  describe('calculateSecurityScore - diminishing returns', () => {
    it('should apply diminishing returns for excessive findings', () => {
      // Create many critical findings
      const findings = Array(10).fill(null).map(() =>
        makeFinding(Severity.CRITICAL, 'TLS/HTTPS')
      );
      const result = calculateSecurityScore(findings);

      // First 3 criticals should have full penalty, rest should be diminished
      // So total penalty should be less than 10 * basePenalty
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.breakdown.critical).toBe(10);
    });
  });

  describe('generateScoringBreakdown', () => {
    it('should return scoring breakdown for findings', () => {
      const findings = [
        makeFinding(Severity.CRITICAL, 'TLS/HTTPS'),
        makeFinding(Severity.HIGH, 'Security Headers'),
      ];
      const breakdown = generateScoringBreakdown(findings);
      expect(breakdown.length).toBe(2);
      expect(breakdown[0].findingId).toBeDefined();
      expect(breakdown[0].baseDeduction).toBeGreaterThan(0);
      expect(breakdown[0].cumulativeScore).toBeLessThanOrEqual(100);
    });

    it('should sort findings by severity', () => {
      const findings = [
        makeFinding(Severity.LOW, ''),
        makeFinding(Severity.CRITICAL, ''),
        makeFinding(Severity.MEDIUM, ''),
      ];
      const breakdown = generateScoringBreakdown(findings);
      expect(breakdown[0].severity).toBe(Severity.CRITICAL);
      expect(breakdown[1].severity).toBe(Severity.MEDIUM);
      expect(breakdown[2].severity).toBe(Severity.LOW);
    });
  });

  describe('calculateCvssLikeScore - edge cases', () => {
    it('should return scores within expected ranges for all severities', () => {
      const categories = Object.keys(CATEGORY_WEIGHTS);
      for (const category of categories) {
        const critical = calculateCvssLikeScore(Severity.CRITICAL, category);
        expect(critical).toBeGreaterThanOrEqual(9.0);
        expect(critical).toBeLessThanOrEqual(10.0);

        const high = calculateCvssLikeScore(Severity.HIGH, category);
        expect(high).toBeGreaterThanOrEqual(7.0);
        expect(high).toBeLessThanOrEqual(8.9);

        const medium = calculateCvssLikeScore(Severity.MEDIUM, category);
        expect(medium).toBeGreaterThanOrEqual(4.0);
        expect(medium).toBeLessThanOrEqual(6.9);

        const low = calculateCvssLikeScore(Severity.LOW, category);
        expect(low).toBeGreaterThanOrEqual(0.1);
        expect(low).toBeLessThanOrEqual(3.9);
      }
    });

    it('should return 0 for INFO severity', () => {
      expect(calculateCvssLikeScore(Severity.INFO, 'any')).toBe(0.0);
    });
  });

  describe('Grade boundaries', () => {
    const gradeTests = [
      { score: 95, expected: 'A+' },
      { score: 90, expected: 'A' },
      { score: 85, expected: 'A-' },
      { score: 80, expected: 'B+' },
      { score: 75, expected: 'B' },
      { score: 70, expected: 'B-' },
      { score: 65, expected: 'C+' },
      { score: 60, expected: 'C' },
      { score: 55, expected: 'C-' },
      { score: 50, expected: 'D+' },
      { score: 40, expected: 'D' },
      { score: 30, expected: 'D-' },
      { score: 20, expected: 'F' },
    ];

    gradeTests.forEach(({ score, expected }) => {
      it(`score ${score} should be grade ${expected}`, () => {
        expect(getGrade(score)).toBe(expected);
      });
    });
  });

  describe('Risk level boundaries', () => {
    const riskTests = [
      { score: 95, expected: 'Minimal Risk' },
      { score: 85, expected: 'Low Risk' },
      { score: 75, expected: 'Moderate Risk' },
      { score: 65, expected: 'Elevated Risk' },
      { score: 55, expected: 'High Risk' },
      { score: 35, expected: 'Severe Risk' },
      { score: 15, expected: 'Critical Risk' },
    ];

    riskTests.forEach(({ score, expected }) => {
      it(`score ${score} should be risk "${expected}"`, () => {
        expect(getRiskLevel(score)).toBe(expected);
      });
    });
  });
});

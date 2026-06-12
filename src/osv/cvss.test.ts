import { describe, expect, it } from 'vitest';
import { cvssBaseScore, severityFromScore } from './client';

describe('cvssBaseScore', () => {
  // Reference vectors validated against the FIRST.org calculator.
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8], // classic RCE
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0], // log4shell
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1], // reflected XSS
    ['CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
  ])('%s → %d', (vector, expected) => {
    expect(cvssBaseScore(vector)).toBeCloseTo(expected, 1);
  });

  it('returns undefined for garbage', () => {
    expect(cvssBaseScore('CVSS:2.0/AV:N')).toBeUndefined();
    expect(cvssBaseScore('')).toBeUndefined();
  });
});

describe('severityFromScore', () => {
  it('buckets correctly', () => {
    expect(severityFromScore(9.8)).toBe('critical');
    expect(severityFromScore(7.5)).toBe('high');
    expect(severityFromScore(5.0)).toBe('medium');
    expect(severityFromScore(2.1)).toBe('low');
  });
});

import { describe, expect, it } from 'vitest';
import { computeScore } from './score';
import type { Finding, Severity } from '../types';

const mk = (severity: Severity, n: number): Finding[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `F${i}`,
    ruleId: 'test',
    title: 't',
    category: 'secret',
    severity,
    file: 'a',
    message: 'm',
    confidence: 'high',
  }));

describe('computeScore', () => {
  it('gives a clean repo 100 / A+ / FORTRESS', () => {
    const s = computeScore([]);
    expect(s.value).toBe(100);
    expect(s.grade).toBe('A+');
    expect(s.threatLevel).toBe('FORTRESS');
  });

  it('punishes criticals hard', () => {
    const s = computeScore(mk('critical', 2));
    expect(s.value).toBeLessThan(60);
    expect(s.bySeverity.critical).toBe(2);
  });

  it('applies diminishing returns', () => {
    const five = computeScore(mk('low', 5)).value;
    const fifty = computeScore(mk('low', 50)).value;
    expect(five).toBeGreaterThan(fifty);
    expect(fifty).toBeGreaterThan(80); // 50 lows shouldn't nuke the score
  });

  it('never goes below zero', () => {
    const s = computeScore(mk('critical', 50));
    expect(s.value).toBeGreaterThanOrEqual(0);
    expect(s.grade).toBe('F');
  });

  it('info findings barely matter', () => {
    expect(computeScore(mk('info', 10)).value).toBeGreaterThanOrEqual(98);
  });
});

describe('test-context weighting', () => {
  it('weighs test-path findings far lighter than production ones', () => {
    const real = computeScore(mk('high', 4));
    const test = computeScore(mk('high', 4).map((f) => ({ ...f, testContext: true })));
    expect(test.value).toBeGreaterThan(real.value + 10);
  });
});

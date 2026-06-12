/** Security posture scoring (single source of truth, applied after OSV merge). */
import type { Category, Finding, ScoreCard, Severity } from '../types';

const WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 11,
  medium: 4,
  low: 1,
  info: 0.2,
};

/** Diminishing returns: the Nth finding of a severity counts less than the 1st. */
const DIMINISH: Record<Severity, number> = {
  critical: 0.97,
  high: 0.94,
  medium: 0.92,
  low: 0.93,
  info: 0.75,
};

export function computeScore(findings: Finding[]): ScoreCard {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory: Partial<Record<Category, number>> = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }

  // Per-severity geometric decay (w, w·d, w·d², …). Real-context findings are
  // ordered first so they absorb the heavy early weights; findings that live
  // under test/example/docs paths additionally count at a fraction — a test
  // fixture key is worth attention, not a failing grade.
  const TEST_WEIGHT = 0.4;
  let penalty = 0;
  for (const sev of Object.keys(WEIGHTS) as Severity[]) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    group.sort((a, b) => Number(a.testContext ?? false) - Number(b.testContext ?? false));
    const w = WEIGHTS[sev];
    const d = DIMINISH[sev];
    group.forEach((f, k) => {
      penalty += w * Math.pow(d, k) * (f.testContext ? TEST_WEIGHT : 1);
    });
  }

  const value = Math.max(0, Math.round(100 - Math.min(100, penalty)));
  return { value, grade: gradeFor(value), threatLevel: threatLevelFor(value, bySeverity), bySeverity, byCategory };
}

function gradeFor(v: number): string {
  if (v >= 95) return 'A+';
  if (v >= 88) return 'A';
  if (v >= 78) return 'B';
  if (v >= 65) return 'C';
  if (v >= 50) return 'D';
  if (v >= 30) return 'E';
  return 'F';
}

function threatLevelFor(v: number, bySev: Record<Severity, number>): string {
  if (bySev.critical > 0 && v < 40) return 'CRITICAL BREACH';
  if (v >= 95) return 'FORTRESS';
  if (v >= 85) return 'GUARDED';
  if (v >= 70) return 'ELEVATED';
  if (v >= 50) return 'EXPOSED';
  if (v >= 30) return 'UNDER SIEGE';
  return 'CRITICAL BREACH';
}

import { describe, expect, it } from 'vitest';
import { planCity, squarify, type Rect } from './layout';
import type { FileInfo } from '../types';

const f = (path: string, size = 1000, lines = 50): FileInfo => ({ path, size, lines });

describe('squarify', () => {
  it('tiles the full rect with no overlaps and conserved area', () => {
    const items = [5, 4, 3, 2, 2, 1].map((value) => ({ value }));
    const rect: Rect = { x: 0, z: 0, w: 60, d: 40 };
    const cells = [...squarify(items, rect).values()];

    expect(cells).toHaveLength(items.length);
    const area = cells.reduce((s, c) => s + c.w * c.d, 0);
    expect(area).toBeCloseTo(60 * 40, 4);

    for (const c of cells) {
      expect(c.x).toBeGreaterThanOrEqual(rect.x - 1e-9);
      expect(c.z).toBeGreaterThanOrEqual(rect.z - 1e-9);
      expect(c.x + c.w).toBeLessThanOrEqual(rect.x + rect.w + 1e-9);
      expect(c.z + c.d).toBeLessThanOrEqual(rect.z + rect.d + 1e-9);
    }
    for (let i = 0; i < cells.length; i++) {
      for (let j = i + 1; j < cells.length; j++) {
        const a = cells[i];
        const b = cells[j];
        const overlapX = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        const overlapZ = Math.min(a.z + a.d, b.z + b.d) - Math.max(a.z, b.z);
        expect(Math.min(overlapX, overlapZ)).toBeLessThanOrEqual(1e-9);
      }
    }
  });

  it('keeps aspect ratios civilized', () => {
    const items = Array.from({ length: 24 }, (_, i) => ({ value: 1 + (i % 5) }));
    const cells = [...squarify(items, { x: 0, z: 0, w: 100, d: 100 }).values()];
    for (const c of cells) {
      const aspect = Math.max(c.w / c.d, c.d / c.w);
      expect(aspect).toBeLessThan(8);
    }
  });
});

describe('planCity', () => {
  it('creates one building per file and districts per top-level dir', () => {
    const files = [
      f('README.md'),
      f('src/index.ts', 4000, 200),
      f('src/util/helpers.ts', 2000, 90),
      f('lib/core.go', 9000, 400),
      f('lib/net/client.go'),
    ];
    const plan = planCity(files);
    expect(plan.buildings).toHaveLength(5);
    const districtNames = plan.districts.filter((d) => d.depth === 1).map((d) => d.name);
    expect(districtNames).toContain('src');
    expect(districtNames).toContain('lib');

    // every building sits inside the city bounds
    for (const b of plan.buildings) {
      expect(Math.abs(b.x)).toBeLessThanOrEqual(plan.size / 2);
      expect(Math.abs(b.z)).toBeLessThanOrEqual(plan.size / 2);
      expect(b.h).toBeGreaterThan(0);
      expect(b.w).toBeGreaterThan(0);
    }
  });

  it('rolls district risk up from contained files', () => {
    const risky: FileInfo = { ...f('src/auth/token.ts'), maxSeverity: 'critical', findings: 2 };
    const plan = planCity([f('src/ok.ts'), risky, f('docs/a.md')]);
    const src = plan.districts.find((d) => d.path === 'src');
    expect(src?.risk).toBe('critical');
    const docs = plan.districts.find((d) => d.path === 'docs');
    expect(docs?.risk).toBeUndefined();
  });

  it('handles a thousand files without overlap explosions', () => {
    const files = Array.from({ length: 1000 }, (_, i) =>
      f(`pkg${i % 12}/mod${i % 30}/file${i}.go`, 500 + (i % 97) * 300, 30 + (i % 211)),
    );
    const plan = planCity(files);
    expect(plan.buildings).toHaveLength(1000);
    expect(plan.size).toBeGreaterThan(100);
  });
});

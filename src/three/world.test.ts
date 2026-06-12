// @vitest-environment jsdom
/**
 * Headless scene-graph smoke test: builds the full 3D world (city + threat
 * actors) from a synthetic analysis and exercises the animation/pick paths.
 * No WebGL needed — this validates construction logic, not pixels.
 */
import { describe, expect, it } from 'vitest';
import * as THREE from 'three';
import { planCity } from '../city/layout';
import { CityView } from './city';
import { ThreatLayer } from './threats';
import type { FileInfo, Finding } from '../types';

function world() {
  const files: FileInfo[] = [
    { path: 'src/index.ts', size: 4000, lines: 160, lang: 'TypeScript', findings: 2, maxSeverity: 'critical' },
    { path: 'src/util/db.ts', size: 2500, lines: 90, lang: 'TypeScript', findings: 1, maxSeverity: 'high' },
    { path: 'api/server.py', size: 7000, lines: 300, lang: 'Python' },
    { path: 'README.md', size: 1200, lines: 40, lang: 'Markdown' },
    { path: 'assets/logo.png', size: 50000, lines: 0, binary: true },
    { path: 'package.json', size: 800, lines: 30, lang: 'JSON', findings: 1, maxSeverity: 'high' },
  ];
  const findings: Finding[] = [
    { id: 'F0001', ruleId: 'secret.github-token', title: 'GitHub token', category: 'secret', severity: 'critical', file: 'src/index.ts', line: 3, message: 'm', confidence: 'high' },
    { id: 'F0002', ruleId: 'js.eval', title: 'eval', category: 'injection', severity: 'high', file: 'src/index.ts', line: 9, message: 'm', confidence: 'medium' },
    { id: 'F0003', ruleId: 'js.sql-concat', title: 'sql', category: 'injection', severity: 'high', file: 'src/util/db.ts', line: 12, message: 'm', confidence: 'medium' },
    { id: 'D0001', ruleId: 'osv.vulnerable-dependency', title: 'lodash', category: 'dependency', severity: 'high', file: 'package.json', line: 0, message: 'm', confidence: 'high' },
    { id: 'F0004', ruleId: 'repo.no-license', title: 'no license', category: 'hygiene', severity: 'info', file: '', message: 'm', confidence: 'high' },
  ];
  const plan = planCity(files);
  const city = new CityView(plan);
  const threats = new ThreatLayer(findings, city);
  return { plan, city, threats, files, findings };
}

describe('3D world construction', () => {
  it('builds a city with buildings, districts and effects', () => {
    const { city, plan } = world();
    expect(plan.buildings).toHaveLength(6);
    expect(city.group.children.length).toBeGreaterThan(5);
    expect(city.roofOf('src/index.ts')).toBeInstanceOf(THREE.Vector3);
    expect(city.roofOf('nope.ts')).toBeNull();
    expect(city.plotOf('api/server.py')!.h).toBeGreaterThan(2);
  });

  it('spawns one actor per (file × category) cluster incl. repo-level', () => {
    const { threats } = world();
    // clusters: (index.ts,secret) (index.ts,injection) (db.ts,injection)
    //           (package.json,dependency) ('' ,hygiene)
    expect(threats.actors).toHaveLength(5);
    const cats = threats.actors.map((a) => a.category).sort();
    expect(cats).toEqual(['dependency', 'hygiene', 'injection', 'injection', 'secret'].sort());
    const secret = threats.actors.find((a) => a.category === 'secret')!;
    expect(secret.severity).toBe('critical');
    expect(secret.group.position.y).toBeGreaterThan(0);
  });

  it('animates without exploding and respects filters', () => {
    const { city, threats } = world();
    const cam = new THREE.PerspectiveCamera();
    for (let i = 0; i < 20; i++) {
      city.tick({ t: i * 0.16, dt: 0.016, camera: cam });
      threats.tick({ t: i * 0.16, dt: 0.016, camera: cam });
    }
    threats.applyFilter(new Set(['secret']), null);
    expect(threats.actors.filter((a) => a.group.visible)).toHaveLength(1);
    threats.applyFilter(null, new Set(['critical']));
    expect(threats.actors.filter((a) => a.group.visible)).toHaveLength(1);
    threats.applyFilter(null, null);
    expect(threats.actors.filter((a) => a.group.visible)).toHaveLength(5);
  });

  it('supports picking via rays', () => {
    const { city, threats } = world();
    const plot = city.plotOf('src/index.ts')!;
    const ray = new THREE.Raycaster(
      new THREE.Vector3(plot.x, 500, plot.z),
      new THREE.Vector3(0, -1, 0),
    );
    const hit = city.pick(ray);
    expect(hit?.file.path).toBe('src/index.ts');

    const actor = threats.actors.find((a) => a.file === 'src/index.ts')!;
    const ray2 = new THREE.Raycaster(
      actor.group.position.clone().add(new THREE.Vector3(0, 0, 120)),
      new THREE.Vector3(0, 0, -1),
    );
    expect(threats.pick(ray2)).toBeTruthy();
    expect(threats.actorForFinding('F0001')?.category).toBe('secret');
  });

  it('highlight + selection survives unknown paths', () => {
    const { city } = world();
    city.highlight('src/index.ts');
    city.highlight('does/not/exist.ts');
    city.highlight(null);
  });
});

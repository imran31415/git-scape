/**
 * Threat actors: animated 3D antagonists hovering over compromised buildings.
 * One actor per (file × category) cluster, with a beam locked onto the roof.
 */
import * as THREE from 'three';
import { SEVERITY_COLOR, severityRank, type Category, type Finding, type Severity } from '../types';
import type { CityView } from './city';
import type { FrameCtx } from './scene';

const MAX_ACTORS = 130;

const SEV_SCALE: Record<Severity, number> = {
  critical: 1.6,
  high: 1.3,
  medium: 1.0,
  low: 0.8,
  info: 0.62,
};

export interface ThreatActor {
  key: string;
  category: Category;
  severity: Severity;
  file: string;
  findings: Finding[];
  group: THREE.Group;
  basePos: THREE.Vector3;
  phase: number;
  radius: number; // pick sphere
  parts: {
    spinner?: THREE.Object3D;
    bobber?: THREE.Object3D;
    beamMat?: THREE.MeshBasicMaterial;
    ringMat?: THREE.MeshBasicMaterial;
    ring?: THREE.Mesh;
    wormSegs?: THREE.Object3D[];
  };
}

let haloTexture: THREE.Texture | null = null;
function getHaloTexture(): THREE.Texture {
  if (haloTexture) return haloTexture;
  const c = document.createElement('canvas');
  c.width = c.height = 128;
  const g = c.getContext('2d');
  if (!g) return (haloTexture = new THREE.Texture()); // headless test environments
  const grad = g.createRadialGradient(64, 64, 4, 64, 64, 64);
  grad.addColorStop(0, 'rgba(255,255,255,0.9)');
  grad.addColorStop(0.35, 'rgba(255,255,255,0.28)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  haloTexture = new THREE.CanvasTexture(c);
  return haloTexture;
}

function countChip(n: number, color: string): THREE.Sprite {
  const c = document.createElement('canvas');
  c.width = 96;
  c.height = 64;
  const g = c.getContext('2d');
  if (!g) return new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true }));
  g.font = '700 44px "JetBrains Mono", ui-monospace, monospace';
  g.fillStyle = color;
  g.textAlign = 'center';
  g.fillText(`×${n}`, 48, 46);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  s.scale.set(4.6, 3, 1);
  return s;
}

const dark = (hex: number) =>
  new THREE.MeshStandardMaterial({ color: 0x12121c, roughness: 0.4, metalness: 0.8, emissive: hex, emissiveIntensity: 0.18 });
const glow = (hex: number) => new THREE.MeshBasicMaterial({ color: hex });

/** Builds the per-category silhouette (≈unit scale; scaled by severity later). */
function buildBody(category: Category, color: number, parts: ThreatActor['parts']): THREE.Group {
  const g = new THREE.Group();
  const spinner = new THREE.Group();
  g.add(spinner);
  parts.spinner = spinner;

  switch (category) {
    case 'secret': {
      // Credential Phantom — hooded wraith with burning eyes and a stolen key
      const hood = new THREE.Mesh(new THREE.ConeGeometry(1.5, 3.4, 8, 1, true), dark(color));
      hood.position.y = 0.4;
      const eyeGeo = new THREE.SphereGeometry(0.17, 8, 8);
      const eyeL = new THREE.Mesh(eyeGeo, glow(color));
      const eyeR = new THREE.Mesh(eyeGeo, glow(color));
      eyeL.position.set(-0.42, 0.8, 1.05);
      eyeR.position.set(0.42, 0.8, 1.05);
      const key = new THREE.Group();
      const shaft = new THREE.Mesh(new THREE.BoxGeometry(0.16, 1.5, 0.16), glow(color));
      const bow = new THREE.Mesh(new THREE.TorusGeometry(0.38, 0.1, 8, 16), glow(color));
      bow.position.y = 0.95;
      const tooth = new THREE.Mesh(new THREE.BoxGeometry(0.42, 0.14, 0.14), glow(color));
      tooth.position.set(0.2, -0.6, 0);
      key.add(shaft, bow, tooth);
      key.position.set(0, -1.3, 0.6);
      key.scale.setScalar(0.9);
      spinner.add(key);
      g.add(hood, eyeL, eyeR);
      break;
    }
    case 'injection': {
      // Injection Wraith — spiked core with a syringe stinger aimed down
      const core = new THREE.Mesh(new THREE.OctahedronGeometry(1.2, 0), dark(color));
      g.add(core);
      for (let i = 0; i < 6; i++) {
        const spike = new THREE.Mesh(new THREE.ConeGeometry(0.16, 1.0, 6), glow(color));
        const a = (i / 6) * Math.PI * 2;
        spike.position.set(Math.cos(a) * 1.35, 0, Math.sin(a) * 1.35);
        spike.rotation.z = Math.PI / 2;
        spike.rotation.y = -a;
        spinner.add(spike);
      }
      const stinger = new THREE.Mesh(new THREE.ConeGeometry(0.22, 2.4, 8), glow(color));
      stinger.rotation.x = Math.PI;
      stinger.position.y = -2.0;
      g.add(stinger);
      break;
    }
    case 'xss': {
      // Script Specter — glass tetra ghost with code shards orbiting
      const body = new THREE.Mesh(
        new THREE.TetrahedronGeometry(1.5, 0),
        new THREE.MeshStandardMaterial({
          color: 0x140a20, roughness: 0.2, metalness: 0.4,
          emissive: color, emissiveIntensity: 0.35, transparent: true, opacity: 0.92,
        }),
      );
      body.rotation.x = Math.PI * 0.18;
      g.add(body);
      for (let i = 0; i < 3; i++) {
        const shard = new THREE.Mesh(new THREE.PlaneGeometry(0.7, 0.42), glow(color));
        (shard.material as THREE.MeshBasicMaterial).side = THREE.DoubleSide;
        const a = (i / 3) * Math.PI * 2;
        shard.position.set(Math.cos(a) * 1.9, (i - 1) * 0.5, Math.sin(a) * 1.9);
        shard.rotation.y = a;
        spinner.add(shard);
      }
      break;
    }
    case 'crypto': {
      // Cipher Breaker — shattered padlock
      const shackleMat = glow(color);
      const shackle = new THREE.Mesh(new THREE.TorusGeometry(0.85, 0.17, 10, 24, Math.PI * 1.25), shackleMat);
      shackle.position.y = 0.95;
      shackle.rotation.z = Math.PI * 0.22;
      const lockBody = new THREE.Mesh(new THREE.BoxGeometry(1.7, 1.5, 0.7), dark(color));
      lockBody.position.y = -0.4;
      const keyhole = new THREE.Mesh(new THREE.CircleGeometry(0.22, 12), glow(color));
      keyhole.position.set(0, -0.35, 0.37);
      g.add(shackle, lockBody, keyhole);
      parts.spinner = shackle; // wobbles instead of full spin
      break;
    }
    case 'network': {
      // Wire Eavesdropper — listening dish with a blinking mast
      const dish = new THREE.Mesh(
        new THREE.SphereGeometry(1.3, 16, 12, 0, Math.PI * 2, 0, Math.PI * 0.42),
        new THREE.MeshStandardMaterial({ color: 0x12121c, roughness: 0.35, metalness: 0.9, emissive: color, emissiveIntensity: 0.2, side: THREE.DoubleSide }),
      );
      dish.rotation.x = Math.PI; // bowl facing down toward the city
      dish.position.y = 0.4;
      const mast = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.07, 1.8), dark(color));
      mast.position.y = 1.1;
      const tip = new THREE.Mesh(new THREE.SphereGeometry(0.2, 8, 8), glow(color));
      tip.position.y = 2.1;
      spinner.add(dish);
      g.add(mast, tip);
      break;
    }
    case 'cicd': {
      // Pipeline Saboteur — interlocked broken gears
      const mkGear = (r: number) => {
        const gear = new THREE.Group();
        const ring = new THREE.Mesh(new THREE.TorusGeometry(r, 0.18, 8, 20), dark(color));
        gear.add(ring);
        for (let i = 0; i < 7; i++) {
          const tooth = new THREE.Mesh(new THREE.BoxGeometry(0.3, 0.3, 0.22), glow(color));
          const a = (i / 7) * Math.PI * 2;
          tooth.position.set(Math.cos(a) * (r + 0.22), Math.sin(a) * (r + 0.22), 0);
          gear.add(tooth);
        }
        return gear;
      };
      const g1 = mkGear(0.95);
      const g2 = mkGear(0.6);
      g2.position.set(1.45, -0.7, 0);
      spinner.add(g1);
      g.add(g2);
      parts.wormSegs = [g2]; // counter-rotates in tick
      break;
    }
    case 'dependency': {
      // Supply-Chain Parasite — segmented worm coiling downward
      const segs: THREE.Object3D[] = [];
      const n = 6;
      for (let i = 0; i < n; i++) {
        const r = 0.62 - i * 0.06;
        const seg = new THREE.Mesh(
          new THREE.SphereGeometry(r, 12, 10),
          i === 0
            ? new THREE.MeshStandardMaterial({ color: 0x18101c, roughness: 0.35, metalness: 0.7, emissive: color, emissiveIntensity: 0.55 })
            : dark(color),
        );
        g.add(seg);
        segs.push(seg);
      }
      const eye = new THREE.Mesh(new THREE.SphereGeometry(0.16, 8, 8), glow(0xffffff));
      eye.position.set(0.3, 0.1, 0.5);
      segs[0].add(eye);
      parts.wormSegs = segs;
      break;
    }
    case 'config': {
      // Config Goblin — cracked control cube with sparking nodes
      const cube = new THREE.Mesh(new THREE.BoxGeometry(1.6, 1.6, 1.6), dark(color));
      cube.rotation.set(0.5, 0.6, 0.2);
      g.add(cube);
      for (const [x, y, z] of [[1, 1, 1], [-1, 1, -1], [1, -1, -1], [-1, -1, 1]] as const) {
        const node = new THREE.Mesh(new THREE.SphereGeometry(0.16, 8, 8), glow(color));
        node.position.set(x * 1.05, y * 1.05, z * 1.05);
        spinner.add(node);
      }
      break;
    }
    default: {
      // Entropy Rat (hygiene) — dim drifting shard
      const shard = new THREE.Mesh(new THREE.OctahedronGeometry(0.9, 0), dark(color));
      shard.scale.y = 1.6;
      g.add(shard);
      const tip = new THREE.Mesh(new THREE.OctahedronGeometry(0.18, 0), glow(color));
      tip.position.y = 1.2;
      g.add(tip);
    }
  }

  // shared halo
  const halo = new THREE.Sprite(
    new THREE.SpriteMaterial({
      map: getHaloTexture(),
      color,
      transparent: true,
      opacity: 0.5,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    }),
  );
  halo.scale.setScalar(7);
  g.add(halo);
  return g;
}

export class ThreatLayer {
  readonly group = new THREE.Group();
  readonly actors: ThreatActor[] = [];
  private sphere = new THREE.Sphere();

  constructor(findings: Finding[], city: CityView) {
    // cluster findings per (file, category)
    const clusters = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = `${f.file}\x00${f.category}`;
      let arr = clusters.get(key);
      if (!arr) clusters.set(key, (arr = []));
      arr.push(f);
    }
    const ordered = [...clusters.entries()].sort((a, b) => {
      const sa = Math.max(...a[1].map((f) => severityRank(f.severity)));
      const sb = Math.max(...b[1].map((f) => severityRank(f.severity)));
      return sb - sa || b[1].length - a[1].length;
    });

    const perBuilding = new Map<string, number>();
    for (const [key, clusterFindings] of ordered.slice(0, MAX_ACTORS)) {
      const [file, category] = key.split('\x00') as [string, Category];
      const severity = clusterFindings.reduce<Severity>(
        (acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc),
        'info',
      );
      const color = SEVERITY_COLOR[severity];
      const scale = SEV_SCALE[severity];

      let anchor: THREE.Vector3;
      let roofY = 0;
      const plot = file ? city.plotOf(file) : null;
      if (plot) {
        roofY = plot.h;
        const siblings = perBuilding.get(file) ?? 0;
        perBuilding.set(file, siblings + 1);
        const jitterA = siblings * 2.4 + (hashStr(file) % 628) / 100;
        const jitterR = siblings === 0 ? 0 : Math.max(plot.w, plot.d) * 0.55 + siblings * 1.2;
        anchor = new THREE.Vector3(
          plot.x + Math.cos(jitterA) * jitterR,
          roofY + 7 + scale * 3.2,
          plot.z + Math.sin(jitterA) * jitterR,
        );
      } else {
        // repo-level findings circle the city outskirts
        const a = (hashStr(key) % 628) / 100;
        const r = city.size * 0.62;
        anchor = new THREE.Vector3(Math.cos(a) * r, 16, Math.sin(a) * r);
      }

      const parts: ThreatActor['parts'] = {};
      const body = buildBody(category, color, parts);
      const actorGroup = new THREE.Group();
      const bobber = new THREE.Group();
      bobber.add(body);
      actorGroup.add(bobber);
      parts.bobber = bobber;
      body.scale.setScalar(scale);

      // beam to the roof
      if (plot) {
        const beamLen = anchor.y - roofY;
        const beam = new THREE.Mesh(
          new THREE.CylinderGeometry(0.16 * scale, 0.5 * scale, beamLen, 8, 1, true),
          new THREE.MeshBasicMaterial({
            color,
            transparent: true,
            opacity: 0.3,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
            side: THREE.DoubleSide,
          }),
        );
        beam.position.y = -beamLen / 2;
        beam.raycast = () => {};
        parts.beamMat = beam.material as THREE.MeshBasicMaterial;
        actorGroup.add(beam);

        const ring = new THREE.Mesh(
          new THREE.RingGeometry(0.8, 1.05, 32),
          new THREE.MeshBasicMaterial({
            color,
            transparent: true,
            opacity: 0.85,
            side: THREE.DoubleSide,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
          }),
        );
        ring.rotation.x = -Math.PI / 2;
        ring.position.y = -(anchor.y - roofY) + 0.3;
        ring.scale.setScalar(Math.max(plot.w, plot.d) * 0.62);
        ring.raycast = () => {};
        parts.ringMat = ring.material as THREE.MeshBasicMaterial;
        parts.ring = ring;
        actorGroup.add(ring);
      }

      if (clusterFindings.length > 1) {
        const chip = countChip(clusterFindings.length, '#ffffff');
        chip.position.y = 4.2 * scale;
        actorGroup.add(chip);
      }

      actorGroup.position.copy(anchor);
      this.group.add(actorGroup);
      this.actors.push({
        key,
        category,
        severity,
        file,
        findings: clusterFindings,
        group: actorGroup,
        basePos: anchor.clone(),
        phase: (hashStr(key) % 1000) / 159,
        radius: 4.4 * scale,
        parts,
      });
    }
  }

  tick(ctx: FrameCtx): void {
    const { t, dt } = ctx;
    for (const a of this.actors) {
      if (!a.group.visible) continue;
      const bob = Math.sin(t * 1.7 + a.phase) * 1.1;
      if (a.parts.bobber) a.parts.bobber.position.y = bob;
      if (a.parts.spinner) a.parts.spinner.rotation.y += dt * (a.severity === 'critical' ? 1.6 : 0.8);
      if (a.parts.beamMat) a.parts.beamMat.opacity = 0.22 + 0.16 * Math.sin(t * 5 + a.phase);
      if (a.parts.ringMat) {
        a.parts.ringMat.opacity = 0.5 + 0.35 * Math.sin(t * 3.2 + a.phase);
      }
      if (a.parts.wormSegs && a.category === 'dependency') {
        a.parts.wormSegs.forEach((seg, i) => {
          const k = t * 2 + a.phase + i * 0.85;
          seg.position.set(Math.sin(k) * 1.1, -i * 0.78 + Math.cos(k * 0.7) * 0.3, Math.cos(k) * 1.1);
        });
      } else if (a.parts.wormSegs) {
        for (const part of a.parts.wormSegs) part.rotation.z -= dt * 1.2;
      }
    }
  }

  /** Manual sphere picking (cheap + robust for ~100 animated groups). */
  pick(raycaster: THREE.Raycaster): ThreatActor | null {
    let best: ThreatActor | null = null;
    let bestDist = Infinity;
    for (const a of this.actors) {
      if (!a.group.visible) continue;
      this.sphere.set(a.group.position, a.radius);
      const hit = raycaster.ray.intersectSphere(this.sphere, new THREE.Vector3());
      if (hit) {
        const d = hit.distanceTo(raycaster.ray.origin);
        if (d < bestDist) {
          bestDist = d;
          best = a;
        }
      }
    }
    return best;
  }

  applyFilter(categories: Set<Category> | null, severities: Set<Severity> | null): void {
    for (const a of this.actors) {
      a.group.visible =
        (!categories || categories.has(a.category)) &&
        (!severities || severities.has(a.severity));
    }
  }

  actorForFinding(findingId: string): ThreatActor | undefined {
    return this.actors.find((a) => a.findings.some((f) => f.id === findingId));
  }
}

function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}

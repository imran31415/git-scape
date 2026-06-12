/** Builds the city: buildings, districts, ground, traffic, radar sweep. */
import * as THREE from 'three';
import type { CityPlan, BuildingPlot } from '../city/layout';
import { SEVERITY_COLOR, type FileInfo, type Severity } from '../types';
import type { FrameCtx } from './scene';

/** GitHub-linguist-inspired facade palette, tuned for a night city. */
const LANG_COLORS: Record<string, number> = {
  JavaScript: 0xc9b458, TypeScript: 0x3178c6, Python: 0x3572a5, Go: 0x00add8,
  Ruby: 0x96222c, Java: 0xb07219, Kotlin: 0xa97bff, PHP: 0x4f5d95,
  'C#': 0x178600, C: 0x555575, 'C++': 0xf34b7d, Rust: 0xdea584,
  Shell: 0x89e051, HTML: 0xe34c26, CSS: 0x563d7c, Vue: 0x41b883,
  Svelte: 0xff3e00, JSON: 0x4a5568, YAML: 0x6b7280, Markdown: 0x4f6d7a,
  Docker: 0x2496ed, Terraform: 0x7b42bc, SQL: 0xe38c00, Swift: 0xf05138,
  Dart: 0x00b4ab, Elixir: 0x6e4a7e, Scala: 0xc22d40, XML: 0x60737d,
  TOML: 0x9c4221, DotEnv: 0xecd078, Text: 0x4b5563, Config: 0x64748b,
};
const DEFAULT_COLOR = 0x39415e;
const BINARY_COLOR = 0x1c2133;

export interface BuildingHit {
  file: FileInfo;
  plot: BuildingPlot;
  roof: THREE.Vector3;
}

interface Bucket {
  mesh: THREE.InstancedMesh;
  plots: BuildingPlot[];
}

function makeWindowTexture(rows: number, cols: number, litRatio: number): THREE.Texture {
  const c = document.createElement('canvas');
  c.width = 64;
  c.height = 128;
  const g = c.getContext('2d');
  if (!g) return new THREE.Texture(); // headless test environments
  g.fillStyle = '#000000';
  g.fillRect(0, 0, c.width, c.height);
  const cw = c.width / cols;
  const ch = c.height / rows;
  for (let r = 0; r < rows; r++) {
    for (let col = 0; col < cols; col++) {
      if (Math.random() > litRatio) continue;
      const warm = Math.random() < 0.75;
      const a = 0.5 + Math.random() * 0.5;
      g.fillStyle = warm
        ? `rgba(255, 214, 140, ${a})`
        : `rgba(140, 220, 255, ${a})`;
      g.fillRect(col * cw + cw * 0.22, r * ch + ch * 0.25, cw * 0.56, ch * 0.5);
    }
  }
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

function makeLabelSprite(text: string, sub: string): THREE.Sprite {
  const c = document.createElement('canvas');
  const g = c.getContext('2d');
  if (!g) {
    const fallback = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true }));
    return Object.assign(fallback, { userData: { aspect: 4 } });
  }
  const pad = 18;
  g.font = '600 44px "JetBrains Mono", ui-monospace, monospace';
  const w = Math.max(g.measureText(text).width, 120) + pad * 2;
  c.width = Math.ceil(w);
  c.height = 110;
  g.font = '600 44px "JetBrains Mono", ui-monospace, monospace';
  g.fillStyle = 'rgba(150, 235, 255, 0.95)';
  g.fillText(text, pad, 50);
  g.font = '400 26px "JetBrains Mono", ui-monospace, monospace';
  g.fillStyle = 'rgba(150, 200, 235, 0.55)';
  g.fillText(sub, pad, 92);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
  const sprite = new THREE.Sprite(mat);
  const aspect = c.width / c.height;
  return Object.assign(sprite, { userData: { aspect } });
}

export class CityView {
  readonly group = new THREE.Group();
  private buckets: Bucket[] = [];
  private byPath = new Map<string, { bucket: number; index: number; plot: BuildingPlot }>();
  private shellMat: THREE.MeshBasicMaterial;
  private sweep: THREE.Mesh;
  private packets: THREE.Points;
  private packetData: Float32Array;
  private packetVel: Float32Array;
  private selectionPillar: THREE.Mesh;
  private selectionRing: THREE.Mesh;
  readonly size: number;

  constructor(private plan: CityPlan) {
    this.size = plan.size;
    const S = plan.size;

    // ---------------------------------------------------------------- ground
    const voidPlane = new THREE.Mesh(
      new THREE.PlaneGeometry(S * 14, S * 14),
      new THREE.MeshStandardMaterial({ color: 0x03040a, roughness: 1 }),
    );
    voidPlane.rotation.x = -Math.PI / 2;
    voidPlane.position.y = -1.6;
    this.group.add(voidPlane);

    const platform = new THREE.Mesh(
      new THREE.BoxGeometry(S * 1.12, 1.4, S * 1.12),
      new THREE.MeshStandardMaterial({ color: 0x070a16, roughness: 0.85, metalness: 0.25 }),
    );
    platform.position.y = -0.7;
    this.group.add(platform);

    const grid = new THREE.GridHelper(S * 1.1, Math.round(S / 11), 0x16315a, 0x0b1730);
    (grid.material as THREE.Material).transparent = true;
    (grid.material as THREE.Material).opacity = 0.42;
    grid.position.y = 0.02;
    this.group.add(grid);

    // ------------------------------------------------------------- districts
    const curbGeo = new THREE.BoxGeometry(1, 1, 1);
    for (const d of plan.districts.filter((x) => x.depth === 1)) {
      const { x, z, w, d: dd } = d.rect;
      const riskColor = d.risk ? SEVERITY_COLOR[d.risk] : 0x0e7490;

      const pad = new THREE.Mesh(
        new THREE.BoxGeometry(w, 0.5, dd),
        new THREE.MeshStandardMaterial({
          color: 0x0a0e1e,
          roughness: 0.9,
          metalness: 0.3,
        }),
      );
      pad.position.set(x + w / 2, 0.25, z + dd / 2);
      this.group.add(pad);

      const curbMat = new THREE.MeshBasicMaterial({ color: riskColor });
      const th = 0.34;
      const mkCurb = (cx: number, cz: number, sx: number, sz: number) => {
        const m = new THREE.Mesh(curbGeo, curbMat);
        m.scale.set(sx, 0.22, sz);
        m.position.set(cx, 0.62, cz);
        this.group.add(m);
      };
      mkCurb(x + w / 2, z + th / 2, w, th);
      mkCurb(x + w / 2, z + dd - th / 2, w, th);
      mkCurb(x + th / 2, z + dd / 2, th, dd - 2 * th);
      mkCurb(x + w - th / 2, z + dd / 2, th, dd - 2 * th);

      if (w * dd > S * S * 0.004) {
        const label = makeLabelSprite(d.name, `${d.fileCount} files`);
        const aspect = (label.userData as { aspect: number }).aspect;
        const scale = Math.min(Math.max(w * 0.34, 7), 26);
        label.scale.set(scale, scale / aspect, 1);
        label.position.set(x + w / 2, 3.4 + scale * 0.16, z + dd / 2);
        this.group.add(label);
      }
    }

    // ------------------------------------------------------------- buildings
    const heightBuckets: Array<{ test: (h: number) => boolean; rows: number; lit: number }> = [
      { test: (h) => h < 8, rows: 6, lit: 0.34 },
      { test: (h) => h < 22, rows: 12, lit: 0.4 },
      { test: () => true, rows: 20, lit: 0.46 },
    ];
    const boxGeo = new THREE.BoxGeometry(1, 1, 1);
    boxGeo.translate(0, 0.5, 0);

    const roofMat = new THREE.MeshStandardMaterial({ color: 0x10141f, roughness: 0.6, metalness: 0.5 });
    const tmpMatrix = new THREE.Matrix4();
    const tmpColor = new THREE.Color();

    heightBuckets.forEach((spec, bi) => {
      const plots = plan.buildings.filter(
        (b) => spec.test(b.h) && !heightBuckets.slice(0, bi).some((s) => s.test(b.h)),
      );
      if (plots.length === 0) {
        this.buckets.push({ mesh: new THREE.InstancedMesh(boxGeo, roofMat, 0), plots: [] });
        return;
      }
      const sideMat = new THREE.MeshStandardMaterial({
        color: 0xffffff,
        roughness: 0.72,
        metalness: 0.35,
        emissive: 0xffffff,
        emissiveMap: makeWindowTexture(spec.rows, 4, spec.lit),
        emissiveIntensity: 0.5,
      });
      const mats = [sideMat, sideMat, roofMat, roofMat, sideMat, sideMat];
      const mesh = new THREE.InstancedMesh(boxGeo, mats, plots.length);
      plots.forEach((p, i) => {
        // base slightly below pad tops: grounded both on pads and bare platform
        tmpMatrix.compose(
          new THREE.Vector3(p.x, 0.06, p.z),
          new THREE.Quaternion(),
          new THREE.Vector3(p.w, p.h, p.d),
        );
        mesh.setMatrixAt(i, tmpMatrix);
        const base = p.file.binary
          ? BINARY_COLOR
          : LANG_COLORS[p.file.lang ?? ''] ?? DEFAULT_COLOR;
        tmpColor.setHex(base);
        // de-saturate + dim so windows carry the night reading
        const hsl = { h: 0, s: 0, l: 0 };
        tmpColor.getHSL(hsl);
        tmpColor.setHSL(hsl.h, hsl.s * 0.62, Math.min(hsl.l * 0.5 + 0.05, 0.42));
        mesh.setColorAt(i, tmpColor);
        this.byPath.set(p.file.path, { bucket: bi, index: i, plot: p });
      });
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      // unit-box geometry bounds would mis-cull the whole skyline
      mesh.frustumCulled = false;
      this.group.add(mesh);
      this.buckets.push({ mesh, plots });
    });

    // ------------------------------------------------- risk shells (glow)
    const risky = plan.buildings.filter((b) => b.file.maxSeverity);
    this.shellMat = new THREE.MeshBasicMaterial({
      transparent: true,
      opacity: 0.22,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    if (risky.length > 0) {
      const shellGeo = new THREE.BoxGeometry(1, 1, 1);
      shellGeo.translate(0, 0.5, 0);
      const shells = new THREE.InstancedMesh(shellGeo, this.shellMat, risky.length);
      risky.forEach((p, i) => {
        tmpMatrix.compose(
          new THREE.Vector3(p.x, 0.04, p.z),
          new THREE.Quaternion(),
          new THREE.Vector3(p.w + 0.9, p.h + 1.1, p.d + 0.9),
        );
        shells.setMatrixAt(i, tmpMatrix);
        tmpColor.setHex(SEVERITY_COLOR[p.file.maxSeverity as Severity]);
        shells.setColorAt(i, tmpColor);
      });
      shells.instanceMatrix.needsUpdate = true;
      if (shells.instanceColor) shells.instanceColor.needsUpdate = true;
      shells.raycast = () => {}; // glow is not pickable
      shells.frustumCulled = false;
      this.group.add(shells);
    }

    // ------------------------------------------------------------ radar sweep
    this.sweep = new THREE.Mesh(
      new THREE.RingGeometry(0.96, 1, 128),
      new THREE.MeshBasicMaterial({
        color: 0x22d3ee,
        transparent: true,
        opacity: 0.5,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    this.sweep.rotation.x = -Math.PI / 2;
    this.sweep.position.y = 0.4;
    this.group.add(this.sweep);

    // ------------------------------------------------------------- traffic
    const N = Math.min(340, Math.max(120, Math.round(S * 0.8)));
    this.packetData = new Float32Array(N * 3);
    this.packetVel = new Float32Array(N * 2); // direction xz per packet
    const lanes: number[] = [];
    for (const d of plan.districts.filter((x) => x.depth === 1)) {
      lanes.push(d.rect.x - DIST_LANE, d.rect.x + d.rect.w + DIST_LANE);
    }
    for (let i = 0; i < N; i++) this.spawnPacket(i, lanes, true);
    const pgeo = new THREE.BufferGeometry();
    pgeo.setAttribute('position', new THREE.BufferAttribute(this.packetData, 3));
    this.packets = new THREE.Points(
      pgeo,
      new THREE.PointsMaterial({
        color: 0x67e8f9,
        size: 1.5,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        sizeAttenuation: true,
      }),
    );
    this.packets.raycast = () => {};
    this.packets.frustumCulled = false; // positions stream every frame
    this.group.add(this.packets);

    // ------------------------------------------------------------ selection
    this.selectionPillar = new THREE.Mesh(
      new THREE.CylinderGeometry(1, 1, 1, 24, 1, true),
      new THREE.MeshBasicMaterial({
        color: 0x67e8f9,
        transparent: true,
        opacity: 0.14,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    this.selectionRing = new THREE.Mesh(
      new THREE.RingGeometry(1, 1.18, 48),
      new THREE.MeshBasicMaterial({
        color: 0x67e8f9,
        transparent: true,
        opacity: 0.9,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    this.selectionRing.rotation.x = -Math.PI / 2;
    this.selectionPillar.visible = false;
    this.selectionRing.visible = false;
    this.selectionPillar.raycast = () => {};
    this.selectionRing.raycast = () => {};
    this.group.add(this.selectionPillar, this.selectionRing);

    // ---------------------------------------------------------------- stars
    const starGeo = new THREE.BufferGeometry();
    const starN = 1500;
    const starPos = new Float32Array(starN * 3);
    for (let i = 0; i < starN; i++) {
      const r = 1500 + Math.random() * 400;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI * 0.46;
      starPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      starPos[i * 3 + 1] = r * Math.cos(phi) * 0.6 + 60;
      starPos[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const stars = new THREE.Points(
      starGeo,
      new THREE.PointsMaterial({ color: 0xbcd2ff, size: 1.3, sizeAttenuation: false, transparent: true, opacity: 0.75 }),
    );
    stars.raycast = () => {};
    this.group.add(stars);
  }

  private spawnPacket(i: number, lanes: number[], randomizeAlong = false): void {
    const S = this.size;
    const half = S / 2 + 4;
    const alongX = Math.random() < 0.5;
    const lane =
      lanes.length > 0 && Math.random() < 0.7
        ? lanes[Math.floor(Math.random() * lanes.length)]
        : (Math.random() - 0.5) * S;
    const dir = Math.random() < 0.5 ? 1 : -1;
    const start = randomizeAlong ? (Math.random() - 0.5) * S : -dir * half;
    const speed = (7 + Math.random() * 16) * dir;
    if (alongX) {
      this.packetData[i * 3] = start;
      this.packetData[i * 3 + 1] = 0.7;
      this.packetData[i * 3 + 2] = lane;
      this.packetVel[i * 2] = speed;
      this.packetVel[i * 2 + 1] = 0;
    } else {
      this.packetData[i * 3] = lane;
      this.packetData[i * 3 + 1] = 0.7;
      this.packetData[i * 3 + 2] = start;
      this.packetVel[i * 2] = 0;
      this.packetVel[i * 2 + 1] = speed;
    }
  }

  /** Per-frame animation: sweep, traffic, shells, selection pulse. */
  tick(ctx: FrameCtx): void {
    const { t, dt } = ctx;
    const S = this.size;

    const cycle = (t % 9) / 9;
    const r = cycle * S * 0.78 + 2;
    this.sweep.scale.set(r, r, 1);
    (this.sweep.material as THREE.MeshBasicMaterial).opacity = 0.5 * (1 - cycle);

    this.shellMat.opacity = 0.16 + 0.1 * Math.sin(t * 2.6);

    const half = S / 2 + 6;
    const n = this.packetData.length / 3;
    const lanes: number[] = [];
    for (let i = 0; i < n; i++) {
      this.packetData[i * 3] += this.packetVel[i * 2] * dt;
      this.packetData[i * 3 + 2] += this.packetVel[i * 2 + 1] * dt;
      if (
        Math.abs(this.packetData[i * 3]) > half ||
        Math.abs(this.packetData[i * 3 + 2]) > half
      ) {
        if (lanes.length === 0) {
          for (const d of this.plan.districts.filter((x) => x.depth === 1)) {
            lanes.push(d.rect.x - DIST_LANE, d.rect.x + d.rect.w + DIST_LANE);
          }
        }
        this.spawnPacket(i, lanes);
      }
    }
    (this.packets.geometry.getAttribute('position') as THREE.BufferAttribute).needsUpdate = true;

    if (this.selectionRing.visible) {
      const k = 1 + 0.1 * Math.sin(t * 4);
      this.selectionRing.scale.setScalar(this.selectionBase * k);
    }
  }

  private selectionBase = 1;

  pick(raycaster: THREE.Raycaster): BuildingHit | null {
    for (let bi = 0; bi < this.buckets.length; bi++) {
      const bucket = this.buckets[bi];
      if (bucket.plots.length === 0) continue;
      const hits = raycaster.intersectObject(bucket.mesh, false);
      if (hits.length > 0 && hits[0].instanceId !== undefined) {
        const plot = bucket.plots[hits[0].instanceId];
        return {
          file: plot.file,
          plot,
          roof: new THREE.Vector3(plot.x, plot.h, plot.z),
        };
      }
    }
    return null;
  }

  roofOf(path: string): THREE.Vector3 | null {
    const entry = this.byPath.get(path);
    if (!entry) return null;
    return new THREE.Vector3(entry.plot.x, entry.plot.h, entry.plot.z);
  }

  plotOf(path: string): BuildingPlot | null {
    return this.byPath.get(path)?.plot ?? null;
  }

  highlight(path: string | null): void {
    if (!path) {
      this.selectionPillar.visible = false;
      this.selectionRing.visible = false;
      return;
    }
    const entry = this.byPath.get(path);
    if (!entry) return;
    const p = entry.plot;
    const radius = Math.max(p.w, p.d) * 0.78;
    this.selectionBase = radius;
    this.selectionPillar.visible = true;
    this.selectionRing.visible = true;
    this.selectionPillar.scale.set(radius, Math.max(p.h * 1.8, 30), radius);
    this.selectionPillar.position.set(p.x, Math.max(p.h * 1.8, 30) / 2, p.z);
    this.selectionRing.position.set(p.x, 0.55, p.z);
    this.selectionRing.scale.setScalar(radius);
  }
}

const DIST_LANE = 2.6;

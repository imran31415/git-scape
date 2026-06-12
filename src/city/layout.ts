/**
 * City planning: turns a repository file tree into a treemapped cityscape.
 * Directories become districts (recursively), files become buildings whose
 * footprint tracks file size and height tracks line count.
 */
import { severityRank, type FileInfo, type Severity } from '../types';

export interface Rect {
  x: number; // min corner
  z: number;
  w: number;
  d: number;
}

export interface BuildingPlot {
  file: FileInfo;
  x: number; // center
  z: number;
  w: number;
  d: number;
  h: number;
}

export interface DistrictPlot {
  name: string;
  path: string;
  rect: Rect;
  depth: number;
  fileCount: number;
  risk?: Severity;
}

export interface CityPlan {
  buildings: BuildingPlot[];
  districts: DistrictPlot[];
  size: number; // square city side length
}

interface TreeNode {
  name: string;
  path: string;
  file?: FileInfo;
  children: Map<string, TreeNode>;
  value: number;
}

const DISTRICT_PAD = 5.5;
const BLOCK_PAD = 2.0;
const BUILDING_MARGIN = 0.42;

function fileValue(f: FileInfo): number {
  const area = 5 + Math.sqrt(Math.max(0, f.size)) * 0.22 + (f.lines ?? 0) * 0.02;
  return Math.min(320, Math.max(7, area));
}

export function buildingHeight(f: FileInfo): number {
  if (f.binary) return 1.6;
  const h = 2 + (f.lines ?? 0) * 0.052 + Math.log2(f.size + 2) * 0.9;
  return Math.min(58, Math.max(2.6, h));
}

function buildTree(files: FileInfo[]): TreeNode {
  const root: TreeNode = { name: '', path: '', children: new Map(), value: 0 };
  for (const f of files) {
    const parts = f.path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const name = parts[i];
      let child = node.children.get(name);
      if (!child) {
        child = {
          name,
          path: node.path ? `${node.path}/${name}` : name,
          children: new Map(),
          value: 0,
        };
        node.children.set(name, child);
      }
      node = child;
    }
    const base = parts[parts.length - 1];
    node.children.set(base + '\x00f', {
      name: base,
      path: f.path,
      file: f,
      children: new Map(),
      value: fileValue(f),
    });
  }
  computeValues(root);
  return root;
}

function computeValues(node: TreeNode): number {
  if (node.file) return node.value;
  let sum = 0;
  for (const c of node.children.values()) sum += computeValues(c);
  node.value = sum * 1.16 + 4; // padding allowance so children always fit
  return node.value;
}

/** Classic squarified treemap (Bruls, Huizing, van Wijk). */
export function squarify<T extends { value: number }>(items: T[], rect: Rect): Map<T, Rect> {
  const out = new Map<T, Rect>();
  const total = items.reduce((s, i) => s + i.value, 0);
  if (total <= 0 || items.length === 0 || rect.w <= 0 || rect.d <= 0) return out;

  const scale = (rect.w * rect.d) / total;
  const sorted = [...items].sort((a, b) => b.value - a.value);
  let x = rect.x;
  let z = rect.z;
  let w = rect.w;
  let d = rect.d;
  let row: T[] = [];

  const worst = (areas: number[], side: number): number => {
    const sum = areas.reduce((s, a) => s + a, 0);
    const max = Math.max(...areas);
    const min = Math.min(...areas);
    const s2 = sum * sum;
    return Math.max((side * side * max) / s2, s2 / (side * side * min));
  };

  const layoutRow = (rowItems: T[]) => {
    const rowArea = rowItems.reduce((s, i) => s + i.value * scale, 0);
    const horizontal = w >= d; // place row along the shorter side
    const side = horizontal ? d : w;
    const thickness = rowArea / side;
    let offset = 0;
    for (const it of rowItems) {
      const len = (it.value * scale) / thickness;
      out.set(
        it,
        horizontal
          ? { x, z: z + offset, w: thickness, d: len }
          : { x: x + offset, z, w: len, d: thickness },
      );
      offset += len;
    }
    if (horizontal) {
      x += thickness;
      w -= thickness;
    } else {
      z += thickness;
      d -= thickness;
    }
  };

  for (const item of sorted) {
    const side = Math.min(w, d);
    if (row.length > 0) {
      const cur = row.map((i) => i.value * scale);
      const withNew = [...cur, item.value * scale];
      if (worst(withNew, side) > worst(cur, side)) {
        layoutRow(row);
        row = [];
      }
    }
    row.push(item);
  }
  if (row.length > 0) layoutRow(row);
  return out;
}

function shrink(r: Rect, pad: number): Rect {
  const p = Math.min(pad, r.w / 4, r.d / 4);
  return { x: r.x + p, z: r.z + p, w: r.w - 2 * p, d: r.d - 2 * p };
}

function layoutNode(node: TreeNode, rect: Rect, depth: number, plan: CityPlan): void {
  if (node.file) {
    const m = Math.min(BUILDING_MARGIN, rect.w * 0.14, rect.d * 0.14);
    const w = Math.max(0.9, rect.w - 2 * m);
    const d = Math.max(0.9, rect.d - 2 * m);
    plan.buildings.push({
      file: node.file,
      x: rect.x + rect.w / 2,
      z: rect.z + rect.d / 2,
      w,
      d,
      h: buildingHeight(node.file),
    });
    return;
  }

  const children = [...node.children.values()];
  if (children.length === 0) return;

  if (depth > 0) {
    plan.districts.push({
      name: node.name,
      path: node.path,
      rect,
      depth,
      fileCount: countFiles(node),
    });
  }

  const inner = shrink(rect, depth === 0 ? DISTRICT_PAD : depth === 1 ? BLOCK_PAD : BLOCK_PAD * 0.6);
  const cells = squarify(children, inner);
  for (const [child, cell] of cells) {
    layoutNode(child, cell, depth + 1, plan);
  }
}

function countFiles(node: TreeNode): number {
  if (node.file) return 1;
  let n = 0;
  for (const c of node.children.values()) n += countFiles(c);
  return n;
}

/**
 * Lay out the city. Districts get risk levels from the worst finding among
 * their files (so their neon borders warn from a distance).
 */
const MAX_BUILDINGS = 12000;

export function planCity(files: FileInfo[]): CityPlan {
  let visible = files.filter((f) => !f.path.startsWith('.git/'));
  if (visible.length > MAX_BUILDINGS) {
    // monster repos: keep every flagged file plus the largest of the rest so
    // raycasting and layout stay interactive
    visible = [...visible]
      .sort((a, b) => (b.findings ?? 0) - (a.findings ?? 0) || b.size - a.size)
      .slice(0, MAX_BUILDINGS);
  }
  const root = buildTree(visible);
  const size = Math.max(120, Math.min(560, Math.sqrt(root.value) * 1.28));
  const plan: CityPlan = { buildings: [], districts: [], size };
  layoutNode(root, { x: -size / 2, z: -size / 2, w: size, d: size }, 0, plan);

  // District risk roll-up (top-level districts only get borders, but risk is
  // useful for all).
  for (const d of plan.districts) {
    let worst: Severity | undefined;
    for (const b of plan.buildings) {
      if (!b.file.maxSeverity) continue;
      if (b.file.path === d.path || b.file.path.startsWith(d.path + '/')) {
        if (!worst || severityRank(b.file.maxSeverity) > severityRank(worst)) {
          worst = b.file.maxSeverity;
        }
      }
    }
    d.risk = worst;
  }
  return plan;
}

import * as THREE from 'three';
import './styles.css';
import { analyzeRepo, prewarmEngine } from './analysis/pipeline';
import { RepoFetchError } from './github/fetch';
import { repoSlug, type RepoTarget } from './github/parse';
import { planCity } from './city/layout';
import { SceneEngine } from './three/scene';
import { CityView } from './three/city';
import { ThreatLayer, type ThreatActor } from './three/threats';
import { Hud, CATEGORY_SYMBOL } from './ui/hud';
import { LandingScreen, LoadingScreen } from './ui/screens';
import {
  CATEGORY_INFO,
  SEVERITY_COLOR_CSS,
  type AnalysisResult,
  type Category,
  type Severity,
} from './types';

// ----------------------------------------------------------------- state --
let engine: SceneEngine | null = null;
let city: CityView | null = null;
let threats: ThreatLayer | null = null;
let result: AnalysisResult | null = null;
let loadToken = 0;

let severityFilter = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);
let categoryFilter: Set<Category> | null = null;

interface TourState {
  stops: ThreatActor[];
  index: number;
  timer: number;
}
let tour: TourState | null = null;

// ------------------------------------------------------------------- HUD --
const hud = new Hud({
  onSeverityFilter(enabled) {
    severityFilter = enabled;
    threats?.applyFilter(categoryFilter, severityFilter);
  },
  onCategoryFilter(enabled) {
    categoryFilter = enabled;
    threats?.applyFilter(categoryFilter, severityFilter);
  },
  onFindingFocus(findingId) {
    const actor = threats?.actorForFinding(findingId);
    if (actor) focusActor(actor);
    else {
      const f = result?.findings.find((x) => x.id === findingId);
      if (f?.file) {
        const roof = city?.roofOf(f.file);
        if (roof && engine) {
          city!.highlight(f.file);
          flyToPoint(roof, 40);
          const file = result!.report.files.find((x) => x.path === f.file);
          if (file) hud.showFilePanel(file);
        }
      }
    }
  },
  onHome: goHome,
  onTourPrev: () => tour && tourGo(tour.index - 1),
  onTourNext: () => tour && tourGo(tour.index + 1),
  onTourExit: exitTour,
});

const loading = new LoadingScreen(() => {
  loadToken++; // soft-cancel: in-flight work is ignored when it lands
  loading.hide();
  landing.show();
});

const landing = new LandingScreen(
  (target, token) => void analyze(target, token),
  () => prewarmEngine(),
);

// -------------------------------------------------------------- analyze --
async function analyze(target: RepoTarget, token?: string): Promise<void> {
  const myToken = ++loadToken;
  landing.hide();
  hud.hide();
  loading.show(repoSlug(target));

  try {
    const analysis = await analyzeRepo(target, token, (e) => {
      if (myToken === loadToken) loading.update(e);
    });
    if (myToken !== loadToken) return; // cancelled meanwhile
    result = analysis;
    document.title = `${repoSlug(target)} · ${analysis.score.grade} · ThreatScape`;
    const url = new URL(location.href);
    url.searchParams.set('repo', repoSlug(target));
    if (target.ref) url.searchParams.set('ref', target.ref);
    else url.searchParams.delete('ref');
    history.replaceState(null, '', url);
    buildWorld(analysis);
    loading.hide();
  } catch (err) {
    if (myToken !== loadToken) return;
    loading.hide();
    landing.show();
    if (err instanceof RepoFetchError) landing.showError(err.message, err.hint);
    else landing.showError('Analysis failed.', String((err as Error)?.message ?? err));
    console.error(err);
  }
}

// ---------------------------------------------------------------- world --
function buildWorld(analysis: AnalysisResult): void {
  if (!engine) {
    engine = new SceneEngine(document.getElementById('viewport')!);
    wirePointer(engine);
    engine.onFrame((ctx) => {
      city?.tick(ctx);
      threats?.tick(ctx);
    });
  }
  engine.clearWorld();
  exitTour();
  categoryFilter = null;
  severityFilter = new Set(['critical', 'high', 'medium', 'low', 'info']);

  const plan = planCity(analysis.report.files);
  city = new CityView(plan);
  threats = new ThreatLayer(analysis.findings, city);
  engine.scene.add(city.group);
  engine.scene.add(threats.group);

  // fog density scaled to city size so big repos stay readable
  (engine.scene.fog as THREE.FogExp2).density = 0.62 / plan.size;

  hud.show(analysis);

  // cinematic approach
  const S = plan.size;
  engine.camera.position.set(S * 1.9, S * 1.5, S * 2.4);
  engine.controls.target.set(0, 0, 0);
  engine.autoOrbit = false;
  void engine.flyTo(overviewPos(), new THREE.Vector3(0, 0, 0), 2700);
}

function overviewPos(): THREE.Vector3 {
  const S = city?.size ?? 200;
  return new THREE.Vector3(S * 0.02, S * 0.95, S * 1.18);
}

function goHome(): void {
  loadToken++;
  exitTour();
  hud.hide();
  landing.show();
  const url = new URL(location.href);
  url.searchParams.delete('repo');
  url.searchParams.delete('ref');
  history.replaceState(null, '', url);
}

// -------------------------------------------------------------- pointing --
function wirePointer(eng: SceneEngine): void {
  let downAt: { x: number; y: number } | null = null;
  let hoverThrottle = 0;

  eng.canvas.addEventListener('pointerdown', (ev) => {
    downAt = { x: ev.clientX, y: ev.clientY };
  });

  eng.canvas.addEventListener('pointerup', (ev) => {
    if (!downAt) return;
    const moved = Math.hypot(ev.clientX - downAt.x, ev.clientY - downAt.y);
    downAt = null;
    if (moved > 6 || !city || !threats) return;

    const ray = eng.raycastFromEvent(ev);
    const actor = threats.pick(ray);
    const building = city.pick(ray);
    // prefer whichever is closer to the camera
    if (actor && (!building || actorDist(actor, ray) < building.roof.distanceTo(ray.ray.origin))) {
      focusActor(actor, false);
      return;
    }
    if (building) {
      city.highlight(building.file.path);
      hud.showFilePanel(building.file);
      return;
    }
    city.highlight(null);
    if (hud.panelOpen) hud.closePanel();
  });

  eng.canvas.addEventListener('dblclick', (ev) => {
    if (!city) return;
    const hit = city.pick(eng.raycastFromEvent(ev));
    if (hit) flyToPoint(hit.roof, Math.max(30, hit.plot.h * 2.2));
  });

  eng.canvas.addEventListener('pointermove', (ev) => {
    const now = performance.now();
    if (now - hoverThrottle < 40 || !city || !threats) return;
    hoverThrottle = now;
    const ray = eng.raycastFromEvent(ev);
    const actor = threats.pick(ray);
    if (actor) {
      eng.canvas.style.cursor = 'pointer';
      const info = CATEGORY_INFO[actor.category];
      hud.showTooltip(
        `<div class="tt-title">${CATEGORY_SYMBOL[actor.category]} ${info.actor}</div>
         <div class="tt-sub">${actor.file || 'repository-level'}</div>
         <div class="tt-warn" style="color:${SEVERITY_COLOR_CSS[actor.severity]}">${actor.findings.length} finding${actor.findings.length === 1 ? '' : 's'} · worst: ${actor.severity}</div>`,
        ev.clientX,
        ev.clientY,
      );
      return;
    }
    const hit = city.pick(ray);
    if (hit) {
      eng.canvas.style.cursor = 'pointer';
      const f = hit.file;
      hud.showTooltip(
        `<div class="tt-title">${f.path}</div>
         <div class="tt-sub">${f.lang ?? 'unknown'} · ${f.lines.toLocaleString()} lines</div>
         ${f.findings ? `<div class="tt-warn" style="color:${SEVERITY_COLOR_CSS[f.maxSeverity ?? 'info']}">⚠ ${f.findings} finding${f.findings === 1 ? '' : 's'}</div>` : ''}`,
        ev.clientX,
        ev.clientY,
      );
      return;
    }
    eng.canvas.style.cursor = '';
    hud.hideTooltip();
  });

  eng.canvas.addEventListener('pointerleave', () => hud.hideTooltip());
}

function actorDist(actor: ThreatActor, ray: THREE.Raycaster): number {
  return actor.group.position.distanceTo(ray.ray.origin);
}

function flyToPoint(point: THREE.Vector3, dist: number): Promise<void> {
  if (!engine) return Promise.resolve();
  const dir = engine.camera.position.clone().sub(point);
  dir.y = Math.max(dir.y, 1);
  dir.normalize().multiplyScalar(dist);
  dir.y = Math.max(dir.y, dist * 0.55);
  return engine.flyTo(point.clone().add(dir), point, 1400);
}

function focusActor(actor: ThreatActor, fly = true): void {
  if (actor.file && city) city.highlight(actor.file);
  hud.showActorPanel(actor);
  if (fly) void flyToPoint(actor.group.position, 34);
}

// ----------------------------------------------------------------- tour --
function startTour(): void {
  if (!threats || threats.actors.length === 0) return;
  exitTour();
  const stops = [...threats.actors]
    .filter((a) => a.group.visible)
    .slice(0, 14);
  if (stops.length === 0) return;
  tour = { stops, index: -1, timer: 0 };
  tourGo(0);
}

function tourGo(index: number): void {
  if (!tour) return;
  clearTimeout(tour.timer);
  tour.index = ((index % tour.stops.length) + tour.stops.length) % tour.stops.length;
  const actor = tour.stops[tour.index];
  hud.setTour(`${tour.index + 1} / ${tour.stops.length} — ${CATEGORY_INFO[actor.category].actor}`);
  if (actor.file && city) city.highlight(actor.file);
  hud.showActorPanel(actor);
  void flyToPoint(actor.group.position, 36).then(() => {
    if (!tour) return;
    tour.timer = window.setTimeout(() => tour && tourGo(tour.index + 1), 6500);
  });
}

function exitTour(): void {
  if (!tour) return;
  clearTimeout(tour.timer);
  tour = null;
  hud.setTour(null);
}

// -------------------------------------------------------------- toolbar --
document.getElementById('btn-tour')!.addEventListener('click', () => (tour ? exitTour() : startTour()));
document.getElementById('btn-overview')!.addEventListener('click', () => {
  exitTour();
  city?.highlight(null);
  void engine?.flyTo(overviewPos(), new THREE.Vector3(0, 0, 0), 1500);
});
document.getElementById('btn-orbit')!.addEventListener('click', (ev) => {
  if (!engine) return;
  engine.autoOrbit = !engine.autoOrbit;
  (ev.currentTarget as HTMLElement).classList.toggle('on', engine.autoOrbit);
});
document.getElementById('btn-shot')!.addEventListener('click', () => {
  if (!engine || !result) return;
  const a = document.createElement('a');
  a.href = engine.screenshot();
  a.download = `threatscape-${result.meta.owner}-${result.meta.repo}.png`;
  a.click();
});

window.addEventListener('keydown', (ev) => {
  if (ev.target instanceof HTMLInputElement || ev.target instanceof HTMLTextAreaElement) return;
  if (ev.key === 'Escape') {
    if (tour) exitTour();
    else if (hud.panelOpen) hud.closePanel();
    city?.highlight(null);
  } else if (ev.key === 'o' || ev.key === 'O') {
    void engine?.flyTo(overviewPos(), new THREE.Vector3(0, 0, 0), 1500);
  } else if (ev.key === 't' || ev.key === 'T') {
    tour ? exitTour() : startTour();
  }
});

// ----------------------------------------------------------------- boot --
const params = new URLSearchParams(location.search);
const repoParam = params.get('repo');
if (repoParam) {
  const ref = params.get('ref') ?? undefined;
  const [owner, repo] = repoParam.split('/');
  if (owner && repo) {
    landing.setInput(repoParam);
    prewarmEngine();
    void analyze({ owner, repo, ref });
  }
}

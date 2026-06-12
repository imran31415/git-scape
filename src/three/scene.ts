/** Rendering core: renderer, camera rig, postprocessing, frame loop. */
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';

export interface FrameCtx {
  t: number;
  dt: number;
  camera: THREE.PerspectiveCamera;
}

const easeInOutCubic = (x: number) =>
  x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;

export class SceneEngine {
  readonly scene = new THREE.Scene();
  readonly camera: THREE.PerspectiveCamera;
  readonly renderer: THREE.WebGLRenderer;
  readonly controls: OrbitControls;
  readonly canvas: HTMLCanvasElement;

  private composer: EffectComposer;
  private bloom: UnrealBloomPass;
  private frameCbs = new Set<(ctx: FrameCtx) => void>();
  private clock = new THREE.Clock();
  private raycaster = new THREE.Raycaster();
  private pointer = new THREE.Vector2();
  private running = true;
  private flight: {
    fromPos: THREE.Vector3;
    toPos: THREE.Vector3;
    fromLook: THREE.Vector3;
    toLook: THREE.Vector3;
    start: number;
    dur: number;
    resolve: () => void;
  } | null = null;
  autoOrbit = false;

  constructor(container: HTMLElement) {
    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      powerPreference: 'high-performance',
      preserveDrawingBuffer: true, // screenshots
    });
    this.canvas = this.renderer.domElement;
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(container.clientWidth, container.clientHeight);
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.12;
    container.appendChild(this.canvas);

    this.camera = new THREE.PerspectiveCamera(
      55,
      container.clientWidth / container.clientHeight,
      0.5,
      4000,
    );
    this.camera.position.set(0, 260, 340);

    this.controls = new OrbitControls(this.camera, this.canvas);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.06;
    this.controls.maxPolarAngle = Math.PI * 0.49;
    this.controls.minDistance = 12;
    this.controls.maxDistance = 1200;
    this.controls.target.set(0, 0, 0);

    this.scene.background = new THREE.Color(0x04060d);
    this.scene.fog = new THREE.FogExp2(0x04060d, 0.0018);

    const hemi = new THREE.HemisphereLight(0x4455aa, 0x0b0d1a, 0.65);
    this.scene.add(hemi);
    const moon = new THREE.DirectionalLight(0x8fb3ff, 0.85);
    moon.position.set(-180, 320, -120);
    this.scene.add(moon);
    const rim = new THREE.DirectionalLight(0xff4d6d, 0.18);
    rim.position.set(220, 80, 240);
    this.scene.add(rim);

    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));
    this.bloom = new UnrealBloomPass(
      new THREE.Vector2(container.clientWidth, container.clientHeight),
      0.78, // strength
      0.38, // radius
      0.62, // threshold
    );
    this.composer.addPass(this.bloom);
    this.composer.addPass(new OutputPass());

    const onResize = () => {
      const w = container.clientWidth;
      const h = container.clientHeight;
      if (w === 0 || h === 0) return;
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
      this.renderer.setSize(w, h);
      this.composer.setSize(w, h);
    };
    window.addEventListener('resize', onResize);

    this.renderer.setAnimationLoop(() => this.tick());
  }

  private tick(): void {
    if (!this.running) return;
    const dt = Math.min(this.clock.getDelta(), 0.05);
    const t = this.clock.elapsedTime;

    if (this.flight) {
      const f = this.flight;
      const k = Math.min(1, (performance.now() - f.start) / f.dur);
      const e = easeInOutCubic(k);
      this.camera.position.lerpVectors(f.fromPos, f.toPos, e);
      this.controls.target.lerpVectors(f.fromLook, f.toLook, e);
      if (k >= 1) {
        this.flight = null;
        this.controls.enabled = true;
        f.resolve();
      }
    } else if (this.autoOrbit) {
      const target = this.controls.target;
      const offset = this.camera.position.clone().sub(target);
      offset.applyAxisAngle(new THREE.Vector3(0, 1, 0), dt * 0.07);
      this.camera.position.copy(target).add(offset);
    }

    this.controls.update();
    for (const cb of this.frameCbs) cb({ t, dt, camera: this.camera });
    this.composer.render();
  }

  onFrame(cb: (ctx: FrameCtx) => void): () => void {
    this.frameCbs.add(cb);
    return () => this.frameCbs.delete(cb);
  }

  /** Cinematic camera move; controls are suspended while in flight. */
  flyTo(pos: THREE.Vector3, look: THREE.Vector3, durationMs = 1600): Promise<void> {
    return new Promise((resolve) => {
      this.flight?.resolve(); // superseded flights must not strand awaiters
      this.controls.enabled = false;
      this.flight = {
        fromPos: this.camera.position.clone(),
        toPos: pos.clone(),
        fromLook: this.controls.target.clone(),
        toLook: look.clone(),
        start: performance.now(),
        dur: durationMs,
        resolve,
      };
    });
  }

  raycastFromEvent(ev: PointerEvent | MouseEvent): THREE.Raycaster {
    const rect = this.canvas.getBoundingClientRect();
    this.pointer.set(
      ((ev.clientX - rect.left) / rect.width) * 2 - 1,
      -((ev.clientY - rect.top) / rect.height) * 2 + 1,
    );
    this.raycaster.setFromCamera(this.pointer, this.camera);
    return this.raycaster;
  }

  screenshot(): string {
    this.composer.render();
    return this.canvas.toDataURL('image/png');
  }

  clearWorld(keepLights = true): void {
    const doomed: THREE.Object3D[] = [];
    for (const child of this.scene.children) {
      if (keepLights && (child as THREE.Light).isLight) continue;
      doomed.push(child);
    }
    const disposeMat = (m: THREE.Material) => {
      for (const key of ['map', 'emissiveMap', 'alphaMap'] as const) {
        const tex = (m as unknown as Record<string, THREE.Texture | null>)[key];
        tex?.dispose?.();
      }
      m.dispose();
    };
    for (const d of doomed) {
      this.scene.remove(d);
      d.traverse((o) => {
        const mesh = o as THREE.Mesh;
        if (mesh.geometry) mesh.geometry.dispose();
        const mat = mesh.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(mat)) mat.forEach(disposeMat);
        else if (mat) disposeMat(mat);
      });
    }
  }

  dispose(): void {
    this.running = false;
    this.renderer.setAnimationLoop(null);
    this.clearWorld(false);
    this.renderer.dispose();
  }
}

/** Landing + loading screens. */
import { parseRepoInput, type RepoTarget } from '../github/parse';
import type { ProgressEvent, ProgressStage } from '../types';

const TOKEN_KEY = 'threatscape.github-token';

export class LandingScreen {
  private root = document.getElementById('landing')!;
  private input = document.getElementById('repo-input') as HTMLInputElement;
  private tokenInput = document.getElementById('token-input') as HTMLInputElement;
  private error = document.getElementById('input-error')!;

  constructor(
    onSubmit: (target: RepoTarget, token?: string) => void,
    onFirstInteraction: () => void,
  ) {
    this.tokenInput.value = localStorage.getItem(TOKEN_KEY) ?? '';
    this.tokenInput.addEventListener('change', () => {
      const v = this.tokenInput.value.trim();
      if (v) localStorage.setItem(TOKEN_KEY, v);
      else localStorage.removeItem(TOKEN_KEY);
    });

    let warmed = false;
    const warm = () => {
      if (!warmed) {
        warmed = true;
        onFirstInteraction();
      }
    };
    this.input.addEventListener('focus', warm, { once: true });
    this.input.addEventListener('pointerenter', warm, { once: true });

    document.getElementById('repo-form')!.addEventListener('submit', (e) => {
      e.preventDefault();
      const target = parseRepoInput(this.input.value);
      if (!target) {
        this.showError(
          'That doesn’t look like a GitHub repository.',
          'Accepted forms: owner/repo · github.com/owner/repo · a full https URL (branch links work too).',
        );
        return;
      }
      this.hideError();
      onSubmit(target, this.token());
    });

    for (const btn of document.querySelectorAll<HTMLButtonElement>('.example')) {
      btn.addEventListener('click', () => {
        warm();
        this.input.value = btn.dataset.repo!;
        const target = parseRepoInput(this.input.value)!;
        this.hideError();
        onSubmit(target, this.token());
      });
    }
  }

  token(): string | undefined {
    return this.tokenInput.value.trim() || undefined;
  }

  setInput(value: string): void {
    this.input.value = value;
  }

  showError(message: string, hint?: string): void {
    this.error.hidden = false;
    this.error.textContent = hint ? `${message}\n${hint}` : message;
  }

  hideError(): void {
    this.error.hidden = true;
  }

  show(): void {
    this.root.style.display = '';
  }

  hide(): void {
    this.root.style.display = 'none';
  }
}

const STAGE_ORDER: ProgressStage[] = ['meta', 'tree', 'download', 'scan', 'osv', 'build'];
/** Rough share of the progress bar each stage owns. */
const STAGE_SPAN: Record<ProgressStage, [number, number]> = {
  meta: [0, 6],
  tree: [6, 12],
  download: [12, 52],
  scan: [52, 86],
  osv: [86, 96],
  build: [96, 100],
};

export class LoadingScreen {
  private root = document.getElementById('loading')!;
  private repoEl = document.getElementById('loading-repo')!;
  private bar = document.getElementById('progress-bar')!;
  private log = document.getElementById('loading-log')!;
  private stages = [...document.querySelectorAll<HTMLElement>('#stage-track .stage')];
  private lastLogAt = 0;

  constructor(onCancel: () => void) {
    document.getElementById('loading-cancel')!.addEventListener('click', onCancel);
  }

  show(slug: string): void {
    this.repoEl.textContent = slug;
    this.bar.style.width = '0%';
    this.log.innerHTML = '';
    for (const s of this.stages) s.classList.remove('active', 'done');
    this.root.hidden = false;
  }

  hide(): void {
    this.root.hidden = true;
  }

  update(e: ProgressEvent): void {
    const idx = STAGE_ORDER.indexOf(e.stage);
    this.stages.forEach((el, i) => {
      el.classList.toggle('active', i === idx);
      el.classList.toggle('done', i < idx);
    });

    const [lo, hi] = STAGE_SPAN[e.stage];
    const frac = e.total ? Math.min(1, (e.done ?? 0) / e.total) : 0.4;
    this.bar.style.width = `${lo + (hi - lo) * frac}%`;

    const now = performance.now();
    if (now - this.lastLogAt > 90 || !e.total || e.done === e.total) {
      this.lastLogAt = now;
      this.addLog(
        e.total ? `[${e.stage}] ${e.done}/${e.total} ${e.message}` : `[${e.stage}] ${e.message}`,
      );
    }
  }

  private addLog(text: string): void {
    const line = document.createElement('div');
    line.className = 'log-line head';
    line.textContent = `▸ ${text}`;
    for (const old of this.log.querySelectorAll('.head')) old.classList.remove('head');
    this.log.prepend(line);
    while (this.log.childElementCount > 9) this.log.lastElementChild!.remove();
  }
}

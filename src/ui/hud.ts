/** HUD: score dial, severity chips, legend, info panel, tooltip, tour bar. */
import {
  CATEGORY_INFO,
  SEVERITY_COLOR_CSS,
  SEVERITY_ORDER,
  severityRank,
  type AnalysisResult,
  type Category,
  type FileInfo,
  type Finding,
  type Severity,
} from '../types';
import type { ThreatActor } from '../three/threats';

export const CATEGORY_SYMBOL: Record<Category, string> = {
  secret: '🗝️',
  injection: '💉',
  xss: '👻',
  crypto: '🔓',
  network: '📡',
  config: '⚙️',
  cicd: '🧨',
  dependency: '🪱',
  hygiene: '🐀',
};

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export interface HudCallbacks {
  onSeverityFilter(enabled: Set<Severity>): void;
  onCategoryFilter(enabled: Set<Category>): void;
  onFindingFocus(findingId: string): void;
  onHome(): void;
  onTourPrev(): void;
  onTourNext(): void;
  onTourExit(): void;
}

export class Hud {
  private root = document.getElementById('hud')!;
  private panel = document.getElementById('panel')!;
  private panelContent = document.getElementById('panel-content')!;
  private tooltip = document.getElementById('tooltip')!;
  private tourBar = document.getElementById('tour-bar')!;
  private tourStatus = document.getElementById('tour-status')!;

  private enabledSeverities = new Set<Severity>(SEVERITY_ORDER);
  private enabledCategories = new Set<Category>();
  private result: AnalysisResult | null = null;

  constructor(private cb: HudCallbacks) {
    document.getElementById('btn-home')!.addEventListener('click', () => cb.onHome());
    document.getElementById('panel-close')!.addEventListener('click', () => this.closePanel());
    document.getElementById('tour-prev')!.addEventListener('click', () => cb.onTourPrev());
    document.getElementById('tour-next')!.addEventListener('click', () => cb.onTourNext());
    document.getElementById('tour-exit')!.addEventListener('click', () => cb.onTourExit());
    document.querySelector('#legend .legend-title')!.addEventListener('click', () => {
      document.getElementById('legend')!.classList.toggle('collapsed');
    });
  }

  show(result: AnalysisResult): void {
    this.result = result;
    this.root.hidden = false;
    this.enabledSeverities = new Set(SEVERITY_ORDER);
    this.enabledCategories = new Set(Object.keys(CATEGORY_INFO) as Category[]);

    const { meta, score } = result;
    const name = document.getElementById('hud-repo-name') as HTMLAnchorElement;
    name.textContent = `${meta.owner}/${meta.repo}`;
    name.href = `https://github.com/${meta.owner}/${meta.repo}`;

    const bits: string[] = [`@${meta.ref}`];
    if (meta.stars !== undefined) bits.push(`★ ${meta.stars.toLocaleString()}`);
    if (meta.license) bits.push(meta.license);
    bits.push(`${result.report.stats.scannedFiles} files scanned`);
    bits.push(`${result.report.stats.durationMs} ms in WASM`);
    document.getElementById('hud-repo-sub')!.textContent = bits.join('  ·  ');

    // score dial
    const circ = 2 * Math.PI * 50;
    const dial = document.getElementById('dial-value')!;
    const dialColor =
      score.value >= 88 ? '#34d399' : score.value >= 65 ? '#ffd60a' : score.value >= 45 ? '#ff9f0a' : '#ff2d55';
    dial.style.stroke = dialColor;
    dial.style.color = dialColor;
    requestAnimationFrame(() => {
      dial.style.strokeDashoffset = String(circ * (1 - score.value / 100));
    });
    document.getElementById('dial-grade')!.textContent = score.grade;
    document.getElementById('dial-number')!.textContent = `${score.value}/100`;
    const lvl = document.getElementById('threat-level')!;
    lvl.textContent = score.threatLevel;
    lvl.style.color = dialColor;

    this.renderSeverityChips();
    this.renderLegend();
    document.getElementById('osv-warning')!.hidden = result.osvStatus !== 'unavailable';
    this.showSummaryPanel();
  }

  hide(): void {
    this.root.hidden = true;
    this.closePanel();
    this.hideTooltip();
    this.setTour(null);
  }

  private renderSeverityChips(): void {
    const host = document.getElementById('sev-chips')!;
    host.innerHTML = '';
    const counts = this.result!.score.bySeverity;
    for (const sev of SEVERITY_ORDER) {
      const chip = document.createElement('button');
      chip.className = 'sev-chip';
      chip.innerHTML = `<span class="dot" style="background:${SEVERITY_COLOR_CSS[sev]};color:${SEVERITY_COLOR_CSS[sev]}"></span>${sev} ${counts[sev]}`;
      chip.title = `Toggle ${sev} threats`;
      chip.addEventListener('click', () => {
        if (this.enabledSeverities.has(sev)) this.enabledSeverities.delete(sev);
        else this.enabledSeverities.add(sev);
        chip.classList.toggle('off', !this.enabledSeverities.has(sev));
        this.cb.onSeverityFilter(new Set(this.enabledSeverities));
      });
      host.appendChild(chip);
    }
  }

  private renderLegend(): void {
    const host = document.getElementById('legend-items')!;
    host.innerHTML = '';
    const byCat = this.result!.score.byCategory;
    const cats = (Object.keys(byCat) as Category[]).sort((a, b) => (byCat[b] ?? 0) - (byCat[a] ?? 0));
    for (const cat of cats) {
      const item = document.createElement('button');
      item.className = 'legend-item cat-row';
      item.innerHTML = `<span class="sym">${CATEGORY_SYMBOL[cat]}</span><span class="cat-label">${CATEGORY_INFO[cat].actor}</span><span class="n">${byCat[cat]}</span>`;
      item.title = `${CATEGORY_INFO[cat].label} — ${CATEGORY_INFO[cat].blurb}\nClick to toggle.`;
      item.addEventListener('click', () => {
        if (this.enabledCategories.has(cat)) this.enabledCategories.delete(cat);
        else this.enabledCategories.add(cat);
        item.style.opacity = this.enabledCategories.has(cat) ? '1' : '0.32';
        this.cb.onCategoryFilter(new Set(this.enabledCategories));
      });
      host.appendChild(item);
    }
  }

  // ------------------------------------------------------------- panels --
  private openPanel(html: string): void {
    this.panelContent.innerHTML = html;
    this.panel.hidden = false;
    this.panelContent.scrollTop = 0;
    for (const el of this.panelContent.querySelectorAll<HTMLElement>('[data-focus-finding]')) {
      el.addEventListener('click', () => this.cb.onFindingFocus(el.dataset.focusFinding!));
    }
  }

  closePanel(): void {
    this.panel.hidden = true;
  }

  get panelOpen(): boolean {
    return !this.panel.hidden;
  }

  private githubLink(file: string, line?: number): string {
    const m = this.result!.meta;
    const frag = line ? `#L${line}` : '';
    return `https://github.com/${m.owner}/${m.repo}/blob/${encodeURIComponent(m.ref)}/${file
      .split('/')
      .map(encodeURIComponent)
      .join('/')}${frag}`;
  }

  private findingHtml(f: Finding, focusable: boolean): string {
    const loc = f.file
      ? `<a href="${this.githubLink(f.file, f.line)}" target="_blank" rel="noopener noreferrer">${esc(f.file)}${f.line ? `:${f.line}` : ''} ↗</a>`
      : 'repository-level';
    return `<div class="finding" data-sev="${f.severity}" ${focusable ? `data-focus-finding="${f.id}" style="cursor:pointer"` : ''}>
      <div class="finding-head">
        <span class="sev-tag" style="background:${SEVERITY_COLOR_CSS[f.severity]}">${f.severity.toUpperCase()}</span>
        <span class="finding-title">${esc(f.title)}</span>
      </div>
      <div class="finding-loc">${loc}</div>
      ${f.snippet ? `<pre class="finding-snippet">${esc(f.snippet)}</pre>` : ''}
      <div class="finding-msg">${esc(f.message)}</div>
      ${f.recommendation ? `<div class="finding-rec">${esc(f.recommendation)}</div>` : ''}
      <div class="finding-meta">${esc(f.ruleId)}${f.cwe ? ` · ${esc(f.cwe)}` : ''} · confidence ${f.confidence}</div>
    </div>`;
  }

  showSummaryPanel(): void {
    const r = this.result!;
    const langs = Object.entries(r.report.languages)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
    const langTotal = langs.reduce((s, [, v]) => s + v, 0) || 1;
    const langBar = langs
      .map(
        ([lang, bytes]) =>
          `<span title="${esc(lang)} ${(100 * bytes / langTotal).toFixed(0)}%" style="display:inline-block;height:8px;border-radius:2px;background:#3178c6;opacity:${0.45 + 0.55 * (bytes / langTotal)};width:${Math.max(3, (100 * bytes) / langTotal)}%"></span>`,
      )
      .join('');

    const byCat = r.score.byCategory;
    const catRows = (Object.keys(byCat) as Category[])
      .sort((a, b) => (byCat[b] ?? 0) - (byCat[a] ?? 0))
      .map(
        (cat) =>
          `<div class="cat-row"><span class="sym">${CATEGORY_SYMBOL[cat]}</span><span class="cat-label">${CATEGORY_INFO[cat].label}</span><span class="n">${byCat[cat]}</span></div>`,
      )
      .join('');

    const worst = r.findings.slice(0, 5);
    const deps = r.vulnerableDeps.length;
    const s = r.report.stats;

    this.openPanel(`
      <div class="panel-kicker">mission briefing</div>
      <div class="panel-title">${esc(r.meta.owner)}/${esc(r.meta.repo)}</div>
      <div class="panel-sub">${esc(r.meta.description ?? '')}</div>
      <div class="file-stats">
        <div class="stat-cell"><div class="stat-num">${s.fileCount.toLocaleString()}</div><div class="stat-label">buildings</div></div>
        <div class="stat-cell"><div class="stat-num">${r.findings.length}</div><div class="stat-label">findings</div></div>
        <div class="stat-cell"><div class="stat-num">${deps}</div><div class="stat-label">vuln deps</div></div>
      </div>
      <div style="margin:2px 0 14px;display:flex;gap:2px">${langBar}</div>
      ${catRows ? `<div class="panel-kicker" style="margin-bottom:6px">active threat actors</div>${catRows}` : '<div class="clean-note">No threat actors detected. The city sleeps safely tonight.</div>'}
      ${worst.length ? `<div class="panel-kicker" style="margin:16px 0 8px">most wanted</div>${worst.map((f) => this.findingHtml(f, true)).join('')}` : ''}
      <div class="finding-meta" style="margin-top:14px">engine scanned ${s.scannedFiles}/${s.fileCount} files · ${(s.totalBytes / 1024 / 1024).toFixed(1)} MB · ${s.totalLines.toLocaleString()} lines · ${s.ruleCount} rules · ${s.durationMs} ms</div>
    `);
  }

  showFilePanel(file: FileInfo): void {
    const r = this.result!;
    const findings = r.findings.filter((f) => f.file === file.path);
    const flags = [
      file.vendored ? 'vendored' : '',
      file.minified ? 'minified' : '',
      file.binary ? 'binary' : '',
    ]
      .filter(Boolean)
      .join(' · ');
    this.openPanel(`
      <div class="panel-kicker">building dossier</div>
      <div class="panel-title">${esc(file.path)}</div>
      <div class="panel-sub">
        <a href="${this.githubLink(file.path)}" target="_blank" rel="noopener noreferrer">view on GitHub ↗</a>
        ${flags ? ` · ${flags}` : ''}
      </div>
      <div class="file-stats">
        <div class="stat-cell"><div class="stat-num">${file.lang ? esc(file.lang) : '—'}</div><div class="stat-label">language</div></div>
        <div class="stat-cell"><div class="stat-num">${file.lines.toLocaleString()}</div><div class="stat-label">lines</div></div>
        <div class="stat-cell"><div class="stat-num">${fmtBytes(file.size)}</div><div class="stat-label">size</div></div>
      </div>
      ${
        findings.length
          ? findings.map((f) => this.findingHtml(f, false)).join('')
          : '<div class="clean-note">✓ No findings in this file — the building is secure.</div>'
      }
    `);
  }

  showActorPanel(actor: ThreatActor): void {
    const info = CATEGORY_INFO[actor.category];
    const sorted = [...actor.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    this.openPanel(`
      <div class="panel-kicker">threat actor engaged</div>
      <div class="actor-card" style="margin-top:8px">
        <div class="actor-emoji">${CATEGORY_SYMBOL[actor.category]}</div>
        <div>
          <div class="actor-name" style="color:${SEVERITY_COLOR_CSS[actor.severity]}">${info.actor}</div>
          <div class="actor-blurb">${info.blurb}</div>
        </div>
      </div>
      <div class="panel-sub">Target: ${actor.file ? esc(actor.file) : 'the repository itself'} · ${sorted.length} finding${sorted.length === 1 ? '' : 's'}</div>
      ${sorted.map((f) => this.findingHtml(f, false)).join('')}
    `);
  }

  // ------------------------------------------------------------ tooltip --
  showTooltip(html: string, x: number, y: number): void {
    this.tooltip.innerHTML = html;
    this.tooltip.hidden = false;
    const pad = 14;
    const rect = this.tooltip.getBoundingClientRect();
    const left = Math.min(x + pad, window.innerWidth - rect.width - 8);
    const top = Math.min(y + pad, window.innerHeight - rect.height - 8);
    this.tooltip.style.left = `${left}px`;
    this.tooltip.style.top = `${top}px`;
  }

  hideTooltip(): void {
    this.tooltip.hidden = true;
  }

  // --------------------------------------------------------------- tour --
  setTour(status: string | null): void {
    if (status === null) {
      this.tourBar.hidden = true;
    } else {
      this.tourBar.hidden = false;
      this.tourStatus.textContent = status;
    }
  }
}

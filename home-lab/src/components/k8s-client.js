import {
  wsl_kubectl_apply_yaml,
  wsl_kubectl_exec,
  wsl_list_instances,
  wsl_sync_windows_kubeconfig,
} from '../tauri.js';
import { showError } from './toast.js';

const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

function splitCommandLine(input) {
  const tokens = [];
  let current = '';
  let quote = null;
  let escaped = false;

  for (const char of String(input ?? '')) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === '\'') {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = '';
      }
      continue;
    }

    current += char;
  }

  if (escaped) {
    current += '\\';
  }
  if (current) {
    tokens.push(current);
  }

  return tokens;
}

function normalizeKubectlArgs(input) {
  const tokens = splitCommandLine(input);
  if (tokens.length === 0) {
    return [];
  }

  let start = 0;
  if (tokens[0].toLowerCase() === 'kubectl') {
    start = 1;
  } else if (
    tokens.length > 1
    && tokens[0].toLowerCase() === 'k3s'
    && tokens[1].toLowerCase() === 'kubectl'
  ) {
    start = 2;
  }

  return tokens.slice(start);
}

class K8sClient extends HTMLElement {
  constructor() {
    super();
    this._instances = [];
    this._selectedInstance = '';
    this._commandInput = 'get nodes -o wide';
    this._running = false;
    this._loading = false;
    this._syncingKubeconfig = false;
    this._message = '';
    this._messageState = 'idle';
    this._kubeconfigPath = '';
    this._result = null;
    this._applyFile = null;
    this._applyFileName = '';
  }

  connectedCallback() {
    this.render();
    this.loadInstances();
  }

  setMessage(state, message = '') {
    this._messageState = state;
    this._message = message;
    this.render();
  }

  async loadInstances() {
    this._loading = true;
    this.render();
    try {
      const instances = await wsl_list_instances();
      this._instances = Array.isArray(instances) ? instances : [];
      const stillValid = this._instances.some(
        (inst) => String(inst?.name || '').trim() === this._selectedInstance,
      );
      if (!stillValid) {
        this._selectedInstance = this._instances[0]?.name || '';
      }

      if (this._instances.length === 0) {
        this.setMessage('warning', 'Aucune instance WSL detectee.');
      } else if (!this._message || this._messageState === 'warning') {
        this.setMessage('idle', '');
      } else {
        this.render();
      }
      return true;
    } catch (err) {
      const message = err?.message || String(err);
      showError(message);
      this.setMessage('error', message);
      return false;
    } finally {
      this._loading = false;
      this.render();
    }
  }

  applyQuickCommand(command) {
    this._commandInput = command;
    this.render();
  }

  async syncKubeconfig() {
    if (this._syncingKubeconfig || this._running) return;
    this._syncingKubeconfig = true;
    this.setMessage('running', 'Synchronisation du kubeconfig Windows...');
    try {
      const result = await wsl_sync_windows_kubeconfig();
      if (result?.path) {
        this._kubeconfigPath = String(result.path);
      }
      const message = result?.message || 'Kubeconfig Windows synchronise.';
      this.setMessage('success', message);
      return true;
    } catch (err) {
      const message = err?.message || String(err);
      this.setMessage('error', message);
      showError(message);
      return false;
    } finally {
      this._syncingKubeconfig = false;
      this.render();
    }
  }

  async runCommand() {
    if (this._running) return;

    const instance = String(this._selectedInstance || '').trim();
    if (!instance) {
      showError('Selectionne une instance WSL.');
      return;
    }

    const args = normalizeKubectlArgs(this._commandInput);
    if (args.length === 0) {
      showError('Saisis une commande kubectl.');
      return;
    }

    this._running = true;
    const startedAt = Date.now();
    this.setMessage('running', `Execution kubectl sur ${instance}...`);
    // eslint-disable-next-line no-console
    console.info('[k8s-client] kubectl start', { instance, args });
    try {
      const result = await wsl_kubectl_exec(instance, args);
      this._result = result;
      // eslint-disable-next-line no-console
      console.info('[k8s-client] kubectl result', {
        instance,
        elapsed_ms: Date.now() - startedAt,
        trace_id: result?.trace_id,
        ok: !!result?.ok,
      });
      if (result?.ok) {
        this.setMessage('success', `Commande terminee sur ${instance}.`);
      } else {
        const stderr = (result?.stderr || '').trim();
        const fallback = `La commande kubectl a echoue sur ${instance}.`;
        const message = stderr || fallback;
        this.setMessage('error', message);
        showError(message);
      }
    } catch (err) {
      const message = err?.message || String(err);
      this._result = null;
      this.setMessage('error', message);
      showError(message);
      // eslint-disable-next-line no-console
      console.error('[k8s-client] kubectl error', {
        instance,
        elapsed_ms: Date.now() - startedAt,
        error: message,
      });
    } finally {
      this._running = false;
      this.render();
    }
  }

  async applyUploadedYaml() {
    if (this._running) return;

    const instance = String(this._selectedInstance || '').trim();
    if (!instance) {
      showError('Selectionne une instance WSL.');
      return;
    }

    if (!this._applyFile) {
      showError('Selectionne un fichier YAML a appliquer.');
      return;
    }

    const file = this._applyFile;
    let manifestYaml = '';
    try {
      manifestYaml = await file.text();
    } catch (err) {
      const message = err?.message || String(err);
      this.setMessage('error', message);
      showError(message);
      return;
    }

    if (!manifestYaml.trim()) {
      showError('Le fichier YAML selectionne est vide.');
      return;
    }

    this._running = true;
    const startedAt = Date.now();
    this.setMessage('running', `Application YAML sur ${instance}...`);
    // eslint-disable-next-line no-console
    console.info('[k8s-client] kubectl apply start', {
      instance,
      file: file.name,
      bytes: manifestYaml.length,
    });
    try {
      const result = await wsl_kubectl_apply_yaml(instance, manifestYaml, file.name);
      this._result = result;
      // eslint-disable-next-line no-console
      console.info('[k8s-client] kubectl apply result', {
        instance,
        elapsed_ms: Date.now() - startedAt,
        trace_id: result?.trace_id,
        ok: !!result?.ok,
      });
      if (result?.ok) {
        this.setMessage('success', `Apply YAML termine sur ${instance}.`);
      } else {
        const stderr = (result?.stderr || '').trim();
        const fallback = `Apply YAML a echoue sur ${instance}.`;
        const message = stderr || fallback;
        this.setMessage('error', message);
        showError(message);
      }
    } catch (err) {
      const message = err?.message || String(err);
      this._result = null;
      this.setMessage('error', message);
      showError(message);
      // eslint-disable-next-line no-console
      console.error('[k8s-client] kubectl apply error', {
        instance,
        elapsed_ms: Date.now() - startedAt,
        error: message,
      });
    } finally {
      this._running = false;
      this.render();
    }
  }

  renderResult() {
    if (!this._result || typeof this._result !== 'object') {
      return '<p class="mt-3 text-xs text-gray-500">Aucun resultat pour le moment.</p>';
    }

    const command = escapeHtml(this._result.command || '');
    const stdout = String(this._result.stdout || '');
    const stderr = String(this._result.stderr || '');
    const traceId = String(this._result.trace_id || '').trim();
    const durationRaw = Number(this._result.duration_ms);
    const durationMs = Number.isFinite(durationRaw) && durationRaw >= 0
      ? Math.round(durationRaw)
      : null;
    const hasStdout = stdout.trim().length > 0;
    const hasStderr = stderr.trim().length > 0;
    const statusText = this._result.ok
      ? 'Succes'
      : `Echec (code ${escapeHtml(String(this._result.exit_code ?? 'inconnu'))})`;

    return `
      <div class="mt-3 rounded border border-gray-200 bg-white p-3">
        <p class="text-[11px] text-gray-500">Commande: <code>${command}</code></p>
        ${
          traceId || durationMs !== null
            ? `<p class="mt-1 text-[11px] text-gray-500">${traceId ? `trace_id: <code>${escapeHtml(traceId)}</code>` : ''}${traceId && durationMs !== null ? ' · ' : ''}${durationMs !== null ? `duree: ${escapeHtml(String(durationMs))} ms` : ''}</p>`
            : ''
        }
        <p class="mt-1 text-xs font-semibold ${this._result.ok ? 'text-green-600' : 'text-red-600'}">${statusText}</p>
        ${hasStdout ? `<div class="mt-2"><p class="text-xs font-semibold text-gray-700">stdout</p><pre class="mt-1 max-h-56 overflow-auto rounded bg-gray-900 p-2 text-[11px] leading-relaxed text-gray-100">${escapeHtml(stdout)}</pre></div>` : ''}
        ${hasStderr ? `<div class="mt-2"><p class="text-xs font-semibold text-gray-700">stderr</p><pre class="mt-1 max-h-40 overflow-auto rounded bg-red-950 p-2 text-[11px] leading-relaxed text-red-100">${escapeHtml(stderr)}</pre></div>` : ''}
      </div>`;
  }

  render() {
    const disableRun = this._running || this._loading || this._instances.length === 0;
    const disableApply = disableRun || !this._applyFile;
    const disableSync = this._running || this._syncingKubeconfig;
    const message = this._message
      ? `<p class="mt-3 text-sm ${
          this._messageState === 'error'
            ? 'text-red-600'
            : this._messageState === 'success'
              ? 'text-green-600'
              : this._messageState === 'running'
                ? 'text-blue-600'
                : 'text-gray-700'
        }">${escapeHtml(this._message)}</p>`
      : '';

    const instanceOptions = this._instances.length > 0
      ? this._instances
          .map((inst) => {
            const raw = String(inst?.name || '').trim();
            const selected = raw === this._selectedInstance ? 'selected' : '';
            return `<option value="${escapeHtml(raw)}" ${selected}>${escapeHtml(raw)}</option>`;
          })
          .join('')
      : '<option value="">Aucune instance</option>';

    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">Client Kubernetes</h2>
        <p class="text-sm text-gray-600 mb-3">
          Execute des commandes <code>kubectl</code> via l'API Kubernetes en utilisant le contexte Windows associe a l'instance WSL.
        </p>
        ${
          this._kubeconfigPath
            ? `<p class="mb-2 text-[11px] text-gray-500">kubeconfig Windows: <code>${escapeHtml(this._kubeconfigPath)}</code></p>`
            : ''
        }

        <div class="flex flex-wrap items-end gap-2">
          <label class="text-xs text-gray-600">
            Instance WSL
            <select
              data-role="instance"
              class="mt-1 block rounded border border-gray-300 bg-white px-2 py-1 text-sm text-gray-800"
              ${this._loading ? 'disabled' : ''}
            >
              ${instanceOptions}
            </select>
          </label>
          <button
            type="button"
            data-action="refresh"
            class="px-3 py-1.5 rounded border border-gray-300 bg-white text-xs font-semibold text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            ${this._running ? 'disabled' : ''}
          >
            ${this._loading ? 'Actualisation...' : 'Actualiser'}
          </button>
          <button
            type="button"
            data-action="sync-kubeconfig"
            class="px-3 py-1.5 rounded border border-green-300 bg-white text-xs font-semibold text-green-700 hover:bg-green-50 disabled:opacity-50 disabled:cursor-not-allowed"
            ${disableSync ? 'disabled' : ''}
          >
            ${this._syncingKubeconfig ? 'Sync kubeconfig...' : 'Sync kubeconfig Windows'}
          </button>
        </div>

        <label class="mt-3 block text-xs text-gray-600">
          Commande kubectl
          <input
            data-role="command"
            type="text"
            value="${escapeHtml(this._commandInput)}"
            class="mt-1 w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-800"
            placeholder="get nodes -o wide"
            ${this._running ? 'disabled' : ''}
          />
        </label>

        <div class="mt-2 flex flex-wrap gap-2">
          <button type="button" data-quick="get nodes -o wide" class="px-2 py-1 rounded border border-gray-300 bg-white text-[11px] text-gray-700 hover:bg-gray-50">Nodes</button>
          <button type="button" data-quick="get pods -A" class="px-2 py-1 rounded border border-gray-300 bg-white text-[11px] text-gray-700 hover:bg-gray-50">Pods all namespaces</button>
          <button type="button" data-quick="get namespaces" class="px-2 py-1 rounded border border-gray-300 bg-white text-[11px] text-gray-700 hover:bg-gray-50">Namespaces</button>
        </div>

        <button
          type="button"
          data-action="run"
          class="mt-3 px-3 py-2 rounded bg-blue-600 text-white text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
          ${disableRun ? 'disabled' : ''}
        >
          ${this._running ? 'Execution...' : 'Executer'}
        </button>

        <div class="mt-4 rounded border border-gray-200 bg-white p-3">
          <p class="text-xs font-semibold text-gray-700">Apply YAML (upload fichier)</p>
          <p class="mt-1 text-[11px] text-gray-500">
            Selectionne un fichier <code>.yaml</code>/<code>.yml</code> puis applique le manifest via l'API Kubernetes.
          </p>
          <input
            data-role="apply-file"
            type="file"
            accept=".yaml,.yml,text/yaml,application/x-yaml,application/yaml"
            class="mt-2 block w-full text-xs text-gray-700 file:mr-3 file:rounded file:border file:border-gray-300 file:bg-white file:px-2 file:py-1 file:text-xs file:font-semibold file:text-gray-700 hover:file:bg-gray-50"
            ${this._running ? 'disabled' : ''}
          />
          ${
            this._applyFileName
              ? `<p class="mt-2 text-[11px] text-gray-500">Fichier: <code>${escapeHtml(this._applyFileName)}</code></p>`
              : '<p class="mt-2 text-[11px] text-gray-500">Aucun fichier selectionne.</p>'
          }
          <button
            type="button"
            data-action="apply-upload"
            class="mt-2 px-3 py-2 rounded bg-emerald-600 text-white text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
            ${disableApply ? 'disabled' : ''}
          >
            ${this._running ? 'Application...' : 'Uploader et appliquer'}
          </button>
        </div>

        ${message}
        ${this.renderResult()}
      </div>
    `;

    const instanceSelect = this.querySelector('[data-role="instance"]');
    const commandInput = this.querySelector('[data-role="command"]');
    const refreshBtn = this.querySelector('[data-action="refresh"]');
    const syncKubeconfigBtn = this.querySelector('[data-action="sync-kubeconfig"]');
    const runBtn = this.querySelector('[data-action="run"]');
    const applyFileInput = this.querySelector('[data-role="apply-file"]');
    const applyUploadBtn = this.querySelector('[data-action="apply-upload"]');

    if (instanceSelect) {
      instanceSelect.addEventListener('change', (event) => {
        const value = event?.target?.value || '';
        this._selectedInstance = String(value).trim();
      });
    }

    if (commandInput) {
      commandInput.addEventListener('input', (event) => {
        this._commandInput = String(event?.target?.value || '');
      });
      commandInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          this.runCommand();
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => this.loadInstances());
    }

    if (syncKubeconfigBtn) {
      syncKubeconfigBtn.addEventListener('click', () => this.syncKubeconfig());
    }

    if (runBtn) {
      runBtn.addEventListener('click', () => this.runCommand());
    }

    if (applyFileInput) {
      applyFileInput.addEventListener('change', (event) => {
        const file = event?.target?.files?.[0] || null;
        this._applyFile = file;
        this._applyFileName = file?.name || '';
        this.render();
      });
    }

    if (applyUploadBtn) {
      applyUploadBtn.addEventListener('click', () => this.applyUploadedYaml());
    }

    this.querySelectorAll('[data-quick]').forEach((button) => {
      button.addEventListener('click', () => {
        const value = button.getAttribute('data-quick') || '';
        this.applyQuickCommand(value);
      });
    });
  }
}

customElements.define('k8s-client', K8sClient);

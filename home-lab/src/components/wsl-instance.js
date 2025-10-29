import { wsl_import_instance, wsl_list_instances, wsl_remove_instance } from '../tauri.js';
import { showError } from './toast.js';

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

class WslInstanceManager extends HTMLElement {
  constructor() {
    super();
    this._busyAction = null;
    this._messageState = 'idle';
    this._message = '';
    this._instances = [];
    this._loadingInstances = false;
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

  setBusy(action, message) {
    this._busyAction = action;
    this._messageState = 'running';
    this._message = message;
    this.render();
  }

  clearBusy() {
    this._busyAction = null;
    this.render();
  }

  async loadInstances() {
    this._loadingInstances = true;
    this.render();
    try {
      const data = await wsl_list_instances();
      this._instances = Array.isArray(data) ? data : [];
      return true;
    } catch (err) {
      const message = err?.message || String(err);
      showError(message);
      this._messageState = 'error';
      this._message = message;
      return false;
    } finally {
      this._loadingInstances = false;
      this.render();
    }
  }

  render() {
    const busyAction = this._busyAction;
    const loading = this._loadingInstances;
    const isBusy = Boolean(busyAction);
    const deletingName = busyAction && busyAction.startsWith('delete:') ? busyAction.slice(7) : null;
    const disableRefresh = isBusy || loading;
    const refreshLabel = loading
      ? busyAction === 'refresh'
        ? 'Actualisation…'
        : 'Chargement…'
      : 'Actualiser la liste';
    const message = this._message
      ? `<p class="mt-3 text-sm whitespace-pre-wrap ${
          this._messageState === 'error'
            ? 'text-red-600'
            : this._messageState === 'success'
              ? 'text-green-600'
              : 'text-gray-700'
        }">${escapeHtml(this._message)}</p>`
      : '';

    const instancesContent = loading
      ? '<p class="mt-4 text-sm text-gray-500">Chargement des instances…</p>'
      : this._instances.length === 0
        ? '<p class="mt-4 text-sm text-gray-500">Aucune instance WSL détectée.</p>'
        : `<ul class="mt-4 divide-y divide-gray-200 rounded border border-gray-200 bg-white overflow-hidden">
            ${this._instances
              .map((inst) => {
                const rawName = inst?.name ?? '';
                const normalizedRawName = rawName.trim();
                const name = escapeHtml(rawName);
                const rawState = inst?.state ?? 'Inconnu';
                const rawVersion = inst?.version ?? '';
                const state = escapeHtml(rawState);
                const version = escapeHtml(rawVersion);
                const badge = inst?.is_default
                  ? '<span class="ml-2 inline-flex items-center rounded bg-blue-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-600">Par défaut</span>'
                  : '';
                const deleteLabel = deletingName === normalizedRawName ? 'Suppression…' : 'Supprimer';
                const disabledAttr = isBusy || loading ? 'disabled' : '';
                const stateLine = rawVersion
                  ? `État : ${state} · Version ${version}`
                  : `État : ${state}`;
                return `
                  <li class="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm text-gray-800">
                    <div>
                      <p class="font-semibold text-gray-900">${name}${badge}</p>
                      <p class="text-xs text-gray-500">${stateLine}</p>
                    </div>
                    <button
                      type="button"
                      data-action="delete"
                      data-name="${escapeHtml(normalizedRawName)}"
                      class="px-3 py-1.5 text-xs font-semibold rounded border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed"
                      ${disabledAttr}
                    >${deleteLabel}</button>
                  </li>`;
              })
              .join('')}
          </ul>`;

    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">Instance WSL k3s</h2>
        <p class="text-sm text-gray-600 mb-3">
          Importez la distribution WSL fournie avec l'installateur et installez la dernière version de k3s.
        </p>
        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            data-action="import"
            class="px-3 py-2 rounded bg-blue-600 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            ${isBusy ? 'disabled' : ''}
          >
            ${busyAction === 'import' ? 'Import en cours…' : 'Ajouter une instance'}
          </button>
          <button
            type="button"
            data-action="force"
            class="px-3 py-2 rounded border border-gray-400 text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            ${isBusy ? 'disabled' : ''}
          >
            ${busyAction === 'force' ? 'Réimport en cours…' : 'Réimporter (forcer)'}
          </button>
          <button
            type="button"
            data-action="refresh"
            class="px-3 py-2 rounded border border-gray-300 text-sm font-medium text-gray-600 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            ${disableRefresh ? 'disabled' : ''}
          >
            ${refreshLabel}
          </button>
        </div>
        ${instancesContent}
        ${message}
      </div>
    `;

    const importBtn = this.querySelector('[data-action="import"]');
    const forceBtn = this.querySelector('[data-action="force"]');
    const refreshBtn = this.querySelector('[data-action="refresh"]');

    if (importBtn) {
      importBtn.addEventListener('click', () => this.runImport(false));
    }
    if (forceBtn) {
      forceBtn.addEventListener('click', () => this.runImport(true));
    }
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => this.refreshInstances());
    }

    this.querySelectorAll('[data-action="delete"]').forEach((btn) => {
      const name = btn.dataset.name;
      if (!name) return;
      btn.addEventListener('click', () => this.deleteInstance(name));
    });
  }

  async refreshInstances() {
    if (this._busyAction || this._loadingInstances) return;
    this.setBusy('refresh', 'Actualisation de la liste…');
    try {
      const refreshed = await this.loadInstances();
      if (refreshed) {
        this._messageState = 'success';
        this._message = 'Liste des instances mise à jour.';
      }
    } catch (err) {
      const message = err?.message || String(err);
      showError(message);
      this._messageState = 'error';
      this._message = message;
    } finally {
      this.clearBusy();
    }
  }

  async runImport(force) {
    if (this._busyAction) return;
    this.setBusy(force ? 'force' : 'import', force ? 'Réimport forcé en cours…' : 'Import en cours…');
    try {
      // eslint-disable-next-line no-console
      console.info('[WslInstanceManager] Import WSL demande', { force });
      const result = await wsl_import_instance({ force });
      // eslint-disable-next-line no-console
      console.info('[WslInstanceManager] Import WSL termine', result);
      if (!result?.ok) {
        throw new Error(result?.message || 'Import WSL échoué.');
      }
      const refreshed = await this.loadInstances();
      if (refreshed) {
        this._messageState = 'success';
        this._message = result.message || 'Instance importée.';
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[WslInstanceManager] Erreur import WSL', err);
      const message = err?.message || String(err);
      showError(message);
      this._messageState = 'error';
      this._message = message;
    } finally {
      this.clearBusy();
    }
  }

  async deleteInstance(name) {
    if (this._busyAction) return;
    const trimmed = (name || '').trim();
    if (!trimmed) {
      showError("Nom d'instance invalide.");
      return;
    }

    this.setBusy(`delete:${trimmed}`, `Suppression de ${trimmed}…`);
    try {
      const result = await wsl_remove_instance(trimmed);
      if (!result?.ok) {
        throw new Error(result?.message || `Suppression de ${trimmed} échouée.`);
      }
      const refreshed = await this.loadInstances();
      if (refreshed) {
        this._messageState = 'success';
        this._message = result.message || `Instance ${trimmed} supprimée.`;
      }
    } catch (err) {
      const message = err?.message || String(err);
      showError(message);
      this._messageState = 'error';
      this._message = message;
    } finally {
      this.clearBusy();
    }
  }
}

customElements.define('wsl-instance-manager', WslInstanceManager);

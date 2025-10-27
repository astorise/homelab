import { wsl_import_instance } from '../tauri.js';
import { showError } from './toast.js';

class WslInstanceManager extends HTMLElement {
  constructor() {
    super();
    this._state = 'idle';
    this._message = '';
  }

  connectedCallback() {
    this.render();
  }

  setState(state, message = '') {
    this._state = state;
    this._message = message;
    this.render();
  }

  render() {
    const busy = this._state === 'running';
    const message = this._message
      ? `<p class="mt-3 text-sm whitespace-pre-wrap ${
          this._state === 'error' ? 'text-red-600' : 'text-gray-700'
        }">${this._message}</p>`
      : '';

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
            ${busy ? 'disabled' : ''}
          >
            ${busy ? 'Import en cours…' : 'Ajouter une instance'}
          </button>
          <button
            type="button"
            data-action="force"
            class="px-3 py-2 rounded border border-gray-400 text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            ${busy ? 'disabled' : ''}
          >
            ${busy ? 'Patientez…' : 'Réimporter (forcer)'}
          </button>
        </div>
        ${message}
      </div>
    `;

    this.querySelector('[data-action="import"]').addEventListener('click', () => this.run(false));
    this.querySelector('[data-action="force"]').addEventListener('click', () => this.run(true));
  }

  async run(force) {
    if (this._state === 'running') return;
    this.setState('running', force ? 'Réimport forcé en cours…' : 'Import en cours…');
    try {
      const result = await wsl_import_instance({ force });
      if (result?.ok) {
        this.setState('success', result.message || 'Instance importée.');
      } else {
        throw new Error(result?.message || 'Import WSL échoué.');
      }
    } catch (err) {
      const message = err?.message || String(err);
      showError(message);
      this.setState('error', message);
    }
  }
}

customElements.define('wsl-instance-manager', WslInstanceManager);

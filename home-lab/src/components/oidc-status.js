import { oidc_get_status } from '../tauri.js';

class OidcStatus extends HTMLElement {
  constructor() {
    super();
    this._retryHandle = null;
    this._hasSuccessfulLoad = false;
    this._lastError = null;
  }

  connectedCallback() {
    this.load();
  }

  disconnectedCallback() {
    this.clearRetry();
  }

  clearRetry() {
    if (this._retryHandle) {
      clearTimeout(this._retryHandle);
      this._retryHandle = null;
    }
  }

  scheduleRetry() {
    this.clearRetry();
    this._retryHandle = setTimeout(() => this.load(), 2000);
  }

  renderLoading() {
    const errorHint = this._lastError
      ? `<p class="text-sm text-red-600 mt-2">Dernière erreur: ${this._lastError}</p>`
      : `<p class="text-sm text-gray-500">Tentative automatique toutes les 2&nbsp;s...</p>`;
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">OIDC Status</h2>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Connexion en cours...</span>
        </div>
        ${errorHint}
      </div>`;
  }

  renderSuccess(status) {
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">OIDC Status</h2>
        <p>State: ${status.state}</p>
        <p>Log level: ${status.log_level}</p>
        ${status.issuer ? `<p>Issuer: <code>${status.issuer}</code></p>` : ''}
        ${status.token_endpoint ? `<p>Token endpoint: <code>${status.token_endpoint}</code></p>` : ''}
      </div>`;
  }

  renderError(err) {
    this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">OIDC Status</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.</p>
      </div>`;
  }

  async load() {
    this.clearRetry();
    if (!this._hasSuccessfulLoad) {
      this.renderLoading();
    }
    try {
      const status = await oidc_get_status();
      this._hasSuccessfulLoad = true;
      this._lastError = null;
      this.renderSuccess(status);
    } catch (err) {
      const message = err?.message || String(err);
      this._lastError = message;
      if (this._hasSuccessfulLoad) {
        this.renderError(err);
        showError(message);
      } else {
        this.renderLoading();
      }
      this.scheduleRetry();
    }
  }
}

customElements.define('oidc-status', OidcStatus);

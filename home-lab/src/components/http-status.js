import { http_get_status } from '../tauri.js';

class HttpStatus extends HTMLElement {
  connectedCallback() {
    this.render();
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
    this._retryHandle = setTimeout(() => this.render(), 2000);
  }
  async render() {
    this.clearRetry();
    try {
      const status = await http_get_status();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Status</h2>
        <p>State: ${status.state}</p>
        <p>Log level: ${status.log_level}</p>
      </div>`;
    } catch (err) {
      this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">HTTP Status</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lance.</p>
      </div>`;
      showError(err.message || String(err));
      this.scheduleRetry();
    }
  }
}

customElements.define('http-status', HttpStatus);

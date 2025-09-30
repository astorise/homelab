import { http_list_routes } from '../tauri.js';

class HttpRoutes extends HTMLElement {
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
      const routes = await http_list_routes();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <ul class="list-disc pl-5">
          ${routes.map((r) => `<li>${JSON.stringify(r)}</li>`).join('')}
        </ul>
      </div>`;
    } catch (err) {
      this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lance.</p>
      </div>`;
      showError(err.message || String(err));
      this.scheduleRetry();
    }
  }
}

customElements.define('http-routes', HttpRoutes);

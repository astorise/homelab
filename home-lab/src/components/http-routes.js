import { http_list_routes } from '../tauri.js';

class HttpRoutes extends HTMLElement {
  constructor() {
    super();
    this._retryHandle = null;
    this._hasSuccessfulLoad = false;
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
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Connexion en cours...</span>
        </div>
      </div>`;
  }

  renderSuccess(routes) {
    const items = routes.length
      ? routes.map((r) => `<li>${JSON.stringify(r)}</li>`).join('')
      : '<li>Aucune route.</li>';
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <ul class="list-disc pl-5">
          ${items}
        </ul>
      </div>`;
  }

  renderError(err) {
    this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lance.</p>
      </div>`;
  }

  async load() {
    this.clearRetry();
    if (!this._hasSuccessfulLoad) {
      this.renderLoading();
    }
    try {
      const routes = await http_list_routes();
      this._hasSuccessfulLoad = true;
      this.renderSuccess(routes);
    } catch (err) {
      if (this._hasSuccessfulLoad) {
        this.renderError(err);
        showError(err.message || String(err));
      } else {
        this.renderLoading();
      }
      this.scheduleRetry();
    }
  }
}

customElements.define('http-routes', HttpRoutes);


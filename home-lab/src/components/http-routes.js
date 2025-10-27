import { http_add_route, http_list_routes, http_remove_route } from '../tauri.js';

class HttpRoutes extends HTMLElement {
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
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Connexion en cours...</span>
        </div>
        ${errorHint}
      </div>`;
  }

  renderRoutesList(routes) {
    if (!routes.length) {
      return '<li class="text-sm text-gray-600">Aucune route.</li>';
    }
    return routes
      .map(
        (route) => `
          <li class="border-b border-gray-200 pb-3 mb-3 last:pb-0 last:mb-0 last:border-none">
            <div class="flex items-center justify-between">
              <span class="font-semibold">${route.host}</span>
              <span class="text-sm text-gray-500">Port: ${route.port}</span>
            </div>
            <button
              type="button"
              class="http-remove-route mt-2 text-xs text-red-600 hover:text-red-800"
              data-host="${route.host}"
            >Supprimer</button>
          </li>`
      )
      .join('');
  }

  attachEventHandlers() {
    const form = this.querySelector('#http-add-form');
    if (form) {
      form.addEventListener('submit', (event) => this.handleAdd(event));
    }
    this.querySelectorAll('.http-remove-route').forEach((btn) => {
      btn.addEventListener('click', (event) => this.handleRemove(event));
    });
  }

  renderSuccess(routes) {
    this._routes = Array.isArray(routes) ? routes : [];
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <ul class="list-disc pl-5 space-y-2">
          ${this.renderRoutesList(this._routes)}
        </ul>
        <form id="http-add-form" class="mt-4 grid gap-2 sm:grid-cols-4" autocomplete="off">
          <input
            name="host"
            type="text"
            required
            placeholder="Hôte"
            class="sm:col-span-2 rounded border border-gray-300 px-2 py-1"
          />
          <input
            name="port"
            type="number"
            min="0"
            step="1"
            required
            placeholder="Port"
            class="rounded border border-gray-300 px-2 py-1"
          />
          <button
            type="submit"
            class="sm:col-span-4 justify-self-start bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
          >Ajouter</button>
        </form>
      </div>`;
    this.attachEventHandlers();
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
      this._lastError = null;
      this.renderSuccess(routes);
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

  async handleAdd(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submitBtn = form.querySelector('button[type="submit"]');
    const data = new FormData(form);
    const host = (data.get('host') || '').trim();
    const portValue = data.get('port');
    const port = portValue === '' || portValue === null ? NaN : Number.parseInt(portValue, 10);
    if (!host || !Number.isInteger(port) || port < 0) {
      showError('Veuillez fournir un hôte et un port valides.');
      return;
    }
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Ajout...';
    }
    try {
      const res = await http_add_route({ host, port });
      if (!res?.ok) {
        throw new Error(res?.message || 'Échec de l\'ajout de la route.');
      }
      form.reset();
      await this.load();
    } catch (err) {
      showError(err.message || String(err));
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Ajouter';
      }
    }
  }

  async handleRemove(event) {
    event.preventDefault();
    const btn = event.currentTarget;
    const { host } = btn.dataset;
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Suppression...';
    }
    try {
      const res = await http_remove_route({ host });
      if (!res?.ok) {
        throw new Error(res?.message || 'Échec de la suppression de la route.');
      }
      await this.load();
    } catch (err) {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Supprimer';
      }
      showError(err.message || String(err));
    }
  }
}

customElements.define('http-routes', HttpRoutes);

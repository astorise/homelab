import { http_list_routes, isTauri } from '../tauri.js';

class HttpRoutes extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    if (!isTauri()) {
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <p>Tauri API not available. Please run via Tauri.</p>
      </div>`;
      return;
    }
    try {
      const routes = await http_list_routes();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Routes</h2>
        <ul class="list-disc pl-5">
          ${routes.map(r => `<li>${JSON.stringify(r)}</li>`).join('')}
        </ul>
      </div>`;
    } catch (err) {
      showError(err.message);
    }
  }
}

customElements.define('http-routes', HttpRoutes);

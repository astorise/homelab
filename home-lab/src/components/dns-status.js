import { dns_get_status } from '../tauri.js';

class DnsStatus extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    try {
      const status = await dns_get_status();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">DNS Status</h2>
        <p>State: ${status.state}</p>
        <p>Log level: ${status.log_level}</p>
      </div>`;
    } catch (err) {
      this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">DNS Status</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.</p>
      </div>`;
      showError(err.message || String(err));
    }
  }
}

customElements.define('dns-status', DnsStatus);

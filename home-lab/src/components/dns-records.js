import { dns_list_records } from '../tauri.js';

class DnsRecords extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    try {
      const records = await dns_list_records();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">DNS Records</h2>
        <ul class="list-disc pl-5">
          ${records.map(r => `<li>${JSON.stringify(r)}</li>`).join('')}
        </ul>
      </div>`;
    } catch (err) {
      this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">DNS Records</h2>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.</p>
      </div>`;
      showError(err.message || String(err));
    }
  }
}

customElements.define('dns-records', DnsRecords);

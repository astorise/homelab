import { dns_list_records } from '../tauri.js';

class DnsRecords extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    const records = await dns_list_records();
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">DNS Records</h2>
        <ul class="list-disc pl-5">
          ${records.map(r => `<li>${JSON.stringify(r)}</li>`).join('')}
        </ul>
      </div>`;
  }
}

customElements.define('dns-records', DnsRecords);

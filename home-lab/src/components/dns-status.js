import { dns_get_status } from '../tauri.js';

class DnsStatus extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    const status = await dns_get_status();
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">DNS Status</h2>
        <p>State: ${status.state}</p>
        <p>Log level: ${status.log_level}</p>
      </div>`;
  }
}

customElements.define('dns-status', DnsStatus);

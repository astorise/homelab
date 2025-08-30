import { http_get_status } from '../tauri.js';

class HttpStatus extends HTMLElement {
  connectedCallback() {
    this.render();
  }
  async render() {
    try {
      const status = await http_get_status();
      this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">HTTP Status</h2>
        <p>State: ${status.state}</p>
        <p>Log level: ${status.log_level}</p>
      </div>`;
    } catch (err) {
      showError(err.message);
    }
  }
}

customElements.define('http-status', HttpStatus);

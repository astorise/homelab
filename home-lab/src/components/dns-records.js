import { dns_add_record, dns_list_records, dns_remove_record } from '../tauri.js';

class DnsRecords extends HTMLElement {
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
        <h2 class="font-bold mb-2">DNS Records</h2>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Connexion en cours...</span>
        </div>
        ${errorHint}
      </div>`;
  }

  renderRecordsList(records) {
    if (!records.length) {
      return '<li class="text-sm text-gray-600">Aucun enregistrement.</li>';
    }
    return records
      .map((record) => {
        const ttl = record.ttl ?? '—';
        const renderValues = (type, values) => {
          if (!Array.isArray(values) || values.length === 0) return '';
          return `
            <ul class="ml-4 mt-2 space-y-1">
              ${values
                .map(
                  (value) => `
                    <li class="flex items-center justify-between gap-2 text-sm">
                      <span class="font-mono">${type} → ${value}</span>
                      <button
                        type="button"
                        class="dns-remove-record text-xs text-red-600 hover:text-red-800"
                        data-name="${record.name}"
                        data-rrtype="${type}"
                        data-value="${value}"
                      >Supprimer</button>
                    </li>`
                )
                .join('')}
            </ul>`;
        };
        return `
          <li class="border-b border-gray-200 pb-3 mb-3 last:pb-0 last:mb-0 last:border-none">
            <div class="flex items-center justify-between">
              <span class="font-semibold">${record.name}</span>
              <span class="text-xs text-gray-500">TTL: ${ttl}</span>
            </div>
            ${renderValues('A', record.a)}
            ${renderValues('AAAA', record.aaaa)}
          </li>`;
      })
      .join('');
  }

  attachEventHandlers() {
    const form = this.querySelector('#dns-add-form');
    if (form) {
      form.addEventListener('submit', (event) => this.handleAdd(event));
    }
    this.querySelectorAll('.dns-remove-record').forEach((btn) => {
      btn.addEventListener('click', (event) => this.handleRemove(event));
    });
  }

  renderSuccess(records) {
    this._records = Array.isArray(records) ? records : [];
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <h2 class="font-bold mb-2">DNS Records</h2>
        <ul class="list-disc pl-5 space-y-2">
          ${this.renderRecordsList(this._records)}
        </ul>
        <form id="dns-add-form" class="mt-4 grid gap-2 sm:grid-cols-5" autocomplete="off">
          <input
            name="name"
            type="text"
            required
            placeholder="Nom"
            class="sm:col-span-2 rounded border border-gray-300 px-2 py-1"
          />
          <select
            name="rrtype"
            class="rounded border border-gray-300 px-2 py-1"
            required
          >
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
          </select>
          <input
            name="value"
            type="text"
            required
            placeholder="Adresse IP"
            class="rounded border border-gray-300 px-2 py-1"
          />
          <input
            name="ttl"
            type="number"
            min="1"
            step="1"
            value="300"
            placeholder="TTL"
            class="rounded border border-gray-300 px-2 py-1"
          />
          <button
            type="submit"
            class="sm:col-span-5 justify-self-start bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
          >Ajouter</button>
        </form>
      </div>`;
    this.attachEventHandlers();
  }

  renderError(err) {
    this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <h2 class="font-bold mb-2">DNS Records</h2>
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
      const records = await dns_list_records();
      this._hasSuccessfulLoad = true;
      this._lastError = null;
      this.renderSuccess(records);
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
    const name = (data.get('name') || '').trim();
    const rrtype = (data.get('rrtype') || '').toString().toUpperCase();
    const value = (data.get('value') || '').trim();
    const ttlValue = data.get('ttl');
    const ttl = ttlValue === '' || ttlValue === null ? undefined : Number.parseInt(ttlValue, 10);
    if (!name || !rrtype || !value) {
      showError('Veuillez remplir tous les champs pour ajouter un enregistrement.');
      return;
    }
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Ajout...';
    }
    try {
      const res = await dns_add_record({ name, rrtype, value, ttl });
      if (!res?.ok) {
        throw new Error(res?.message || 'Échec de l\'ajout de l\'enregistrement.');
      }
      form.reset();
      if (form.querySelector('input[name="ttl"]')) {
        form.querySelector('input[name="ttl"]').value = '300';
      }
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
    const { name, rrtype, value } = btn.dataset;
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Suppression...';
    }
    try {
      const res = await dns_remove_record({ name, rrtype, value });
      if (!res?.ok) {
        throw new Error(res?.message || 'Échec de la suppression de l\'enregistrement.');
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

customElements.define('dns-records', DnsRecords);


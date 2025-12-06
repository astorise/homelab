import { oidc_list_clients, oidc_register_client, oidc_remove_client } from '../tauri.js';

function parseListInput(value) {
  if (!value) {
    return [];
  }
  return String(value)
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

class OidcClients extends HTMLElement {
  constructor() {
    super();
    this._retryHandle = null;
    this._hasSuccessfulLoad = false;
    this._lastError = null;
    this._clients = [];
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
    this._retryHandle = setTimeout(() => this.load(), 4000);
  }

  renderLoading() {
    const errorHint = this._lastError
      ? `<p class="text-sm text-red-600 mt-2">Dernière erreur: ${this._lastError}</p>`
      : `<p class="text-sm text-gray-500">Tentative automatique toutes les 4&nbsp;s...</p>`;
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <div class="flex items-center justify-between mb-2">
          <h2 class="font-bold">Clients OIDC</h2>
        </div>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Chargement en cours...</span>
        </div>
        ${errorHint}
      </div>`;
  }

  renderClients(clients) {
    if (!clients.length) {
      return '<p class="text-sm text-gray-600">Aucun client enregistré.</p>';
    }
    return clients
      .map(
        (client) => `
          <div class="border border-gray-200 rounded p-3 space-y-1 bg-white">
            <div class="flex items-center justify-between">
              <div>
                <span class="font-semibold">${client.client_id}</span>
                <span class="text-xs text-gray-500 ml-2">${client.auth_method || 'inconnu'}</span>
              </div>
              ${
                client.auth_method === 'private_key_jwt'
                  ? `<button
                type="button"
                class="oidc-remove text-xs text-red-600 hover:text-red-800"
                data-client-id="${client.client_id}"
              >Supprimer</button>`
                  : ''
              }
            </div>
            ${client.subject ? `<div class="text-xs text-gray-500">sub: ${client.subject}</div>` : ''}
            <div class="text-sm text-gray-700">
              <span class="font-semibold">Scopes:</span>
              ${client.allowed_scopes.length ? client.allowed_scopes.join(', ') : '<em>hérités</em>'}
            </div>
            <div class="text-sm text-gray-700">
              <span class="font-semibold">Audiences:</span>
              ${client.audiences.length ? client.audiences.join(', ') : '<em>non définies</em>'}
            </div>
            ${this.renderPasswordUsers(client.password_users)}
            ${client.public_key_pem
              ? `<details class="text-xs mt-2">
                  <summary class="cursor-pointer text-blue-700">Clé publique (pem)</summary>
                  <pre class="bg-gray-50 border rounded p-2 overflow-auto mt-1 whitespace-pre-wrap text-[11px]">${client.public_key_pem}</pre>
                </details>`
              : ''}
          </div>`
      )
      .join('');
  }

  renderPasswordUsers(users) {
    if (!users.length) {
      return '';
    }
    const rows = users
      .map(
        (user) => `
          <li class="flex flex-col">
            <span class="text-sm font-medium">${user.username}</span>
            <span class="text-xs text-gray-500">
              ${user.subject ? `sub: ${user.subject} · ` : ''}scopes: ${
          user.scopes.length ? user.scopes.join(', ') : 'none'
        }
            </span>
          </li>`
      )
      .join('');
    return `
      <div class="text-sm text-gray-700">
        <span class="font-semibold">Utilisateurs Password:</span>
        <ul class="list-disc ml-5 space-y-1 mt-1">
          ${rows}
        </ul>
      </div>`;
  }

  renderForm() {
    return `
      <form id="oidc-register-form" class="mt-4 bg-white border border-gray-200 rounded p-3 space-y-2" autocomplete="off">
        <p class="text-sm text-gray-600">Ajoutez un client basé sur une paire de clés (private_key_jwt).</p>
        <div class="grid gap-2 sm:grid-cols-2">
          <input name="client_id" type="text" required placeholder="Identifiant client" class="rounded border border-gray-300 px-2 py-1" />
          <input name="subject" type="text" placeholder="Subject (optionnel)" class="rounded border border-gray-300 px-2 py-1" />
        </div>
        <div class="grid gap-2 sm:grid-cols-2">
          <input name="allowed_scopes" type="text" placeholder="Scopes (séparés par espace)" class="rounded border border-gray-300 px-2 py-1" />
          <input name="audiences" type="text" placeholder="Audiences (séparées par espace)" class="rounded border border-gray-300 px-2 py-1" />
        </div>
        <textarea
          name="public_key_pem"
          rows="4"
          required
          placeholder="Collez la clé publique (PEM)"
          class="w-full rounded border border-gray-300 px-2 py-1 font-mono text-xs"
        ></textarea>
        <button
          type="submit"
          class="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 text-sm"
        >Enregistrer</button>
      </form>`;
  }

  renderSuccess(clients) {
    this._clients = Array.isArray(clients) ? clients : [];
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="font-bold">Clients OIDC</h2>
          <button type="button" class="oidc-refresh text-sm text-blue-600 hover:text-blue-800">Rafraîchir</button>
        </div>
        <div class="space-y-3">
          ${this.renderClients(this._clients)}
        </div>
        ${this.renderForm()}
      </div>`;
    this.attachHandlers();
  }

  renderError(err) {
    this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <div class="flex items-center justify-between mb-2">
          <h2 class="font-bold">Clients OIDC</h2>
          <button type="button" class="oidc-refresh text-sm underline">Réessayer</button>
        </div>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.</p>
      </div>`;
    this.attachHandlers();
  }

  attachHandlers() {
    const refresh = this.querySelector('.oidc-refresh');
    if (refresh) {
      refresh.addEventListener('click', () => this.load());
    }
    this.querySelectorAll('.oidc-remove').forEach((btn) => {
      btn.addEventListener('click', (event) => this.handleRemove(event));
    });
    const form = this.querySelector('#oidc-register-form');
    if (form) {
      form.addEventListener('submit', (event) => this.handleRegister(event));
    }
  }

  async handleRegister(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const data = new FormData(form);
    const client_id = (data.get('client_id') || '').trim();
    const subject = (data.get('subject') || '').trim();
    const allowed_scopes = parseListInput(data.get('allowed_scopes'));
    const audiences = parseListInput(data.get('audiences'));
    const public_key_pem = (data.get('public_key_pem') || '').trim();
    if (!client_id || !public_key_pem) {
      showError("L'identifiant client et la clé publique sont requis.");
      return;
    }
    if (submit) {
      submit.disabled = true;
      submit.textContent = 'Enregistrement...';
    }
    try {
      await oidc_register_client({
        client_id,
        subject,
        allowed_scopes,
        audiences,
        public_key_pem,
        auth_method: 'private_key_jwt',
      });
      form.reset();
      await this.load();
    } catch (err) {
      showError(err?.message || String(err));
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = 'Enregistrer';
      }
    }
  }

  async handleRemove(event) {
    event.preventDefault();
    const btn = event.currentTarget;
    const clientId = btn?.dataset?.clientId;
    if (!clientId) {
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Suppression...';
    try {
      await oidc_remove_client(clientId);
      await this.load();
    } catch (err) {
      showError(err?.message || String(err));
      btn.disabled = false;
      btn.textContent = 'Supprimer';
    }
  }

  async load() {
    this.clearRetry();
    if (!this._hasSuccessfulLoad) {
      this.renderLoading();
    }
    try {
      const clients = await oidc_list_clients();
      this._hasSuccessfulLoad = true;
      this._lastError = null;
      this.renderSuccess(clients);
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
}

customElements.define('oidc-clients', OidcClients);

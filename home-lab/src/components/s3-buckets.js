import {
  s3_create_bucket,
  s3_delete_bucket,
  s3_list_buckets,
  s3_update_bucket,
} from '../tauri.js';
import { showError } from './toast.js';

function formatDate(value) {
  if (!value) {
    return 'inconnue';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

class S3Buckets extends HTMLElement {
  constructor() {
    super();
    this._retryHandle = null;
    this._hasSuccessfulLoad = false;
    this._lastError = null;
    this._buckets = [];
    this._editingBucket = null;
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
    this._retryHandle = setTimeout(() => this.load(), 2500);
  }

  renderLoading() {
    const errorHint = this._lastError
      ? `<p class="text-sm text-red-600 mt-2">DerniÃ¨re erreur: ${this._lastError}</p>`
      : `<p class="text-sm text-gray-500">Tentative automatique toutes les 2,5&nbsp;s...</p>`;
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded">
        <div class="flex items-center justify-between mb-2">
          <h2 class="font-bold">Buckets S3</h2>
        </div>
        <div class="flex items-center gap-2 text-gray-600">
          <span class="spinner" aria-hidden="true"></span>
          <span>Chargement en cours...</span>
        </div>
        ${errorHint}
      </div>`;
  }

  get editingBucket() {
    return this._buckets.find((bucket) => bucket.name === this._editingBucket) ?? null;
  }

  renderBucketsList() {
    if (!this._buckets.length) {
      return '<li class="text-sm text-gray-600">Aucun bucket.</li>';
    }
    return this._buckets
      .map((bucket) => `
        <li
          class="border-b border-gray-200 pb-3 mb-3 last:pb-0 last:mb-0 last:border-none"
          data-bucket-row
          data-name="${bucket.name}"
        >
          <div class="flex items-center justify-between gap-3">
            <div>
              <span class="font-semibold">${bucket.name}</span>
              <p class="text-xs text-gray-500">Créé le: ${formatDate(bucket.created_at)}</p>
            </div>
            <div class="flex items-center gap-2">
              <button
                type="button"
                class="s3-edit-bucket text-xs text-blue-600 hover:text-blue-800"
                data-name="${bucket.name}"
              >Modifier</button>
              <button
                type="button"
                class="s3-delete-bucket text-xs text-red-600 hover:text-red-800"
                data-name="${bucket.name}"
              >Supprimer</button>
            </div>
          </div>
          <label class="mt-2 inline-flex items-center gap-2 text-xs text-gray-600">
            <input type="checkbox" class="s3-delete-objects" />
            Supprimer aussi les objets du bucket
          </label>
        </li>`)
      .join('');
  }

  renderCreateForm() {
    return `
      <form id="s3-create-form" class="mt-4 bg-white border border-gray-200 rounded p-3 space-y-2" autocomplete="off">
        <h3 class="font-semibold">Créer un bucket</h3>
        <div class="grid gap-2 sm:grid-cols-2">
          <input
            name="bucket_name"
            type="text"
            required
            placeholder="Nom du bucket"
            class="rounded border border-gray-300 px-2 py-1"
          />
          <input
            name="source_path"
            type="text"
            placeholder="Chemin Windows à importer (optionnel)"
            class="rounded border border-gray-300 px-2 py-1"
          />
        </div>
        <p class="text-xs text-gray-500">Si un chemin est fourni, son contenu est importé dans le bucket.</p>
        <button
          type="submit"
          class="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 text-sm"
        >Créer</button>
      </form>`;
  }

  renderEditForm() {
    const bucket = this.editingBucket;
    if (!bucket) {
      return '';
    }
    return `
      <form id="s3-update-form" class="mt-4 bg-white border border-gray-200 rounded p-3 space-y-2" autocomplete="off">
        <div class="flex items-center justify-between gap-2">
          <h3 class="font-semibold">Modifier le bucket</h3>
          <button type="button" class="s3-cancel-edit text-xs text-gray-600 hover:text-gray-800">Annuler</button>
        </div>
        <input name="current_bucket_name" type="hidden" value="${bucket.name}" />
        <div class="grid gap-2 sm:grid-cols-2">
          <input
            name="new_bucket_name"
            type="text"
            value="${bucket.name}"
            placeholder="Nouveau nom"
            class="rounded border border-gray-300 px-2 py-1"
          />
          <input
            name="source_path"
            type="text"
            placeholder="Chemin Windows à importer (optionnel)"
            class="rounded border border-gray-300 px-2 py-1"
          />
        </div>
        <label class="inline-flex items-center gap-2 text-sm text-gray-700">
          <input name="replace_objects" type="checkbox" />
          Remplacer le contenu du bucket avec le chemin source
        </label>
        <p class="text-xs text-gray-500">Changer le nom renomme le bucket. Fournir un chemin source permet de réimporter un dossier ou un fichier Windows.</p>
        <button
          type="submit"
          class="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 text-sm"
        >Enregistrer</button>
      </form>`;
  }

  renderSuccess(buckets) {
    this._buckets = Array.isArray(buckets) ? buckets : [];
    if (this._editingBucket && !this.editingBucket) {
      this._editingBucket = null;
    }
    this.innerHTML = `
      <div class="p-4 bg-gray-100 rounded space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="font-bold">Buckets S3</h2>
          <button type="button" class="s3-refresh text-sm text-blue-600 hover:text-blue-800">Rafraîchir</button>
        </div>
        <ul class="list-disc pl-5 space-y-2">
          ${this.renderBucketsList()}
        </ul>
        ${this.renderCreateForm()}
        ${this.renderEditForm()}
      </div>`;
    this.attachHandlers();
  }

  renderError(err) {
    this.innerHTML = `
      <div class="p-4 bg-yellow-100 text-yellow-900 rounded">
        <div class="flex items-center justify-between mb-2">
          <h2 class="font-bold">Buckets S3</h2>
          <button type="button" class="s3-refresh text-sm underline">Réessayer</button>
        </div>
        <p class="mb-1">Erreur: ${err?.message || err}</p>
        <p class="text-sm opacity-80">Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.</p>
      </div>`;
    this.attachHandlers();
  }

  attachHandlers() {
    const refresh = this.querySelector('.s3-refresh');
    if (refresh) {
      refresh.addEventListener('click', () => this.load());
    }
    const createForm = this.querySelector('#s3-create-form');
    if (createForm) {
      createForm.addEventListener('submit', (event) => this.handleCreate(event));
    }
    const updateForm = this.querySelector('#s3-update-form');
    if (updateForm) {
      updateForm.addEventListener('submit', (event) => this.handleUpdate(event));
    }
    const cancelEdit = this.querySelector('.s3-cancel-edit');
    if (cancelEdit) {
      cancelEdit.addEventListener('click', () => {
        this._editingBucket = null;
        this.renderSuccess(this._buckets);
      });
    }
    this.querySelectorAll('.s3-edit-bucket').forEach((button) => {
      button.addEventListener('click', (event) => this.handleEditStart(event));
    });
    this.querySelectorAll('.s3-delete-bucket').forEach((button) => {
      button.addEventListener('click', (event) => this.handleDelete(event));
    });
  }

  async handleCreate(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const data = new FormData(form);
    const bucket_name = (data.get('bucket_name') || '').trim();
    const source_path = (data.get('source_path') || '').trim();
    if (!bucket_name) {
      showError('Le nom du bucket est requis.');
      return;
    }
    if (submit) {
      submit.disabled = true;
      submit.textContent = 'Création...';
    }
    try {
      const result = await s3_create_bucket({ bucket_name, source_path });
      if (!result?.ok) {
        throw new Error(result?.message || 'Échec de la création du bucket.');
      }
      form.reset();
      await this.load();
    } catch (err) {
      showError(err?.message || String(err));
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = 'Créer';
      }
    }
  }

  handleEditStart(event) {
    const bucketName = event.currentTarget?.dataset?.name;
    if (!bucketName) {
      return;
    }
    this._editingBucket = bucketName;
    this.renderSuccess(this._buckets);
  }

  async handleUpdate(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const data = new FormData(form);
    const current_bucket_name = (data.get('current_bucket_name') || '').trim();
    const new_bucket_name = (data.get('new_bucket_name') || '').trim();
    const source_path = (data.get('source_path') || '').trim();
    const replace_objects = data.get('replace_objects') === 'on';
    if (!current_bucket_name) {
      showError('Le nom actuel du bucket est requis.');
      return;
    }
    if (replace_objects && !source_path) {
      showError('Un chemin source est requis pour remplacer le contenu du bucket.');
      return;
    }
    if (submit) {
      submit.disabled = true;
      submit.textContent = 'Enregistrement...';
    }
    try {
      const result = await s3_update_bucket({
        current_bucket_name,
        new_bucket_name,
        source_path,
        replace_objects,
      });
      if (!result?.ok) {
        throw new Error(result?.message || 'Échec de la mise à jour du bucket.');
      }
      this._editingBucket = null;
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

  async handleDelete(event) {
    event.preventDefault();
    const button = event.currentTarget;
    const bucket_name = button?.dataset?.name;
    const row = button?.closest('[data-bucket-row]');
    const delete_objects = !!row?.querySelector('.s3-delete-objects')?.checked;
    if (!bucket_name) {
      return;
    }
    const confirmed = window.confirm(
      delete_objects
        ? `Supprimer le bucket ${bucket_name} et tous ses objets ?`
        : `Supprimer le bucket ${bucket_name} ?`
    );
    if (!confirmed) {
      return;
    }
    button.disabled = true;
    button.textContent = 'Suppression...';
    try {
      const result = await s3_delete_bucket({ bucket_name, delete_objects });
      if (!result?.ok) {
        throw new Error(result?.message || 'Échec de la suppression du bucket.');
      }
      if (this._editingBucket === bucket_name) {
        this._editingBucket = null;
      }
      await this.load();
    } catch (err) {
      button.disabled = false;
      button.textContent = 'Supprimer';
      showError(err?.message || String(err));
    }
  }

  async load() {
    this.clearRetry();
    if (!this._hasSuccessfulLoad) {
      this.renderLoading();
    }
    try {
      const buckets = await s3_list_buckets();
      this._hasSuccessfulLoad = true;
      this._lastError = null;
      this.renderSuccess(buckets);
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

customElements.define('s3-buckets', S3Buckets);

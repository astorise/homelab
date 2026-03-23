import { dns_get_status } from '../tauri.js';
import gsap from 'gsap';

class DnsStatus extends HTMLElement {
  constructor() {
    super();
    this._retryHandle = null;
    this._hasSuccessfulLoad = false;
    this._lastError = null;
    // On force le composant à se comporter comme un block dans la grille
    this.classList.add('block', 'h-full'); 
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

  // Utilitaire pour animer le changement de contenu
  updateContent(html) {
    // Si du contenu existe déjà, on fait un fondu enchaîné
    if (this.innerHTML.trim() !== '') {
      gsap.to(this, { 
        opacity: 0, 
        duration: 0.2, 
        onComplete: () => {
          this.innerHTML = html;
          gsap.to(this, { opacity: 1, duration: 0.3 });
        }
      });
    } else {
      this.innerHTML = html;
    }
  }

  renderLoading() {
    const errorHint = this._lastError
      ? `<p class="text-xs text-red-500 mt-3 font-medium flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-red-500 block"></span> ${this._lastError}</p>`
      : `<p class="text-xs text-slate-400 mt-3">Tentative automatique toutes les 2s...</p>`;

    this.updateContent(`
      <div class="p-6 bg-white border border-slate-200 rounded-xl shadow-sm h-full flex flex-col justify-between transition-shadow hover:shadow-md">
        <div>
          <div class="flex items-center justify-between mb-4">
            <h2 class="font-semibold text-slate-800">DNS Status</h2>
            <span class="relative flex h-3 w-3">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full h-3 w-3 bg-blue-500"></span>
            </span>
          </div>
          <div class="flex items-center gap-3 text-slate-500 text-sm">
             <svg class="animate-spin h-4 w-4 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
            <span>Connexion en cours...</span>
          </div>
        </div>
        ${errorHint}
      </div>`);
  }

  renderSuccess(status) {
    // Statut visuel dynamique basé sur l'état retourné
    const isRunning = status.state.toLowerCase() === 'running';
    const statusColor = isRunning ? 'bg-emerald-500' : 'bg-slate-400';

    this.updateContent(`
      <div class="p-6 bg-white border border-slate-200 rounded-xl shadow-sm h-full flex flex-col transition-shadow hover:shadow-md">
        <div class="flex items-center justify-between mb-4">
          <h2 class="font-semibold text-slate-800">DNS Status</h2>
          <span class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-50 text-xs font-medium text-slate-600 border border-slate-200">
            <span class="w-2 h-2 rounded-full ${statusColor}"></span>
            ${status.state}
          </span>
        </div>
        <div class="mt-auto">
          <p class="text-sm text-slate-500 flex justify-between border-t border-slate-100 pt-3">
            <span>Log level</span>
            <span class="font-mono text-slate-700">${status.log_level}</span>
          </p>
        </div>
      </div>`);
  }

  renderError(err) {
    this.updateContent(`
      <div class="p-6 bg-red-50/50 border border-red-100 rounded-xl shadow-sm h-full flex flex-col transition-shadow hover:shadow-md">
        <div class="flex items-center justify-between mb-4">
          <h2 class="font-semibold text-red-900">DNS Status</h2>
          <span class="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-100 text-xs font-medium text-red-700 border border-red-200">
            <span class="w-2 h-2 rounded-full bg-red-500"></span>
            Erreur
          </span>
        </div>
        <div class="mt-2 text-sm text-red-800 bg-white/60 p-3 rounded-lg border border-red-100 font-mono break-all">
          ${err?.message || err}
        </div>
        <p class="text-xs text-red-600/80 mt-4 border-t border-red-100/50 pt-3">
          Activez le mock (VITE_TAURI_MOCK=1) si le backend n'est pas lancé.
        </p>
      </div>`);
  }

   async load() {
    this.clearRetry();
    if (!this._hasSuccessfulLoad) {
      this.renderLoading();
    }
    try {
      const status = await dns_get_status();
      this._hasSuccessfulLoad = true;
       this._lastError = null;
      this.renderSuccess(status);
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

customElements.define('dns-status', DnsStatus);
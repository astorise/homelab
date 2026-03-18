class ToastContainer extends HTMLElement {
  connectedCallback() {
    this.className = 'fixed top-4 right-4 space-y-2 z-50';
  }
  show(message, kind = 'error') {
    const toast = document.createElement('div');
    toast.textContent = message;
    const tone = kind === 'success' ? 'bg-green-600' : 'bg-red-500';
    toast.className = `${tone} text-white px-4 py-2 rounded shadow`;
    this.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }
}

customElements.define('toast-container', ToastContainer);

export function showError(message) {
  document.querySelector('toast-container')?.show(message, 'error');
}

export function showSuccess(message) {
  document.querySelector('toast-container')?.show(message, 'success');
}

globalThis.showError = showError;
globalThis.showSuccess = showSuccess;

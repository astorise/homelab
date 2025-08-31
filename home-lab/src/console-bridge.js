/*
  Relaye les logs de l'IHM vers Tauri (console + fichier) quand disponible,
  et capture les erreurs globales pour aider au debug d'écran blanc.
*/

const levels = ["error", "warn", "info", "debug", "trace", "log"];

function toMessage(args) {
  try {
    return args.map((a) => {
      if (a instanceof Error) return `${a.name}: ${a.message}\n${a.stack || ''}`;
      if (typeof a === 'object') return JSON.stringify(a);
      return String(a);
    }).join(' ');
  } catch (_) {
    return args.map((a) => String(a)).join(' ');
  }
}

function invokeLog(level, message) {
  try {
    const api = globalThis?.__TAURI__?.invoke;
    if (typeof api === 'function') {
      api('ui_log', { level, message }).catch(() => {});
    }
  } catch (_) {
    // ignore
  }
}

// Proxy console methods → conserve sortie locale + envoie à Tauri
try {
  const original = {};
  levels.forEach((lvl) => { original[lvl] = console[lvl] ? console[lvl].bind(console) : console.log.bind(console); });
  ["error", "warn", "info", "debug", "log"].forEach((lvl) => {
    console[lvl] = (...args) => {
      try { original[lvl](...args); } catch (_) {}
      invokeLog(lvl, toMessage(args));
    };
  });
} catch (_) {
  // ignore
}

// Erreurs globales
try {
  globalThis.addEventListener('error', (evt) => {
    const msg = evt?.error ? `${evt.error?.name || 'Error'}: ${evt.error?.message || ''}\n${evt.error?.stack || ''}` : String(evt?.message || 'Unknown error');
    invokeLog('error', msg);
  });
  globalThis.addEventListener('unhandledrejection', (evt) => {
    const r = evt?.reason;
    const msg = r instanceof Error ? `${r.name}: ${r.message}\n${r.stack || ''}` : toMessage([r]);
    invokeLog('error', `UnhandledRejection: ${msg}`);
  });
} catch (_) {
  // ignore
}

// Indique le mode de fonctionnement détecté
try {
  const tauri = !!globalThis.__TAURI__;
  const env = (() => { try { return (typeof import.meta !== 'undefined' && import.meta.env) || {}; } catch { return {}; } })();
  const viaTauri = Boolean(env?.TAURI_PLATFORM) || tauri;
  const mocked = (() => {
    try { return String(env?.VITE_TAURI_MOCK || '') === '1' || (typeof localStorage !== 'undefined' && localStorage.getItem('VITE_TAURI_MOCK') === '1'); } catch { return false; }
  })();
  console.info(`[console-bridge] Tauri=${viaTauri} Mock=${mocked}`);
  // Aides console: alias globaux pour l'invoke en DevTools
  (async () => {
    try {
      const mod = await import('@tauri-apps/api/core');
      // taInvoke(cmd, args) → Promise
      globalThis.taInvoke = (cmd, args) => mod.invoke(cmd, args);
      // Compatibilité v1 → v2: __TAURI__.core.invoke devient __TAURI__.invoke si absent
      if (globalThis.__TAURI__ && globalThis.__TAURI__.core && !globalThis.__TAURI__.invoke) {
        globalThis.__TAURI__.invoke = (...a) => globalThis.__TAURI__.core.invoke(...a);
      }
      console.info('[console-bridge] taInvoke disponible. Exemple: await taInvoke("dns_get_status")');
    } catch {}
  })();
} catch (_) {}

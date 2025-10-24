import { invoke } from '@tauri-apps/api/core';

export function isTauri() {
  // 1) Global injecté par Tauri si withGlobalTauri=true
  const fromGlobal = typeof window !== 'undefined' && !!window.__TAURI__;
  // 2) Variables d'env exposées par Vite quand lancé via Tauri CLI
  let fromEnv = false;
  try {
    // import.meta est supporté en ESM; on le protège avec try/catch
    // pour éviter des erreurs de parsing sur certains environnements.
    // eslint-disable-next-line no-undef
    fromEnv = typeof import.meta !== 'undefined' && !!import.meta.env && !!import.meta.env.TAURI_PLATFORM;
  } catch (_) {
    fromEnv = false;
  }
  return fromGlobal || fromEnv;
}

function useMock() {
  // Priorité: variable d'env → localStorage → ?mock=1|#mock
  let fromEnv = false;
  try {
    // eslint-disable-next-line no-undef
    fromEnv = typeof import.meta !== 'undefined' && !!import.meta.env && String(import.meta.env.VITE_TAURI_MOCK || '') === '1';
  } catch (_) {
    fromEnv = false;
  }
  const fromStorage = typeof localStorage !== 'undefined' && localStorage.getItem('VITE_TAURI_MOCK') === '1';
  const href = typeof window !== 'undefined' ? window.location.href : '';
  const fromUrl = /[?#&]mock(=1)?(\b|$)/.test(href);
  return fromEnv || fromStorage || fromUrl;
}

// --- Mock helpers (navigateur) ---
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const __MOCK = {
  dns: {
    status: { state: 'running', log_level: 'INFO' },
    records: [
      { name: 'router.home', a: ['192.168.0.1'], aaaa: [], ttl: 300 },
      { name: 'nas.home', a: ['192.168.0.20'], aaaa: [], ttl: 300 },
      { name: 'media.home', a: ['192.168.0.30'], aaaa: [], ttl: 300 },
    ],
  },
  http: {
    status: { state: 'running', log_level: 'INFO' },
    routes: [
      { host: 'app.home', port: 8080 },
      { host: 'grafana.home', port: 3000 },
    ],
  },
};

async function mockInvoke(cmd, args = {}) {
  // Petite latence pour simuler un appel
  await delay(150);
  switch (cmd) {
    // DNS
    case 'dns_get_status':
      return { ...__MOCK.dns.status };
    case 'dns_stop_service':
      __MOCK.dns.status.state = 'stopped';
      return { ok: true, message: 'DNS stopped' };
    case 'dns_reload_config':
      return { ok: true, message: 'DNS config reloaded' };
    case 'dns_list_records':
      return { records: __MOCK.dns.records.map((r) => ({ ...r })) };
    case 'dns_add_record': {
      // Accepte soit { record }, soit { name, rrtype, value, ttl }
      let rec = null;
      if (args && args.record) {
        rec = args.record;
      } else if (args && args.name && args.rrtype && args.value) {
        rec = { name: args.name, a: [], aaaa: [], ttl: args.ttl ?? 300 };
        if ((args.rrtype || '').toUpperCase() === 'A') rec.a = [args.value];
        if ((args.rrtype || '').toUpperCase() === 'AAAA') rec.aaaa = [args.value];
      }
      if (rec) {
        __MOCK.dns.records.push(rec);
        return { ok: true, message: 'Record added' };
      }
      return { ok: false, message: 'Invalid record payload' };
    }
    case 'dns_remove_record': {
      // Accepte soit { id }, soit { name, rrtype, value }
      if (args && args.id) {
        const before = __MOCK.dns.records.length;
        __MOCK.dns.records = __MOCK.dns.records.filter((r) => r.name !== args.id);
        const removed = before !== __MOCK.dns.records.length;
        return { ok: removed, message: removed ? 'Record removed' : 'Not found' };
      }
      if (args && args.name) {
        const before = __MOCK.dns.records.length;
        __MOCK.dns.records = __MOCK.dns.records.filter((r) => r.name !== args.name);
        const removed = before !== __MOCK.dns.records.length;
        return { ok: removed, message: removed ? 'Record removed' : 'Not found' };
      }
      return { ok: false, message: 'Invalid remove payload' };
    }

    // HTTP
    case 'http_get_status':
      return { ...__MOCK.http.status };
    case 'http_stop_service':
      __MOCK.http.status.state = 'stopped';
      return { ok: true, message: 'HTTP stopped' };
    case 'http_reload_config':
      return { ok: true, message: 'HTTP config reloaded' };
    case 'http_list_routes':
      return { routes: __MOCK.http.routes.map((r) => ({ ...r })) };
    case 'http_add_route': {
      let route = null;
      if (args && args.route) route = args.route;
      else if (args && args.host && (args.port ?? null) !== null) route = { host: args.host, port: args.port };
      if (route) {
        // Remplace si host existe
        __MOCK.http.routes = __MOCK.http.routes.filter((r) => r.host !== route.host).concat([route]);
        return { ok: true, message: 'Route added' };
      }
      return { ok: false, message: 'Invalid route payload' };
    }
    case 'http_remove_route': {
      const key = args?.id || args?.host;
      if (!key) return { ok: false, message: 'Invalid remove payload' };
      const before = __MOCK.http.routes.length;
      __MOCK.http.routes = __MOCK.http.routes.filter((r) => r.host !== key);
      const removed = before !== __MOCK.http.routes.length;
      return { ok: removed, message: removed ? 'Route removed' : 'Not found' };
    }

    default:
      return { ok: false, message: `Unknown mock command: ${cmd}` };
  }
}

async function invokeWithRetry(cmd, args, tries = 8, delayMs = 200) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await invoke(cmd, args);
    } catch (e) {
      lastErr = e;
      const msg = (e && (e.message || e.toString())) || '';
      const maybeTransient = /transport|connect|pipe|ECONN|EPIPE|ENOENT|EACCES/i.test(msg);
      if (!maybeTransient || i === tries - 1) throw e;
      await delay(delayMs * Math.min(5, i + 1));
    }
  }
  throw lastErr;
}

export async function safeInvoke(cmd, args) {
  if (isTauri() && !useMock()) {
    return invokeWithRetry(cmd, args);
  }
  if (!__MOCK.__notified) {
    __MOCK.__notified = true;
    // eslint-disable-next-line no-console
    console.info('[tauri.js] Mode MOCK actif (Tauri non détecté ou VITE_TAURI_MOCK=1).');
  }
  return mockInvoke(cmd, args);
}

export async function dns_get_status() { return safeInvoke('dns_get_status'); }

export async function dns_stop_service() {
  return safeInvoke('dns_stop_service');
}

export async function dns_reload_config() { return safeInvoke('dns_reload_config'); }

export async function dns_list_records() {
  const res = await safeInvoke('dns_list_records');
  return Array.isArray(res) ? res : (res?.records ?? []);
}

function normalizeDnsAddArgs(arg1, arg2, arg3, arg4) {
  if (arg1 && typeof arg1 === 'object') {
    const { name, rrtype, value, ttl } = arg1;
    return { name, rrtype, value, ttl };
  }
  return { name: arg1, rrtype: arg2, value: arg3, ttl: arg4 };
}

function normalizeDnsRemoveArgs(arg1, arg2, arg3) {
  if (arg1 && typeof arg1 === 'object') {
    const { name, rrtype, value } = arg1;
    return { name, rrtype, value };
  }
  if (arg2 && typeof arg2 === 'object') {
    const { rrtype, value } = arg2;
    return { name: arg1, rrtype, value };
  }
  return { name: arg1, rrtype: arg2, value: arg3 };
}

export async function dns_add_record(arg1, arg2, arg3, arg4) {
  const payload = normalizeDnsAddArgs(arg1, arg2, arg3, arg4);
  const name = (payload?.name || '').trim();
  const rrtype = (payload?.rrtype || '').toUpperCase();
  const value = (payload?.value || '').trim();
  const ttl = Number.isFinite(payload?.ttl) ? payload.ttl : Number.parseInt(payload?.ttl, 10);
  const safeTtl = Number.isFinite(ttl) && ttl > 0 ? ttl : 300;
  if (!name) throw new Error('Le nom de l\'enregistrement est requis.');
  if (!rrtype) throw new Error('Le type d\'enregistrement est requis.');
  if (!value) throw new Error('La valeur de l\'enregistrement est requise.');
  return safeInvoke('dns_add_record', { name, rrtype, value, ttl: safeTtl });
}

export async function dns_remove_record(arg1, arg2, arg3) {
  const payload = normalizeDnsRemoveArgs(arg1, arg2, arg3);
  const name = (payload?.name || '').trim();
  const rrtype = (payload?.rrtype || '').toUpperCase();
  const value = (payload?.value || '').trim();
  if (!name) throw new Error('Le nom de l\'enregistrement est requis pour la suppression.');
  if (!rrtype) throw new Error('Le type d\'enregistrement est requis pour la suppression.');
  if (!value) throw new Error('La valeur de l\'enregistrement est requise pour la suppression.');
  return safeInvoke('dns_remove_record', { name, rrtype, value });
}

export async function http_get_status() { return safeInvoke('http_get_status'); }

export async function http_stop_service() {
  return safeInvoke('http_stop_service');
}

export async function http_reload_config() { return safeInvoke('http_reload_config'); }

export async function http_list_routes() {
  const res = await safeInvoke('http_list_routes');
  return Array.isArray(res) ? res : (res?.routes ?? []);
}

export async function http_add_route(arg1, arg2) {
  const payload = typeof arg1 === 'object' && arg1 !== null ? arg1 : { host: arg1, port: arg2 };
  const host = (payload?.host || '').trim();
  const portNum = Number.isFinite(payload?.port)
    ? payload.port
    : Number.parseInt(payload?.port, 10);
  if (!host) throw new Error('L\'hôte est requis.');
  if (!Number.isFinite(portNum) || portNum < 0) throw new Error('Le port fourni est invalide.');
  return safeInvoke('http_add_route', { host, port: portNum });
}

export async function http_remove_route(arg1) {
  const host = typeof arg1 === 'object' && arg1 !== null ? arg1.host || arg1.id : arg1;
  if (!host) throw new Error('L\'hôte est requis pour la suppression.');
  return safeInvoke('http_remove_route', { host });
}

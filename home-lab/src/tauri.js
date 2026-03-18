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
  s3: {
    status: {
      state: 'running',
      log_level: 'INFO',
      endpoint: 'http://127.0.0.1:9000',
      region: 'us-east-1',
      access_key_id: 'rustfsadmin',
      force_path_style: true,
    },
    buckets: [
      {
        name: 'media',
        created_at: '2026-03-15T08:15:00Z',
        source_path: 'C:\\Users\\demo\\Media Library',
      },
      {
        name: 'backups',
        created_at: '2026-03-15T08:30:00Z',
        source_path: 'D:\\Backups\\Nightly',
      },
    ],
    objects: {
      media: [
        { key: 'movies/Inception.mkv', size: 4294967296, last_modified: '2026-03-17T22:15:00Z' },
        { key: 'series/Dark/S01E01.mkv', size: 2147483648, last_modified: '2026-03-16T21:00:00Z' },
      ],
      backups: [
        { key: 'postgres/2026-03-17.sql.gz', size: 15728640, last_modified: '2026-03-17T03:10:00Z' },
        { key: 'photos/2026-03-17.tar.zst', size: 73400320, last_modified: '2026-03-17T03:12:00Z' },
      ],
    },
  },
  oidc: {
    status: {
      state: 'running',
      log_level: 'INFO',
      issuer: 'https://127.0.0.1:8443',
      token_endpoint: 'https://127.0.0.1:8443/token',
    },
    clients: [
      {
        client_id: 'demo-client',
        subject: 'demo-client',
        allowed_scopes: ['demo.read'],
        audiences: ['https://example-app'],
        password_users: [
          { username: 'demo-user', subject: 'demo-user', scopes: ['demo.read'] },
        ],
        auth_method: 'client_secret_post',
        public_key_pem: '',
      },
      {
        client_id: 'k3s-home',
        subject: 'home-lab-k3s',
        allowed_scopes: ['k3s.admin'],
        audiences: [],
        password_users: [],
        auth_method: 'private_key_jwt',
        public_key_pem:
          '-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMockKeyExample=====\\n-----END PUBLIC KEY-----',
      },
    ],
  },
  wsl: {
    instances: [
      { name: 'home-lab', state: 'Running', version: '2', is_default: false },
      { name: 'Ubuntu-22.04', state: 'Stopped', version: '2', is_default: false },
    ],
  },
};

const toManagedContextId = (name) => {
  const normalized = String(name ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'cluster';
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

    // S3
    case 's3_get_status':
      return { ...__MOCK.s3.status };
    case 's3_reload_config':
      return { ok: true, message: 'S3 config reloaded' };
    case 's3_stop_service':
      __MOCK.s3.status.state = 'stopped';
      return { ok: true, message: 'S3 stopped' };
    case 's3_list_buckets':
      return { buckets: __MOCK.s3.buckets.map((bucket) => ({ ...bucket })) };
    case 's3_list_bucket_objects': {
      const name = (args?.bucketName || args?.bucket_name || '').trim().toLowerCase();
      if (!name) {
        return { ok: false, message: 'Bucket name required' };
      }
      return {
        objects: (__MOCK.s3.objects[name] || []).map((object) => ({ ...object })),
      };
    }
    case 's3_create_bucket': {
      const name = (args?.bucketName || args?.bucket_name || '').trim().toLowerCase();
      const sourcePath = (args?.sourcePath || args?.source_path || '').trim();
      if (!name) {
        return { ok: false, message: 'Bucket name required' };
      }
      const existed = __MOCK.s3.buckets.some((bucket) => bucket.name === name);
      if (!existed) {
        __MOCK.s3.buckets.push({
          name,
          created_at: new Date().toISOString(),
          source_path: sourcePath,
        });
        __MOCK.s3.objects[name] = [];
      } else if (sourcePath) {
        __MOCK.s3.buckets = __MOCK.s3.buckets.map((bucket) => (
          bucket.name === name ? { ...bucket, source_path: sourcePath } : bucket
        ));
      }
      return {
        ok: true,
        message: existed
          ? sourcePath
            ? `Bucket ${name} existed already and source path was imported (mock).`
            : `Bucket ${name} existed already (mock).`
          : sourcePath
            ? `Bucket ${name} created and source path imported (mock).`
            : `Bucket ${name} created (mock).`,
      };
    }
    case 's3_update_bucket': {
      const currentName = (args?.currentBucketName || args?.current_bucket_name || '').trim().toLowerCase();
      const newNameRaw = (args?.newBucketName || args?.new_bucket_name || '').trim().toLowerCase();
      const sourcePath = (args?.sourcePath || args?.source_path || '').trim();
      const replaceObjects = !!(args?.replaceObjects ?? args?.replace_objects);
      const newName = newNameRaw || currentName;
      if (!currentName) {
        return { ok: false, message: 'Current bucket name required' };
      }
      const currentBucket = __MOCK.s3.buckets.find((bucket) => bucket.name === currentName);
      if (!currentBucket) {
        return { ok: false, message: `Bucket ${currentName} not found (mock).` };
      }
      if (replaceObjects && !sourcePath) {
        return { ok: false, message: 'replace_objects requires a source path (mock).' };
      }
      if (newName !== currentName && __MOCK.s3.buckets.some((bucket) => bucket.name === newName)) {
        return { ok: false, message: `Bucket ${newName} exists already (mock).` };
      }
      currentBucket.name = newName;
      if (sourcePath) {
        currentBucket.source_path = sourcePath;
      }
      if (newName !== currentName) {
        __MOCK.s3.objects[newName] = __MOCK.s3.objects[currentName] || [];
        delete __MOCK.s3.objects[currentName];
      }
      if (replaceObjects) {
        __MOCK.s3.objects[newName] = sourcePath
          ? [{ key: 'imported/mock-file.txt', size: 128, last_modified: new Date().toISOString() }]
          : [];
      } else if (sourcePath) {
        __MOCK.s3.objects[newName] = [
          ...(__MOCK.s3.objects[newName] || []),
          { key: 'imported/mock-file.txt', size: 128, last_modified: new Date().toISOString() },
        ];
      }
      let message = newName !== currentName
        ? `Bucket ${currentName} renamed to ${newName} (mock).`
        : `Bucket ${currentName} updated (mock).`;
      if (sourcePath) {
        message += replaceObjects
          ? ' Existing objects replaced from source path.'
          : ' Source path imported.';
      }
      return { ok: true, message };
    }
    case 's3_delete_bucket': {
      const name = (args?.bucketName || args?.bucket_name || '').trim().toLowerCase();
      const deleteObjects = !!(args?.deleteObjects ?? args?.delete_objects);
      if (!name) {
        return { ok: false, message: 'Bucket name required' };
      }
      const before = __MOCK.s3.buckets.length;
      __MOCK.s3.buckets = __MOCK.s3.buckets.filter((bucket) => bucket.name !== name);
      delete __MOCK.s3.objects[name];
      const removed = before !== __MOCK.s3.buckets.length;
      return {
        ok: removed,
        message: removed
          ? deleteObjects
            ? `Bucket ${name} and its objects deleted (mock).`
            : `Bucket ${name} deleted (mock).`
          : `Bucket ${name} not found (mock).`,
      };
    }

    // OIDC
    case 'oidc_get_status':
      return { ...__MOCK.oidc.status };
    case 'oidc_list_clients':
      return {
        clients: __MOCK.oidc.clients.map((client) => ({
          ...client,
          allowed_scopes: [...client.allowed_scopes],
          audiences: [...client.audiences],
          password_users: client.password_users.map((user) => ({
            ...user,
            scopes: [...user.scopes],
          })),
        })),
      };
    case 'oidc_register_client': {
      const payload = args || {};
      const clientId = (payload.client_id || '').trim();
      if (!clientId) {
        return { ok: false, message: 'client_id requis (mock).' };
      }
      const subject = (payload.subject || clientId).trim();
      const allowed_scopes = Array.isArray(payload.allowed_scopes)
        ? [...payload.allowed_scopes]
        : [];
      const audiences = Array.isArray(payload.audiences) ? [...payload.audiences] : [];
      const public_key_pem = (payload.public_key_pem || '').trim();
      const auth_method = (payload.auth_method || 'private_key_jwt').trim();
      const client = {
        client_id: clientId,
        subject,
        allowed_scopes,
        audiences,
        password_users: [],
        auth_method,
        public_key_pem,
      };
      __MOCK.oidc.clients = __MOCK.oidc.clients
        .filter((c) => c.client_id !== clientId)
        .concat([client]);
      return { ok: true, message: 'Client OIDC ajouté (mock).' };
    }
    case 'oidc_remove_client': {
      const clientId =
        typeof args === 'string' ? args : typeof args?.client_id === 'string' ? args.client_id : '';
      const trimmed = clientId.trim();
      if (!trimmed) {
        return { ok: false, message: 'client_id requis (mock).' };
      }
      const before = __MOCK.oidc.clients.length;
      __MOCK.oidc.clients = __MOCK.oidc.clients.filter((client) => client.client_id !== trimmed);
      const removed = before !== __MOCK.oidc.clients.length;
      return { ok: removed, message: removed ? 'Client supprimé (mock).' : 'Client introuvable.' };
    }

    case 'wsl_import_instance': {
      const rawName = typeof args?.name === 'string' ? args.name.trim() : 'home-lab-k3s';
      if (!rawName) {
        return { ok: false, message: "Nom d'instance invalide (mock)." };
      }
      const normalized = rawName.toLowerCase();
      const existsIndex = __MOCK.wsl.instances.findIndex(
        (inst) => (inst?.name || '').toLowerCase() === normalized,
      );

      if (existsIndex !== -1 && !args?.force) {
        return { ok: false, message: `Instance ${rawName} existe déjà (mock).` };
      }

      const instance = {
        name: rawName,
        state: 'Stopped',
        version: '2',
        is_default: false,
      };

      if (existsIndex === -1) {
        __MOCK.wsl.instances.push(instance);
      } else {
        __MOCK.wsl.instances.splice(existsIndex, 1, instance);
      }

      return {
        ok: true,
        message: args?.force
          ? `Instance ${rawName} réimportée (mock).`
          : `Instance ${rawName} importée (mock).`,
      };
    }

    case 'wsl_list_instances': {
      return __MOCK.wsl.instances.map((inst) => ({ ...inst }));
    }

    case 'wsl_remove_instance': {
      const name = (args?.name || args?.id || '').trim();
      if (!name) {
        return { ok: false, message: "Nom d'instance invalide." };
      }
      const before = __MOCK.wsl.instances.length;
      __MOCK.wsl.instances = __MOCK.wsl.instances.filter((inst) => inst.name !== name);
      const removed = __MOCK.wsl.instances.length !== before;
      return removed
        ? { ok: true, message: `Instance ${name} supprimée (mock).` }
        : { ok: false, message: `Instance ${name} introuvable (mock).` };
    }

    case 'wsl_sync_windows_kubeconfig': {
      const contexts = __MOCK.wsl.instances.map(
        (inst) => `home-lab-wsl-${toManagedContextId(inst?.name || '')}`,
      );
      return {
        ok: true,
        path: 'C:\\\\Users\\\\mock\\\\.kube\\\\config',
        contexts,
        skipped: [],
        message: `Kubeconfig Windows synchronise: ${contexts.length} contexte(s) Home Lab ecrit(s).`,
      };
    }

    case 'wsl_kubectl_exec': {
      const instance = (args?.instance || '').trim();
      const commandArgs = Array.isArray(args?.args)
        ? args.args
            .map((arg) => String(arg ?? '').trim())
            .filter((arg) => arg.length > 0)
        : [];
      const context = `home-lab-wsl-${toManagedContextId(instance)}`;
      const command = `kubectl --context "${context}" ${commandArgs.join(' ')}`.trim();

      if (!instance) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          stdout: '',
          stderr: "Le nom de l'instance WSL est requis (mock).",
        };
      }
      if (commandArgs.length === 0) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          stdout: '',
          stderr: 'La commande kubectl est requise (mock).',
        };
      }

      const target = __MOCK.wsl.instances.find(
        (inst) => String(inst?.name || '').toLowerCase() === instance.toLowerCase(),
      );
      if (!target) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          stdout: '',
          stderr: `Instance ${instance} introuvable (mock).`,
        };
      }

      const normalized = commandArgs.join(' ').toLowerCase();
      let stdout = '';
      let stderr = '';
      let exitCode = 0;

      if (normalized === 'get nodes' || normalized === 'get nodes -o wide') {
        stdout = [
          'NAME               STATUS   ROLES                  AGE   VERSION',
          `${target.name}-srv    Ready    control-plane,master   5m    v1.32.1+k3s1`,
        ].join('\n');
      } else if (normalized === 'get namespaces') {
        stdout = [
          'NAME              STATUS   AGE',
          'default           Active   5m',
          'kube-system       Active   5m',
          'kube-public       Active   5m',
          'kube-node-lease   Active   5m',
        ].join('\n');
      } else if (
        normalized === 'get pods -a'
        || normalized === 'get pods --all-namespaces'
        || normalized === 'get pods -a -o wide'
        || normalized === 'get pods --all-namespaces -o wide'
        || normalized === 'get pods -o wide -a'
        || normalized === 'get pods -o wide --all-namespaces'
      ) {
        stdout = [
          'NAMESPACE     NAME                                      READY   STATUS    RESTARTS   AGE',
          'kube-system   coredns-6f6b679f8f-bj9zz                1/1     Running   0          5m',
          'kube-system   local-path-provisioner-84bb864455-z4gxk 1/1     Running   0          5m',
          'kube-system   metrics-server-ff9dbcb6c-2vzl7          1/1     Running   0          5m',
        ].join('\n');
      } else if (normalized.startsWith('get ')) {
        stdout = `Commande mock executee sur ${target.name}: kubectl ${commandArgs.join(' ')}`;
      } else {
        exitCode = 1;
        stderr = `Commande non supportee dans le mock: kubectl ${commandArgs.join(' ')}`;
      }

      return {
        ok: exitCode === 0,
        instance: target.name,
        exit_code: exitCode,
        command,
        stdout,
        stderr,
      };
    }

    case 'wsl_kubectl_apply_yaml': {
      const instance = (args?.instance || '').trim();
      const manifestYaml = typeof args?.manifestYaml === 'string'
        ? args.manifestYaml
        : (typeof args?.manifest_yaml === 'string' ? args.manifest_yaml : '');
      const sourceName = (args?.sourceName || args?.source_name || '').trim() || '<uploaded-yaml>';
      const context = `home-lab-wsl-${toManagedContextId(instance)}`;
      const command = `kubectl --context "${context}" apply -f ${sourceName}`;
      const startedAt = Date.now();

      if (!instance) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          trace_id: `mock-${Date.now()}`,
          duration_ms: Date.now() - startedAt,
          stdout: '',
          stderr: "Le nom de l'instance WSL est requis (mock).",
        };
      }
      if (!manifestYaml.trim()) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          trace_id: `mock-${Date.now()}`,
          duration_ms: Date.now() - startedAt,
          stdout: '',
          stderr: 'Le contenu YAML est vide (mock).',
        };
      }

      const target = __MOCK.wsl.instances.find(
        (inst) => String(inst?.name || '').toLowerCase() === instance.toLowerCase(),
      );
      if (!target) {
        return {
          ok: false,
          instance,
          exit_code: 1,
          command,
          trace_id: `mock-${Date.now()}`,
          duration_ms: Date.now() - startedAt,
          stdout: '',
          stderr: `Instance ${instance} introuvable (mock).`,
        };
      }

      const documents = manifestYaml
        .split(/^---\s*$/m)
        .map((chunk) => chunk.trim())
        .filter((chunk) => chunk.length > 0);
      const appliedCount = Math.max(documents.length, 1);
      const stdout = [
        ...Array.from({ length: appliedCount }, (_, i) => `resource/${i + 1} configured`),
        `${appliedCount} ressource(s) appliquee(s).`,
      ].join('\n');

      return {
        ok: true,
        instance: target.name,
        exit_code: 0,
        command,
        trace_id: `mock-${Date.now()}`,
        duration_ms: Date.now() - startedAt,
        stdout,
        stderr: '',
      };
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

export async function s3_get_status() { return safeInvoke('s3_get_status'); }

export async function s3_reload_config() { return safeInvoke('s3_reload_config'); }

export async function s3_stop_service() {
  return safeInvoke('s3_stop_service');
}

export async function s3_list_buckets() {
  const res = await safeInvoke('s3_list_buckets');
  return Array.isArray(res) ? res : (res?.buckets ?? []);
}

export async function s3_list_bucket_objects(bucketName) {
  const name = typeof bucketName === 'object' && bucketName !== null
    ? String(bucketName.bucket_name ?? bucketName.bucketName ?? bucketName.name ?? '').trim()
    : String(bucketName ?? '').trim();
  if (!name) throw new Error('Le nom du bucket est requis pour lister son contenu.');
  const res = await safeInvoke('s3_list_bucket_objects', {
    bucketName: name,
  });
  return Array.isArray(res) ? res : (res?.objects ?? []);
}

export async function s3_create_bucket(bucketName, sourcePath = '') {
  const name = typeof bucketName === 'object' && bucketName !== null
    ? String(bucketName.bucket_name ?? bucketName.name ?? '').trim()
    : String(bucketName ?? '').trim();
  const pathValue = typeof bucketName === 'object' && bucketName !== null
    ? String(bucketName.source_path ?? bucketName.sourcePath ?? '').trim()
    : String(sourcePath ?? '').trim();
  if (!name) throw new Error('Le nom du bucket est requis.');
  return safeInvoke('s3_create_bucket', {
    bucketName: name,
    sourcePath: pathValue,
  });
}

export async function s3_update_bucket(payload = {}) {
  const current_bucket_name = String(
    payload.current_bucket_name ?? payload.currentBucketName ?? ''
  ).trim();
  const new_bucket_name = String(
    payload.new_bucket_name ?? payload.newBucketName ?? ''
  ).trim();
  const source_path = String(
    payload.source_path ?? payload.sourcePath ?? ''
  ).trim();
  const replace_objects = !!(payload.replace_objects ?? payload.replaceObjects);
  if (!current_bucket_name) {
    throw new Error('Le nom actuel du bucket est requis.');
  }
  if (replace_objects && !source_path) {
    throw new Error('Un chemin source est requis pour remplacer le contenu du bucket.');
  }
  return safeInvoke('s3_update_bucket', {
    currentBucketName: current_bucket_name,
    newBucketName: new_bucket_name,
    sourcePath: source_path,
    replaceObjects: replace_objects,
  });
}

export async function s3_delete_bucket(bucketName, deleteObjects = false) {
  const name = typeof bucketName === 'object' && bucketName !== null
    ? String(bucketName.bucket_name ?? bucketName.name ?? '').trim()
    : String(bucketName ?? '').trim();
  const delete_objects = typeof bucketName === 'object' && bucketName !== null
    ? !!(bucketName.delete_objects ?? bucketName.deleteObjects)
    : !!deleteObjects;
  if (!name) throw new Error('Le nom du bucket est requis pour la suppression.');
  return safeInvoke('s3_delete_bucket', {
    bucketName: name,
    deleteObjects: delete_objects,
  });
}

export async function oidc_get_status() { return safeInvoke('oidc_get_status'); }

export async function oidc_list_clients() {
  const res = await safeInvoke('oidc_list_clients');
  return Array.isArray(res) ? res : (res?.clients ?? []);
}

export async function oidc_register_client(payload = {}) {
  const data = typeof payload === 'object' && payload !== null ? { ...payload } : {};
  const client_id = (data.client_id || '').trim();
  if (!client_id) throw new Error("L'identifiant client est requis.");
  const public_key_pem = (data.public_key_pem || '').trim();
  if (!public_key_pem) throw new Error('La clé publique du client est requise.');
  const subject = (data.subject || '').trim();
  const allowed_scopes = Array.isArray(data.allowed_scopes) ? data.allowed_scopes : [];
  const audiences = Array.isArray(data.audiences) ? data.audiences : [];
  const auth_method = (data.auth_method || 'private_key_jwt').trim();
  return safeInvoke('oidc_register_client', {
    client_id,
    subject,
    allowed_scopes,
    audiences,
    public_key_pem,
    auth_method,
  });
}

export async function oidc_remove_client(clientId) {
  const value = typeof clientId === 'string' ? clientId.trim() : '';
  if (!value) throw new Error("L'identifiant client est requis pour la suppression.");
  const result = await safeInvoke('oidc_remove_client', { client_id: value });
  if (!result?.ok) {
    throw new Error(result?.message || `Suppression du client OIDC '${value}' impossible.`);
  }
  return result;
}

export async function wsl_import_instance(options = {}) {
  const payload = { ...options };
  if (payload.name !== undefined) {
    payload.name = String(payload.name ?? '').trim();
    if (!payload.name) {
      throw new Error("Le nom de l'instance WSL est requis.");
    }
  }
  // eslint-disable-next-line no-console
  console.info('[tauri.js] wsl_import_instance invoked', payload);
  const result = await safeInvoke('wsl_import_instance', payload);
  // eslint-disable-next-line no-console
  console.info('[tauri.js] wsl_import_instance result', result);
  return result;
}

export async function wsl_list_instances() {
  const res = await safeInvoke('wsl_list_instances');
  return Array.isArray(res) ? res : res?.instances ?? [];
}

export async function wsl_remove_instance(name) {
  const value = typeof name === 'string' ? name.trim() : '';
  if (!value) {
    throw new Error("Le nom de l'instance WSL est requis.");
  }
  return safeInvoke('wsl_remove_instance', { name: value });
}

export async function wsl_sync_windows_kubeconfig() {
  return safeInvoke('wsl_sync_windows_kubeconfig');
}

export async function wsl_kubectl_exec(instance, args = []) {
  const value = typeof instance === 'string' ? instance.trim() : '';
  if (!value) {
    throw new Error("Le nom de l'instance WSL est requis.");
  }

  const commandArgs = Array.isArray(args)
    ? args.map((arg) => String(arg ?? '').trim()).filter((arg) => arg.length > 0)
    : String(args ?? '')
        .split(/\s+/)
        .map((arg) => arg.trim())
        .filter((arg) => arg.length > 0);
  if (commandArgs.length === 0) {
    throw new Error('La commande kubectl est requise.');
  }

  const startedAt = Date.now();
  // eslint-disable-next-line no-console
  console.info('[tauri.js] wsl_kubectl_exec invoke', { instance: value, args: commandArgs });
  try {
    const result = await safeInvoke('wsl_kubectl_exec', { instance: value, args: commandArgs });
    // eslint-disable-next-line no-console
    console.info('[tauri.js] wsl_kubectl_exec result', {
      instance: value,
      elapsed_ms: Date.now() - startedAt,
      trace_id: result?.trace_id,
      ok: !!result?.ok,
    });
    return result;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[tauri.js] wsl_kubectl_exec error', {
      instance: value,
      elapsed_ms: Date.now() - startedAt,
      error: err?.message || String(err),
    });
    throw err;
  }
}

export async function wsl_kubectl_apply_yaml(instance, manifestYaml, sourceName = '') {
  const value = typeof instance === 'string' ? instance.trim() : '';
  if (!value) {
    throw new Error("Le nom de l'instance WSL est requis.");
  }

  const yaml = typeof manifestYaml === 'string' ? manifestYaml : String(manifestYaml ?? '');
  if (!yaml.trim()) {
    throw new Error('Le contenu YAML est vide.');
  }

  const source = typeof sourceName === 'string' ? sourceName.trim() : '';
  const startedAt = Date.now();
  const invokeWithCamelCase = () => safeInvoke('wsl_kubectl_apply_yaml', {
    instance: value,
    manifestYaml: yaml,
    sourceName: source || null,
  });
  const invokeWithSnakeCase = () => safeInvoke('wsl_kubectl_apply_yaml', {
    instance: value,
    manifest_yaml: yaml,
    source_name: source || null,
  });
  // eslint-disable-next-line no-console
  console.info('[tauri.js] wsl_kubectl_apply_yaml invoke', {
    instance: value,
    source_name: source || '<uploaded-yaml>',
    bytes: yaml.length,
  });
  try {
    let result;
    try {
      result = await invokeWithCamelCase();
    } catch (firstErr) {
      const firstMessage = String(firstErr?.message || firstErr || '');
      const shouldRetrySnakeCase = /manifest[_]?yaml|source[_]?name|unknown field|missing required key|invalid args/i.test(firstMessage);
      if (!shouldRetrySnakeCase) {
        throw firstErr;
      }
      // eslint-disable-next-line no-console
      console.warn('[tauri.js] wsl_kubectl_apply_yaml retry with snake_case args', {
        instance: value,
        reason: firstMessage,
      });
      result = await invokeWithSnakeCase();
    }
    // eslint-disable-next-line no-console
    console.info('[tauri.js] wsl_kubectl_apply_yaml result', {
      instance: value,
      elapsed_ms: Date.now() - startedAt,
      trace_id: result?.trace_id,
      ok: !!result?.ok,
    });
    return result;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[tauri.js] wsl_kubectl_apply_yaml error', {
      instance: value,
      elapsed_ms: Date.now() - startedAt,
      error: err?.message || String(err),
    });
    throw err;
  }
}

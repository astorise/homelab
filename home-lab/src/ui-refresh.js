export const HOME_LAB_UI_REFRESH_EVENT = 'home-lab:ui-refresh';

const REFRESHABLE_COMPONENTS = Object.freeze([
  { selector: 'dns-status', method: 'load' },
  { selector: 'dns-records', method: 'load' },
  { selector: 'http-status', method: 'load' },
  { selector: 'http-routes', method: 'load' },
  { selector: 's3-status', method: 'load' },
  { selector: 's3-buckets', method: 'load' },
  { selector: 'oidc-status', method: 'load' },
  { selector: 'oidc-clients', method: 'load' },
  { selector: 'wsl-instance-manager', method: 'loadInstances' },
  { selector: 'k8s-client', method: 'loadInstances' },
]);

let listenerInstalled = false;

function tryRefreshComponent(component, method) {
  if (!component || typeof component[method] !== 'function') {
    return false;
  }
  try {
    const maybePromise = component[method]();
    if (maybePromise && typeof maybePromise.catch === 'function') {
      maybePromise.catch((error) => {
        // eslint-disable-next-line no-console
        console.error('[ui-refresh] asynchronous refresh failed', { component, method, error });
      });
    }
    return true;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('[ui-refresh] refresh failed', { component, method, error });
    return false;
  }
}

export function refreshDashboardComponents(options = {}) {
  if (typeof document === 'undefined') {
    return 0;
  }

  const skipSelectors = Array.isArray(options?.skipSelectors) ? options.skipSelectors : [];
  const skip = new Set(skipSelectors);
  let refreshed = 0;

  REFRESHABLE_COMPONENTS.forEach(({ selector, method }) => {
    if (skip.has(selector)) {
      return;
    }
    document.querySelectorAll(selector).forEach((component) => {
      if (tryRefreshComponent(component, method)) {
        refreshed += 1;
      }
    });
  });

  return refreshed;
}

export function dispatchUiRefresh(detail = {}) {
  if (typeof globalThis?.dispatchEvent === 'function' && typeof CustomEvent === 'function') {
    globalThis.dispatchEvent(
      new CustomEvent(HOME_LAB_UI_REFRESH_EVENT, {
        detail,
      }),
    );
    return;
  }

  refreshDashboardComponents(detail);
}

export function installUiRefreshListener() {
  if (listenerInstalled || typeof globalThis?.addEventListener !== 'function') {
    return;
  }

  globalThis.addEventListener(HOME_LAB_UI_REFRESH_EVENT, (event) => {
    refreshDashboardComponents(event?.detail ?? {});
  });
  listenerInstalled = true;
}

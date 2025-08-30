import { invoke } from '@tauri-apps/api/core';

export function safeInvoke(cmd, args) {
  if (!window.__TAURI__?.invoke) {
    return Promise.reject(new Error('Tauri API not available'));
  }
  return invoke(cmd, args);
}

export async function dns_get_status() {
  return safeInvoke('dns_get_status');
}

export async function dns_stop_service() {
  return safeInvoke('dns_stop_service');
}

export async function dns_reload_config() {
  return safeInvoke('dns_reload_config');
}

export async function dns_list_records() {
  return safeInvoke('dns_list_records');
}

export async function dns_add_record(record) {
  return safeInvoke('dns_add_record', { record });
}

export async function dns_remove_record(id) {
  return safeInvoke('dns_remove_record', { id });
}

export async function http_get_status() {
  return safeInvoke('http_get_status');
}

export async function http_stop_service() {
  return safeInvoke('http_stop_service');
}

export async function http_reload_config() {
  return safeInvoke('http_reload_config');
}

export async function http_list_routes() {
  return safeInvoke('http_list_routes');
}

export async function http_add_route(route) {
  return safeInvoke('http_add_route', { route });
}

export async function http_remove_route(id) {
  return safeInvoke('http_remove_route', { id });
}

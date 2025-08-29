import { invoke } from '@tauri-apps/api/core';

export async function dns_get_status() {
  return invoke('dns_get_status');
}

export async function dns_stop_service() {
  return invoke('dns_stop_service');
}

export async function dns_reload_config() {
  return invoke('dns_reload_config');
}

export async function dns_list_records() {
  return invoke('dns_list_records');
}

export async function dns_add_record(record) {
  return invoke('dns_add_record', { record });
}

export async function dns_remove_record(id) {
  return invoke('dns_remove_record', { id });
}

export async function http_get_status() {
  return invoke('http_get_status');
}

export async function http_stop_service() {
  return invoke('http_stop_service');
}

export async function http_reload_config() {
  return invoke('http_reload_config');
}

export async function http_list_routes() {
  return invoke('http_list_routes');
}

export async function http_add_route(route) {
  return invoke('http_add_route', { route });
}

export async function http_remove_route(id) {
  return invoke('http_remove_route', { id });
}

// frontend/src/tauri.js
import { invoke } from '@tauri-apps/api/core';

export async function stopService() {
  return invoke('dns_stop_service');
}

export async function reloadConfig() {
  return invoke('dns_reload_config');
}

export async function listRecords() {
  return invoke('dns_list_records');
}

export async function addRecord(record) {
  return invoke('dns_add_record', { record });
}

export async function removeRecord(id) {
  return invoke('dns_remove_record', { id });
}

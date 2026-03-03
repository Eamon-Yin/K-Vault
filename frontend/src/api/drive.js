import { apiFetch } from './client';

export async function getDriveTree(storage = 'all') {
  const query = new URLSearchParams();
  if (storage && storage !== 'all') query.set('storage', storage);
  const data = await apiFetch(`/api/drive/tree?${query.toString()}`);
  return data.nodes || [];
}

export async function getDriveExplorer({
  path = '',
  storage = 'all',
  search = '',
  listType = 'all',
  limit = 100,
  cursor = '',
  includeStats = true,
} = {}) {
  const query = new URLSearchParams();
  if (path) query.set('path', path);
  if (storage && storage !== 'all') query.set('storage', storage);
  if (search) query.set('search', search);
  if (listType && listType !== 'all') query.set('listType', listType);
  query.set('limit', String(limit));
  if (cursor) query.set('cursor', cursor);
  if (includeStats) query.set('includeStats', '1');

  return apiFetch(`/api/drive/explorer?${query.toString()}`);
}

export async function createFolder(path) {
  return apiFetch('/api/drive/folders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
}

export async function moveFolder(sourcePath, targetPath) {
  return apiFetch('/api/drive/folders/move', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sourcePath, targetPath }),
  });
}

export async function deleteFolder(path, recursive = false) {
  const query = new URLSearchParams({ path });
  if (recursive) query.set('recursive', '1');
  return apiFetch(`/api/drive/folders?${query.toString()}`, {
    method: 'DELETE',
  });
}

export async function moveFiles(ids, targetFolderPath) {
  return apiFetch('/api/drive/files/move', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids, targetFolderPath }),
  });
}

export async function renameFile(id, fileName) {
  return apiFetch('/api/drive/files/rename', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, fileName }),
  });
}

export async function deleteFiles(ids) {
  return apiFetch('/api/drive/files/delete-batch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids }),
  });
}

export async function signShareLink(fileId, ttlSeconds = 7 * 24 * 60 * 60) {
  return apiFetch('/api/share/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileId, ttlSeconds }),
  });
}

<template>
  <section class="card panel drive-panel">
    <header class="drive-header">
      <div>
        <h2>Drive Console</h2>
        <p class="muted">Upload, organize folders, and copy direct/share links in one place.</p>
      </div>
      <div class="drive-head-actions">
        <button class="btn btn-ghost" @click="refreshAll">Refresh</button>
      </div>
    </header>

    <section class="adapter-visibility card-lite">
      <div class="adapter-visibility-head">
        <h3>Storage Capability Visibility</h3>
        <p class="muted">All adapters stay visible even when not configured.</p>
      </div>
      <div class="adapter-grid">
        <article
          v-for="cap in capabilityCards"
          :key="cap.type"
          class="adapter-card"
          :class="{ active: selectedStorage === cap.type, unavailable: !cap.available }"
          @click="selectStorage(cap)"
        >
          <div class="adapter-card-top">
            <strong>{{ cap.label }}</strong>
            <span class="badge">{{ cap.layerLabel }}</span>
          </div>
          <p class="muted">{{ cap.description }}</p>
          <p class="adapter-status" :class="cap.available ? 'ok' : (cap.configured ? 'warn' : 'fail')">
            {{ cap.statusText }}
          </p>
          <p class="adapter-hint">{{ cap.hint }}</p>
        </article>
      </div>
    </section>

    <section
      class="drive-dropzone"
      :class="{ active: dragActive }"
      @dragover.prevent="dragActive = true"
      @dragleave.prevent="dragActive = false"
      @drop.prevent="handleDrop"
      @click="openPicker"
    >
      <input ref="picker" type="file" multiple hidden @change="handleFilePick" />
      <p class="dropzone-title">Drop files here or click to upload</p>
      <p class="muted">Current storage: {{ currentStorageLabel }} | Folder: /{{ currentPath || '' }}</p>
    </section>

    <form class="url-row" @submit.prevent="uploadUrl">
      <input v-model.trim="urlInput" placeholder="https://example.com/file.zip" />
      <button class="btn" :disabled="urlUploading || !urlInput">
        {{ urlUploading ? 'Uploading...' : 'Upload URL to Current Folder' }}
      </button>
    </form>

    <div v-if="queue.length" class="list-wrap">
      <h3>Upload Queue</h3>
      <ul class="list">
        <li v-for="item in queue" :key="item.id" class="list-item">
          <div class="list-title">
            <strong>{{ item.file.name }}</strong>
            <span>{{ formatSize(item.file.size) }}</span>
          </div>
          <p class="muted" v-if="item.relativePath">Relative path: {{ item.relativePath }}</p>
          <p class="muted">Target folder: /{{ item.targetFolderPath || '' }}</p>
          <div class="progress-track">
            <span class="progress-fill" :style="{ width: `${item.progress}%` }"></span>
          </div>
          <div class="list-meta">
            <span>{{ item.status }}</span>
            <span v-if="item.error" class="error">{{ item.error }}</span>
          </div>
          <div class="result-actions">
            <button class="btn btn-ghost" v-if="item.status === 'error'" @click="retryUpload(item.id)">Retry</button>
            <button class="btn btn-ghost" v-if="item.status === 'uploading'" @click="cancelUpload(item.id)">Cancel</button>
          </div>
        </li>
      </ul>
    </div>

    <div class="drive-layout">
      <aside class="folder-tree card-lite">
        <div class="folder-tree-head">
          <h3>Folders</h3>
          <button class="btn btn-ghost" @click="promptCreateFolder">New</button>
        </div>
        <ul class="tree-list">
          <li
            v-for="node in flatTreeNodes"
            :key="node.path || '__root__'"
            class="tree-item"
            :class="{ active: currentPath === node.path }"
            :style="{ paddingLeft: `${12 + node.depth * 14}px` }"
          >
            <button class="tree-link" @click="openPath(node.path)">
              <span>{{ node.name }}</span>
              <small>{{ node.fileCount }}</small>
            </button>
          </li>
        </ul>
      </aside>

      <article class="drive-main card-lite">
        <div class="drive-toolbar">
          <div class="breadcrumbs">
            <button
              v-for="crumb in breadcrumbs"
              :key="crumb.path || '__root__'"
              class="crumb"
              @click="openPath(crumb.path)"
            >
              {{ crumb.name }}
            </button>
          </div>
          <div class="toolbar">
            <input v-model.trim="search" placeholder="Search in current view" @keyup.enter="reloadExplorer" />
            <select v-model="storageFilter" @change="refreshAll">
              <option value="all">All Storage</option>
              <option v-for="type in STORAGE_TYPES" :key="type.value" :value="type.value">{{ type.label }}</option>
            </select>
            <select v-model="viewMode">
              <option value="list">List</option>
              <option value="grid">Grid</option>
            </select>
            <button class="btn btn-ghost" @click="promptMoveSelected" :disabled="selectedFileIds.length === 0">Move</button>
            <button class="btn btn-danger" @click="deleteSelected" :disabled="selectedFileIds.length === 0">Delete</button>
          </div>
        </div>

        <div class="folder-inline-list" v-if="folders.length">
          <article v-for="folder in folders" :key="folder.path" class="folder-card">
            <button class="folder-open" @dblclick="openPath(folder.path)" @click="openPath(folder.path)">
              <strong>{{ folder.name }}</strong>
              <small>{{ folder.fileCount }} files</small>
            </button>
            <div class="folder-card-actions">
              <button class="btn btn-ghost" @click="promptRenameFolder(folder)">Rename</button>
              <button class="btn btn-ghost" @click="promptMoveFolder(folder)">Move</button>
              <button class="btn btn-danger" @click="deleteFolderAction(folder)">Delete</button>
            </div>
          </article>
        </div>

        <div v-if="viewMode === 'grid'" class="file-grid">
          <article v-for="file in files" :key="file.name" class="file-card">
            <label class="file-check">
              <input type="checkbox" :checked="selectedSet.has(file.name)" @change="toggleFileSelection(file.name)" />
            </label>
            <a :href="fileLink(file.name)" target="_blank" rel="noopener" class="file-preview">
              <img v-if="isImage(file.metadata?.fileName || file.name)" :src="fileLink(file.name)" :alt="file.metadata?.fileName || file.name" />
              <span v-else>FILE</span>
            </a>
            <strong class="file-name">{{ file.metadata?.fileName || file.name }}</strong>
            <small class="muted">{{ formatSize(file.metadata?.fileSize || 0) }}</small>
            <div class="file-actions">
              <button class="btn btn-ghost" @click="copyDirect(file)">Direct</button>
              <button class="btn btn-ghost" @click="copyShare(file)">Share</button>
              <button class="btn btn-ghost" @click="promptRenameFile(file)">Rename</button>
              <button class="btn btn-ghost" @click="promptMoveFile(file)">Move</button>
              <button class="btn btn-danger" @click="deleteFile(file)">Delete</button>
            </div>
          </article>
        </div>

        <div v-else class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th><input type="checkbox" :checked="allSelected" @change="toggleSelectAll" /></th>
                <th>Name</th>
                <th>Storage</th>
                <th>Size</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="file in files" :key="file.name">
                <td><input type="checkbox" :checked="selectedSet.has(file.name)" @change="toggleFileSelection(file.name)" /></td>
                <td>
                  <div class="file-col">
                    <strong>{{ file.metadata?.fileName || file.name }}</strong>
                    <small>{{ file.name }}</small>
                  </div>
                </td>
                <td><span class="badge">{{ file.metadata?.storageType || 'unknown' }}</span></td>
                <td>{{ formatSize(file.metadata?.fileSize || 0) }}</td>
                <td>{{ formatTime(file.metadata?.TimeStamp) }}</td>
                <td>
                  <div class="table-actions">
                    <button class="btn btn-ghost" @click="copyDirect(file)">Direct</button>
                    <button class="btn btn-ghost" @click="copyShare(file)">Share</button>
                    <button class="btn btn-ghost" @click="promptRenameFile(file)">Rename</button>
                    <button class="btn btn-ghost" @click="promptMoveFile(file)">Move</button>
                    <button class="btn btn-danger" @click="deleteFile(file)">Delete</button>
                  </div>
                </td>
              </tr>
              <tr v-if="!loading && files.length === 0">
                <td colspan="6" class="empty">No files in this folder.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="footer-actions">
          <button v-if="nextCursor" class="btn" :disabled="loading" @click="loadMore">
            {{ loading ? 'Loading...' : 'Load More' }}
          </button>
        </div>
      </article>
    </div>

    <p v-if="message" class="muted">{{ message }}</p>
    <p v-if="error" class="error">{{ error }}</p>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { apiFetch, absoluteFileUrl, getApiBase } from '../api/client';
import {
  createFolder,
  deleteFiles,
  deleteFolder,
  getDriveExplorer,
  getDriveTree,
  moveFiles,
  moveFolder,
  renameFile,
  signShareLink,
} from '../api/drive';
import { STORAGE_TYPES, getStorageLabel, storageEnabledFromStatus } from '../config/storage-definitions';

const picker = ref(null);
const dragActive = ref(false);
const queue = ref([]);
const uploading = ref(false);
const urlInput = ref('');
const urlUploading = ref(false);
const status = ref(null);
const selectedStorage = ref('telegram');

const treeNodes = ref([]);
const folders = ref([]);
const files = ref([]);
const breadcrumbs = ref([{ path: '', name: 'All Files' }]);
const currentPath = ref('');
const storageFilter = ref('all');
const search = ref('');
const nextCursor = ref(null);
const loading = ref(false);
const viewMode = ref('list');
const selectedFileIds = ref([]);
const message = ref('');
const error = ref('');

const DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024;
const SMALL_FILE_THRESHOLD = 20 * 1024 * 1024;

const selectedSet = computed(() => new Set(selectedFileIds.value));
const allSelected = computed(() => files.value.length > 0 && selectedFileIds.value.length === files.value.length);

const capabilityCards = computed(() => {
  const capabilityList = Array.isArray(status.value?.capabilities)
    ? status.value.capabilities
    : STORAGE_TYPES.map((item) => ({
      type: item.value,
      label: item.label,
      layer: item.layer || 'direct',
      enableHint: 'Configure this adapter in Storage Config.',
    }));

  return capabilityList.map((cap) => {
    const detail = status.value?.[cap.type] || {};
    const configured = Boolean(detail.configured);
    const available = storageEnabledFromStatus(status.value, cap.type);
    const layerLabel = cap.layer === 'mounted' ? 'Mounted' : 'Direct';
    let statusText = 'Not configured';
    if (available) statusText = 'Available';
    else if (configured) statusText = detail.message || 'Configured but unavailable';
    return {
      ...cap,
      description: STORAGE_TYPES.find((x) => x.value === cap.type)?.description || '',
      configured,
      available,
      layerLabel,
      statusText,
      hint: available ? 'Ready to use' : (detail.message || cap.enableHint || 'Configure to enable'),
    };
  });
});

const availableModes = computed(() => capabilityCards.value.filter((item) => item.available));

const currentStorageLabel = computed(() => {
  const found = capabilityCards.value.find((item) => item.type === selectedStorage.value);
  return found?.label || 'Telegram';
});

const flatTreeNodes = computed(() => {
  const sorted = [...treeNodes.value].sort((a, b) => {
    const depthA = a.path ? a.path.split('/').length : 0;
    const depthB = b.path ? b.path.split('/').length : 0;
    if (depthA !== depthB) return depthA - depthB;
    return String(a.path || '').localeCompare(String(b.path || ''), 'en', { sensitivity: 'base' });
  });
  return sorted.map((node) => ({
    ...node,
    depth: node.path ? node.path.split('/').length : 0,
  }));
});

onMounted(async () => {
  await refreshStatus();
  await refreshAll();
});

function selectStorage(capability) {
  if (!capability.available) return;
  selectedStorage.value = capability.type;
}

async function refreshStatus() {
  try {
    status.value = await apiFetch('/api/status');
    if (!availableModes.value.some((item) => item.type === selectedStorage.value)) {
      selectedStorage.value = availableModes.value[0]?.type || 'telegram';
    }
  } catch (err) {
    error.value = err.message || 'Failed to load status';
  }
}

async function refreshAll() {
  await Promise.all([loadTree(), reloadExplorer()]);
}

async function loadTree() {
  try {
    treeNodes.value = await getDriveTree(storageFilter.value);
  } catch (err) {
    error.value = err.message || 'Failed to load folder tree';
  }
}

async function reloadExplorer() {
  nextCursor.value = null;
  await loadExplorer(true);
}

async function loadMore() {
  await loadExplorer(false);
}

async function loadExplorer(reset) {
  if (loading.value) return;
  loading.value = true;
  error.value = '';

  try {
    const data = await getDriveExplorer({
      path: currentPath.value,
      storage: storageFilter.value,
      search: search.value,
      limit: 100,
      cursor: reset ? '' : (nextCursor.value || ''),
      includeStats: reset,
    });

    folders.value = Array.isArray(data.folders) ? data.folders : [];
    breadcrumbs.value = Array.isArray(data.breadcrumbs) ? data.breadcrumbs : [{ path: '', name: 'All Files' }];

    const incomingFiles = Array.isArray(data.files) ? data.files : [];
    if (reset) {
      files.value = incomingFiles;
      selectedFileIds.value = [];
    } else {
      const seen = new Set(files.value.map((item) => item.name));
      for (const item of incomingFiles) {
        if (!seen.has(item.name)) files.value.push(item);
      }
    }

    nextCursor.value = data.list_complete ? null : data.cursor;
  } catch (err) {
    error.value = err.message || 'Failed to load drive explorer';
  } finally {
    loading.value = false;
  }
}

function openPath(path) {
  currentPath.value = path || '';
  void reloadExplorer();
}

function openPicker() {
  picker.value?.click();
}

function handleFilePick(event) {
  const filesPicked = Array.from(event.target.files || []);
  enqueueFiles(filesPicked.map((file) => ({ file, relativePath: '' })));
  event.target.value = '';
}

async function handleDrop(event) {
  dragActive.value = false;
  const dropped = await extractDroppedFiles(event.dataTransfer);
  enqueueFiles(dropped);
}

async function extractDroppedFiles(dataTransfer) {
  const output = [];
  if (!dataTransfer?.items?.length) {
    return Array.from(dataTransfer?.files || []).map((file) => ({ file, relativePath: '' }));
  }

  const tasks = [];
  for (const item of Array.from(dataTransfer.items)) {
    const entry = item.webkitGetAsEntry?.();
    if (!entry) {
      const file = item.getAsFile?.();
      if (file) output.push({ file, relativePath: '' });
      continue;
    }
    tasks.push(readEntry(entry, ''));
  }

  const nested = await Promise.all(tasks);
  for (const list of nested) {
    output.push(...list);
  }
  return output;
}

function readEntry(entry, parentPath) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file((file) => {
        resolve([{ file, relativePath: parentPath ? `${parentPath}/${file.name}` : file.name }]);
      });
      return;
    }

    if (!entry.isDirectory) {
      resolve([]);
      return;
    }

    const reader = entry.createReader();
    const entries = [];

    function readBatch() {
      reader.readEntries(async (batch) => {
        if (!batch.length) {
          const children = await Promise.all(entries.map((child) => readEntry(child, parentPath ? `${parentPath}/${entry.name}` : entry.name)));
          resolve(children.flat());
          return;
        }
        entries.push(...batch);
        readBatch();
      });
    }

    readBatch();
  });
}

function joinPath(base, extra) {
  const segments = [];
  for (const piece of [base, extra]) {
    const normalized = String(piece || '').replace(/\\/g, '/');
    for (const part of normalized.split('/')) {
      const cleaned = part.trim();
      if (!cleaned || cleaned === '.') continue;
      if (cleaned === '..') {
        segments.pop();
      } else {
        segments.push(cleaned);
      }
    }
  }
  return segments.join('/');
}

function enqueueFiles(list) {
  for (const item of list) {
    const file = item.file;
    const relativePath = item.relativePath || '';
    const parentPath = relativePath.includes('/')
      ? relativePath.split('/').slice(0, -1).join('/')
      : '';
    const targetFolderPath = joinPath(currentPath.value, parentPath);

    queue.value.push({
      id: `${Date.now()}_${Math.random().toString(16).slice(2)}`,
      file,
      relativePath,
      targetFolderPath,
      progress: 0,
      status: 'pending',
      error: '',
      cancelled: false,
      xhr: null,
    });
  }
  void processQueue();
}

async function processQueue() {
  if (uploading.value) return;
  uploading.value = true;
  let shouldReload = false;

  try {
    for (const item of queue.value) {
      if (item.status !== 'pending') continue;
      if (!availableModes.value.some((mode) => mode.type === selectedStorage.value)) {
        item.status = 'error';
        item.error = 'Selected storage is not available.';
        continue;
      }

      item.status = 'uploading';
      item.error = '';
      item.cancelled = false;

      try {
        if (item.file.size > SMALL_FILE_THRESHOLD) {
          await chunkUpload(item);
        } else {
          await directUpload(item);
        }
        item.status = 'success';
        item.progress = 100;
        shouldReload = true;
      } catch (err) {
        if (item.cancelled) {
          item.status = 'cancelled';
          item.error = '';
        } else {
          item.status = 'error';
          item.error = err.message || 'Upload failed';
        }
      }
    }
  } finally {
    uploading.value = false;
    if (shouldReload) {
      await refreshAll();
    }
  }
}

function apiUrl(path) {
  return `${getApiBase()}${path}`;
}

function directUpload(item) {
  return new Promise((resolve, reject) => {
    const formData = new FormData();
    formData.append('file', item.file);
    formData.append('storageMode', selectedStorage.value);
    formData.append('folderPath', item.targetFolderPath || '');

    const xhr = new XMLHttpRequest();
    item.xhr = xhr;
    xhr.open('POST', apiUrl('/upload'));
    xhr.withCredentials = true;

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      item.progress = Math.max(1, Math.floor((event.loaded / event.total) * 100));
    };

    xhr.onload = () => {
      item.xhr = null;
      let body = {};
      try {
        body = JSON.parse(xhr.responseText || '{}');
      } catch {
        reject(new Error('Invalid upload response'));
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(body.error || body.errorDetail || `Upload failed (${xhr.status})`));
        return;
      }
      resolve(body);
    };

    xhr.onerror = () => {
      item.xhr = null;
      reject(new Error('Network error'));
    };

    xhr.onabort = () => {
      item.xhr = null;
      item.cancelled = true;
      reject(new Error('Upload cancelled'));
    };

    xhr.send(formData);
  });
}

async function chunkUpload(item) {
  const totalChunks = Math.ceil(item.file.size / DEFAULT_CHUNK_SIZE);
  const init = await apiFetch('/api/chunked-upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fileName: item.file.name,
      fileSize: item.file.size,
      fileType: item.file.type,
      totalChunks,
      storageMode: selectedStorage.value,
      folderPath: item.targetFolderPath || '',
    }),
  });

  const uploadId = init.uploadId;
  const chunkSize = Number(init.chunkSize || DEFAULT_CHUNK_SIZE);

  for (let index = 0; index < totalChunks; index += 1) {
    if (item.cancelled) throw new Error('Upload cancelled');

    const start = index * chunkSize;
    const end = Math.min(item.file.size, start + chunkSize);
    const chunk = item.file.slice(start, end);

    const body = new FormData();
    body.append('uploadId', uploadId);
    body.append('chunkIndex', String(index));
    body.append('chunk', chunk);

    await apiFetch('/api/chunked-upload/chunk', {
      method: 'POST',
      body,
    });

    item.progress = Math.min(95, Math.floor(((index + 1) / totalChunks) * 95));
  }

  await apiFetch('/api/chunked-upload/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uploadId }),
  });
}

function cancelUpload(id) {
  const target = queue.value.find((item) => item.id === id);
  if (!target) return;
  target.cancelled = true;
  if (target.xhr) {
    target.xhr.abort();
    return;
  }
  if (target.status === 'pending') {
    target.status = 'cancelled';
  }
}

function retryUpload(id) {
  const target = queue.value.find((item) => item.id === id);
  if (!target) return;
  target.status = 'pending';
  target.progress = 0;
  target.error = '';
  target.cancelled = false;
  void processQueue();
}

async function uploadUrl() {
  if (!urlInput.value || urlUploading.value) return;
  urlUploading.value = true;
  error.value = '';

  try {
    await apiFetch('/api/upload-from-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: urlInput.value,
        storageMode: selectedStorage.value,
        folderPath: currentPath.value,
      }),
    });
    urlInput.value = '';
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'URL upload failed';
  } finally {
    urlUploading.value = false;
  }
}

function toggleFileSelection(id) {
  if (selectedSet.value.has(id)) {
    selectedFileIds.value = selectedFileIds.value.filter((item) => item !== id);
  } else {
    selectedFileIds.value = [...selectedFileIds.value, id];
  }
}

function toggleSelectAll() {
  if (allSelected.value) {
    selectedFileIds.value = [];
  } else {
    selectedFileIds.value = files.value.map((file) => file.name);
  }
}

async function promptCreateFolder() {
  const name = window.prompt('Folder name');
  if (!name) return;
  const path = joinPath(currentPath.value, name);
  try {
    await createFolder(path);
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Create folder failed';
  }
}

async function promptRenameFolder(folder) {
  const nextName = window.prompt('Rename folder', folder.name);
  if (!nextName || nextName === folder.name) return;
  const parent = folder.parentPath || '';
  const targetPath = joinPath(parent, nextName);
  try {
    await moveFolder(folder.path, targetPath);
    if (currentPath.value.startsWith(`${folder.path}/`) || currentPath.value === folder.path) {
      currentPath.value = currentPath.value.replace(folder.path, targetPath);
    }
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Rename folder failed';
  }
}

async function promptMoveFolder(folder) {
  const target = window.prompt('Move folder to path (e.g. assets/images)', folder.path);
  if (!target || target === folder.path) return;
  try {
    await moveFolder(folder.path, target);
    if (currentPath.value.startsWith(`${folder.path}/`) || currentPath.value === folder.path) {
      currentPath.value = currentPath.value.replace(folder.path, target);
    }
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Move folder failed';
  }
}

async function deleteFolderAction(folder) {
  if (!window.confirm(`Delete folder "${folder.name}"?`)) return;
  try {
    await deleteFolder(folder.path, false);
    await refreshAll();
  } catch (err) {
    if (String(err.message || '').includes('not empty')) {
      const recursive = window.confirm('Folder not empty. Delete recursively (including files)?');
      if (!recursive) return;
      try {
        await deleteFolder(folder.path, true);
        if (currentPath.value.startsWith(folder.path)) {
          currentPath.value = '';
        }
        await refreshAll();
      } catch (nestedError) {
        error.value = nestedError.message || 'Recursive delete failed';
      }
      return;
    }
    error.value = err.message || 'Delete folder failed';
  }
}

async function promptRenameFile(file) {
  const nextName = window.prompt('Rename file', file.metadata?.fileName || file.name);
  if (!nextName) return;
  try {
    await renameFile(file.name, nextName);
    await reloadExplorer();
  } catch (err) {
    error.value = err.message || 'Rename failed';
  }
}

async function promptMoveFile(file) {
  const target = window.prompt('Move file to folder path (empty = root)', currentPath.value);
  if (target == null) return;
  try {
    await moveFiles([file.name], target);
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Move failed';
  }
}

async function deleteFile(file) {
  if (!window.confirm(`Delete ${file.metadata?.fileName || file.name}?`)) return;
  try {
    await deleteFiles([file.name]);
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Delete failed';
  }
}

async function promptMoveSelected() {
  const target = window.prompt('Move selected files to folder path (empty = root)', currentPath.value);
  if (target == null) return;
  try {
    await moveFiles(selectedFileIds.value, target);
    selectedFileIds.value = [];
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Batch move failed';
  }
}

async function deleteSelected() {
  if (selectedFileIds.value.length === 0) return;
  if (!window.confirm(`Delete ${selectedFileIds.value.length} selected files?`)) return;
  try {
    await deleteFiles(selectedFileIds.value);
    selectedFileIds.value = [];
    await refreshAll();
  } catch (err) {
    error.value = err.message || 'Batch delete failed';
  }
}

function fileLink(id) {
  return absoluteFileUrl(id);
}

async function copyDirect(file) {
  await copyText(fileLink(file.name));
  message.value = 'Direct link copied.';
}

async function copyShare(file) {
  try {
    const payload = await signShareLink(file.name);
    await copyText(payload.shareUrl);
    const expireAt = payload.expiresAt ? new Date(payload.expiresAt).toLocaleString() : 'Never';
    message.value = `Share link copied. Permission: ${payload.permission}. Expires: ${expireAt}.`;
  } catch (err) {
    error.value = err.message || 'Failed to create share link';
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const input = document.createElement('textarea');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
  }
}

function isImage(name = '') {
  const ext = String(name).split('.').pop()?.toLowerCase() || '';
  return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico', 'avif', 'heic'].includes(ext);
}

function formatSize(bytes = 0) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatTime(timestamp) {
  if (!timestamp) return '-';
  try {
    return new Date(Number(timestamp)).toLocaleString();
  } catch {
    return '-';
  }
}
</script>

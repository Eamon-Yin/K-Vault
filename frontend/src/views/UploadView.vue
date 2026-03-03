<template>
  <section class="card panel">
    <div class="panel-head">
      <h2>Upload Center</h2>
      <div class="storage-group">
        <button
          v-for="mode in modes"
          :key="mode.value"
          class="chip"
          :class="{ active: selectedStorage === mode.value, disabled: !mode.available }"
          :disabled="!mode.available"
          :title="mode.hint"
          @click="selectedStorage = mode.value"
        >
          {{ mode.label }}
        </button>
      </div>
    </div>

    <div
      class="dropzone"
      :class="{ active: dragActive }"
      @dragover.prevent="dragActive = true"
      @dragleave.prevent="dragActive = false"
      @drop.prevent="handleDrop"
      @click="openPicker"
    >
      <input ref="picker" type="file" multiple hidden @change="handleFilePick" />
      <p class="dropzone-title">Drag files here or click to upload</p>
      <p class="muted">Current target: {{ currentStorageLabel }}</p>
    </div>

    <form class="url-row" @submit.prevent="uploadUrl">
      <input v-model.trim="urlInput" placeholder="https://example.com/file.png" />
      <button class="btn" :disabled="urlUploading || !urlInput">
        {{ urlUploading ? 'Uploading...' : 'Upload URL' }}
      </button>
    </form>

    <div v-if="queue.length" class="list-wrap">
      <h3>Queue</h3>
      <ul class="list">
        <li v-for="item in queue" :key="item.id" class="list-item">
          <div class="list-title">
            <strong>{{ item.file.name }}</strong>
            <span>{{ formatSize(item.file.size) }}</span>
          </div>
          <div class="progress-track">
            <span class="progress-fill" :style="{ width: `${item.progress}%` }"></span>
          </div>
          <div class="list-meta">
            <span>{{ item.status }}</span>
            <span v-if="item.error" class="error">{{ item.error }}</span>
          </div>
        </li>
      </ul>
    </div>

    <div v-if="results.length" class="list-wrap">
      <h3>Uploaded</h3>
      <ul class="list">
        <li v-for="item in results" :key="item.id" class="result-item">
          <div>
            <strong>{{ item.fileName }}</strong>
            <p class="muted">{{ item.link }}</p>
          </div>
          <div class="result-actions">
            <button class="btn btn-ghost" @click="copy(item.link)">Copy</button>
            <a class="btn btn-ghost" :href="item.link" target="_blank" rel="noopener">Open</a>
          </div>
        </li>
      </ul>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { apiFetch, getApiBase } from '../api/client';
import { STORAGE_TYPES, getStorageLabel, storageEnabledFromStatus } from '../config/storage-definitions';

const picker = ref(null);
const dragActive = ref(false);
const queue = ref([]);
const results = ref([]);
const selectedStorage = ref('telegram');
const status = ref(null);
const uploading = ref(false);
const error = ref('');
const urlInput = ref('');
const urlUploading = ref(false);

const DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024;
const SMALL_FILE_THRESHOLD = 20 * 1024 * 1024;

const modes = computed(() => {
  return STORAGE_TYPES.map((item) => {
    const detail = status.value?.[item.value] || {};
    const available = storageEnabledFromStatus(status.value, item.value);
    const configured = Boolean(detail.configured);
    return {
      value: item.value,
      label: item.label,
      available,
      hint: available
        ? 'Ready'
        : (configured ? (detail.message || 'Configured but unavailable') : 'Not configured'),
    };
  });
});

const currentStorageLabel = computed(() => {
  const found = modes.value.find((x) => x.value === selectedStorage.value);
  return found ? found.label : 'Telegram';
});

onMounted(async () => {
  try {
    status.value = await apiFetch('/api/status');
    const first = modes.value.find((item) => item.available);
    if (first) selectedStorage.value = first.value;
  } catch (err) {
    error.value = err.message;
  }
});

function openPicker() {
  picker.value?.click();
}

function handleFilePick(event) {
  const files = Array.from(event.target.files || []);
  enqueueFiles(files);
  event.target.value = '';
}

function handleDrop(event) {
  dragActive.value = false;
  const files = Array.from(event.dataTransfer?.files || []);
  enqueueFiles(files);
}

function enqueueFiles(files) {
  for (const file of files) {
    queue.value.push({
      id: `${Date.now()}_${Math.random().toString(16).slice(2)}`,
      file,
      progress: 0,
      status: 'pending',
      error: '',
    });
  }
  void processQueue();
}

async function processQueue() {
  if (uploading.value) return;
  uploading.value = true;
  error.value = '';

  try {
    for (const item of queue.value) {
      if (item.status !== 'pending') continue;
      item.status = 'uploading';
      item.error = '';

      try {
        const link = item.file.size > SMALL_FILE_THRESHOLD
          ? await chunkUpload(item)
          : await directUpload(item);

        item.status = 'success';
        item.progress = 100;
        results.value.unshift({
          id: item.id,
          fileName: item.file.name,
          link,
        });
      } catch (err) {
        item.status = 'error';
        item.error = err.message || 'Upload failed';
      }
    }
  } finally {
    uploading.value = false;
  }
}

function apiUrl(path) {
  return `${getApiBase()}${path}`;
}

function toAbsoluteUrl(path) {
  return new URL(path, window.location.origin).toString();
}

function directUpload(item) {
  return new Promise((resolve, reject) => {
    const formData = new FormData();
    formData.append('file', item.file);
    formData.append('storageMode', selectedStorage.value);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', apiUrl('/upload'));
    xhr.withCredentials = true;

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      item.progress = Math.max(1, Math.floor((event.loaded / event.total) * 100));
    };

    xhr.onload = () => {
      try {
        const body = JSON.parse(xhr.responseText || '{}');
        if (xhr.status < 200 || xhr.status >= 300) {
          reject(new Error(body.error || `Upload failed: ${xhr.status}`));
          return;
        }

        const src = Array.isArray(body) ? body[0]?.src : body?.src;
        if (!src) {
          reject(new Error('Upload response missing src'));
          return;
        }
        resolve(toAbsoluteUrl(src));
      } catch (err) {
        reject(new Error('Invalid upload response'));
      }
    };

    xhr.onerror = () => reject(new Error('Network error'));
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
    }),
  });

  const uploadId = init.uploadId;
  const chunkSize = Number(init.chunkSize || DEFAULT_CHUNK_SIZE);

  for (let index = 0; index < totalChunks; index += 1) {
    const start = index * chunkSize;
    const end = Math.min(item.file.size, start + chunkSize);
    const chunk = item.file.slice(start, end);

    const chunkBody = new FormData();
    chunkBody.append('uploadId', uploadId);
    chunkBody.append('chunkIndex', String(index));
    chunkBody.append('chunk', chunk);

    await apiFetch('/api/chunked-upload/chunk', {
      method: 'POST',
      body: chunkBody,
    });

    item.progress = Math.min(95, Math.floor(((index + 1) / totalChunks) * 95));
  }

  const done = await apiFetch('/api/chunked-upload/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uploadId }),
  });

  if (!done?.src) {
    throw new Error('Chunk upload complete response missing src');
  }

  return toAbsoluteUrl(done.src);
}

async function uploadUrl() {
  if (!urlInput.value || urlUploading.value) return;

  urlUploading.value = true;
  error.value = '';

  try {
    const body = await apiFetch('/api/upload-from-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: urlInput.value,
        storageMode: selectedStorage.value,
      }),
    });

    const src = Array.isArray(body) ? body[0]?.src : body?.src;
    if (!src) {
      throw new Error('Upload response missing src');
    }

    results.value.unshift({
      id: `url_${Date.now()}`,
      fileName: urlInput.value.split('/').pop() || 'remote-file',
      link: toAbsoluteUrl(src),
    });

    urlInput.value = '';
  } catch (err) {
    error.value = err.message || 'URL upload failed';
  } finally {
    urlUploading.value = false;
  }
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

async function copy(text) {
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
</script>

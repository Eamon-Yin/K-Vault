<template>
  <section class="card panel storage-panel">
    <div class="panel-head storage-head">
      <div>
        <h2>Storage Config</h2>
        <p class="muted">Manage backend profiles, test connectivity, and switch default target.</p>
        <p class="muted">WebDAV is recommended as a mounted aggregation entry (for example alist/openlist WebDAV endpoint).</p>
      </div>
      <button class="btn btn-ghost" @click="resetForm">New Config</button>
    </div>

    <div class="storage-layout">
      <article class="storage-list card-lite">
        <h3>Configured Backends</h3>
        <ul v-if="items.length" class="list storage-listing">
          <li v-for="item in items" :key="item.id" class="storage-row">
            <div class="storage-row-main">
              <div class="storage-row-top">
                <strong>{{ item.name }}</strong>
                <span class="badge">{{ getStorageLabel(item.type) }}</span>
                <span class="badge" :class="item.enabled ? 'badge-ok' : 'badge-danger'">
                  {{ item.enabled ? 'Enabled' : 'Disabled' }}
                </span>
                <span class="badge" v-if="item.isDefault">Default</span>
              </div>
              <p class="muted">ID: {{ item.id }}</p>
              <p v-if="testResults[item.id]" class="storage-test" :class="testResults[item.id].connected ? 'ok' : 'fail'">
                {{ formatTestMessage(testResults[item.id]) }}
              </p>
            </div>

            <div class="storage-actions">
              <button class="btn btn-ghost" @click="editItem(item)">Edit</button>
              <button class="btn btn-ghost" @click="testItem(item.id)">Test</button>
              <button class="btn btn-ghost" @click="toggleEnabled(item)">
                {{ item.enabled ? 'Disable' : 'Enable' }}
              </button>
              <button class="btn btn-ghost" @click="setDefault(item.id)" :disabled="item.isDefault">Set Default</button>
              <button class="btn btn-danger" @click="removeItem(item.id)">Delete</button>
            </div>
          </li>
        </ul>
        <p v-else class="muted">No storage config yet.</p>
      </article>

      <article class="storage-editor card-lite">
        <h3>{{ editingId ? 'Edit Storage' : 'Create Storage' }}</h3>

        <form class="form-grid" @submit.prevent="submit">
          <label>
            Name
            <input v-model.trim="form.name" required placeholder="Readable name" />
          </label>

          <label>
            Type
            <select v-model="form.type" @change="onTypeChanged">
              <optgroup label="Direct Upload Backends">
                <option v-for="type in directTypes" :key="type.value" :value="type.value">{{ type.label }}</option>
              </optgroup>
              <optgroup label="Mounted / Aggregation Backends">
                <option v-for="type in mountedTypes" :key="type.value" :value="type.value">{{ type.label }}</option>
              </optgroup>
            </select>
          </label>

          <div class="toggle-row">
            <label><input v-model="form.enabled" type="checkbox" /> Enabled</label>
            <label><input v-model="form.isDefault" type="checkbox" /> Set as default</label>
          </div>

          <div class="field-grid">
            <label v-for="field in currentFields" :key="field.key">
              <span>{{ field.label }}</span>

              <select
                v-if="field.input === 'select'"
                v-model="form.config[field.key]"
                :required="field.required"
              >
                <option
                  v-for="option in field.options || []"
                  :key="`${field.key}-${option.value}`"
                  :value="option.value"
                >
                  {{ option.label }}
                </option>
              </select>

              <textarea
                v-else-if="field.input === 'textarea'"
                v-model="form.config[field.key]"
                :placeholder="field.placeholder"
                :required="field.required"
                rows="4"
              ></textarea>

              <input
                v-else
                v-model.trim="form.config[field.key]"
                :type="field.secret ? 'password' : 'text'"
                :placeholder="field.placeholder"
                :required="field.required"
              />
            </label>
          </div>

          <p v-if="STORAGE_NOTES[form.type]" class="muted">{{ STORAGE_NOTES[form.type] }}</p>

          <div class="form-actions">
            <button class="btn" :disabled="saving">{{ saving ? 'Saving...' : 'Save Config' }}</button>
            <button class="btn btn-ghost" type="button" :disabled="testing" @click="testDraftConfig">
              {{ testing ? 'Testing...' : 'Test Draft' }}
            </button>
          </div>
        </form>

        <div v-if="draftTest" class="test-detail" :class="draftTest.connected ? 'ok' : 'fail'">
          <strong>{{ draftTest.connected ? 'Draft connection successful' : 'Draft connection failed' }}</strong>
          <pre>{{ stringifyDetail(draftTest) }}</pre>
        </div>
      </article>
    </div>

    <p v-if="message" class="muted">{{ message }}</p>
    <p v-if="error" class="error">{{ error }}</p>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import {
  createStorageConfig,
  deleteStorageConfig,
  listStorageConfigs,
  setDefaultStorageConfig,
  testStorageConfigById,
  testStorageDraft,
  updateStorageConfig,
} from '../api/storage';
import {
  STORAGE_FIELDS,
  STORAGE_NOTES,
  STORAGE_TYPES,
  getStorageFields,
  getStorageLabel,
} from '../config/storage-definitions';

const items = ref([]);
const editingId = ref('');
const saving = ref(false);
const testing = ref(false);
const message = ref('');
const error = ref('');
const draftTest = ref(null);
const testResults = reactive({});

const form = reactive({
  name: '',
  type: 'telegram',
  enabled: true,
  isDefault: false,
  config: {},
});

const currentFields = computed(() => getStorageFields(form.type));
const directTypes = computed(() => STORAGE_TYPES.filter((item) => item.layer !== 'mounted'));
const mountedTypes = computed(() => STORAGE_TYPES.filter((item) => item.layer === 'mounted'));

onMounted(async () => {
  form.config = buildConfigByType(form.type);
  await loadItems();
});

function buildConfigByType(type, source = {}) {
  const fields = STORAGE_FIELDS[type] || [];
  const target = {};
  for (const field of fields) {
    if (source[field.key] != null) {
      target[field.key] = source[field.key];
      continue;
    }
    if (field.input === 'select') {
      target[field.key] = field.options?.[0]?.value || '';
      continue;
    }
    target[field.key] = '';
  }
  return target;
}

async function loadItems() {
  error.value = '';
  try {
    items.value = await listStorageConfigs();
  } catch (err) {
    error.value = err.message || 'Failed to load storage configs.';
  }
}

function resetForm() {
  editingId.value = '';
  form.name = '';
  form.type = 'telegram';
  form.enabled = true;
  form.isDefault = false;
  form.config = buildConfigByType('telegram');
  draftTest.value = null;
  message.value = '';
  error.value = '';
}

function onTypeChanged() {
  form.config = buildConfigByType(form.type, form.config);
}

function editItem(item) {
  editingId.value = item.id;
  form.name = item.name;
  form.type = item.type;
  form.enabled = Boolean(item.enabled);
  form.isDefault = Boolean(item.isDefault);
  form.config = buildConfigByType(item.type, item.config || {});
  draftTest.value = null;
  message.value = '';
  error.value = '';
}

function buildPayload() {
  return {
    name: form.name,
    type: form.type,
    enabled: Boolean(form.enabled),
    isDefault: Boolean(form.isDefault),
    config: { ...form.config },
  };
}

async function submit() {
  saving.value = true;
  error.value = '';
  message.value = '';

  try {
    const payload = buildPayload();
    if (editingId.value) {
      await updateStorageConfig(editingId.value, payload);
      message.value = 'Storage config updated.';
    } else {
      await createStorageConfig(payload);
      const successMessage = 'Storage config created.';
      resetForm();
      message.value = successMessage;
    }

    await loadItems();
  } catch (err) {
    error.value = err.message || 'Save failed';
  } finally {
    saving.value = false;
  }
}

async function testDraftConfig() {
  testing.value = true;
  error.value = '';
  message.value = '';

  try {
    const result = await testStorageDraft(form.type, { ...form.config });
    draftTest.value = result || { connected: false };
    message.value = result?.connected ? 'Draft test succeeded.' : 'Draft test failed.';
  } catch (err) {
    draftTest.value = null;
    error.value = err.message || 'Connection test failed';
  } finally {
    testing.value = false;
  }
}

async function testItem(id) {
  error.value = '';
  message.value = '';

  try {
    const result = await testStorageConfigById(id);
    testResults[id] = {
      ...(result || {}),
      testedAt: Date.now(),
    };
    message.value = result?.connected ? 'Connection successful.' : 'Connection failed.';
  } catch (err) {
    error.value = err.message || 'Storage test failed';
  }
}

async function toggleEnabled(item) {
  error.value = '';
  message.value = '';

  try {
    await updateStorageConfig(item.id, {
      enabled: !item.enabled,
    });
    message.value = 'Storage status updated.';
    await loadItems();
  } catch (err) {
    error.value = err.message || 'Update failed';
  }
}

async function setDefault(id) {
  error.value = '';
  message.value = '';

  try {
    await setDefaultStorageConfig(id);
    message.value = 'Default storage updated.';
    await loadItems();
  } catch (err) {
    error.value = err.message || 'Set default failed';
  }
}

async function removeItem(id) {
  if (!window.confirm('Delete this storage config?')) return;

  error.value = '';
  message.value = '';

  try {
    await deleteStorageConfig(id);
    message.value = 'Storage config deleted.';
    await loadItems();

    if (editingId.value === id) {
      resetForm();
    }
  } catch (err) {
    error.value = err.message || 'Delete failed';
  }
}

function formatTestMessage(result) {
  const statusText = result.connected ? 'Connected' : 'Failed';
  const statusCode = result.status ? ` (HTTP ${result.status})` : '';
  const detail = result.detail ? ` - ${String(result.detail)}` : '';
  return `${statusText}${statusCode}${detail}`;
}

function stringifyDetail(data) {
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return String(data || '');
  }
}
</script>

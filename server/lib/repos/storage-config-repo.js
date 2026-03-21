const { all, get, run, transaction } = require('../../db');
const { encryptJson, decryptJson, randomId } = require('../utils/crypto');
const { normalizeStorageType } = require('../storage/common');

class StorageConfigRepository {
  constructor(db, appConfig) {
    this.db = db;
    this.appConfig = appConfig;
  }

  parseRow(row, includeSecrets = false) {
    if (!row) return null;

    const payloadBlob = JSON.parse(row.encrypted_payload || '{}');
    let decrypted = {};
    try {
      decrypted = decryptJson(payloadBlob, this.appConfig.configEncryptionKey);
    } catch (error) {
      throw new Error(`Failed to decrypt storage config "${row.name}". Check CONFIG_ENCRYPTION_KEY.`);
    }

    const result = {
      id: row.id,
      name: row.name,
      type: row.type,
      enabled: Boolean(row.enabled),
      isDefault: Boolean(row.is_default),
      metadata: JSON.parse(row.metadata_json || '{}'),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      config: includeSecrets ? decrypted : this.maskSensitiveFields(row.type, decrypted),
    };

    return result;
  }

  maskSensitiveFields(type, config) {
    const cloned = { ...(config || {}) };

    const secretFieldsByType = {
      telegram: ['botToken'],
      r2: ['accessKeyId', 'secretAccessKey'],
      s3: ['accessKeyId', 'secretAccessKey'],
      discord: ['botToken', 'webhookUrl'],
      huggingface: ['token'],
      webdav: ['password', 'bearerToken', 'token'],
      github: ['token'],
    };

    const fields = secretFieldsByType[type] || [];
    fields.forEach((field) => {
      if (cloned[field]) cloned[field] = '********';
    });

    return cloned;
  }

  mergeConfigPreserveSecrets(type, currentConfig, patchConfig) {
    if (!patchConfig || typeof patchConfig !== 'object') {
      return { ...(currentConfig || {}) };
    }

    const merged = { ...(currentConfig || {}) };
    const incoming = { ...patchConfig };

    const secretFieldsByType = {
      telegram: ['botToken'],
      r2: ['accessKeyId', 'secretAccessKey'],
      s3: ['accessKeyId', 'secretAccessKey'],
      discord: ['botToken', 'webhookUrl'],
      huggingface: ['token'],
      webdav: ['password', 'bearerToken', 'token'],
      github: ['token'],
    };

    const fields = secretFieldsByType[type] || [];
    fields.forEach((field) => {
      if (incoming[field] === '********') {
        delete incoming[field];
      }
    });

    return { ...merged, ...incoming };
  }

  list(includeSecrets = false) {
    const rows = all(
      this.db,
      `SELECT * FROM storage_configs ORDER BY is_default DESC, type ASC, created_at ASC`
    );
    return rows.map((row) => this.parseRow(row, includeSecrets));
  }

  getById(id, includeSecrets = true) {
    const row = get(this.db, 'SELECT * FROM storage_configs WHERE id = ?', [id]);
    return this.parseRow(row, includeSecrets);
  }

  getDefault() {
    const row = get(this.db, 'SELECT * FROM storage_configs WHERE is_default = 1 ORDER BY updated_at DESC LIMIT 1');
    return this.parseRow(row, true);
  }

  findEnabledByType(type) {
    const normalized = normalizeStorageType(type);
    const rows = all(
      this.db,
      `SELECT * FROM storage_configs
       WHERE type = ? AND enabled = 1
       ORDER BY is_default DESC, updated_at DESC`,
      [normalized]
    );
    return rows.map((row) => this.parseRow(row, true));
  }

  resolveStorageSelection({ storageId, storageMode }) {
    if (storageId) {
      const byId = this.getById(storageId, true);
      if (!byId || !byId.enabled) {
        throw new Error('Selected storage config not found or disabled.');
      }
      return byId;
    }

    if (storageMode) {
      const typed = this.findEnabledByType(storageMode);
      if (typed.length > 0) {
        return typed[0];
      }
    }

    const defaultConfig = this.getDefault();
    if (defaultConfig && defaultConfig.enabled) {
      return defaultConfig;
    }

    const any = all(
      this.db,
      `SELECT * FROM storage_configs WHERE enabled = 1 ORDER BY is_default DESC, created_at ASC LIMIT 1`
    )[0];

    return this.parseRow(any, true);
  }

  create({ name, type, config, enabled = true, isDefault = false, metadata = {} }) {
    const normalizedType = normalizeStorageType(type);
    const now = Date.now();
    const id = randomId('sc');
    const encrypted = encryptJson(config, this.appConfig.configEncryptionKey);

    transaction(this.db, () => {
      if (isDefault) {
        run(this.db, 'UPDATE storage_configs SET is_default = 0');
      }

      run(
        this.db,
        `INSERT INTO storage_configs(
          id, name, type, encrypted_payload, is_default, enabled, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          name,
          normalizedType,
          JSON.stringify(encrypted),
          isDefault ? 1 : 0,
          enabled ? 1 : 0,
          JSON.stringify(metadata || {}),
          now,
          now,
        ]
      );
    });

    return this.getById(id, true);
  }

  update(id, patch) {
    const current = this.getById(id, true);
    if (!current) return null;

    const nextType = normalizeStorageType(patch.type || current.type);
    const nextConfig = this.mergeConfigPreserveSecrets(nextType, current.config, patch.config);

    const encrypted = encryptJson(nextConfig, this.appConfig.configEncryptionKey);
    const now = Date.now();

    transaction(this.db, () => {
      if (patch.isDefault) {
        run(this.db, 'UPDATE storage_configs SET is_default = 0 WHERE id != ?', [id]);
      }

      run(
        this.db,
        `UPDATE storage_configs
         SET name = ?,
             type = ?,
             encrypted_payload = ?,
             is_default = ?,
             enabled = ?,
             metadata_json = ?,
             updated_at = ?
         WHERE id = ?`,
        [
          patch.name || current.name,
          nextType,
          JSON.stringify(encrypted),
          patch.isDefault != null ? (patch.isDefault ? 1 : 0) : (current.isDefault ? 1 : 0),
          patch.enabled != null ? (patch.enabled ? 1 : 0) : (current.enabled ? 1 : 0),
          JSON.stringify(patch.metadata || current.metadata || {}),
          now,
          id,
        ]
      );
    });

    return this.getById(id, true);
  }

  setDefault(id) {
    return transaction(this.db, () => {
      run(this.db, 'UPDATE storage_configs SET is_default = 0');
      run(this.db, 'UPDATE storage_configs SET is_default = 1, updated_at = ? WHERE id = ?', [Date.now(), id]);
      return this.getById(id, true);
    });
  }

  delete(id) {
    const inUse = get(this.db, 'SELECT COUNT(1) AS c FROM files WHERE storage_config_id = ?', [id]);
    if (inUse && Number(inUse.c) > 0) {
      throw new Error('Storage config is in use by existing files and cannot be deleted.');
    }

    const result = run(this.db, 'DELETE FROM storage_configs WHERE id = ?', [id]);
    return Number(result.changes || 0) > 0;
  }

  ensureBootstrapStorage() {
    const bootstrap = this.appConfig.bootstrapDefaultStorage;
    const type = normalizeStorageType(bootstrap.type || 'telegram');

    const hasRequired = {
      telegram: Boolean(bootstrap.telegram?.botToken && bootstrap.telegram?.chatId),
      r2: Boolean(bootstrap.r2?.endpoint && bootstrap.r2?.bucket && bootstrap.r2?.accessKeyId && bootstrap.r2?.secretAccessKey),
      s3: Boolean(bootstrap.s3?.endpoint && bootstrap.s3?.bucket && bootstrap.s3?.accessKeyId && bootstrap.s3?.secretAccessKey),
      discord: Boolean(bootstrap.discord?.webhookUrl || (bootstrap.discord?.botToken && bootstrap.discord?.channelId)),
      huggingface: Boolean(bootstrap.huggingface?.token && bootstrap.huggingface?.repo),
      webdav: Boolean(bootstrap.webdav?.baseUrl && (bootstrap.webdav?.bearerToken || (bootstrap.webdav?.username && bootstrap.webdav?.password))),
      github: Boolean(bootstrap.github?.repo && bootstrap.github?.token),
    };

    const configs = this.list(true);
    const defaultExists = configs.some((item) => Boolean(item.isDefault));
    const preferredTypeReady = Boolean(hasRequired[type]);
    const preferredType = preferredTypeReady ? type : (hasRequired.telegram ? 'telegram' : '');

    const shouldDefaultByType = (storageType) => !defaultExists && preferredType === storageType;

    const ensureBootstrapType = (storageType, config, name) => {
      if (!hasRequired[storageType]) return;

      const existingType = configs.find((item) => item.type === storageType);
      if (existingType) return;

      this.create({
        name,
        type: storageType,
        config,
        enabled: true,
        isDefault: shouldDefaultByType(storageType),
        metadata: {
          source: 'env-bootstrap',
          envSource: config?.envSource || {},
        },
      });
    };

    ensureBootstrapType('telegram', bootstrap.telegram || {}, 'Telegram (Env Bootstrap)');
    ensureBootstrapType('r2', bootstrap.r2 || {}, 'R2 (Env Bootstrap)');
    ensureBootstrapType('s3', bootstrap.s3 || {}, 'S3 (Env Bootstrap)');
    ensureBootstrapType('discord', bootstrap.discord || {}, 'Discord (Env Bootstrap)');
    ensureBootstrapType('huggingface', bootstrap.huggingface || {}, 'HUGGINGFACE (Env Bootstrap)');
    ensureBootstrapType('webdav', bootstrap.webdav || {}, 'WEBDAV (Env Bootstrap)');
    ensureBootstrapType('github', bootstrap.github || {}, 'GITHUB (Env Bootstrap)');

    if (!defaultExists) {
      const fallback = this.getDefault();
      if (!fallback) {
        const anyEnabled = this.list(true).find((item) => item.enabled);
        if (anyEnabled) {
          this.setDefault(anyEnabled.id);
        }
      }
    }
  }
}

module.exports = {
  StorageConfigRepository,
};

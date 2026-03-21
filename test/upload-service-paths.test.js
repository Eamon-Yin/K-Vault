const assert = require('assert');
const { UploadService } = require('../server/lib/services/upload-service');

describe('UploadService storage key routing', function () {
  it('preserves folder path for huggingface uploads under uploads/ prefix', async function () {
    let capturedStorageKey = '';

    const storageRepo = {
      resolveStorageSelection() {
        return {
          id: 'sc_hf',
          name: 'HF',
          type: 'huggingface',
          enabled: true,
          config: { token: 'hf_x', repo: 'u/r' },
        };
      },
    };

    const fileRepo = {
      create(payload) {
        return {
          id: payload.id,
          file_name: payload.fileName,
          file_size: payload.fileSize,
          metadata: payload.extra || {},
        };
      },
    };

    const storageFactory = {
      createAdapter() {
        return {
          async upload({ storageKey }) {
            capturedStorageKey = storageKey;
            return {
              storageKey,
              metadata: { hfPath: storageKey },
            };
          },
        };
      },
    };

    const service = new UploadService({ storageRepo, fileRepo, storageFactory });

    await service.uploadFile({
      fileName: 'photo.png',
      mimeType: 'image/png',
      fileSize: 10,
      buffer: new Uint8Array([1, 2, 3]).buffer,
      folderPath: 'album/2026',
    });

    assert.ok(capturedStorageKey.startsWith('uploads/album/2026/huggingface_'));
    assert.ok(capturedStorageKey.endsWith('.png'));
  });
});

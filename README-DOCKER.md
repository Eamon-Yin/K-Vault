# K-Vault Docker Runtime Guide

This repository now supports two deployment modes:

1. Cloudflare Pages + Functions (existing mode)
2. Docker self-host mode (new)

## Quick Start (Docker)

1. Initialize `.env` and secrets (safe to rerun):

```bash
npm run docker:init-env
```

Alternative shell entrypoint:

```bash
./scripts/bootstrap-env.sh
```

Note: `scripts/bootstrap-env.sh` must have executable permission.  
If you are on Windows or the execute bit is unavailable, use:

```bash
node scripts/bootstrap-env.js
```

What this does:
- if `.env` is missing, copy from `.env.example`
- if `CONFIG_ENCRYPTION_KEY` / `SESSION_SECRET` are empty or placeholder values, generate secure random values
- if those keys are already real values, keep them unchanged (prevents breaking decryption of existing storage configs)

2. Fill at least these values in `.env`:

- `BASIC_USER` / `BASIC_PASS` (optional, set both to enable login)
- one bootstrap storage config (for example Telegram: `TG_BOT_TOKEN` + `TG_CHAT_ID`)
- optional settings store mode:
  - default: `SETTINGS_STORE=sqlite`
  - Redis mode: set `SETTINGS_STORE=redis` and `SETTINGS_REDIS_URL`

3. Start services:

```bash
npm run docker:up
```

4. Open:

- Legacy UI: `http://<host>:8080/`
- Vue3 App: `http://<host>:8080/app/`

Expected startup status:

```bash
docker compose ps
```

You should see:
- `kvault-api` -> `Up ... (healthy)`
- `kvault-web` -> `Up ...`
- `kvault-redis` -> `Up ... (healthy)` when started with `--profile redis`

### Optional: start with local Redis settings store

If you prefer Redis for basic app settings (also compatible with Upstash/KVrocks protocol):

1. Set in `.env`:
   - `SETTINGS_STORE=redis`
   - `SETTINGS_REDIS_URL=redis://redis:6379`
2. Start compose with Redis profile:

```bash
docker compose --profile redis up -d --build
```

## Login API (curl)

`/api/auth/login` accepts both payload shapes:
- new: `{ "username": "...", "password": "..." }`
- compatible: `{ "user": "...", "pass": "..." }`

Example:

```bash
curl -i -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'
```

Compatibility example:

```bash
curl -i -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"your_password"}'
```

## Architecture

- `api`: Node.js Hono backend (`server/`)
  - SQLite metadata (`storage_configs`, `files`, `sessions`, `chunk_uploads`)
  - Settings store abstraction:
    - `sqlite` (`app_settings` table)
    - `redis` (Upstash / Redis / KVrocks compatible via Redis protocol)
  - Encrypted storage secrets (`CONFIG_ENCRYPTION_KEY`)
  - Multi-backend adapters: Telegram / R2 / S3 / Discord / HuggingFace / WebDAV / GitHub / Google Drive / OneDrive
- `web`: Nginx static host + reverse proxy
  - `/api/*` -> backend
  - `/upload` -> backend
  - `/file/*` -> backend
  - `/app/*` -> Vue3 SPA
  - `/` and other legacy pages -> static legacy HTML

Persistent data is stored in Docker volume `kvault_data` (and `kvault_redis` when Redis profile is enabled).

## Drive Console Update (2026-03)

Docker runtime now includes a new Vue Drive Console at:

- `http://<host>:8080/app/drive`
- legacy alias route: `http://<host>:8080/app/admin` (redirects to Drive)

What is new:

- Folder tree + breadcrumbs + list/grid view
- Create/rename/move/delete folders
- Batch file move/delete
- Drag-and-drop upload with queue, progress, retry, cancel
- Copy direct links and signed share links (with expiry metadata)
- Storage capability visibility now shows all adapters (configured or not), with status hints

Direct-link compatibility:

- Existing `/file/:id` links remain unchanged
- Signed share links are additive (`/share/:id?...`) and do not break old links

## Recommended Aggregation Pattern (alist/openlist)

To reduce long-term adapter maintenance, recommended production pattern:

1. K-Vault focuses on:
   - Drive UX
   - direct/share links
   - auth/audit/metadata
2. alist/openlist focuses on:
   - multi-provider aggregation (Google Drive/OneDrive/etc.)
   - upstream mount/credential complexity
3. K-Vault connects to alist/openlist through WebDAV adapter as a mounted backend.

Suggested deployment:

- Same VPS Docker host (simplest): deploy alist/openlist alongside K-Vault
- Or independent node: expose WebDAV endpoint securely and connect from K-Vault WebDAV profile

Failure isolation:

- If aggregation layer is unavailable, only that WebDAV profile is unavailable
- K-Vault site and other storage profiles continue to work
- `/api/status` and Drive adapter cards show degraded state explicitly

## Networking Notes

- `ports` publishes container ports to host (`web` uses `${WEB_PORT:-8080}:80`)
- `expose` is internal-only for compose services (`api:8787`, `redis:6379`)

## Important Environment Variables

| Variable | Description |
| :--- | :--- |
| `CONFIG_ENCRYPTION_KEY` | Required. Encrypt/decrypt dynamic storage secrets in SQLite |
| `SESSION_SECRET` | Session/signature secret |
| `BASIC_USER` / `BASIC_PASS` | Admin login credentials (set both to enable auth) |
| `UPLOAD_MAX_SIZE` | Global upload limit (bytes), default 100MB |
| `UPLOAD_SMALL_FILE_THRESHOLD` | Switch threshold for direct/chunk upload |
| `CHUNK_SIZE` | Chunk size in bytes |
| `DEFAULT_STORAGE_TYPE` | Bootstrap storage type (`telegram`/`r2`/`s3`/`discord`/`huggingface`/`webdav`/`github`/`gdrive`/`onedrive`) |
| `SETTINGS_STORE` | `sqlite` (default) or `redis` for basic app settings |
| `SETTINGS_REDIS_URL` | Redis URL, for Upstash/Redis/KVrocks (required if `SETTINGS_STORE=redis`) |
| `SETTINGS_REDIS_PREFIX` | Redis key prefix, default `k-vault` |
| `SETTINGS_REDIS_CONNECT_TIMEOUT_MS` | Redis connect/ping timeout (ms), default `5000` |
| `TG_BOT_TOKEN` + `TG_CHAT_ID` | Telegram bootstrap storage |
| `R2_*` / `S3_*` / `DISCORD_*` / `HF_*` | Optional bootstrap configs for existing backends |
| `WEBDAV_*` | WebDAV bootstrap config (`WEBDAV_BASE_URL`, auth, optional root path) |
| `GITHUB_*` | GitHub bootstrap config (`repo`, `token`, `mode`, optional `release tag`/`prefix`) |
| `GDRIVE_*` | Google Drive bootstrap config (`folderId`, service account or token) |
| `ONEDRIVE_*` | OneDrive bootstrap config (access token or Graph client credentials) |

## Security Notes

- Never expose or commit tokens/secrets (`TG_BOT_TOKEN`, `DISCORD_BOT_TOKEN`, `HF_TOKEN`, `SESSION_SECRET`, `CONFIG_ENCRYPTION_KEY`, etc.)
- If any token/secret may be leaked, rotate it immediately and restart related services

## Manage List API

`GET /api/manage/list` now defaults to the first page when query parameters are omitted.

Supported query parameters:
- `limit` (or `pageSize` / `size`): items per page, default `100`, max `1000`
- `cursor` (or `offset`): next offset returned by previous response
- `page` (or `current`): page number (1-based), used when `cursor` is not provided
- `storage`: `all`/`telegram`/`r2`/`s3`/`discord`/`huggingface`/`webdav`/`github`/`gdrive`/`onedrive`
- `search`: fuzzy match on file name and id
- `listType` (or `list_type`): `all`/`None`/`White`/`Block`
- `includeStats` (or `stats`): `1|true|yes` to include summary stats

## New Storage Notes

- WebDAV adapter supports `PUT`/`GET`/`DELETE` and auto `MKCOL`; connection test uses `OPTIONS` then `PROPFIND`.
- GitHub adapter supports two modes:
  - `releases`: preferred for binary files and larger payloads.
  - `contents`: best for small files/text and has tighter API write/size/rate constraints.
- Google Drive adapter minimal mode:
  - Recommended: service account + shared folder (`folderId` required).
  - Supports `upload`/`download`/`delete`/`testConnection`.
- OneDrive adapter minimal mode:
  - Supports Graph access token mode and client-credentials mode.
  - In client-credentials mode, `driveId` is required.

## Regression Checklist

Automated script:

```bash
npm run regression:storage
```

Optional create/update smoke config:

```bash
BASE_URL=http://localhost:8080 \
BASIC_USER=admin BASIC_PASS=your_password \
SMOKE_STORAGE_TYPE=webdav \
SMOKE_STORAGE_CONFIG_JSON='{"baseUrl":"https://dav.example.com","username":"u","password":"p"}' \
node scripts/storage-regression.js
```

The script covers:
- `health` / `status`
- `login` (both payloads)
- `storage` list/create/update/test/default
- `upload/download/delete` on enabled storages

## Deployment Notes

- Legacy and Vue3 frontends coexist in Docker mode.
- Existing Cloudflare deployment flow remains unchanged.
- In Docker mode, Cloudflare runtime quotas do not apply to the Node runtime itself.
- Secrets must come from environment variables; do not hard-code.
- New image workflow is available at `.github/workflows/docker-image.yml`:
  - PR: build only
  - main/tag push: build and push `k-vault-api` + `k-vault-web` images to GHCR
- Default image names:
  - `ghcr.io/<your-org-or-user>/k-vault-api`
  - `ghcr.io/<your-org-or-user>/k-vault-web`
- If your repository is private, make sure GitHub Packages visibility/permissions allow your target platform to pull images.

## Platform Compatibility Notes

### Vercel

- Not recommended for current Docker runtime architecture.
- Main blockers are runtime and persistence model mismatch.
  - Serverless function request body limit (4.5MB) conflicts with K-Vault upload flow.
  - Function file system is read-only except temporary `/tmp`, which does not fit persistent SQLite + chunk files.
- If deploying to Vercel, only static frontend hosting is practical without major backend refactor.

### Zeabur

- Suitable.
- Supports Dockerfile/image-based deployment (Compose file is not directly supported as-is).
- Recommended: deploy both `api` and `web` services, mount persistent volume for `/app/data`.

### ClawCloud

- Suitable with container deployment flow.
- Can migrate from Compose model to platform services.
- Recommended: create separate services for backend and web (or adapt compose), and bind persistent storage for `/app/data`.

### NAS (e.g. fnOS / Feiniu NAS)

- Usually suitable when Docker/Compose is available.
- Requirements: enable Docker/Compose, import `docker-compose.yml`, map persistent volume, and expose port 8080 (or custom `WEB_PORT`).

## FAQ

### `.env` missing

Run:

```bash
npm run docker:init-env
```

This recreates `.env` from `.env.example` and only auto-fills secret keys when needed.

### `Failed to decrypt storage config "...". Check CONFIG_ENCRYPTION_KEY.`

Cause: `CONFIG_ENCRYPTION_KEY` changed after encrypted configs were written to SQLite.

Fix:
- restore the original `CONFIG_ENCRYPTION_KEY`
- if the original key is lost, delete/recreate affected storage configs in DB
- avoid editing `CONFIG_ENCRYPTION_KEY` on running instances unless you are doing a planned migration

### Docker Compose buildx/bake warning

Some Docker versions print a bake-related hint/warning during `docker compose build`.

Options:
- ignore it (build still works)
- enable bake explicitly: `set COMPOSE_BAKE=true` (PowerShell: `$env:COMPOSE_BAKE='true'`)
- or disable it: `set COMPOSE_BAKE=false`
- if you see `Docker Compose is configured to build using Bake, but buildx isn't installed`:
  - Ubuntu install command: `sudo apt-get install docker-buildx`

## Local Development

- Backend:

```bash
npm --prefix server install
npm --prefix server run dev
```

- Frontend:

```bash
npm --prefix frontend install
npm --prefix frontend run dev
```

Vue app runs under `/app/` in production build. Legacy pages are copied into the frontend image to keep feature parity during migration.


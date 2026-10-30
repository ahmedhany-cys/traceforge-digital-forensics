# Installation

Everything runs locally with free, open-source software. No cloud services or paid APIs are used.

## Requirements

* Python **3.12** (3.11+ should work; 3.12 is what the project is tested with)
* Node.js **22.12+** and npm (tested with Node 26 / npm 11; required by Vitest 5)
* macOS, Linux or WSL2. `yara-python` ships wheels for common platforms; otherwise a C compiler is needed.

## Option A – run from source

```bash
git clone https://github.com/ahmedhany-cys/traceforge-digital-forensics.git
cd traceforge-digital-forensics

# Backend
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt

# Optional: regenerate the synthetic dataset (matches the committed copy; the SQLite file
# may differ in header bytes depending on your SQLite version)
.venv/bin/python dataset/generator/generate.py --out dataset/meridian

# Load the demo case (creates demo users with random passwords)
cd backend
../.venv/bin/python -m app.cli load-demo
cat data/demo-credentials.txt           # admin / arivera (investigator) / viewer

# Start the API on http://127.0.0.1:8000
../.venv/bin/python -m uvicorn app.main:get_app --factory --port 8000
```

In a second terminal:

```bash
cd frontend
npm ci
npm run dev        # http://127.0.0.1:5173 (proxies /api to :8000)
```

To serve the production build from the backend instead: `npm run build` (outputs `frontend/dist`), then open http://127.0.0.1:8000.

Set a known demo password instead of random ones with `TRACEFORGE_DEMO_PASSWORD=...` (must satisfy the password policy). Create real accounts with:

```bash
cd backend
../.venv/bin/python -m app.cli create-user --username alice --role investigator --display-name "Alice"
```

## Option B – Docker Compose

```bash
docker compose up --build -d
docker compose exec traceforge python -m app.cli load-demo
docker compose exec traceforge cat /data/demo-credentials.txt
# open http://127.0.0.1:8000
```

The container runs as a non-root user with a read-only root filesystem, all capabilities dropped and `no-new-privileges`; evidence, database and reports persist in the `traceforge-data` volume. The port is bound to `127.0.0.1` – put a TLS reverse proxy in front for remote access and set `TRACEFORGE_COOKIE_SECURE=true`.

> The Docker files were written and reviewed but could not be built in the environment used to prepare this release (Docker was not installed). Option A is the verified path.

## Configuration

Environment variables (prefix `TRACEFORGE_`, see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `TRACEFORGE_ENV` | `development` | `production` disables the OpenAPI docs |
| `TRACEFORGE_DATA_DIR` | `backend/data` | Vault, database, reports, temp files |
| `TRACEFORGE_MAX_UPLOAD_BYTES` | 52428800 | Per-file evidence size limit |
| `TRACEFORGE_SESSION_TTL_MINUTES` | 480 | Absolute session lifetime |
| `TRACEFORGE_SESSION_IDLE_MINUTES` | 60 | Idle timeout |
| `TRACEFORGE_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `TRACEFORGE_STATIC_DIR` | `frontend/dist` | Built SPA served by the backend |

Analyst-adjustable settings (assumed timezone, correlation window, large-transfer threshold, sensitive path keywords, internal domains) are managed by admins in *System Settings* and are audited.

## Running the tests

```bash
cd backend && ../.venv/bin/python -m pytest
cd frontend && npm test
```

See [TESTING.md](TESTING.md).

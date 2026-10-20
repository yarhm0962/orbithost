# OrbitHost — real Discord bot hosting control plane

OrbitHost is a self-hostable web control plane for Python Discord bots. It ships with a real worker integration that builds and runs uploaded source in Docker containers, encrypted environment variables, container-backed status/resource reporting, persistent build logs, and live stdout/stderr streaming.

The front-end uses the existing vanilla HTML/CSS/JavaScript stack. See [`UI-REDESIGN-REPORT.md`](./UI-REDESIGN-REPORT.md) for the responsive UI refresh, accessibility updates, before/after summary, and browser/device test checklist. The refreshed presentation is loaded from `public/ui-polish.css`; no third-party front-end dependency is required.

**There is no demo mode, sample bot, seeded project, simulated deployment, random metric, or synthetic bot log.** The dashboard starts empty and shows actual records created by an account. The server removes old prototype/sample project records from an existing database on startup. A worker must be configured before real deployments can run.

This repository is application source, not a pre-provisioned hosting service. Running bots 24/7 requires a reachable server, Docker, persistent storage, networking, monitoring, and a plan from your infrastructure provider. OrbitHost does not promise a hosting SLA.

## Features

- Email registration and sign-in, HTTP-only sessions, CSRF protection, password hashing, and authentication-attempt throttling.
- Create projects from ZIP archives or public HTTPS Git repositories.
- Select Python 3.10, 3.11, 3.12, or 3.13, install `requirements.txt`, and define build and start commands (including `python bot.py`).
- Set/restart encrypted environment variables. Secret values are never returned to the browser and are redacted from worker logs where recognized. Changes apply to the next deployment.
- Build and start actual containers; start, stop, restart, redeploy, or delete projects.
- Query the actual Docker container state, uptime, CPU and memory usage. Unavailable readings display as unavailable rather than fabricated zeroes.
- Show deployment history and actual Docker stdout/stderr, with server-sent events for live runtime logs and live build-log updates.
- No per-account bot-minute quota, artificial runtime quota, log-retention row cap, or fixed log-tail cap is implemented. Logs are persisted without OrbitHost log truncation. Each project also receives a persistent Docker volume at `/var/lib/orbithost-data`, exposed to bot code through `ORBIT_DATA_DIR`; use it for SQLite files, JSON state, or other files that must survive redeploys. Your server disk and memory are still finite; configure external monitoring, backups, and storage maintenance.

## Requirements

- Node.js 22 or later and npm.
- Docker Engine on the worker host.
- Persistent storage for the control-plane database/uploads and worker source/build logs/secrets.
- A private network between the control plane and worker. Prefer a dedicated worker VM connected by a private VPN or an authenticated HTTPS endpoint.

## 1. Configure secrets

Copy the templates:

```sh
cp .env.example .env
cp .worker.env.example .worker.env
```

Generate independent secrets. Do not reuse encryption keys, commit `.env` files, or send secrets to clients.

```sh
openssl rand -base64 48  # SESSION_SECRET
openssl rand -hex 32     # ENV_ENCRYPTION_KEY (64 hex characters)
openssl rand -hex 32     # WORKER_TOKEN
openssl rand -hex 32     # WORKER_ENCRYPTION_KEY (64 hex characters; separate key)
```

Put the same generated `WORKER_TOKEN` value in both `.env` and `.worker.env`. Set unique generated values for the other three fields. Replace every `replace-with-...` placeholder.

The sample control-plane template is configured for Compose (`WORKER_URL=http://worker:8787`). For a separately hosted worker, set `WORKER_URL` to its private HTTPS or VPN-reachable URL. Never expose port 8787 publicly without a private network/firewall and TLS strategy.

## 2. Run the app with the worker

For a single-host smoke test or trusted development machine:

```sh
docker compose --profile worker up --build -d
docker compose ps
docker compose logs -f control-plane
docker compose logs -f worker
```

Open `http://localhost:8080`, register your own account, create a project, set environment variables (for example `DISCORD_TOKEN`), and deploy it. The account begins with no projects. For production, terminate TLS at a trusted reverse proxy and use the secure cookie configuration in the provided production environment template.

**Security note:** the worker mounts `/var/run/docker.sock`, which effectively grants host-level control. The combined Compose setup is useful for a controlled test, but it is not an isolation boundary suitable for a shared public hosting service. In production, run the worker on a dedicated VM with minimal credentials, restricted network access, host monitoring, and only private authenticated control-plane connectivity.

## 3. Separate production worker

1. Provision a dedicated Linux VM with Docker Engine, Node.js 22+, and the repository's `worker/` service.
2. Generate the worker token and separate worker encryption key; configure `.worker.env` on that VM. Keep both files readable only by the worker administrator.
3. Start the worker with `npm install --omit=dev && npm run worker` or use `worker/Dockerfile` with the worker's private environment. Store `WORKER_DATA_DIR` on persistent disk.
4. Restrict inbound access to the worker API to the control-plane network. Use a VPN/private address or TLS endpoint plus firewall rules. Do not publish the worker port to the public internet.
5. Configure the control plane's `WORKER_URL` and matching `WORKER_TOKEN`; restart the control plane and verify the Hosting integration screen reports the worker connected.
6. Configure the deployment ingress/reverse proxy for HTTPS and long-running deployment responses. `WORKER_TIMEOUT_MS` must allow for the worker's build time, and any proxy/request timeout must be compatible. The default build timeout is one hour and is configurable.

Do not put user-provided source, tokens, or credentials into logs manually. A dedicated worker VM is strongly recommended because bot code is untrusted code even when executed as a non-root container user.

## Upload and archive safety settings

The app has no plan-based usage quotas, but upload and archive extraction need configurable safety boundaries to mitigate disk exhaustion and ZIP bombs. Set matching values in `.env` and `.worker.env`:

| Variable | Default | Meaning |
|---|---:|---|
| `MAX_UPLOAD_MB` / `WORKER_MAX_UPLOAD_MB` | `1024` | Compressed ZIP upload size |
| `MAX_ZIP_ENTRIES` / `WORKER_MAX_ZIP_ENTRIES` | `100000` | Maximum archive entries |
| `MAX_ZIP_EXPANDED_MB` / `WORKER_MAX_ZIP_EXPANDED_MB` | `4096` | Maximum total expanded archive size |
| `MAX_ZIP_ENTRY_MB` / `WORKER_MAX_ZIP_ENTRY_MB` | `2048` | Maximum uncompressed size of a single entry |
| `WORKER_BUILD_TIMEOUT_MS` | `3600000` | Build timeout; milliseconds |
| `WORKER_GIT_TIMEOUT_MS` | `900000` | Git clone timeout; milliseconds |
| `WORKER_LOG_HISTORY_TIMEOUT_MS` | `3600000` | Runtime log history retrieval timeout; milliseconds |
| `WORKER_TIMEOUT_MS` | `3600000` | Control plane timeout for worker API requests; milliseconds |

These boundaries are operator-configurable, not subscription quotas. Keep archive safety limits enabled and monitor free disk space. Unlimited retention does not mean the host has unlimited storage.

## Optional per-container resource ceilings

No fixed CPU, memory, or process-count ceilings are applied by OrbitHost's worker when these values are blank. The worker supports operator-defined Docker cgroup ceilings:

- `WORKER_CONTAINER_MEMORY`, e.g. `1g` or `2048m`
- `WORKER_CONTAINER_CPUS`, e.g. `1` or `2.5`
- `WORKER_CONTAINER_PIDS`, e.g. `512`

If you run multiple users' untrusted bots on a shared worker, configure resource boundaries and system-level monitoring. Leaving resource variables blank removes per-container cgroup ceilings; it does **not** remove the physical limits of the host or provider. A single noisy bot can starve other workloads if the worker is not sized and isolated appropriately.

## Real-time logs

The Logs tab calls the worker for actual persisted build output and Docker runtime logs. Runtime history is read from `docker logs --timestamps --tail all`; live runtime output follows the running container's Docker stdout/stderr stream. Before a redeploy replaces a container, the worker stops it gracefully and archives its full historical output after redaction, including shutdown messages. Build output is append-only across deployments. `PYTHONUNBUFFERED=1` is set so ordinary Python output, including `print()` from `bot.py`, appears without Python's normal stdout buffering. Build-log updates are read from the worker's persisted build log. Secret values are redacted where recognized.

There is no built-in line count or byte-retention cap for log files/history; history is removed only when the project is explicitly deleted. That means disk usage grows over time. Monitor and provision storage, and use an external log archiver/retention policy if needed; external policies should be explicit rather than silently dropping lines in the app. If a bot does not write to stdout or stderr, OrbitHost cannot display messages that the process never emits.

## Bot setup

1. Put your bot source in a ZIP archive, or connect a public HTTPS Git repository.
2. Include `requirements.txt` if your bot uses third-party dependencies.
3. Select the Python version, set an optional build command, and choose a start command such as `python bot.py`.
4. Add `DISCORD_TOKEN` through the Environment tab; do not hard-code the token in source code.
5. Deploy. Watch the actual build log; when finished, open Runtime logs to see the process output and Discord library errors.

Private Git repositories are not enabled by this starter; do not put credentials or tokens into repository URLs. Use a dedicated deployment-key/provider integration before adding private repositories.

## Useful environment variables

See `.env.example` and `.worker.env.example` for the full list. Core control-plane variables:

- `SESSION_SECRET`: session signing secret, at least 32 high-entropy characters.
- `ENV_ENCRYPTION_KEY`: 32-byte key encoded as 64 hex characters.
- `DATABASE_PATH` and `UPLOAD_DIR`: persistent database and ZIP source locations.
- `WORKER_URL` and `WORKER_TOKEN`: worker endpoint and shared API credential.
- `MAX_UPLOAD_MB`, `MAX_ZIP_ENTRIES`, `MAX_ZIP_EXPANDED_MB`, `MAX_ZIP_ENTRY_MB`: operator-controlled upload safety settings.
- `TRUST_PROXY=1`: set only when the app is behind a trusted proxy that overwrites forwarded headers.

Core worker variables:

- `WORKER_TOKEN`: same shared token as control plane.
- `WORKER_ENCRYPTION_KEY`: separate 32-byte encryption key encoded as 64 hex characters.
- `WORKER_DATA_DIR`: persistent worker data (project source, logs, and encrypted runtime secrets).
- `WORKER_CONTAINER_MEMORY`, `WORKER_CONTAINER_CPUS`, `WORKER_CONTAINER_PIDS`: optional per-container ceilings.
- `WORKER_BUILD_TIMEOUT_MS`, `WORKER_GIT_TIMEOUT_MS`, `WORKER_LOG_HISTORY_TIMEOUT_MS`: operator-set timeouts.

## Checks

```sh
npm install
npm run check
npm test
```

`npm run check` runs Node syntax checks for the control plane, worker, frontend JavaScript, and tests. `npm test` runs the security-focused unit tests. A successful unit test run does not prove your Docker daemon, firewall, TLS proxy, persistent volumes, or Discord bot credentials are configured correctly. Verify a complete deployment on the target host before accepting workloads.

## API overview

All project routes require an authenticated session and CSRF token for state-changing requests.

- `GET /api/config` — configuration and worker readiness.
- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout` — account/session operations.
- `GET /api/dashboard`, `GET /api/projects`, `POST /api/projects` — workspace and project creation.
- `GET/PATCH/DELETE /api/projects/:id` — project details, settings, and deletion.
- `PUT/GET/DELETE /api/projects/:id/env` — masked environment variable management.
- `POST /api/projects/:id/deploy`, `POST /api/projects/:id/action` — deployment and lifecycle actions.
- `GET /api/projects/:id/deployments` — full deployment history.
- `GET /api/projects/:id/logs` — complete log history for a selected stream.
- `GET /api/projects/:id/logs/stream` — server-sent event stream for live build/runtime logs.
- `GET /api/projects/:id/metrics` — measurements from the worker's Docker container.

## Known deployment considerations

- The hosting provider and infrastructure decide actual uptime, outbound access, persistent storage, and service restart behavior.
- Builds use generated Dockerfiles and ignore uploaded Dockerfiles, keeping a consistent runtime baseline. Some Python packages may need system build tools; extend the worker's generated build image deliberately if you need them.
- Runtime containers have no published host ports by default, which is appropriate for bots connecting outward to Discord. Web dashboards hosted by a bot would need an explicitly designed, secured ingress feature. The app working directory is writable inside the container, but container-layer writes can be lost on redeploy; use `ORBIT_DATA_DIR` for persistent bot data.
- Keep worker traffic private and encrypt it in transit. The worker controls Docker and should be considered host-privileged.
- OrbitHost does not provision a server or deploy itself to a hosting vendor. Configure and verify the infrastructure described above before using it as a real service.

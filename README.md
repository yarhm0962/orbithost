# OrbitHost — Discord bot hosting control plane

OrbitHost is an original, responsive control panel for organizing Discord bot projects. It includes account registration/sign-in, ZIP and public Git source flows, Python runtime settings, encrypted environment variables, deployment history, project actions, resource metrics, and searchable logs.

**Default hosting mode is `demo`.** In demo mode the UI and API are functional, but deployment/status/resource data is simulated. Uploaded source archives are stored, but no user code is executed and no Discord connection is started. To run real bot processes, configure the separate worker described below. Actual uptime depends on your hosting plan, worker availability, networking, storage, and monitoring; this project does not itself provide a 24/7 hosting SLA.

## Features

- Responsive dark dashboard with mobile navigation, overview metrics, searchable projects, activity feed, and project detail tabs.
- Email/password accounts, bcrypt password hashing, persistent HTTP-only sessions, CSRF protection, Helmet headers, and request rate limits.
- ZIP upload limits and archive path, symlink, entry-count, and expanded-size checks.
- Public HTTPS Git repository connection. The starter intentionally does not accept credentials embedded in a repository URL and does not yet implement a private-repository token/deploy-key integration.
- Python 3.10, 3.11, 3.12, and 3.13 selection; automatic `requirements.txt` installation; optional build command; configurable start command.
- Environment variables encrypted at rest with AES-256-GCM. Read APIs expose variable names and masked status only, not secret values. Logs redact configured secret values and common credential assignments.
- Optional worker uses generated Dockerfiles (not uploaded Dockerfiles) and non-root bot containers with a read-only root filesystem, no published ports, a dedicated per-project bridge network, dropped capabilities, `no-new-privileges`, memory/CPU/process limits, and a temporary filesystem.
- Sample data and clearly labeled simulation mode when real hosting is not configured.

## Requirements

- Node.js 22 or newer and npm. Node 24 LTS is the preferred deployment runtime.
- For real hosting: a Linux VM running Docker Engine and Git, plus a private network or TLS-protected route between the control plane and worker.
- For production deployment: HTTPS, persistent storage for SQLite and uploaded archives, backups, log/disk monitoring, and firewall rules.

## Run locally (demo mode)

1. Copy the configuration templates:

   ```bash
   cp .env.example .env
   cp .worker.env.example .worker.env
   chmod 600 .env .worker.env
   ```

2. Generate keys:

   ```bash
   openssl rand -base64 48   # SESSION_SECRET
   openssl rand -hex 32      # ENV_ENCRYPTION_KEY
   openssl rand -hex 32      # WORKER_TOKEN
   openssl rand -hex 32      # WORKER_ENCRYPTION_KEY (separate key, in .worker.env)
   ```

   Put the generated session and control-plane encryption keys in `.env`. Set `WORKER_TOKEN` to the **same** random value in `.env` and `.worker.env`. Set `WORKER_ENCRYPTION_KEY` to a **different** random value in `.worker.env`. Do not commit either file. The included placeholder values must be replaced before storing any real secrets. `.env` and `.worker.env` are separate so the control plane does not receive the worker-only encryption key.

3. Keep `HOSTING_MODE=demo` in `.env`, install dependencies, and start the server:

   ```bash
   npm install
   npm run check
   npm test
   npm start
   ```

4. Open `http://localhost:8080`, create an account, and use the dashboard. The first account in demo mode gets two clearly labeled sample projects. Real source uploads can be added, but deploying in demo mode only creates simulated events and does not execute the uploaded code.

## Run the control plane with Docker Compose

After copying and editing `.env` and `.worker.env` as above:

```bash
docker compose up --build -d
```

The control plane is published on port `8080`. The named `control-data` volume stores the database and uploads. Back up that volume; the database and uploaded source archives are important state.

For a **local development/staging-only** worker in the same Compose project, set `HOSTING_MODE=worker` and `WORKER_URL=http://worker:8787` in `.env`, then run:

```bash
docker compose --profile worker up --build -d
```

The worker service does not publish its port to the host. It is reachable only on the Compose network by default. Mounting `/var/run/docker.sock` gives the worker host-level control of Docker, so this convenience topology is **not an isolation boundary**. For production, run the worker on a dedicated VM, keep its port private, and allow only authenticated control-plane traffic. Do not expose the worker directly to the public internet.

## Connecting a separate container worker

1. Provision a dedicated Linux worker VM with Docker Engine, Git, outbound DNS/HTTPS access needed for Git and Python package installs, and a restrictive inbound firewall. Keep unrelated services and credentials off this VM. Apply outbound firewall rules to limit access to cloud metadata, private networks, and internal services; URL validation alone cannot prevent DNS rebinding or all network-based SSRF risks.
2. Deploy `worker/server.js` on the worker VM with the worker dependencies installed. Set the variables from `.worker.env`, including a unique `WORKER_TOKEN` (shared with the control plane) and a unique `WORKER_ENCRYPTION_KEY`. Persist `WORKER_DATA_DIR` on a worker-only disk with restrictive permissions.
3. Expose the worker only over an internal network, VPN, or TLS-protected private endpoint. The example Docker Compose worker has no host-published port by design. Configure network routing/firewall rules rather than making the service public.
4. On the control plane, set `HOSTING_MODE=worker`, `WORKER_URL` to the private worker URL (including HTTPS when crossing an untrusted network), and the matching `WORKER_TOKEN`. Keep `ENV_ENCRYPTION_KEY` different from the worker key. Restart the control plane after changing environment variables.
5. Create a new ZIP- or Git-backed project, add its environment secrets, then deploy. Worker deployments use the generated Python image, execute `requirements.txt` installation and custom build commands during image build, and run the configured start command in a constrained container.
6. Verify status and logs in the UI, then set monitoring and alerting for worker availability, disk usage, build failures, and stopped/restarting containers.

The worker needs access to Docker Engine. Docker daemon access is effectively host-privileged; a container's runtime restrictions do not protect the host from a compromised worker service or Docker daemon. Run it on a dedicated, patched VM with minimal credentials and an explicit recovery process. For higher assurance, use a managed build system or an isolated per-tenant worker architecture rather than sharing one Docker daemon among mutually untrusted users.

## Environment variables

### Control plane (`.env`)

| Variable | Purpose |
|---|---|
| `NODE_ENV` | Use `production` behind HTTPS in production. |
| `PORT` | HTTP listen port; defaults to `8080`. |
| `APP_BASE_URL` | Canonical URL for deployment/proxy configuration. |
| `SESSION_SECRET` | High-entropy session signing secret, at least 32 characters in production. |
| `ENV_ENCRYPTION_KEY` | Exactly 64 hex characters (32 random bytes) used for AES-256-GCM encryption of saved environment values. Back it up separately; losing it makes existing secret values undecryptable. |
| `DATABASE_PATH` | SQLite path; defaults to `./.data/orbithost.sqlite`. Must be on persistent storage in production. |
| `UPLOAD_DIR` | Directory for validated source archives. Persist and back it up or configure object storage. |
| `MAX_UPLOAD_MB` | ZIP upload cap (1–100 MB; default `25`). |
| `HOSTING_MODE` | `demo` by default; use `worker` only after the worker is reachable. |
| `WORKER_URL` | Private worker base URL, e.g. `http://worker:8787` on the local Compose network. |
| `WORKER_TOKEN` | Long random bearer credential shared with the worker. |
| `WORKER_TIMEOUT_MS` | Control-plane timeout for worker deployments (default `180000`). |
| `TRUST_PROXY` | Set to `1` only behind a trusted reverse proxy that correctly sanitizes forwarded headers. |

### Worker (`.worker.env`)

| Variable | Purpose |
|---|---|
| `WORKER_PORT` | Worker listen port, default `8787`. |
| `WORKER_TOKEN` | Must match the control plane token. Use a long random value. |
| `WORKER_ENCRYPTION_KEY` | Worker-only 32-byte hex key for encrypted redaction metadata; do not reuse `ENV_ENCRYPTION_KEY`. |
| `WORKER_DATA_DIR` | Persistent worker build logs, source workspaces, and encrypted redaction metadata. |
| `WORKER_MAX_UPLOAD_MB` | Worker upload limit, default `25`. |

## Supported API surface

All authenticated write requests must include the CSRF token returned by `GET /api/auth/csrf` in `X-CSRF-Token`. The included browser app handles this automatically.

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` | Account/session management |
| `GET /api/dashboard`, `GET /api/projects` | Workspace overview |
| `POST /api/projects` | Create project from multipart ZIP (`bundle`) or a public Git URL |
| `GET/PATCH/DELETE /api/projects/:id` | Read/update/delete an owned project |
| `POST /api/projects/:id/deploy` | Build and deploy (simulated in demo mode) |
| `POST /api/projects/:id/action` | `start`, `stop`, `restart`, or `redeploy` |
| `GET /api/projects/:id/deployments` | Deployment history |
| `GET/PUT/DELETE /api/projects/:id/env` | Read masked environment variable metadata, save/rotate a secret, or remove a secret |
| `GET /api/projects/:id/logs?stream=runtime&search=...` | Search build/runtime logs; values are redacted before response |
| `GET /api/projects/:id/metrics` | Current worker metrics or labeled simulated values |

## Security and operational notes

- **Secrets:** The frontend never receives stored values. Do not put tokens into Git URLs, project names, or commands. In worker mode Docker itself stores container environment in daemon metadata, which privileged Docker/host administrators can inspect; protect the worker host accordingly. Container/application logs may still emit unexpected data, so avoid printing secrets in bot code.
- **Source:** User-provided Python packages and build commands execute code during builds. The worker deliberately ignores uploaded Dockerfiles, avoids host bind mounts, runs bot containers as UID 10001, drops Linux capabilities, uses no-new-privileges, a read-only root filesystem, and default CPU/RAM/PID constraints. The builder/worker is still privileged and must be isolated at the VM/network level.
- **Git:** Public HTTPS URLs only; credentials in URLs, IP literal hosts, local hostname patterns, and common private schemes are rejected. Restrictive network egress is still required to defend against DNS/network-based SSRF.
- **Uploads:** ZIP uploads are capped, validated for common archive traversal paths and symbolic links, and checked for excessive entries/expanded size. Archive validation is not a guarantee that source code is safe to execute.
- **Uptime:** This project does not promise 24/7 uptime. Restart policy, VM availability, disk persistence, provider quotas, networking, and monitoring all affect whether a bot remains online.
- **Production scaling:** SQLite is intended for a single-node starter. Use a managed database/session backend, object storage for source bundles, tenant quotas, audit retention, alerting, and a proper worker queue before running a large or untrusted multi-tenant service.

## Verification

`npm run check` validates JavaScript syntax. `npm test` runs focused tests for authenticated secret encryption, ciphertext tamper detection, environment-variable allowlisting, Git URL validation, and basic log redaction. Full runtime/integration tests require installing npm dependencies and a reachable npm registry. The development environment used to assemble this source package could not resolve `registry.npmjs.org`, so dependency installation and an end-to-end browser session were not verified here.

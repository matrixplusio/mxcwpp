# Installation and Deployment

**English | [中文](deployment.md)**

## Prerequisites

### Server

- Linux server (CentOS 7+ / Rocky Linux 8+ / Ubuntu 20.04+)
- Docker Engine >= 24, Docker Compose v2
- Clock synchronization (NTP); all nodes must keep their clocks consistent

### Agent Target Hosts

- A supported operating system (see the platform support list below)
- Linux kernel >= 4.18 (required by eBPF / Tetragon)
- Network reachability to the AgentCenter gRPC port (default 6751)

### Platform Support

| Distribution | Versions |
|--------|------|
| Rocky Linux | 9, 10 |
| Oracle Linux | 7, 8, 9 |
| CentOS | 7, 8, 9 |
| Debian | 10, 11, 12 |
| Ubuntu | 20.04, 22.04 |

Runtime types: physical machine / VM, Docker container host, Kubernetes node

---

## Deployment Modes Overview

The project supports four deployment modes, each aimed at a different stage:

| Mode | Configuration file | Characteristics | Use case |
|------|---------|------|---------|
| Development | `docker-compose.dev.yml` | Source hot reload (Air), single Kafka node, includes all 6 microservices including engine/llmproxy/vulnsync | Day-to-day development and debugging |
| **Official single-host deployment** | `docker-compose.yml` (via `deploy.sh`) | **The only official single-host topology**: all server microservices + infrastructure + gotenberg | Single-host production, POC, offline delivery |
| Load testing | `docker-compose.pret.yml` | Prebuilt images, 3 Kafka nodes, supports `--scale` for multiple replicas | Performance load testing, pre-release validation |
| Production | `cluster.example.yaml` + `mxctl deploy` | Multi-node role separation, full HA | Formal production deployment |

---

## Development Environment

The development environment uses `docker-compose.dev.yml` + Air hot reload, and does not build Agent / plugin artifacts.

```bash
make dev-docker-up       # Start the development environment (foreground, with logs)
make dev-docker-up-d     # Start the development environment (background)
make dev-docker-logs     # View logs
make dev-docker-down     # Stop services
make dev-docker-restart  # Restart the backend (manager)
make web-dev             # Start the frontend locally (port 3000, fast hot reload)
```

> The web frontend does not run in a container: on macOS, bind mounts go through virtiofs and hot reload is slow. The backend runs in Docker, the frontend runs locally via `make web-dev`, proxying /api to host:8080.

| Service | Address |
|------|------|
| Manager API | http://localhost:8080 |
| UI (local make web-dev) | http://localhost:3000 |
| AgentCenter gRPC | localhost:6751 |
| AgentCenter HTTP | localhost:6752 -> 8080 |
| Engine HTTP | localhost:8090 |
| LLMProxy HTTP | localhost:8091 |
| VulnSync HTTP | localhost:8092 |
| MySQL | localhost:13306 -> 3306 |
| Redis | localhost:16379 -> 6379 |
| Kafka | localhost:9092 |
| ClickHouse HTTP | localhost:8123 |
| ClickHouse TCP | localhost:9000 |
| Prometheus | localhost:9090 |

> Ports are examples; the actual mappings in `deploy/docker-compose.dev.yml` are authoritative.

---

## Load Testing Environment

The load testing environment uses `docker-compose.pret.yml` with prebuilt images, configures 3 Kafka nodes, and supports starting multiple replicas via the `--scale` parameter.

```bash
make pret-docker-up      # Start the load testing environment (foreground, with logs)
make pret-docker-up-d    # Start the load testing environment (background)
make pret-docker-down    # Stop the load testing environment
```

---

## The Only Official Single-Host Topology

`deploy/docker-compose.yml` is the only official single-host deployment topology; both `deploy.sh` and the offline release bundle use it.

Previously there were three mutually different topologies: `docker-compose.yml` (missing engine / vulnsync / llmproxy /
gotenberg), `docker-compose.v2.yml`, and a third one generated inline by the packaging script (**only
mysql / agentcenter / manager / ui**, with no Kafka, ClickHouse, Redis, or Consumer).
Which one a customer received depended on which path they took, and the one-click deployment happened to use the one missing the detection engine:
it installed, the UI opened, and none of the core capabilities were there.

Now there is only one, and packaging only rewrites image prefixes (removes the `build` sections, adds a registry prefix to `mxcwpp-*` images,
and leaves third-party images untouched).

Included services:

| Category | Services |
|------|------|
| Server microservices | manager, agentcenter, consumer, engine, vulnsync, llmproxy |
| Frontend | ui |
| Support | gotenberg (report PDF rendering) |
| Infrastructure | mysql, redis, kafka ×3, clickhouse |

**Gate**: `internal/deploy/topology_test.go` binds `cmd/server/*` to this topology:
adding a server microservice without adding it to the deployment fails the test; changing the packaging script back to inline generation also fails it.
A missing service is not "one container short"; it means that capability has never run in the customer environment.


## Production Deployment

### Choosing a Deployment Form

| Form | Nodes | Agent scale | Use case |
|------|--------|-----------|---------|
| Single-host All-in-One | 1 | <= 50 | Evaluation and trials, small internal networks |
| Standard production | 3 | 50 - 500 | Small and medium enterprises |
| High-spec production | 5+ | 500+ | Large-scale, multi-cluster |

### Single-Host All-in-One

All services run on the same machine, orchestrated with `deploy/docker-compose.yml`.

**Hardware requirements**: 8-core CPU / 32 GB RAM / 100 GB SSD system disk / 200 GB data disk (recommended: 16 cores / 64 GB / 500 GB SSD)

```bash
cd deploy/
cp .env.example .env
vim .env
# Edit: SERVER_IP / JWT_SECRET / database passwords / *_REPLICAS=2

docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

Verify:

```bash
docker compose ps
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Visit `http://<SERVER_IP>` to open the management UI; the default account is `admin / admin123`.

### Standard Production (3 Nodes) -- Cluster Deployment

The control plane, storage layer, and message queue are deployed separately.

```
+--------------------+    +--------------------+    +--------------------+
|  control-1         |    |  storage-1         |    |  kafka-1           |
|  roles: [control]  |    |  roles: [storage]  |    |  roles: [kafka]    |
|                    |    |                    |    |                    |
|  Nginx (80/443)    |    |  MySQL 8.0         |    |  Kafka Broker x3   |
|  Manager           |    |  Redis 7           |    |  (KRaft mode)      |
|  AgentCenter       |    |  ClickHouse 24     |    |                    |
|  Consumer          |    |  Prometheus        |    |                    |
|  Engine            |    |                    |    |                    |
|  LLMProxy          |    |                    |    |                    |
|  VulnSync          |    |                    |    |                    |
|  UI (SPA)          |    |                    |    |                    |
+--------------------+    +--------------------+    +--------------------+
```

**Hardware requirements**:

| Node | CPU | RAM | System disk | Data disk |
|------|-----|------|--------|--------|
| control-1 control plane | 8 cores | 16 GB minimum | 100 GB SSD | For logs; size by retention days |
| storage-1 storage layer | 8 cores | 32 GB minimum | 100 GB SSD | SSD; size by Agent count and retention period (see "Storage Capacity Estimation") |
| kafka-1 message queue | 4 cores | 16 GB minimum | 50 GB SSD | SSD; size by peak throughput × retention time |

#### mxctl Cluster Deployment Tool

`mxctl` is the core CLI tool for cluster deployment, located at `cmd/tools/mxctl/`. It handles configuration validation, preflight checks, rendering deployment files, and remote deployment.

**Build**:

```bash
go build -o ./bin/mxctl ./cmd/tools/mxctl
```

**Subcommands**:

| Subcommand | Description |
|--------|------|
| `check` (alias `validate`) | Validate the cluster.yaml configuration file (syntax, field completeness, node role constraints) |
| `preflight` | Pre-deployment checks (local environment + SSH connectivity + remote OS / sudo / directory writability) |
| `render` | Render each node's deployment files from cluster.yaml (Compose, server.yaml, certificates, scripts) |
| `deploy` | Full deployment flow (render + SCP upload + start in role order + health check) |

**Common parameters**:

| Parameter | Default | Description |
|------|--------|------|
| `-f` | `deploy/prod/cluster.example.yaml` | Path to the cluster.yaml configuration file |
| `-o` | `deploy/prod/out` | Render output directory (render / deploy) |
| `--skip-install` | `false` | Skip installing remote dependencies (deploy) |
| `--skip-healthcheck` | `false` | Skip the post-deployment health check (deploy) |

**Typical workflow**:

```bash
# 1. Validate the configuration
./bin/mxctl check -f deploy/prod/my-cluster.yaml

# 2. Preflight check (SSH connectivity, remote OS detection, sudo privileges)
./bin/mxctl preflight -f deploy/prod/my-cluster.yaml

# 3. Render only (review the output before deciding whether to deploy)
./bin/mxctl render -f deploy/prod/my-cluster.yaml -o deploy/prod/out

# 4. Full deployment
./bin/mxctl deploy -f deploy/prod/my-cluster.yaml
```

**check validation items**:
- `metadata.name`, `release.version`, and `app.jwt_secret` must not be empty
- `network.ui.host` and `network.grpc.host` must not be empty
- `infrastructure.mysql.root_password` and `infrastructure.mysql.password` must not be empty
- At least one control node, exactly one storage node, exactly one kafka node
- Each node must configure `name`, `host`, and `roles`
- `roles` can only be `control` / `storage` / `kafka`
- Node name / host must not be duplicated
- Kafka broker_ports must configure 3 ports
- `control_plane.manager_replicas` and `agentcenter_replicas` must not be less than the number of control nodes
- When Prometheus is enabled, there must be a storage node

**preflight check items**:
- Local environment: `ssh` and `scp` commands are available
- Remote nodes: SSH is reachable, OS is a supported distribution (Ubuntu / Debian / Rocky / CentOS / RHEL / Oracle / AlmaLinux)
- Non-root users: passwordless sudo is available
- The install directory and data directory can be created

**deploy execution order (5 steps)**:

```
[1/5] Prepare remote nodes  -- create release directory, SCP upload bundle, switch the current symlink, install dependencies, Docker login
[2/5] Start Kafka           -- docker compose up kafka nodes
[3/5] Start Storage         -- docker compose up storage nodes (MySQL / Redis / ClickHouse)
[4/5] Start Control         -- docker compose up control nodes (Manager / AgentCenter / Consumer / Engine / LLMProxy / VulnSync / UI)
[5/5] Health check          -- docker compose ps + curl /health
```

Each deployment produces its own release directory `{install_dir}/releases/{version}-{timestamp}/`, and versions are switched via the `{install_dir}/current` symlink, which supports fast rollback.

#### Cluster Configuration Toolchain

Cluster deployment uses the configuration toolchain under `deploy/prod/`:

- `cluster.example.yaml`: defines the cluster topology (nodes, roles, versions, infrastructure configuration)
- Go package `internal/deploy/cluster/`: configuration parsing, validation, template rendering, certificate generation, remote deployment
- Template directory `deploy/prod/templates/`:
  - `docker-compose.control.yml.tmpl` -- control plane node template
  - `docker-compose.storage.yml.tmpl` -- storage layer node template
  - `docker-compose.kafka.yml.tmpl` -- Kafka node template
- Rendered output goes to `deploy/prod/out/{cluster-name}/nodes/{node-name}/`

Rendered output structure:

```
deploy/prod/out/{cluster-name}/
├── resolved-cluster.yaml              # Full configuration after applying defaults (for troubleshooting)
└── nodes/
    ├── control-1/
    │   ├── compose/
    │   │   └── docker-compose.control.yml
    │   ├── config/
    │   │   ├── server.yaml            # Manager server configuration
    │   │   ├── server-ac.yaml         # AgentCenter server configuration
    │   │   └── nginx.conf             # Nginx reverse proxy configuration
    │   ├── certs/                     # mTLS certificates
    │   └── scripts/                   # Deployment helper scripts
    ├── storage-1/
    │   ├── compose/
    │   │   └── docker-compose.storage.yml
    │   └── config/
    │       ├── mysql.cnf              # MySQL configuration
    │       ├── clickhouse.xml         # ClickHouse configuration
    │       └── prometheus.yml         # Prometheus configuration
    └── kafka-1/
        └── compose/
            └── docker-compose.kafka.yml
```

#### Cluster Configuration Example

Edit `deploy/prod/cluster.example.yaml` (or copy it to a custom file) to define the cluster topology:

```yaml
api_version: mxcwpp.io/v1alpha1
kind: ClusterConfig

metadata:
  name: example-cluster
  environment: prod

release:
  version: v1.0.0
  install_dir: /opt/mxcwpp
  data_root: /data/mxcwpp
  timezone: Asia/Shanghai         # Default Asia/Shanghai

registry:                          # Private image registry (optional)
  domain: registry.example.com
  namespace: mxcwpp
  username: deploy
  password: change-registry-password

network:
  ui:
    scheme: https
    host: security.example.com     # Management UI entry domain or IP
    port: 443
  grpc:
    host: 10.0.0.10                # AgentCenter gRPC entry (L4 LB or control plane IP)
    port: 6751
  additional_sans:                 # Additional SANs (included in the certificate)
    ips: ["10.0.0.100"]
    dns: ["security-internal.example.com"]

app:
  jwt_secret: change-jwt-secret
  log_level: info
  log_format: json
  prometheus_enabled: true

infrastructure:
  mysql:
    root_password: change-root-password
    database: mxcwpp
    user: mxcwpp_user
    password: change-mysql-password
    port: 13306
  redis:
    password: change-redis-password
    port: 16379
  clickhouse:
    database: mxcwpp
    user: default
    password: change-clickhouse-password
    http_port: 8123
    tcp_port: 9000
  kafka:
    enabled: true
    broker_ports: [9092, 9094, 9095]

control_plane:                     # Control plane replica counts (default = number of control nodes)
  manager_replicas: 2
  agentcenter_replicas: 2
  consumer_replicas: 2

nodes:
  - name: control-1
    host: 10.0.0.10
    ssh_user: root                 # Default root
    ssh_port: 22                   # Default 22
    ssh_key_path: ~/.ssh/id_rsa    # Relative paths supported (relative to the directory containing cluster.yaml)
    roles: [control]
  - name: storage-1
    host: 10.0.0.11
    roles: [storage]
  - name: kafka-1
    host: 10.0.0.12
    roles: [kafka]
```

> Production clusters use `network_mode: host` (not bridge networking); nodes communicate directly via host IPs.

**Deployment order**: kafka-1 (Kafka) -> storage-1 (storage) -> control-1 (control plane)

**Multi-control-plane replica allocation**: when multiple control nodes are configured, `control_plane.*_replicas` is automatically distributed evenly across the control plane nodes. For example, 2 control nodes + `manager_replicas: 3` = control-1 runs 2 Managers and control-2 runs 1 Manager.

### High-Spec Production (5+ Nodes)

Each control plane component is deployed independently; the storage layer can optionally use primary/replica.

```
Node 1: Manager x2 + Nginx / UI
Node 2: AgentCenter x2 + HAProxy(:6751)
Node 3: Consumer x2
Node 4: MySQL + Redis + ClickHouse + Prometheus
Node 5: Kafka Broker x3 (KRaft)
Node 6: MySQL replica + Redis Sentinel (optional)
```

Nodes 1-3 can scale out further horizontally, using either Docker Compose `--scale` or systemd deployment.

---

## deploy.sh Deployment Script

`deploy/deploy.sh` is the deployment management script for production environments and supports the following commands:

| Command | Description |
|------|------|
| `./deploy.sh` | Interactive full deployment (first time) |
| `./deploy.sh start` | Start services |
| `./deploy.sh stop` | Stop services |
| `./deploy.sh restart` | Restart services (a service name can be specified: `restart agentcenter`) |
| `./deploy.sh status` | View service status |
| `./deploy.sh logs` | View logs (a service name can be specified: `logs agentcenter`) |
| `./deploy.sh backup` | Back up the database (gzip-compressed, automatically cleans up backups older than 30 days) |
| `./deploy.sh upgrade` | Upgrade services (back up -> update version number -> update configuration -> build and restart, 4 steps in total) |
| `./deploy.sh clean-logs` | Clean up old logs (keeps 7 days by default) |
| `./deploy.sh build` | Build images |
| `./deploy.sh help` | Show help (also supports `--help` / `-h`) |

### First Deployment Flow (7 Steps)

Run `./deploy.sh` (no arguments) to start the interactive first deployment. The flow is:

1. **Environment detection** -- detect the operating system and Docker version
2. **Port check** -- check whether required ports are already in use
3. **Interactive configuration** -- initialize `.env` environment variables (SERVER_IP, passwords, etc.)
4. **Initialize directories** -- create data, log, certificate, and other directories
5. **Generate certificates** -- generate self-signed mTLS certificates
6. **Generate server.yaml** -- render the server configuration from `.env`
7. **Start services** -- build images and start all containers

---

## HA Replica Configuration

The replica counts of control plane components are controlled via the `.env` file:

```bash
# deploy/.env
MANAGER_REPLICAS=1       # Manager replica count (2+ recommended for production)
AGENTCENTER_REPLICAS=1   # AgentCenter replica count (2+ recommended for production)
CONSUMER_REPLICAS=1      # Consumer replica count (2+ recommended for production)
```

The `start` / `upgrade` commands of `deploy.sh` read these values and automatically generate `--scale` parameters, keeping replica counts the same before and after an upgrade.

When starting manually, replica counts must be specified explicitly:

```bash
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

---

## Certificate Management

```bash
# Generate self-signed mTLS certificates
./scripts/generate-certs.sh
# Or use the Makefile
make certs
```

Certificate directory structure:

```
deploy/certs/
  ca.crt / ca.key            # CA certificate (ca.key lets AC issue per-host certificates online)
  server.crt / server.key    # Used by AgentCenter (must include serverAuth + a SAN covering SERVER_IP)
  agent.crt / agent.key      # Used by the Agent
  client.crt / client.key    # Copy of agent.crt/key, for compatibility with the old name
  ssl/server.crt,server.key  # Only this subdirectory is mounted into nginx (443)
  enroll_token.secret        # Enroll token generated by cluster rendering, 0600, not committed
```

> The nginx container mounts only `certs/ssl`. The full `certs` directory contains the CA private key, the client private key, and the enroll token;
> mounting it into a container that faces the public internet is the same as handing over the entire trust chain.

### Agent Enrollment (One Certificate per Host)

On first connection, the Agent no longer uses a shared client certificate; instead it exchanges an **enroll token** for a per-host certificate issued for its AgentID:

1. An Agent without a client certificate can only go through enroll: it submits a valid AgentID + enroll token;
2. After validation, AgentCenter issues on the spot a per-host certificate with `CN=AgentID`, delivers it, and then immediately ends that connection;
3. The Agent reconnects with the new certificate and goes through full mTLS, and the certificate CN must match the reported AgentID.

The enroll phase does not register an online connection, does not process heartbeats, does not dispatch plugin tasks, and cannot access any other RPC. A compromised host can be revoked individually, and a leaked private key does not affect other hosts.

**An enroll token must be provided at install time** (taken from `ENROLL_TOKEN` in `deploy/.env` on the deployment machine):

```bash
MXCWPP_ENROLL_TOKEN=<token> bash -c "$(curl -fsSL http://SERVER_IP:8080/agent/install.sh)"
```

The token is written to `/etc/mxcwpp-agent/agent.env` (root-only 0600) and injected by systemd via `EnvironmentFile`; it does not appear in process arguments or the unit file. **The token is not delivered via `/agent/install.sh`**: that endpoint is anonymously accessible, so injecting the token there would be the same as publishing it.

Hosts that already hold a per-host certificate do not need to provide the token again when reinstalling or upgrading.

**Cloned machines**: by default the AgentID is derived from machine-id, so machines cloned from the same system template compute the same ID.
The Agent detects on its own that "the ID file was copied along with the image" and regenerates it; the case where machine-id itself is identical is detected by AgentCenter
comparing machine fingerprints (see `identity_conflict` in [Configuration · mtls](configuration.md#mtls)).
To handle it manually, use `mxcwpp-agent --reset-identity` to invalidate this host's identity and certificate, then `systemctl restart mxcwpp-agent`
(this requires the enroll token to still be present in `agent.env`). When building a system image, do not start the Agent after installing it, or run `--reset-identity` once before sealing the image. Install packages contain only `ca.crt` by default and do not bundle the shared client certificate (it is bundled only when `INCLUDE_SHARED_CLIENT_CERT=1` is set explicitly, for development and debugging only). Production builds (`PROD_BUILD=1`) also embed the CA fingerprint and the plugin signing public key into the binary, and require `SIGN_PUBLIC_KEY` (the plugin signing public key); the build fails immediately if it is missing.

---

## Image Build

```bash
# Build all images (manager / agentcenter / consumer / ui, 4 in total)
./scripts/build-images.sh --version v1.0.0

# Build and push to a private registry
./scripts/build-images.sh --version v1.0.0 --registry registry.example.com/mxcwpp --push
```

Supported parameters: `--version` (version number), `--registry` (image registry prefix), `--push` (push after build). The script builds all 4 images in one run.

It is recommended to build images on a machine of the target architecture to avoid cross-platform issues.

---

## Agent Deployment

### Build Install Packages

```bash
# Build Agent RPM/DEB (SERVER_HOST is embedded at compile time and points to the AC gRPC entry)
make package-agent-all VERSION=1.0.0 SERVER_HOST=<AC_LB_IP>:6751

# Build plugin packages
make package-plugins-all VERSION=1.0.0
```

> `SERVER_HOST` is an Agent build parameter, not a server configuration item. In production it should point to the L4 LB or the external entry address of AC.

### Installation

Preparation before installation (once per platform deployment):

1. In **System Management → Basic Settings**, fill in the backend API address (e.g. `https://<SERVER_IP>`). The Agent uses this address to download plugins and updates; if it is left empty it falls back to `localhost`, and all plugin downloads fail.
2. In **Operations Center → Component Management**, upload the install packages: upload the Agent package to the component named `agent` (the download endpoint looks it up by this name), and upload plugins to components with the same name. Upload the package matching each host's architecture.

The one-click install script is recommended; it writes the enroll token first and then installs the package:

```bash
# 1. Trust the platform CA (deploy/certs/ca.crt); when the console uses a self-signed certificate, the install package cannot be downloaded over HTTPS unless the CA is trusted
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/mxcwpp-ca.crt && sudo update-ca-trust          # RHEL family
# sudo cp ca.crt /usr/local/share/ca-certificates/mxcwpp-ca.crt && sudo update-ca-certificates  # Debian family

# 2. Install (the token is taken from ENROLL_TOKEN in deploy/.env on the deployment machine)
read -rs MXCWPP_ENROLL_TOKEN && export MXCWPP_ENROLL_TOKEN
export MXCWPP_HTTP_SERVER=https://<SERVER_IP> MXCWPP_AGENT_SERVER=<SERVER_IP>:6751
sudo -E bash -c "$(curl -fsSL https://<SERVER_IP>/agent/install.sh)"
```

When installing the package manually, **you must write the token before installing the package**: the package starts the service immediately, and if it cannot read the token at startup it cannot enroll; you would have to write the token afterward and restart.

```bash
sudo install -d -m 700 /etc/mxcwpp-agent
echo "MXCWPP_ENROLL_TOKEN=<token>" | sudo tee /etc/mxcwpp-agent/agent.env >/dev/null
sudo chmod 600 /etc/mxcwpp-agent/agent.env

sudo rpm -ivh mxcwpp-agent-1.0.0-amd64.rpm        # RPM (CentOS / Rocky / Oracle)
sudo dpkg -i mxcwpp-agent_1.0.0_amd64.deb         # DEB (Debian / Ubuntu)
```

The Agent relies on systemd for process management; container hosts are identified as a container runtime, and the platform does not dispatch host plugins to them.

### Directory Structure

| Path | Description |
|------|------|
| `/var/lib/mxcwpp-agent/` | Working directory |
| `/var/lib/mxcwpp-agent/certs/` | Certificate directory |
| `/var/lib/mxcwpp-agent/plugin/` | Plugin directory |
| `/var/log/mxcwpp-agent/` | Log directory |

### Management

```bash
systemctl status mxcwpp-agent
systemctl restart mxcwpp-agent
journalctl -u mxcwpp-agent -f
```

---

## Reproducible Builds and SBOM

The same source must build **byte-for-byte identical** binaries; otherwise the packages customers receive cannot be reconciled against the source,
and when something goes wrong there is no way to confirm "whether what is running is actually this code."

Previously two things broke reproducibility; both have been confirmed by measurement and fixed:

| Problem | Consequence | Now |
|---|---|---|
| Missing `-trimpath` | Binaries embedded absolute paths from the build machine (**3985 occurrences** measured), so builds on different machines differed and leaked the build environment | Added to all three `go build` invocations and all six places in the Makefile |
| `BUILD_TIME=$(date)` | Each build of the same source produced a different binary | Uses the git commit time; can be overridden with `SOURCE_DATE_EPOCH` |

`gitCommit` is embedded in the binary for reconciling against the source after delivery.

**SBOM**: `./scripts/gen-sbom.sh` produces a CycloneDX 1.5 bill of materials (439 components),
which is automatically placed in the release bundle during packaging. It uses only Go's built-in `go list -m` and does not depend on external tools such as cyclonedx-gomod:
it is common that extra tools cannot be installed in offline environments and at customer sites, and every additional dependency is one more reason something cannot be installed.

The manifest carries `go.sum` checksums (verifiable, not merely listed), entries are sorted, the timestamp is the commit time,
and the serialNumber is derived from the content, so **the SBOM itself is also reproducible**: the same commit always yields the same file.

Compliance audits require it; when a supply chain incident (such as Log4Shell) occurs, it decides whether you can answer within ten minutes whether you are affected,
or have to dig through source code for two days.


## Backup, Restore, and Rollback

```bash
./deploy.sh backup                    # Back up (kept after verification)
./deploy.sh restore <backup file>     # Restore from a backup
./deploy.sh rollback                  # Roll back to the version before the upgrade
```

**Backups verify themselves**. The original implementation was `mysqldump | gzip > file` without `pipefail`:
when the dump failed, gzip still succeeded and the pipeline returned 0, leaving a file of twenty-odd bytes and printing
"backup complete", and the upgrade proceeded as usual. A backup that can deceive you is more dangerous than no backup at all: operators think they have a way back.

Now a backup counts as successful only if it passes all three checks: gzip integrity, a minimum decompressed size, and content that actually contains table creation statements.
If any check fails, the file is deleted and an error is reported. The size threshold uses the **decompressed** size, because SQL dumps are extremely repetitive,
and a threshold on the compressed size would misjudge normal backups as failures.

**Upgrades leave a rollback point**. `upgrade` writes the pre-upgrade version number and backup path into `.env`
(`PREV_VERSION` / `PREV_BACKUP`), and aborts immediately if the backup fails: with no way back, it does not move forward.
At the end it actually waits for services to become healthy, rather than unconditionally printing "upgrade complete" after `sleep 10`; if they are not ready,
it explicitly prints the rollback command and exits with a non-zero code.

**Rollback does not restore the database by default**. New data may have been written after the upgrade, and rolling it back too would erase it.
Version rollback and data restore are two independent decisions; when a restore is needed, run `restore` explicitly.

**The current database is backed up before a restore**. Overwriting still-usable data with a bad backup is the worst outcome,
so a restore first verifies the target backup, then saves a copy of the current state, then stops the application services, and finally imports.

## Upgrade

### Server Upgrade

Using `deploy.sh upgrade` is recommended (automatic backup -> version update -> container rebuild):

```bash
git pull origin main
./scripts/build-images.sh --version v1.1.0
cd deploy && ./deploy.sh upgrade
```

When upgrading manually, you must explicitly pass `--scale` to preserve replica counts:

```bash
cd deploy
sed -i 's/^VERSION=.*/VERSION=v1.1.0/' .env
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

> `docker compose restart` only restarts containers and does not switch images; upgrades must use `up -d`.

Data that Consumer cannot write to ClickHouse is spilled to `<topic_prefix>mxcwpp.consumer.ch-spill`. The retention period of this topic must be
longer than the time needed for troubleshooting and replay. Create it manually before the first deployment (or before upgrading from a version without spill), rather than relying on the default retention of auto-created topics:

```bash
kafka-topics --bootstrap-server <broker> --create --if-not-exists \
  --topic <topic_prefix>mxcwpp.consumer.ch-spill --partitions 6 --replication-factor 2 \
  --config retention.ms=2592000000 --config retention.bytes=-1 --config min.insync.replicas=2
```

`retention.bytes=-1` is required: by default the broker deletes segments based on partition size, so data could be gone before replay. Consumer checks
these two settings at startup (`retention.bytes` is -1, retention period is no shorter than 7 days); if they do not match, it does not enable spill and raises the `MxCwppConsumerCHSpillUnavailable` alert.
`min.insync.replicas=2` makes the spill fail when only one replica remains (the data stays in memory and is retried), instead of counting a write to a single replica as success.

### AgentCenter Multiple Instances and Rolling Upgrades

The agent's connection address is fixed at compile time, so the entry point must stay at the original address. With multiple ACs, place an L4 forwarder in front of the entry address
(template `deploy/config/haproxy-agentcenter-ha.cfg`, TCP passthrough, mTLS still terminates on AC):

- The forwarding layer listens on the `IP:port` compiled into the agent; the AC on the same machine changes `server.grpc.host` to `127.0.0.1`,
  with the port unchanged. The two do not conflict, and the compose health check does not need to change.
- Each AC is configured with a different `server.instance_id` and shares the same MySQL / Kafka / certificates (including the CA private key, used to issue per-host certificates).
  `internal_secret` and `ac_admin_secret` must be identical on all ACs; command forwarding between instances and the drain endpoint authenticate with the latter.
- Do not enable AC's per-IP rate limiting behind the forwarding layer: all connections come from the forwarding layer's address and would share a single bucket.

Behavior with multiple instances:

| Item | Approach |
|---|---|
| Engine commands (`mxcwpp.engine.command`) | Each AC uses its own consumer group (`mxcwpp-ac-command-<instance_id>`), all receive the full stream, and each only pushes to agents connected to itself |
| Tasks dispatched by Manager | Routed precisely via Redis `agent:ac:<agentID>` to the AC holding the connection; broadcast when not found |
| Agent upgrade / restart push | One AC is elected via a lease (`scheduler_leases`) to execute it; commands are forwarded by `hosts.ac_instance` to the instance holding the connection |
| Offline determination | Only the AC that `hosts.ac_instance` points to marks a host offline; switching instances does not cause false offline reports |

Primary/standby by default: normally all connections are on the primary AC, while the standby AC is up and on standby without accepting connections (the standby AC is marked `backup` in the forwarding configuration),
taking connections only temporarily while the primary AC is being upgraded. The standby AC is configured with `server.standby: true`: it does not participate in the upgrade/restart push lease,
because pushing requires reading the install packages uploaded by manager, which the standby AC's node does not have; during the minute or two the primary AC is down, pushes pause and resume when it comes back. Run the upgrade with the script in one go:

```bash
scripts/ac-rolling-upgrade.sh -p <primary AC>:8081 -s <standby AC>:8081 -k <AC admin secret file> -- \
  docker compose -p mxcwpp-control -f docker-compose.control.yml up -d --no-deps --force-recreate agentcenter
```

The script, in order: confirms the standby AC is ready → drains the primary AC (`/ready` returns 503, the forwarding layer removes it within about 4 seconds, connections are dropped in batches) →
runs the upgrade command → waits for the primary AC to be ready → drains the standby AC, connections switch back in batches → the standby AC returns to standby → waits for the primary AC's connection count to return to its pre-upgrade level.
If any step fails, it stops where it is and prints the status; at that point connections are on the standby AC and service is not interrupted. The standby AC has no connections of its own and can be upgraded directly at any time.

Draining is judged complete when `tcp_connections` returned by `/admin/drain` reaches zero: after establishing a stream, an agent may wait up to one heartbeat interval (60 seconds by default)
before sending its first packet and being registered, so looking only at the registered count `connections` would miss these connections. The end of the drain closes them as well.
After an agent is disconnected, it rebuilds the connection only on its next failed send, so idle hosts can lag by up to one heartbeat interval; during that time data is cached locally and resent after reconnecting.
Connections dropped during draining are not recorded as offline and do not raise offline alerts; if an agent fails to connect elsewhere, the other instance's heartbeat timeout detection will mark it offline as usual.
With a single instance, a direct `docker compose up -d` also drops connections in batches before stopping (stop grace period 70 seconds), and agents reconnect automatically once the new container is up.

### Plugin Canary Release

Plugin configuration is a single global copy: after the new version is set as latest, any agent that reconnects will upgrade, which amounts to a full rollout. To canary by host, use the canary API:

1. Upload the new version's package, and **do not set it as the latest version**.
2. `POST /api/v1/components/plugins/<plugin>/canary`, `{"version": "<new version>", "host_ids": ["<host>"]}`:
   only these hosts get the new version (the download URL carries `?version=`), and it is dispatched immediately without waiting for reconnection.
3. Observe the plugin's running status and data on these hosts; to widen the scope, submit again with the same version, and hosts are appended to the list.
4. If there is a problem: `DELETE .../canary`, and hosts on the list immediately revert to the global version.
5. If there is no problem: `POST .../canary/promote` sets the canary version as the latest version; the remaining hosts upgrade on their next reconnection,
   and to roll out fully right away, also call `POST /api/v1/components/plugins/broadcast`.

Only one version of a given plugin can be in canary at a time.

### Agent Upgrade

```bash
# Server-side push (triggered from the management UI)
# Active update via CLI
mxcwpp-agent --update
mxcwpp-agent --update --server http://manager:8080
# Update from a local package
mxcwpp-agent --update --file ./mxcwpp-agent-1.1.0.rpm
```

### Agent Operations Commands

```bash
# View running status (systemd status, PID, uptime, Server reachability, Agent ID)
mxcwpp-agent --status
mxcwpp-agent --status --json      # Machine-parseable format

# View local logs (last 100 lines by default)
sudo mxcwpp-agent --logs
sudo mxcwpp-agent --logs -n 500   # Last 500 lines
sudo mxcwpp-agent --logs -f       # Follow in real time (Ctrl-C to exit)

# Show a configuration snapshot (build-embedded Server address, certificate bundle status, Agent ID)
mxcwpp-agent --config
mxcwpp-agent --config --json

# Generate a diagnostic bundle (last 7 days of logs + systemctl/journalctl/uname/ss output)
sudo mxcwpp-agent --diag
sudo mxcwpp-agent --diag -o /tmp/diag.tar.gz
# Output file permissions are 0600; check for sensitive information before uploading
```

> `--logs` and `--diag` require root privileges to read `/var/log/mxcwpp-agent/`.

---

## Backup

```bash
./deploy/deploy.sh backup
```

Backup files are stored in the `deploy/backup/` directory and include the database and configuration files.

---

## Network and Ports

| Port | Host port | Protocol | Direction | Description |
|------|-----------|------|------|------|
| 80 / 443 | 80 / 443 | HTTP/S | User -> Nginx | Management UI + API (UI) |
| 8080 | 8080 | HTTP | Internal | Manager HTTP API |
| 6751 | 6751 | gRPC | Agent -> AC | AgentCenter access (mTLS); an L4 LB is required for production deployments |
| 3306 | 13306 | TCP | Internal | MySQL |
| 6379 | 16379 | TCP | Internal | Redis |
| 9000 | 9000 | TCP | Internal | ClickHouse Native (TCP) |
| 8123 | 8123 | HTTP | Operations | ClickHouse HTTP |
| 9092 / 9094 / 9095 | 9092 / 9094 / 9095 | TCP | Internal | Kafka Broker |
| 9090 | 9090 | HTTP | Internal | Prometheus |

**Firewall rules**: only 80/443 and 6751 are open externally; storage layer ports are restricted to access from control plane nodes.

---

## Makefile Command Reference

| Command | Description |
|------|------|
| `make proto` | Generate Protobuf Go code |
| `make build-server` | Build Server binaries (agentcenter + manager) |
| `make build-consumer` | Build the Consumer binary |
| `make package-agent` | Package the Agent (single-architecture RPM/DEB) |
| `make package-agent-all` | Package the Agent (amd64 + arm64) |
| `make package-plugins` | Build all plugins (single architecture) |
| `make package-plugins-all` | Build all plugins (amd64 + arm64) |
| `make package-all` | Build everything (single architecture) |
| `make package-all-arch` | Build everything (amd64 + arm64) |
| `make test` | Run tests |
| `make fmt` | Format code |
| `make lint` | Lint code |
| `make deps` | Download dependencies |
| `make clean` | Clean build artifacts |
| `make certs` | Generate mTLS certificates |
| `make dev-docker-up` | Start the development environment (foreground) |
| `make dev-docker-up-d` | Start the development environment (background) |
| `make dev-docker-down` | Stop the development environment |
| `make dev-docker-logs` | View development environment logs |
| `make dev-docker-restart` | Restart the backend (manager) |
| `make web-dev` | Start the frontend locally (port 3000) |
| `make pret-docker-up` | Start the load testing environment (foreground) |
| `make pret-docker-up-d` | Start the load testing environment (background) |
| `make pret-docker-down` | Stop the load testing environment |

Build examples:

```bash
make package-agent-all VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751
make package-all-arch VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751
```

Output directories: Agent RPM/DEB in `dist/packages/`, plugin binaries in `dist/plugins/`.

---

## Storage Capacity Estimation

Baseline: 100 Agents, 30-day retention:

| Data type | Storage location | Estimate |
|---------|---------|--------|
| Heartbeats | MySQL | ~4 GB |
| Asset fingerprints | MySQL | ~1 GB |
| Baseline results | ClickHouse | ~180 MB |
| FIM events | ClickHouse | ~150 MB |
| eBPF events | ClickHouse | ~130 GB (automatically cleaned up by 30-day TTL) |
| Alerts | MySQL + ClickHouse | ~500 MB |
| Kafka messages | Kafka disk | ~50 GB peak (72h retention) |

eBPF event volume depends on the Tetragon policy configuration; it is recommended to adjust disk planning based on trial-run data.

---

## Health Checks

```bash
# Service status
docker compose ps

# API health check
curl http://localhost/health
curl http://localhost/api/v1/health

# AC service discovery (authentication required)
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.data.token')
curl -H "Authorization: Bearer $TOKEN" http://localhost/api/v1/discovery/agentcenter

# Consumer consumption status
docker compose logs consumer | tail -20

# Agent connectivity (requires the AC gRPC port to be exposed)
nc -zv <AC_HOST> 6751
```

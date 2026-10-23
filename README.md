# MxCwpp

**English | [中文](README_ZH.md)**

[![Go Version](https://img.shields.io/github/go-mod/go-version/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp)
[![License](https://img.shields.io/github/license/matrixplusio/mxcwpp)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/matrixplusio/mxcwpp?style=social)](https://github.com/matrixplusio/mxcwpp/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp/issues)
[![Last Commit](https://img.shields.io/github/last-commit/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp/commits/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/matrixplusio/mxcwpp)](https://goreportcard.com/report/github.com/matrixplusio/mxcwpp)

An open-source host and container security platform (CWPP) for Linux and Kubernetes. It covers security baselines, asset inventory, vulnerability management, malware scanning, file integrity monitoring, runtime detection and response, and gives security operations teams a single management console.

The whole platform is in this repository — agent, plugins, backend services and console — free to deploy under AGPL-3.0.

## Capabilities

| Area | What it does |
|------|--------------|
| Security baseline | CIS Benchmark, MLPS 2.0 (等保) and middleware checks — 30 policies, 614 rules; single-host and batch auto-remediation |
| Asset inventory | Processes, ports, users, packages, containers and more, with relationship mapping, global fingerprinting and export; Kubernetes cluster assets |
| Vulnerability management | Package PURL collection, OS vendor advisories plus OSV.dev matching, CVSS v3.1 scoring, SBOM and VEX (CycloneDX 1.5 / CSAF 2.0) export |
| Malware scanning | ClamAV and YARA-X engines, scan tasks and file quarantine |
| File integrity monitoring | AIDE-based FIM with policies, events and tasks |
| Runtime detection | eBPF event collection, CEL rule engine with MITRE ATT&CK mapping, behavioral sequence rules, ML anomaly scoring |
| Memory and rootkit detection | memfd_exec, process hollowing, shellcode injection, LSASS dump; DKOM hidden PID / kernel module / port / LD_PRELOAD |
| Kubernetes security | Cluster management, container CIS baseline, audit-log intrusion detection via audit webhook |
| AD / LDAP audit | DCSync, Kerberoasting, brute force, off-hour RDP, privilege assignment and more |
| Alerting and response | Aggregation, whitelists, attack storyline (ATT&CK kill-chain timeline), kill / quarantine / network block |
| Threat intelligence | MISP IOC import with real-time matching in the rule engine |
| Threat hunting | SPL-like query language translated to SQL over the ClickHouse event archive |
| Operations | Audit log, component and plugin distribution, Prometheus monitoring, inspection reports |

**In development, not yet shipped:** honeypot sensors (SSH / HTTP decoys), NPatch eBPF virtual patching (Log4j proof of concept only), Windows support.

## Architecture

```
Browser ─→ Nginx ─→ Manager ×N ─→ MySQL / Redis / ClickHouse / Prometheus
Agent ─→ gRPC(mTLS) ─→ AgentCenter ×N ─→ Kafka ─┬→ Consumer ×N ─→ Storage (persist)
                                                 └→ Engine ×N    ─→ Alerts (detection)
Manager ──HTTP──→ LLMProxy ×N (multi-LLM gateway)   VulnSync ×N ──Kafka──→ Manager/Engine
```

The backend consists of seven services: Manager, AgentCenter, Consumer, Engine, LLMProxy, VulnSync and Scanner. The control plane is stateless and scales horizontally. Kafka decouples persistence from detection (separate consumer groups with independent offsets), Redis handles service discovery and distributed locks, and ClickHouse stores time-series analytics and the event archive. VulnSync pulls OS vendor advisories and publishes them to Kafka for matching against host software.

See [Architecture](docs/architecture.md) for details.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Go 1.26 (Gin / gRPC / GORM / Zap) |
| Frontend | Next.js 15 + React 19 + TypeScript + TailwindCSS + Zustand + TanStack Query |
| Storage | MySQL 8.0+ / Redis 7 / ClickHouse 24 |
| Messaging | Kafka (KRaft mode) |
| Monitoring | Prometheus |
| Communication | gRPC bidirectional streaming + mTLS + Protobuf |
| Deployment | Docker Compose / systemd + Nginx |

## Supported Platforms

**Host OS**: Rocky Linux 9/10, Oracle Linux 7/8/9, CentOS 7/8/9, Debian 10/11/12, Ubuntu 20.04/22.04

**Runtime**: Physical and virtual machines, Docker hosts, Kubernetes nodes and clusters

## Quick Start

```bash
git clone https://github.com/matrixplusio/mxcwpp.git
cd mxcwpp/deploy

cp .env.example .env
vim .env  # Edit SERVER_IP / JWT_SECRET / database passwords

# Start the control plane (HA mode)
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

Open `http://<SERVER_IP>` and sign in as `admin / admin123`. You will be required to change the password on first login.

See [Deployment](docs/deployment.md) for prerequisites, cluster deployment and agent installation.

## Build

```bash
make build-server                                        # Build server
make build-consumer                                      # Build consumer
make package-agent-all VERSION=1.0.0 SERVER_HOST=IP:6751 # Package agent (RPM/DEB)
make package-plugins-all VERSION=1.0.0                   # Package plugins
make proto                                               # Generate Protobuf code
make test                                                # Run tests
make lint                                                # Lint
```

## Project Structure

```
mxcwpp/
├── cmd/
│   ├── agent/              # Agent entry point
│   ├── server/             # agentcenter / consumer / engine / llmproxy / manager / scanner / vulnsync
│   └── tools/              # Maintenance tools (replay, ETL, migration)
├── internal/
│   ├── agent/              # Agent (connection, transport, plugin management, EDR modules)
│   ├── server/             # Backend services and shared server packages
│   ├── common/             # Packages shared by agent and server
│   └── deploy/             # Deployment rendering and repository checks
├── plugins/                # avscanner / baseline / collector / fim / logcollector / remediation / scanner
│                           # rasp-go / rasp-java / rasp-node / rasp-php / rasp-python; lib/ is the shared plugin SDK
├── api/proto/              # Protobuf definitions
├── web/                    # Console (Next.js 15 + React 19 + TypeScript)
├── configs/                # Configuration samples and detection rules
├── deploy/                 # Docker Compose, Nginx, systemd and cluster deployment
├── sdk/                    # Client SDKs (Go / Java / Python)
├── scripts/                # Build and deployment scripts
├── tests/                  # API, end-to-end, performance and rule tests
└── docs/                   # Documentation
```

## Documentation

- [Architecture](docs/architecture.md) - System topology, component responsibilities, data pipeline, HA design
- [Deployment](docs/deployment.md) - Prerequisites, single-node and cluster deployment, agent installation, upgrades and backups
- [Configuration](docs/configuration.md) - Server and agent configuration, environment variables
- [API Reference](docs/api-reference.md) - REST endpoints, request/response formats, authentication
- [FAQ](docs/faq.md) - Common issues and troubleshooting
- [Development](docs/development.md) - Local setup, database migrations, plugin development
- [Contributing](CONTRIBUTING.md) - How to report bugs and request features
- [Governance](docs/governance.md) - Project roles, decision process, security policy

The detailed documents under `docs/` are currently written in Chinese.

## Star History

[![Star History](docs/assets/star-history.svg)](https://github.com/matrixplusio/mxcwpp/stargazers)

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

## License

[GNU Affero General Public License v3.0](LICENSE)

AGPL-3.0 requires that modifications remain available under the same licence, including when the software is offered as a network service.

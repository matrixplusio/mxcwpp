# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.1] - 2026-10-24

### Changed
- Release images are built for both linux/amd64 and linux/arm64
- Build and release tooling is pinned to fixed versions

### Fixed
- When `deploy.sh` runs as root, `config/server.yaml` is restricted to the service user (0640)

## [1.0.0] - 2026-10-24

### Added
- Security baseline: 30 policies, 614 rules covering CIS Benchmark, MLPS 2.0 and middleware checks
- Asset center: processes, ports, users, packages, containers and more
- Vulnerability management: PURL collection + OSV.dev matching + CVSS v3.1 scoring + SBOM export
- Antivirus: ClamAV + YARA-X dual-engine scanning with quarantine
- File integrity monitoring: AIDE-based FIM with policy, event, and task management
- Runtime detection: Tetragon/eBPF event collection + CEL rule engine + MITRE ATT&CK mapping
- Container security: K8s cluster management, container CIS baseline
- Alert center: aggregation, whitelisting, auto-response, tracing timeline
- Threat intelligence: MISP IOC import + Redis cache + CEL real-time matching
- Embedded detection rules with builtin tagging system
- Plugins are delivered per host architecture: one platform can manage amd64 and arm64 hosts at the same time
- Single-node quick start: `./deploy.sh quickstart` generates all secrets and certificates and starts the stack

### Known issues
- With a non-default `HTTPS_PORT`, the HTTP-to-HTTPS redirect drops the port.
- Vulnerability matching for Rocky Linux only covers advisories published after the first start.
- The agent's self-protection raises a "file attribute lock" alert on the host it is installed on.

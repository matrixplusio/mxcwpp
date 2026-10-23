# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

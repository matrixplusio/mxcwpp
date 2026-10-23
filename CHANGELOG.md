# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Security baseline: 9 checkers, 212 rules covering CIS Benchmark core items
- Asset center: 11 asset types collection (processes, ports, users, packages, containers, etc.)
- Vulnerability management: PURL collection + OSV.dev matching + CVSS v3.1 scoring + SBOM export
- Antivirus: ClamAV + YARA-X dual-engine scanning with quarantine
- File integrity monitoring: AIDE-based FIM with policy, event, and task management
- Runtime detection: Tetragon/eBPF event collection + CEL rule engine + MITRE ATT&CK mapping
- Container security: K8s cluster management, container CIS baseline (80 rules)
- Alert center: aggregation, whitelisting, auto-response, tracing timeline
- Threat intelligence: MISP IOC import + Redis cache + CEL real-time matching
- Embedded detection rules with builtin tagging system

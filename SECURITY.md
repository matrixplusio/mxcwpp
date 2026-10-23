# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, **please DO NOT open a public issue**.

Please report it privately via email:

- **Email**: contact@matrixplus.io
- **Subject format**: `[SECURITY] Brief description`

## Response SLA

| Stage | Timeframe | Type |
|-------|-----------|------|
| Acknowledge receipt | 48 hours | Hard requirement |
| Initial assessment & severity rating | 7 business days | Target |
| Start fix for critical vulnerabilities (CVSS >= 9.0) | Within 24 hours | Hard requirement |

## Process

1. A security response lead is assigned upon receiving the report
2. Acknowledge receipt within 48 hours
3. Validate the vulnerability and assess impact with CVSS scoring
4. If CVSS >= 9.0, initiate fix within 24 hours
5. Develop fix in a private branch
6. Notify affected users before releasing the fix
7. Publish security update and advisory
8. Record in CHANGELOG (without exposing exploit details)

## Security Updates

Security fixes are released as PATCH versions and communicated through:

- GitHub Security Advisory
- Release Notes
- Direct notification to affected users

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

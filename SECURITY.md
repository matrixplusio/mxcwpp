# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, **please do not open a public issue**.

Report it privately by email:

- **Email**: contact@matrixplus.io
- **Subject**: `[SECURITY] Brief description`

Please include the affected component and version, reproduction steps or a proof of concept, and the impact you observed. Remove host names, addresses and credentials from logs before sending.

## What to Expect

This project is maintained on a best-effort basis. Our targets are:

| Stage | Target |
|-------|--------|
| Acknowledge receipt | Within 3 business days |
| Initial assessment and severity rating (CVSS v3.1) | Within 10 business days |
| Fix | Prioritised by severity; critical issues are handled ahead of all other work |

We will keep you informed of progress and credit you in the advisory unless you prefer to remain anonymous.

## Process

1. Validate the report and assess impact
2. Develop the fix privately
3. Publish the fix together with a GitHub Security Advisory
4. Record it in the CHANGELOG without exploit details

Please allow us to publish a fix before disclosing the issue publicly.

## Supported Versions

Security fixes are made on the `main` branch. Once versioned releases are published, fixes will be shipped in a patch release of the latest minor version.

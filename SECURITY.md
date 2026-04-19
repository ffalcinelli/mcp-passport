# Security Policy

## Supported Versions

Currently, only the `main` branch is supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a potential security vulnerability in `mcp-passport` seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

, please do **not** open a public issue. Instead, report it privately to the maintainers:

- Fabio Falcinelli: [fabio.falcinelli@gmail.com](mailto:fabio.falcinelli@gmail.com)

We aim to acknowledge receipt of your report as soon as possible (typically within a few business days). Please note that while we take security seriously, we are a community-maintained project and cannot guarantee a specific resolution timeframe. We will provide updates as we investigate the issue and work toward a fix.

### What to Include in a Report

To help us address the issue quickly, please include:
- A clear description of the vulnerability.
- A minimal reproducible example (PoC) if possible.
- Any potential impact or exploitation scenarios.


## FAPI 2.0 and DPoP Security

`mcp-passport` is designed to provide high-level security for MCP servers. We rely on:
- **DPoP**: To prevent token theft and replay.
- **PAR**: To protect authorization parameters.
- **PKCE**: To prevent authorization code injection.

If you find a bypass in our implementation of these protocols, please report it immediately.

## Security Considerations

### Local Machine Trust
The proxy communicates with the AI Client via local `stdio`. The security model assumes the local machine is safe. If a user's machine is compromised, local malware could bypass the network authentication by simply hijacking the `stdio` pipeline or querying the OS Vault while unlocked.

## Disclosure Policy

We follow a responsible disclosure policy:
1.  Acknowledge the report.
2.  Investigate and confirm the vulnerability.
3.  Work on a fix.
4.  Release a new version with the fix.
5.  Publicly disclose the vulnerability (e.g., via GitHub Security Advisories) after a fix is available and users have had time to update.

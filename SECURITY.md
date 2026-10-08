# Security policy

## Supported versions

`mcp-passport` is pre-1.0. Security fixes go to `main` and to the latest release.

| Version | Supported |
| ------- | --------- |
| `main` | ✅ |
| latest 0.0.x release | ✅ |
| older releases | ❌ |

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately by email to the maintainer, Fabio Falcinelli <fabio.falcinelli@gmail.com>, or through the repository's *Security → Report a vulnerability* form when it is available.

Please include:

- a description of the issue and its impact;
- the affected version or commit;
- a minimal reproduction (proof of concept) if possible.

You'll get an acknowledgement within a few business days. This is a community-maintained project, so there is no guaranteed fix timeline, but we'll keep you informed while we investigate and fix it.

## Disclosure

1. We acknowledge the report and confirm the issue.
2. We prepare a fix and a release.
3. We publish a GitHub Security Advisory once users have had time to update, and credit the reporter unless they prefer otherwise.

## Threat model

`mcp-passport` runs on the user's machine, between a local AI client (over stdio) and a remote MCP server (over HTTPS). It aims to protect the user's credentials and to send them only where they belong.

**What it defends against**

- **Token theft and replay**: access tokens are DPoP-bound (RFC 9449) to a P-256 key generated for each login. Proofs carry `htm`, `htu`, `ath` and server nonces, and PAR binds the authorization code to the key (`dpop_jkt`).
- **Authorization code interception and injection**: PKCE S256 is mandatory (authorization servers that don't advertise it are refused), parameters go through Pushed Authorization Requests, and the callback checks `state`.
- **Mix-up attacks**: the authorization response's `iss` is compared with the discovered issuer (RFC 9207). Discovered metadata must name exactly the expected issuer.
- **Token misuse across servers**: credentials are stored per MCP server and bound to the issuer that granted them. Refresh tokens are never sent to another authorization server. RFC 8707 resource indicators are always sent.
- **SSRF through challenges**: a `resource_metadata` URL is followed only on the MCP server's own origin.
- **Network exposure**: remote endpoints must use HTTPS (except on loopback). The login callback listens only on a loopback address.
- **Local disclosure via logs**: logs live in a private `0700` directory that may not be a symlink. Tokens, keys and codes are never logged.

**What is out of scope**

- A compromised local machine or user account. Anything that can drive the proxy's stdio or read the unlocked keychain can act as the user.
- Malicious or compromised MCP or authorization servers acting within the permissions the user granted them.
- Weaknesses of the operating system's credential store.

Reports of bypasses of any defence listed above are very welcome.

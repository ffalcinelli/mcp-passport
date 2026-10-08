# mcp-passport setup guide

This guide covers connecting an AI client to an OAuth-protected MCP server through `mcp-passport`: installation, registering the OAuth client, configuring the AI client, provider notes, and troubleshooting. For an overview, see the [README](README.md).

## 1. Prerequisites

- An MCP server reachable over HTTPS that protects itself with OAuth (it answers `401` with a `WWW-Authenticate` challenge and publishes RFC 9728 protected resource metadata), **or** you know its authorization server's metadata URL.
- An authorization server that supports **PKCE S256** and **Pushed Authorization Requests**, and ideally **DPoP**. [Keycloak](https://www.keycloak.org/) 26.8.0 is tested; see [section 5](#5-keycloak-tested-with-2680).
- A desktop session with a keychain: macOS Keychain, Windows Credential Manager, or a Linux Secret Service such as GNOME Keyring or KWallet.

## 2. Installation

Download the archive for your platform from the [releases page](https://github.com/ffalcinelli/mcp-passport/releases), or build it with Rust 1.88+:

```bash
cargo install --git https://github.com/ffalcinelli/mcp-passport
```

## 3. Configuration

Every setting is a CLI flag or an `MCP_PASSPORT_*` environment variable; flags win. The [README](README.md#configuration) has the full table, and `mcp-passport --help` lists everything. The settings you usually need:

| Variable | Purpose |
|----------|---------|
| `MCP_PASSPORT_REMOTE_MCP_URL` | The MCP endpoint, e.g. `https://mcp.example.com/mcp` (required). |
| `MCP_PASSPORT_OIDC_CLIENT_ID` | Your client ID (default `mcp-passport`). |
| `MCP_PASSPORT_OIDC_ISSUER` | The issuer that client ID belongs to (recommended for pre-registered clients). |
| `MCP_PASSPORT_OIDC_REDIRECT_URL` | Login callback, default `http://127.0.0.1:8082/callback`. It must be registered with the provider. |
| `MCP_PASSPORT_OIDC_DISCOVERY_URL` | Only if the MCP server doesn't publish protected resource metadata. |

### How the authorization server is found

1. If `--kc-auth-url`, `--kc-token-url` and `--kc-par-url` are all set, they are used as is.
2. Otherwise, `--oidc-discovery-url` is fetched as the authorization server metadata.
3. Otherwise, the server is discovered from the MCP server:
   1. the `resource_metadata` URL of its 401 challenge (same origin only), or `/.well-known/oauth-protected-resource/<path>`, then `/.well-known/oauth-protected-resource`;
   2. the first `authorization_servers` entry, fetched via the RFC 8414 / OpenID Connect well-known URLs; its `issuer` must match exactly.

### Client registration

- **Pre-registered client** (most common): register a public client with your provider and set `MCP_PASSPORT_OIDC_CLIENT_ID`. Also set `MCP_PASSPORT_OIDC_ISSUER`, so that the client ID is never presented to a different authorization server.
- **Client ID Metadata Document**: host a JSON document at an https URL with a path, and use that URL as the client ID. The authorization server must advertise `client_id_metadata_document_supported`. Example document at `https://example.com/mcp-passport.json`:

  ```json
  {
    "client_id": "https://example.com/mcp-passport.json",
    "client_name": "mcp-passport",
    "redirect_uris": ["http://127.0.0.1:8082/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }
  ```

Credentials are bound to the authorization server that issued them. If the MCP server starts pointing at a different issuer, the stored tokens are discarded and you log in again.

### Scopes

The first login requests the scopes from the server's challenge, or else the resource's `scopes_supported`. `openid` is added when the provider offers it, and `offline_access` only with `--oidc-offline-access`. A `403 insufficient_scope` triggers a step-up login that requests the new scopes **plus** the ones requested before.

## 4. AI client integration

### Claude Desktop

`claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "secure-proxy": {
      "command": "/path/to/mcp-passport",
      "env": {
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/mcp",
        "MCP_PASSPORT_OIDC_CLIENT_ID": "mcp-passport",
        "MCP_PASSPORT_OIDC_ISSUER": "https://auth.example.com/realms/mcp"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add secure-proxy \
  -e MCP_PASSPORT_OIDC_ISSUER=https://auth.example.com/realms/mcp \
  -- /path/to/mcp-passport --remote-mcp-url https://mcp.example.com/mcp
```

### Gemini CLI

`settings.json`:

```json
{
  "mcpServers": {
    "secure-proxy": {
      "command": "/path/to/mcp-passport",
      "env": {
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/mcp",
        "MCP_PASSPORT_OIDC_CLIENT_ID": "mcp-passport"
      },
      "trust": true
    }
  }
}
```

The first request opens your browser on the provider's login page. The URL is also printed to stderr, so you can copy it if no browser opens; `MCP_PASSPORT_SKIP_OPEN_BROWSER=1` only prints it.

## 5. Keycloak (tested with 26.8.0)

In the `mcp-passport` client:

- **Client authentication** off (public client), **Standard flow** on.
- **Advanced**: *Pushed authorization request required* on, *Proof Key for Code Exchange Code Challenge Method* `S256`, *OAuth 2.0 DPoP Bound Access Tokens* on.
- **Valid redirect URIs**: `http://127.0.0.1:8082/callback`.
- **Client scopes**: add the scopes your MCP server challenges for (e.g. `mcp:tools`, `mcp:admin`) as *optional*.
- **Audience**: if the MCP server validates tokens by introspection, add an *Audience* mapper that includes the server's client. Keycloak ignores the RFC 8707 `resource` parameter and only lets clients in the token's audience introspect it.

[`keycloak-realm.json`](keycloak-realm.json) is a working realm (user `jdoe` / `password`), and `docker compose up` starts it with a mock MCP server. When the browser and the MCP server reach Keycloak on different URLs, pin the issuer with `KC_HOSTNAME=<public URL>` and `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`, as `docker-compose.yml` does.

## 6. Troubleshooting

### Logs

Logs go to stderr and to `mcp-passport.log` in the log directory; the path is printed at startup. Defaults:

- **Linux**: `$XDG_STATE_HOME/mcp-passport/logs` (usually `~/.local/state/mcp-passport/logs`)
- **macOS**: `~/Library/Application Support/mcp-passport/logs`
- **Windows**: `%LOCALAPPDATA%\mcp-passport\logs`

Use `--log-level debug` (or `RUST_LOG=debug`) for detail.

### Common errors

| Message | Cause and fix |
|---------|---------------|
| `… must use HTTPS (plain HTTP is only allowed for loopback hosts …)` | A remote URL uses `http://`. Use HTTPS; for local experiments only, pass `--allow-insecure-http`. |
| `Redirect URL … must be an http URL on 127.0.0.1, [::1] or localhost` | The callback must be a loopback `http` URL with an explicit port. |
| `Failed to fetch protected resource metadata` | The MCP server publishes no RFC 9728 metadata. Set `--oidc-discovery-url` to its authorization server's metadata URL. |
| `Issuer mismatch: … declares issuer …` | The authorization server's metadata names a different issuer than the one the resource points at. This is a server misconfiguration; the metadata is not used. |
| `… does not advertise PKCE S256 …; refusing to proceed` | MCP clients must confirm PKCE support. Enable S256 at the provider (it must list it in `code_challenge_methods_supported`). |
| `… is not the one this client is registered with (--oidc-issuer …)` | The MCP server now points at a different authorization server than your client ID belongs to. Check the server, or update `--oidc-issuer` and the client ID. |
| `Authorization failed: access_denied: …` | The login was cancelled or refused at the provider. The provider's description follows the colon. |
| `Authentication timed out or failed to receive callback` | Nobody completed the login within `--auth-timeout-secs` (default 300). |
| `Authentication loop detected: the server rejected a freshly issued token` | The MCP server rejects tokens right after login, typically because of an audience or scope mismatch at the server. `mcp-passport` stops instead of reopening the browser. |
| `Failed to bind to 127.0.0.1:8082 after 5 retries` | Another program uses the callback port. Pick another port with `--oidc-redirect-url` and register it with the provider. |
| `Failed to store … in the OS keychain (on Linux this needs a running Secret Service …)` | No Secret Service on this Linux session. Start GNOME Keyring or KWallet, or use `MCP_PASSPORT_USE_MEMORY_VAULT=1` (credentials last only for the process lifetime). |
| `Token endpoint returned 400 …"not_allowed"…Offline tokens not allowed` | `--oidc-offline-access` is set, but the provider doesn't allow offline tokens for this client or user. Drop the flag. |
| Server side: Keycloak introspection says `"active": false` | The resource server isn't in the token's audience. Add an audience mapper (section 5). |

### Clearing stored credentials

Each MCP server has its own entries, all for the `--user-id` (default `default_user`): `mcp-passport:<id>` (access token), `mcp-passport:<id>-dpop` (DPoP key), `mcp-passport:<id>-refresh` (refresh token) and `mcp-passport:<id>-meta` (issuer, scopes, expiry). `<id>` is derived from the MCP server URL.

- **macOS**: Keychain Access, search for `mcp-passport`.
- **Windows**: Credential Manager → Windows Credentials.
- **Linux**: Seahorse / KWallet Manager, or `secret-tool search --all service mcp-passport:<id>`. Entries are also cached in the kernel keyring until you log out.

## 7. How the airlock works

1. A request gets `401` (expired or missing token) or `403 insufficient_scope` (more scopes needed). Tokens that are about to expire are refreshed before the request is even sent.
2. Outgoing requests are suspended. Requests rejected at the same time share one re-authentication.
3. For a `401`, a silent refresh with the stored, DPoP-bound refresh token is tried first.
4. Otherwise your browser opens the login page. After you log in, the code is exchanged for a DPoP-bound token, which is stored in the keychain.
5. The suspended requests resume with the new credentials.

If the login fails (access denied, a provider error, or the timeout), the waiting requests get a JSON-RPC error. If a freshly issued token is rejected again right away, `mcp-passport` reports an authentication loop instead of reopening the browser.

## 8. Customizing the login pages

After the login, the browser shows an "Authentication Successful" or "Authentication Failed" page served by `mcp-passport`. To brand them:

1. Create a directory with `success.html` and `failure.html`.
2. Use `{{ISSUER_NAME}}` and `{{RESOURCE_NAME}}` in either file, and `{{ERROR_MESSAGE}}` in `failure.html`. The values are HTML-escaped.
3. Start `mcp-passport` with `--template-dir <dir>` (or `MCP_PASSPORT_TEMPLATE_DIR`).

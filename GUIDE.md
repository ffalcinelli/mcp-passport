# mcp-passport: Setup & Configuration Guide 🛡️

This guide explains how to protect a remote MCP server using `mcp-passport` with FAPI 2.0 (PAR + DPoP) security and how to connect a local AI client (like Claude Desktop or Gemini CLI).

## 1. Prerequisites
- **Rust Toolchain**: [Install Rust](https://rustup.rs/) (1.75+)
- **OIDC Provider**: A FAPI 2.0 compliant provider (e.g., [Keycloak](https://www.keycloak.org/)) with a client configured for:
  - **Public Client** (with PKCE)
  - **PAR Enabled**
  - **DPoP Enabled**
  - **Redirect URI**: `http://127.0.0.1:8082/callback`

## 2. Installation
Build the binary from source for maximum security:
```bash
cargo build --release
```
The binary will be at `target/release/mcp-passport`.

## 3. Configuration

### Environment Variables (Recommended)
All variables are prefixed with `MCP_PASSPORT_`.

| Option | Environment Variable | Description |
|--------|----------------------|-------------|
| Remote MCP URL | `MCP_PASSPORT_REMOTE_MCP_URL` | The JSON-RPC endpoint of your remote server. |
| Remote SSE URL | `MCP_PASSPORT_REMOTE_SSE_URL` | The SSE endpoint for notifications. Optional: defaults to the MCP URL (Streamable HTTP). |
| Discovery URL | `MCP_PASSPORT_OIDC_DISCOVERY_URL` | Optional `.well-known/openid-configuration` URL. Without it, the authorization server is discovered from the MCP server (RFC 9728 → RFC 8414). |
| Client ID | `MCP_PASSPORT_OIDC_CLIENT_ID` | Your OIDC client ID (default: `mcp-passport`). |
| Redirect URL | `MCP_PASSPORT_OIDC_REDIRECT_URL` | Local callback URL (default: `http://127.0.0.1:8082/callback`). |
| Template Dir | `MCP_PASSPORT_TEMPLATE_DIR` | Directory containing custom `success.html` and `failure.html`. |
| Login timeout | `MCP_PASSPORT_AUTH_TIMEOUT_SECS` | How long to wait for the browser login (default: `300`). |
| Log Dir | `MCP_PASSPORT_LOG_DIR` | Where `mcp-passport.log` is written (default: a private per-user directory). |
| Allow plain HTTP | `MCP_PASSPORT_ALLOW_INSECURE_HTTP` | Accept `http://` URLs on non-loopback hosts. For development only. |
| Expected issuer | `MCP_PASSPORT_OIDC_ISSUER` | The issuer your client ID is registered with. Discovery fails if the MCP server points elsewhere. |
| Offline access | `MCP_PASSPORT_OIDC_OFFLINE_ACCESS` | Also request `offline_access` (long-lived refresh tokens) when the provider offers it. |

### Client registration
- **Pre-registered client** (most common): set `MCP_PASSPORT_OIDC_CLIENT_ID` and, ideally, `MCP_PASSPORT_OIDC_ISSUER`, so the client ID is never presented to another authorization server.
- **Client ID Metadata Document**: set the client ID to the https URL of a JSON document you host, e.g. `https://example.com/mcp-passport.json` containing `{"client_id": "<that URL>", "client_name": "mcp-passport", "redirect_uris": ["http://127.0.0.1:8082/callback"], "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none"}`. The authorization server must advertise `client_id_metadata_document_supported`.

Credentials are bound to the authorization server that issued them: if the MCP server starts pointing at a different issuer, the stored tokens are discarded and you log in again.

### CLI Overrides
You can also use CLI flags (e.g., `--remote-mcp-url`) which take precedence over environment variables. Run `./mcp-passport --help` for the full list.

## 4. AI Client Integration

### Claude Desktop
Edit your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "secure-proxy": {
      "command": "/path/to/mcp-passport",
      "env": {
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/mcp",
        "MCP_PASSPORT_OIDC_DISCOVERY_URL": "https://auth.example.com/realms/mcp/.well-known/openid-configuration"
      }
    }
  }
}
```

### Gemini CLI
Edit your `settings.json`:
```json
{
  "mcpServers": {
    "secure-proxy": {
      "command": "/path/to/mcp-passport",
      "env": {
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/mcp",
        "MCP_PASSPORT_OIDC_DISCOVERY_URL": "https://auth.example.com/realms/mcp/.well-known/openid-configuration"
      },
      "trust": true
    }
  }
}
```

## 5. Keycloak (tested with 26.8.0)
In the `mcp-passport` client:
- **Client authentication** off (public client), **Standard flow** on.
- **Advanced → Pushed authorization request required** on, **PKCE method** S256, **OAuth 2.0 DPoP Bound Access Tokens** on.
- **Valid redirect URIs**: `http://127.0.0.1:8082/callback`.
- If your MCP server validates tokens by introspection: add an **Audience** mapper including the MCP server's client. Keycloak ignores the RFC 8707 `resource` parameter and only lets audience clients introspect a token.
- For step-up flows, define the scopes your MCP server challenges for (e.g. `mcp:tools`, `mcp:admin`) as client scopes and assign them to the client as optional.

`keycloak-realm.json` contains a working realm (user `jdoe` / `password`).

## 6. Troubleshooting

### Logs
Logs are written to stderr and to `mcp-passport.log` in the log directory. The path is printed at startup. By default this is:
- **Linux**: `$XDG_STATE_HOME/mcp-passport/logs` (usually `~/.local/state/mcp-passport/logs`)
- **macOS**: `~/Library/Application Support/mcp-passport/logs`
- **Windows**: `%LOCALAPPDATA%\mcp-passport\logs`

Use `MCP_PASSPORT_LOG_LEVEL=debug` for more detail.

### Vault Issues
If authentication keeps failing, you can clear the stored tokens from your system's keychain. Each MCP server has its own entries, named `mcp-passport:<id>` (access token), `mcp-passport:<id>-dpop` (DPoP key) and `mcp-passport:<id>-refresh` (refresh token).
- **macOS**: Use "Keychain Access" and search for `mcp-passport`.
- **Linux**: Use `secret-tool search --all service mcp-passport:<id>` (or Seahorse / KWallet Manager). Entries are also cached in the kernel keyring for the session.
- **Windows**: Use "Credential Manager".

### Loopback Port Collision
If port `8082` is occupied, change the `MCP_PASSPORT_OIDC_REDIRECT_URL` (e.g., to `http://127.0.0.1:9999/callback`) and ensure this new URI is whitelisted in your OIDC provider.

## 7. How the "Airlock" Works
When you send a request and your token is missing or expired:
1. `mcp-passport` detects the `401` (or a `403 insufficient_scope` step-up challenge).
2. It suspends all outgoing requests. Requests rejected at the same time share one re-authentication.
3. For an expired token it first tries a silent refresh with the stored, DPoP-bound refresh token. Tokens about to expire are refreshed before the request is even sent.
4. Otherwise your default browser opens to the login page. Once you log in, `mcp-passport` captures the code, exchanges it for a DPoP-bound token, and stores it securely.
5. The suspended requests are automatically resumed and signed with the new credentials.

If the login fails (you deny access, the provider returns an error, or the timeout expires), the waiting requests get a JSON-RPC error. If a freshly issued token is rejected again right away, `mcp-passport` reports an authentication loop instead of reopening the browser.

## 8. Customizing Landing Pages
By default, `mcp-passport` provides a clean, modern "Authentication Successful" or "Authentication Failed" page. You can customize these by providing a directory with your own HTML files:

1. Create a directory (e.g., `my-templates/`).
2. Add `success.html` and `failure.html`.
3. In `failure.html`, you can use the `{{ERROR_MESSAGE}}` placeholder to display the specific error that occurred.
4. Run `mcp-passport` with `--template-dir my-templates/` or set the `MCP_PASSPORT_TEMPLATE_DIR` environment variable.

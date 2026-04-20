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
| Remote SSE URL | `MCP_PASSPORT_REMOTE_SSE_URL` | The SSE endpoint for notifications. |
| Discovery URL | `MCP_PASSPORT_OIDC_DISCOVERY_URL` | The `.well-known/openid-configuration` URL. |
| Client ID | `MCP_PASSPORT_OIDC_CLIENT_ID` | Your OIDC client ID (default: `mcp-passport`). |
| Redirect URL | `MCP_PASSPORT_OIDC_REDIRECT_URL` | Local callback URL (default: `http://127.0.0.1:8082/callback`). |
| Template Dir | `MCP_PASSPORT_TEMPLATE_DIR` | Directory containing custom `success.html` and `failure.html`. |

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
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/rpc",
        "MCP_PASSPORT_REMOTE_SSE_URL": "https://mcp.example.com/sse",
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
        "MCP_PASSPORT_REMOTE_MCP_URL": "https://mcp.example.com/rpc",
        "MCP_PASSPORT_REMOTE_SSE_URL": "https://mcp.example.com/sse",
        "MCP_PASSPORT_OIDC_DISCOVERY_URL": "https://auth.example.com/realms/mcp/.well-known/openid-configuration"
      },
      "trust": true
    }
  }
}
```

## 5. Troubleshooting

### Logs
`mcp-passport` stores logs in the `logs/` directory relative to the binary's location.
- `logs/mcp-passport.log`: Daily rotating debug logs.

### Vault Issues
If authentication keeps failing, you can clear the stored tokens from your system's keychain.
- **macOS**: Use "Keychain Access" and search for `mcp-passport`.
- **Linux**: Use `secret-tool lookup service mcp-passport` or similar.
- **Windows**: Use "Credential Manager".

### Loopback Port Collision
If port `8082` is occupied, change the `MCP_PASSPORT_OIDC_REDIRECT_URL` (e.g., to `http://127.0.0.1:9999/callback`) and ensure this new URI is whitelisted in your OIDC provider.

## 6. How the "Airlock" Works
When you send a request and your token is missing or expired:
1. `mcp-passport` detects the `401` or missing token.
2. It suspends all outgoing requests.
3. Your default browser opens automatically to the login page.
4. Once you log in, `mcp-passport` captures the code, exchanges it for a DPoP-bound token, and stores it securely.
5. The suspended requests are automatically resumed and signed with the new credentials.

## 7. Customizing Landing Pages
By default, `mcp-passport` provides a clean, modern "Authentication Successful" or "Authentication Failed" page. You can customize these by providing a directory with your own HTML files:

1. Create a directory (e.g., `my-templates/`).
2. Add `success.html` and `failure.html`.
3. In `failure.html`, you can use the `{{ERROR_MESSAGE}}` placeholder to display the specific error that occurred.
4. Run `mcp-passport` with `--template-dir my-templates/` or set the `MCP_PASSPORT_TEMPLATE_DIR` environment variable.

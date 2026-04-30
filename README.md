# Example MCP Server with OAuth 2.0

A complete, runnable example of an OAuth-protected [MCP](https://modelcontextprotocol.io) server using [mcp-authflow](https://github.com/brooksmcmillin/mcp-authflow) and [mcp-authflow-resource](https://github.com/brooksmcmillin/mcp-authflow-resource).

**What's inside:**

- **Auth server** — OAuth 2.0 authorization server with client registration, authorization code + PKCE, client credentials, and token introspection
- **Resource server** — MCP server exposing a notes CRUD API, protected by OAuth tokens
- **Example client** — Python script demonstrating the full flow end-to-end

## Quick Start

```bash
docker compose up
```

This starts:
- PostgreSQL (token storage)
- Auth server on `http://localhost:9000`
- Resource server (MCP) on `http://localhost:9001`

## Using with MCP Clients

MCP clients discover auth configuration automatically via `.well-known` endpoints.
When you connect a client to the resource server, it will:

1. Get a `401` with a pointer to the auth server
2. Discover registration, authorization, and token endpoints
3. Register itself as an OAuth client
4. Open your browser for authorization (you click "Approve")
5. Exchange the authorization code for an access token
6. Use the token for all subsequent MCP requests

### Claude Code

Add to `.mcp.json` in your project root (or `~/.claude/.mcp.json` for global):

```json
{
  "mcpServers": {
    "notes": {
      "type": "streamable-http",
      "url": "http://localhost:9001/mcp"
    }
  }
}
```

### Claude Desktop

Add to your Claude Desktop MCP config:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "notes": {
      "url": "http://localhost:9001/mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "notes": {
      "url": "http://localhost:9001/mcp",
      "transport": "streamable-http"
    }
  }
}
```

### Client Quirks

| Client | OAuth Support | Notes |
|--------|--------------|-------|
| Claude Code | Full (authorization_code + PKCE) | Opens browser for consent. Uses `http://127.0.0.1:<port>/callback` as redirect URI with ephemeral port. |
| Claude Desktop | Full (authorization_code + PKCE) | Opens system browser for consent. Config path varies by OS. |
| Cursor | Partial | MCP support available; OAuth discovery support may vary by version. If OAuth doesn't work automatically, use the manual token flow below. |
| MCP Inspector | Manual tokens only | Pass `--header "Authorization: Bearer TOKEN"` (see Step-by-Step Tutorial). |

**Common issues:**

- **Port conflicts:** If `localhost:9000` or `localhost:9001` are in use, change the ports in `docker-compose.yml` and update the `AUTH_SERVER_URL` / `RESOURCE_SERVER_URL` environment variables.
- **Loopback redirect URIs:** The auth server accepts any port for `127.0.0.1` and `localhost` redirect URIs per [RFC 8252 §7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3), so native MCP clients can bind ephemeral ports.
- **Token expiry:** Tokens are valid for 1 hour. If tools stop working, the client should re-authorize.

## Step-by-Step Tutorial (Manual)

For programmatic or manual testing without an MCP client.

### 1. Register an OAuth Client

**For authorization code flow (interactive):**

```bash
curl -s -X POST http://localhost:9000/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-app",
    "redirect_uris": ["http://127.0.0.1/callback"],
    "grant_types": ["authorization_code"],
    "token_endpoint_auth_method": "none",
    "scope": "notes:read notes:write"
  }' | jq .
```

**For client credentials flow (machine-to-machine):**

```bash
curl -s -X POST http://localhost:9000/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-service",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_post",
    "scope": "notes:read notes:write"
  }' | jq .
```

### 2a. Get a Token (Authorization Code + PKCE)

Generate a PKCE code verifier and challenge:

```bash
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
```

Open the authorization URL in a browser:

```
http://localhost:9000/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http://127.0.0.1/callback&scope=notes:read%20notes:write&state=test&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

Click "Approve", then extract the `code` from the redirect URL and exchange it:

```bash
curl -s -X POST http://localhost:9000/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=http://127.0.0.1/callback" \
  -d "client_id=CLIENT_ID" \
  -d "code_verifier=$CODE_VERIFIER" | jq .
```

### 2b. Get a Token (Client Credentials)

```bash
curl -s -X POST http://localhost:9000/token \
  -d "grant_type=client_credentials" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "scope=notes:read notes:write" | jq .
```

### 3. Call MCP Tools with the Token

```bash
npx @anthropic-ai/mcp-inspector \
  --transport streamable-http \
  --url http://localhost:9001/mcp \
  --header "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. See Rejection Without a Token

```bash
curl -s -X POST http://localhost:9001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}}'
```

Returns `401 Unauthorized`.

### 5. Run the Full Demo

```bash
docker compose --profile demo run --rm example-client
```

## Architecture

```
                                  ┌──────────────────┐
                                  │    PostgreSQL     │
                                  │  (token storage)  │
                                  └────────▲─────────┘
                                           │
┌──────────────┐    register/authorize ┌───┴───────────┐    introspect     ┌──────────────────┐
│  MCP Client  │ ───────────────────►  │  Auth Server  │ ◄──────────────── │  Resource Server  │
│              │                       │  :9000        │                   │  (MCP) :9001      │
│              │    MCP + Bearer       │               │                   │                   │
│              │ ─────────────────────────────────────────────────────────► │  Notes API        │
└──────────────┘                       └───────────────┘                   └──────────────────┘
```

**Authorization code flow (MCP clients):**
1. Client connects to the MCP server, gets `401`
2. Client discovers auth server via `.well-known/oauth-protected-resource`
3. Client registers via `/register` (dynamic client registration)
4. Client opens browser to `/authorize` with PKCE challenge
5. User clicks "Approve" on the consent page
6. Auth server redirects back with authorization code
7. Client exchanges code + PKCE verifier for access token at `/token`
8. Client connects to MCP server with `Authorization: Bearer <token>`
9. MCP server introspects the token with the auth server
10. If valid, tool calls proceed; otherwise, `401`

**Client credentials flow (machine-to-machine):**
1. Client registers with `client_secret_post` auth method
2. Client exchanges `client_id` + `client_secret` for token at `/token`
3. Same steps 8-10 as above

## OAuth Endpoints (Auth Server)

| Method | Path | RFC | Description |
|--------|------|-----|-------------|
| GET | `/.well-known/oauth-authorization-server` | 8414 | Server metadata |
| POST | `/register` | 7591 | Dynamic client registration |
| GET/POST | `/authorize` | 6749 | Authorization endpoint (consent page) |
| POST | `/token` | 6749 | Token endpoint (auth code + client credentials) |
| POST | `/introspect` | 7662 | Token introspection |

## MCP Tools (Resource Server)

| Tool | Scope | Description |
|------|-------|-------------|
| `list_notes` | `notes:read` | List all notes |
| `get_note` | `notes:read` | Get a note by ID |
| `create_note` | `notes:write` | Create a new note |
| `update_note` | `notes:write` | Update an existing note |
| `delete_note` | `notes:write` | Delete a note |

## Running Without Docker

```bash
# Install dependencies
pip install -e .

# Terminal 1: Auth server (uses in-memory storage without DATABASE_URL)
python -m auth_server

# Terminal 2: Resource server
python -m resource_server

# Terminal 3: Example client
python -m example_client
```

## Configuration

### Auth Server

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_SERVER_URL` | `http://localhost:9000` | Public URL of the auth server |
| `DATABASE_URL` | _(none, uses memory)_ | PostgreSQL connection string |

### Resource Server

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_SERVER_PUBLIC_URL` | `http://localhost:9000` | Auth server URL for client-facing discovery metadata |
| `INTROSPECTION_URL` | `{AUTH_SERVER_PUBLIC_URL}/introspect` | Token introspection endpoint (can use internal URL) |
| `RESOURCE_SERVER_URL` | `http://localhost:9001` | Public URL of this server |

## License

MIT

# Example MCP Server with OAuth 2.0

A complete, runnable example of an OAuth-protected [MCP](https://modelcontextprotocol.io) server using [mcp-authflow](https://github.com/brooksmcmillin/mcpauth) and [mcp-authflow-resource](https://github.com/brooksmcmillin/mcpauth-resource).

**What's inside:**

- **Auth server** — OAuth 2.0 authorization server with client registration, token issuance, and introspection
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

## Step-by-Step Tutorial

### 1. Register an OAuth Client

```bash
curl -s -X POST http://localhost:9000/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "my-app", "scope": "notes:read notes:write"}' | jq .
```

Response:
```json
{
  "client_id": "client_a1b2c3d4e5f6a7b8",
  "client_secret": "abc123...",
  "client_name": "my-app",
  "scope": "notes:read notes:write",
  "grant_types_supported": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

Save the `client_id` and `client_secret`.

### 2. Get an Access Token

```bash
curl -s -X POST http://localhost:9000/token \
  -d "grant_type=client_credentials" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "scope=notes:read notes:write" | jq .
```

Response:
```json
{
  "access_token": "xyz789...",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "notes:read notes:write"
}
```

### 3. Call MCP Tools with the Token

The MCP server runs at `http://localhost:9001/mcp`. Use any MCP client with the bearer token in the `Authorization` header.

Using the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

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

The server returns `401 Unauthorized` — no valid token, no access.

### 5. Run the Full Demo

```bash
docker compose --profile demo run --rm example-client
```

This runs the example client which registers, authenticates, calls tools, and shows rejection — all automatically.

## Architecture

```
                                  ┌──────────────────┐
                                  │    PostgreSQL     │
                                  │  (token storage)  │
                                  └────────▲─────────┘
                                           │
┌──────────────┐    register/token    ┌────┴──────────┐    introspect     ┌──────────────────┐
│  MCP Client  │ ──────────────────►  │  Auth Server  │ ◄──────────────── │  Resource Server  │
│              │                      │  :9000        │                   │  (MCP) :9001      │
│              │    MCP + Bearer      │               │                   │                   │
│              │ ────────────────────────────────────────────────────────► │  Notes API        │
└──────────────┘                      └───────────────┘                   └──────────────────┘
```

1. Client registers with the auth server and gets credentials
2. Client exchanges credentials for an access token
3. Client connects to the MCP server with `Authorization: Bearer <token>`
4. MCP server introspects the token with the auth server to verify it
5. If valid, the tool call proceeds; otherwise, 401

## OAuth Endpoints (Auth Server)

| Method | Path | RFC | Description |
|--------|------|-----|-------------|
| GET | `/.well-known/oauth-authorization-server` | 8414 | Server metadata |
| POST | `/register` | 7591 | Dynamic client registration |
| POST | `/token` | 6749 | Token endpoint (client_credentials) |
| POST | `/introspect` | 7662 | Token introspection |

## MCP Tools (Resource Server)

| Tool | Scope | Description |
|------|-------|-------------|
| `list_notes` | `notes:read` | List all notes |
| `get_note` | `notes:read` | Get a note by ID |
| `create_note` | `notes:write` | Create a new note |
| `update_note` | `notes:write` | Update an existing note |
| `delete_note` | `notes:write` | Delete a note |

## Using with Claude Desktop

Add to your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

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

Claude Desktop will discover the auth server via the `.well-known` endpoints and handle the OAuth flow automatically.

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
| `AUTH_SERVER_URL` | `http://localhost:9000` | Auth server URL for metadata |
| `INTROSPECTION_URL` | `{AUTH_SERVER_URL}/introspect` | Token introspection endpoint |
| `RESOURCE_SERVER_URL` | `http://localhost:9001` | Public URL of this server |

## License

MIT

"""Example client that demonstrates the full OAuth + MCP flow.

Usage:
    python -m example_client.demo

This script:
1. Registers a client with the auth server
2. Obtains an access token via client_credentials
3. Connects to the MCP server and calls tools
4. Demonstrates token rejection without valid credentials
"""

import asyncio
import os
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import TextContent

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:9000")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "http://localhost:9001")


async def register_client(http: httpx.AsyncClient) -> tuple[str, str]:
    """Register an OAuth client and return (client_id, client_secret)."""
    resp = await http.post(
        f"{AUTH_SERVER_URL}/register",
        json={
            "client_name": "example-demo",
            "scope": "notes:read notes:write",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    resp.raise_for_status()
    data = resp.json()
    return data["client_id"], data["client_secret"]


async def get_token(
    http: httpx.AsyncClient,
    client_id: str,
    client_secret: str,
    scope: str = "notes:read notes:write",
) -> str:
    """Get an access token via client_credentials grant."""
    resp = await http.post(
        f"{AUTH_SERVER_URL}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def call_tool(
    session: ClientSession, name: str, arguments: dict[str, str] | None = None
) -> str:
    """Call an MCP tool and return the text result."""
    result = await session.call_tool(name, arguments=arguments or {})
    texts = [c.text for c in result.content if isinstance(c, TextContent)]
    return "\n".join(texts)


async def demo_with_token(token: str) -> None:
    """Connect to the MCP server with a token and exercise the notes API."""
    mcp_url = f"{RESOURCE_SERVER_URL}/mcp"
    headers = {"Authorization": f"Bearer {token}"}

    async with (
        streamablehttp_client(mcp_url, headers=headers) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        tools = await session.list_tools()
        print(f"\nAvailable tools: {[t.name for t in tools.tools]}")

        print("\n--- list_notes (empty) ---")
        print(await call_tool(session, "list_notes"))

        print("\n--- create_note ---")
        print(
            await call_tool(
                session,
                "create_note",
                {"title": "Hello World", "content": "This is my first note."},
            )
        )

        print("\n--- create_note ---")
        print(
            await call_tool(
                session,
                "create_note",
                {"title": "Shopping List", "content": "Eggs, milk, bread."},
            )
        )

        print("\n--- list_notes ---")
        print(await call_tool(session, "list_notes"))

        print("\n--- get_note 1 ---")
        print(await call_tool(session, "get_note", {"note_id": "1"}))

        print("\n--- update_note 1 ---")
        print(
            await call_tool(
                session,
                "update_note",
                {"note_id": "1", "content": "Updated content!"},
            )
        )

        print("\n--- delete_note 2 ---")
        print(await call_tool(session, "delete_note", {"note_id": "2"}))

        print("\n--- list_notes (after changes) ---")
        print(await call_tool(session, "list_notes"))


async def demo_without_token() -> None:
    """Attempt to connect without a token — should be rejected."""
    mcp_url = f"{RESOURCE_SERVER_URL}/mcp"
    print("\n--- Connecting WITHOUT a token ---")
    try:
        async with (
            streamablehttp_client(mcp_url) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            print("ERROR: Connection succeeded without a token (unexpected)")
    except Exception as e:
        print(f"Rejected as expected: {type(e).__name__}: {e}")


async def main() -> None:
    print("=" * 60)
    print("  MCP Auth Example — Notes API Demo")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=10.0) as http:
        # Step 1: Register
        print("\n[1] Registering OAuth client...")
        client_id, client_secret = await register_client(http)
        print(f"    client_id:     {client_id}")
        print(f"    client_secret: {client_secret[:8]}...")

        # Step 2: Get token
        print("\n[2] Requesting access token (client_credentials)...")
        token = await get_token(http, client_id, client_secret)
        print(f"    access_token:  {token[:8]}...")

        # Step 3: Introspect token
        print("\n[3] Introspecting token...")
        resp = await http.post(
            f"{AUTH_SERVER_URL}/introspect",
            data={"token": token},
        )
        print(f"    {resp.json()}")

    # Step 4: Use MCP tools with token
    print("\n[4] Calling MCP tools WITH a valid token...")
    await demo_with_token(token)

    # Step 5: Attempt without token
    print("\n[5] Calling MCP tools WITHOUT a token...")
    await demo_without_token()

    print("\n" + "=" * 60)
    print("  Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

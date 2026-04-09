"""Run the MCP resource server."""

import uvicorn

from resource_server.app import starlette_app

uvicorn.run(starlette_app, host="0.0.0.0", port=9001, log_level="info")  # noqa: S104

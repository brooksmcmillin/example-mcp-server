"""Run the authorization server."""

import uvicorn

from auth_server.app import app

uvicorn.run(app, host="0.0.0.0", port=9000, log_level="info")  # noqa: S104

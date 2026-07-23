FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency resolution.
# Pin to a released version and digest so builds are reproducible and not
# exposed to a compromised/rolled-forward floating tag (index digest covers
# all platforms). Update deliberately when bumping uv.
COPY --from=ghcr.io/astral-sh/uv:0.11.31@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437 /uv /usr/local/bin/uv

# Copy project metadata and install dependencies
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-dev --frozen

# Copy application code
COPY auth_server/ auth_server/
COPY resource_server/ resource_server/
COPY example_client/ example_client/

# Default: run auth server. Override CMD in docker-compose.
CMD ["uv", "run", "python", "-m", "auth_server"]

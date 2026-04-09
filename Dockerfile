FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project metadata and install dependencies
COPY pyproject.toml README.md ./
RUN uv sync --no-dev --frozen 2>/dev/null || uv sync --no-dev

# Copy application code
COPY auth_server/ auth_server/
COPY resource_server/ resource_server/
COPY example_client/ example_client/

# Default: run auth server. Override CMD in docker-compose.
CMD ["uv", "run", "python", "-m", "auth_server"]

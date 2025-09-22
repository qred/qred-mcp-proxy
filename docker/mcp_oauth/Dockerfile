# Build stage with explicit platform specification
FROM python:3.13-alpine AS uv

# Copy uv packages to python image
COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

# Update Alpine packages to get latest security patches
RUN apk update && apk upgrade && apk add --no-cache ca-certificates && apk cache clean

# Install the project into /app
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev --no-editable

# Add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable \
    && uv pip install .

# Final stage with explicit platform specification
FROM python:3.13-alpine

# Update Alpine packages and install curl for health checks
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates curl && \
    apk cache clean

# Create non-root user
RUN addgroup -g 1001 -S mcpoauth && \
    adduser -S mcpoauth -u 1001 -G mcpoauth

COPY --from=uv --chown=mcpoauth:mcpoauth /app/.venv /app/.venv

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Switch to non-root user
USER mcpoauth

# Expose port
EXPOSE 8001

# Run the application
ENTRYPOINT ["mcp-oauth"]

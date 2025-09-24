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

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable \
    && uv pip install .

# Final stage with explicit platform specification
FROM python:3.13-alpine

# Update Alpine packages and install Java (OpenJDK) and Node.js for running JAR files and npx
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates openjdk21-jre nodejs npm util-linux && \
    apk cache clean

# Create non-root user
RUN addgroup -g 1001 -S app && \
    adduser -S app -u 1001 -G app

# Switch to app user and create npm config/cache directories
USER app
WORKDIR /home/app

# Configure npm to install packages locally for the app user
RUN npm config set prefix /home/app/.npm-global
ENV PATH="/home/app/.npm-global/bin:$PATH"

# Install mcp-remote as the app user to avoid permission issues
RUN npm install -g mcp-remote

# Switch back to root for copying files and setting permissions, then switch to app user
# Note: Root is required temporarily to fix ECS volume permissions in entrypoint.sh
# The actual application process runs as non-root user via setpriv in entrypoint
USER root
WORKDIR /app
COPY --from=uv --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app servers.json /app/config/servers.json
COPY --chmod=755 entrypoint.sh /entrypoint.sh

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:/home/app/.npm-global/bin:$PATH"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["mcp-proxy"]

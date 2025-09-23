#!/bin/sh
set -e

echo "Fixing permissions for ECS mounted volumes..."

# Create and fix permissions for keepalive logs (always needed for the application)
if [ ! -d "/app/keepalive" ]; then
    echo "Creating /app/keepalive directory"
    mkdir -p /app/keepalive
fi
echo "Setting permissions for /app/keepalive"
chown -R app:app /app/keepalive
chmod -R 755 /app/keepalive

# Fix permissions for SonarQube storage (if directory exists)
if [ -d "/app/sonarqube/storage" ]; then
    echo "Setting permissions for /app/sonarqube/storage"
    chown -R app:app /app/sonarqube/storage
    chmod -R 755 /app/sonarqube/storage
fi

echo "Switching to app user and starting command..."

# Check if the first argument starts with mcp-proxy
if [ $# -eq 0 ] || [ "${1#mcp-proxy}" = "$1" ]; then
    # No arguments or first argument doesn't start with mcp-proxy
    # Add mcp-proxy as prefix
    set -- mcp-proxy "$@"
fi

# Drop privileges and execute the main command as app user using setpriv
# Preserve environment variables including npm paths
exec setpriv --reuid=app --regid=app --init-groups \
    env PATH="/app/.venv/bin:/home/app/.npm-global/bin:$PATH" \
    HOME="/home/app" \
    "$@"

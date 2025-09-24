#!/bin/bash
set -e

# Build and deploy script for MCP OAuth service

echo "Building MCP OAuth Docker image..."

# Generate/update lockfile
echo "Updating uv.lock..."
uv lock

PUSH=0
ARTIFACTS_ACCOUNT_ID=123456789012  # Replace with actual account ID if needed

# Parse flags
for arg in "$@"; do
  case $arg in
    --push)
      PUSH=1
      shift
      ;;
    --account_id)
      ARTIFACTS_ACCOUNT_ID=$2
      shift 2
      ;;
    *)
      # ignore unknown flags for now
      ;;
  esac

done

CONTAINER_IMAGE_TAG=sha-$(git rev-parse HEAD)
SERVICE="mcp-oauth"
docker build -t $ARTIFACTS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/$SERVICE\:latest -t $ARTIFACTS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/$SERVICE:$CONTAINER_IMAGE_TAG .

if [ "$PUSH" -eq 1 ]; then
  CALLER_ACCOUNT_ID=$(aws sts get-caller-identity --output json | jq '.Account' | sed 's/"//g')
  if [ "$CALLER_ACCOUNT_ID" != "$ARTIFACTS_ACCOUNT_ID" ]; then
    echo "Must have a logged in session in artificats account $ARTIFACTS_ACCOUNT_ID for pushing image to ecr but are in $CALLER_ACCOUNT_ID"
    exit 1
  fi

  aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin $ARTIFACTS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com
  docker push $ARTIFACTS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/$SERVICE:$CONTAINER_IMAGE_TAG
  docker push $ARTIFACTS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/$SERVICE:latest
fi

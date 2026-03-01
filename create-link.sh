#!/bin/bash
set -e

# Usage: ./create-link.sh <target_url> [custom_short_id]
# Example: ./create-link.sh https://example.com
# Example: ./create-link.sh https://example.com mylink

if [ -z "$1" ]; then
    echo "Usage: $0 <target_url> [custom_short_id]"
    echo "Example: $0 https://example.com"
    echo "Example: $0 https://example.com mylink"
    exit 1
fi

TARGET_URL="$1"
CUSTOM_ID="${2:-}"
CONTAINER_NAME="lnky-standalone"
PORT="8080"

echo "Building Docker image..."
docker build -t lnky .

echo "Stopping any existing container..."
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

echo "Starting lnky container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$PORT:$PORT" \
    -e AWS_REGION="${AWS_REGION:-us-east-1}" \
    -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    -e URLS_TABLE="${URLS_TABLE:-URLs}" \
    -e ANALYTICS_TABLE="${ANALYTICS_TABLE:-Analytics}" \
    -e ENABLE_ADMIN_ENDPOINTS=true \
    lnky

echo "Waiting for service to start..."
MAX_RETRIES=10
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
        break
    fi
    if [ $i -eq $MAX_RETRIES ]; then
        echo "Service failed to start after $MAX_RETRIES attempts"
        exit 1
    fi
    sleep 1
done

# Build JSON payload
if [ -n "$CUSTOM_ID" ]; then
    JSON_PAYLOAD=$(jq -n --arg url "$TARGET_URL" --arg id "$CUSTOM_ID" '{url: $url, shortId: $id}')
else
    JSON_PAYLOAD=$(jq -n --arg url "$TARGET_URL" '{url: $url}')
fi

echo "Creating short link..."
RESPONSE=$(curl -s -X POST "http://localhost:$PORT/api/shorten" \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD")

echo ""
echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

echo ""
echo "Container is running. To stop it, run:"
echo "  docker stop $CONTAINER_NAME"
echo ""
echo "To view logs:"
echo "  docker logs -f $CONTAINER_NAME"

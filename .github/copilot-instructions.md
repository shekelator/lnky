# Lnky - AI Coding Instructions

## Architecture Overview

**Lnky** is a FastAPI-based URL shortener designed for AWS App Runner with DynamoDB backend. The entire application logic lives in `main.py` (~400 lines) as a single-file service.

### Key Components
- **FastAPI app** with lifespan context manager for startup/shutdown
- **Synchronous analytics logging**: Click tracking is written directly in the redirect handler (no background worker)
- **DynamoDB tables**: `URLs` (hash key: `short_id`) and `Analytics` (composite key: `short_id` + `timestamp`)
- **Feature flags**: All endpoints can be disabled via `ENABLE_SHORTEN`, `ENABLE_REDIRECT`, `ENABLE_STATS` env vars

### Data Flow
1. `/api/shorten` → DynamoDB `put_item` → Returns short URL with proper `X-Forwarded-Host`/`X-Forwarded-Proto` handling for proxies
2. `/{short_id}` → DynamoDB `get_item` → Write analytics synchronously → 302 redirect
3. `/api/stats/{short_id}` → DynamoDB `query` on Analytics table → Return click count + details

## Development Workflow

### Local Setup (Docker Compose - Recommended)
```bash
docker-compose up --build  # Starts DynamoDB Local + app + auto-creates tables
```

The compose stack:
- **dynamodb-local**: Runs on `:8000`, persists to `./docker/dynamodb`
- **dynamodb-setup**: One-shot container that creates tables using AWS CLI
- **lnky**: App on `:8080`, configured to use local DynamoDB

### Testing Strategy
```bash
docker-compose up -d          # Must be running first
pytest -v test_main.py        # Runs against live compose stack
pytest -m "not slow"          # Skip slow tests
```

**Critical**: Tests in `test_main.py` are integration tests that:
- Connect to `http://localhost:8080` (compose service) and `http://localhost:8000` (DynamoDB Local)
- Use `wait_for_service` fixture with retries to ensure stack is ready
- Clean up test data via `cleanup_test_data` fixture scanning for `test.example.com` URLs
- Use real HTTP client (`httpx`) and DynamoDB client, not mocks

### DynamoDB Local Management
Use AWS CLI with `--endpoint-url http://localhost:8000`:
```bash
aws dynamodb scan --table-name URLs --endpoint-url http://localhost:8000
aws dynamodb delete-item --table-name URLs --key '{"short_id": {"S": "xyz"}}' --endpoint-url http://localhost:8000
```

## Code Patterns & Conventions

### Settings Management
Uses `pydantic-settings` with `BaseSettings`:
- All config via env vars (e.g., `AWS_REGION`, `AWS_ENDPOINT`)
- Aliases support both formats: `aws_region` or `AWS_REGION`
- `AWS_ENDPOINT` triggers local mode with dummy credentials

### DynamoDB Client Creation
`get_dynamodb_client()` returns boto3 client with conditional logic:
- If `AWS_ENDPOINT` set → inject dummy credentials for local dev
- Uses `botocore.Config` for region configuration
- Global `dynamodb_client` initialized in `lifespan()` startup

### Analytics Tracking
- Analytics are written synchronously in the redirect handler.
- Each redirect request records analytics data directly to DynamoDB before issuing the 302 response.
- This approach is simple and reliable, but may add a small amount of latency to redirects.
- There is no background queue or worker; all analytics logic runs inline with the request.

### Privacy: IP Hashing
`hash_ip()` extracts IP (strips port), SHA256 hashes it before storing in Analytics table

### Error Handling
- DynamoDB exceptions → Log + raise `HTTPException` with 500 status
- Validation errors from Pydantic → FastAPI auto-returns 422
- Custom ID conflicts → 409 status
- Missing short_id on redirect → 404

## AWS Deployment Context

### App Runner Requirements
- Expects `PORT` env var (defaults to 8080)
- IAM policy in `apprunner-iam-policy.json` grants only `GetItem`, `PutItem`, `Query` on specific tables
- CloudFormation template in `dynamodb-tables.yaml` defines PAY_PER_REQUEST tables

### Short URL Generation
- Auto-generated: `shortuuid.uuid()[:9]` (9 chars from shortuuid)
- Custom: Client provides `shortId` in request, checked for uniqueness via `get_item`

## Common Gotchas

1. **Devcontainer**: Uses Python 3.12 with Docker-in-Docker feature for running compose inside container
2. **URL validation**: Only accepts `http://` or `https://` prefixed URLs (see `is_valid_url()`)
3. **Request headers**: App respects `X-Forwarded-Host` and `X-Forwarded-Proto` for short URL construction
4. **Analytics timing**: Background worker may lag; use `await analytics_queue.join()` if you need synchronous guarantees
5. **Table names**: Configurable via `URLS_TABLE`/`ANALYTICS_TABLE`, defaults to "URLs"/"Analytics"

## File Structure
- `main.py`: Entire application (models, endpoints, lifespan, worker)
- `test_main.py`: Integration tests (requires compose stack running)
- `requirements.txt`: Pinned dependencies (FastAPI, boto3, shortuuid, pytest)
- `docker-compose.yml`: 3-service local dev environment
- `dynamodb-tables.yaml`: CloudFormation for AWS tables
- `apprunner-iam-policy.json`: Minimal permissions for App Runner role

# lnky
Link shortener built with Python FastAPI

## Features
- URL shortening with automatic or custom short IDs
- Analytics tracking for URL clicks
- Configurable endpoints via environment variables
- DynamoDB backend (works with DynamoDB Local for development)

## Running

### Docker standalone

```bash
docker build -t lnky .
docker run -p 8080:8080 lnky
```

### Local development with DynamoDB Local

```bash
# Install dependencies
pip install -r requirements.txt

# Run a DynamoDB Local instance
docker run -p 8000:8000 amazon/dynamodb-local

# Run the application
AWS_ENDPOINT=http://localhost:8000 python main.py
```

### Docker Compose (recommended for development)

Run both the application and DynamoDB Local together:

```bash
docker-compose up
```

Or to rebuild the containers:

```bash
docker-compose up --build
```

To run in detached mode:

```bash
docker-compose up -d
```

To stop the containers:

```bash
docker-compose down
```

## Environment Variables

### Required for AWS deployment:
* `AWS_REGION` - The region where your DynamoDB tables are located (default: us-east-1)

### Optional:
* `PORT` - Port to run the server on (default: 8080, AppRunner sets this automatically)
* `AWS_ENDPOINT` - Custom DynamoDB endpoint for local development
* `URLS_TABLE` - Name of the URLs table (default: "URLs")
* `ANALYTICS_TABLE` - Name of the Analytics table (default: "Analytics")

### Feature flags:
* `ENABLE_SHORTEN` - Enable the /api/shorten endpoint (default: true)
* `ENABLE_REDIRECT` - Enable the /{short_id} redirect endpoint (default: true)
* `ENABLE_STATS` - Enable the /api/stats/{short_id} endpoint (default: true)

## API Examples

```bash
# Generate a random shortID
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Use a custom shortID
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com", "shortId":"example"}'

# Access a shortened URL
curl -L http://localhost:8080/example

# Get stats for a short URL
curl http://localhost:8080/api/stats/example
```

## Managing DynamoDB Data

When using DynamoDB Local, you can use these AWS CLI commands:

```bash
# List all entries in the URLs table
aws dynamodb scan --table-name URLs --endpoint-url http://localhost:8000

# Get a specific URL by shortID
aws dynamodb get-item --table-name URLs \
  --key '{"short_id": {"S": "example"}}' \
  --endpoint-url http://localhost:8000

# Delete a URL by shortID
aws dynamodb delete-item --table-name URLs \
  --key '{"short_id": {"S": "example"}}' \
  --endpoint-url http://localhost:8000

# View analytics data
aws dynamodb scan --table-name Analytics --endpoint-url http://localhost:8000
```

When using with a real AWS DynamoDB instance, omit the `--endpoint-url` parameter.

## Running Tests

```bash
# Make sure docker-compose is running first
docker-compose up -d

# Install test dependencies
pip install -r requirements.txt

# Run tests
pytest -v test_main.py

# Run tests excluding slow tests
pytest -v test_main.py -m "not slow"

# Run with coverage
pytest --cov=main test_main.py
```

## Deployment

Designed to run in AWS App Runner with DynamoDB backend.

## Resources
* [FastAPI Documentation](https://fastapi.tiangolo.com/)
* [Deploying DynamoDB locally on your computer](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html)

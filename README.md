# lnky
Link shortener

### Running

#### Docker standalone

```
docker build -t lnky .
docker run -p 8080:8080 lnky
```

#### Local development with DynamoDB Local

```
# run a dynamo-local instance
docker run -p 8000:8000 amazon/dynamodb-local
AWS_ENDPOINT=http://localhost:8000 go run main.go
```

#### Docker Compose (recommended for development)

Run both the application and DynamoDB Local together:

```
docker-compose up
```

Or to rebuild the containers:

```
docker-compose up --build
```

To run in detached mode:

```
docker-compose up -d
```

To stop the containers:

```
docker-compose down
```

### Deployment

Runs in App runner. Environment variables:
* `AWS_REGION` (the region where your DynamoDB tables are located)
* `PORT` (AppRunner will set this automatically)
* `URLS_TABLE` (optional, defaults to "URLs")
* `ANALYTICS_TABLE` (optional, defaults to "Analytics")


### Testing

```
# Generate a random shortID
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Use a custom shortID
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com", "shortId":"example"}'

curl http://localhost:8080/LHD-CMPHg
```

### Managing DynamoDB Data

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

## Resources
* [Deploying DynamoDB locally on your computer](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html)

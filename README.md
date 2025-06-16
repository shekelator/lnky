# lnky
Link shortener

### Running

```
docker build -t lnky .
docker run -p 8080:8080 lnky
```

```
# run a dynamo-local instance
docker run -p 8000:8000 amazon/dynamodb-local
# Create the URLs table
aws dynamodb create-table \
  --table-name URLs \
  --attribute-definitions AttributeName=short_id,AttributeType=S \
  --key-schema AttributeName=short_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --endpoint-url http://localhost:8000

# Create the Analytics table
aws dynamodb create-table \
  --table-name Analytics \
  --attribute-definitions AttributeName=short_id,AttributeType=S \
  --key-schema AttributeName=short_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --endpoint-url http://localhost:8000

AWS_ENDPOINT=http://localhost:8000 go run main.go
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

# read
aws dynamodb scan --table-name URLs --endpoint-url http://localhost:8000
aws dynamodb scan --table-name Analytics --endpoint-url http://localhost:8000

```

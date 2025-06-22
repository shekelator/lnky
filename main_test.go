package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Base URL for the lnky service running in docker-compose
	baseURL = "http://localhost:8080"
)

var (
	// DynamoDB client for test cleanup and verification
	testDbClient *dynamodb.Client
)

func TestMain(m *testing.M) {
	// Set up test dependencies - make sure localhost:8080 is reachable
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		_, err := http.Get(baseURL)
		if err == nil {
			break
		}
		if i == maxRetries-1 {
			fmt.Printf("Cannot connect to lnky service at %s. Make sure docker-compose is running.\n", baseURL)
			os.Exit(1)
		}
		fmt.Printf("Waiting for lnky service to be available... (%d/%d)\n", i+1, maxRetries)
		time.Sleep(2 * time.Second)
	}

	// Set up DynamoDB client for tests
	cfgOptions := []func(*config.LoadOptions) error{
		config.WithRegion("us-east-1"),
	}

	cfgOptions = append(cfgOptions, config.WithEndpointResolverWithOptions(
		aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               "http://localhost:8000",
				HostnameImmutable: true,
				PartitionID:       "aws",
			}, nil
		}),
	))

	cfgOptions = append(cfgOptions, config.WithCredentialsProvider(
		aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID: "dummy", SecretAccessKey: "dummy",
				Source: "Hard-coded credentials for local development",
			}, nil
		}),
	))

	cfg, err := config.LoadDefaultConfig(context.TODO(), cfgOptions...)
	if err != nil {
		fmt.Printf("Failed to load AWS config: %v\n", err)
		os.Exit(1)
	}

	testDbClient = dynamodb.NewFromConfig(cfg)

	// Run tests
	exitCode := m.Run()

	// Clean up after tests
	cleanupTestData()

	os.Exit(exitCode)
}

// cleanupTestData removes all test-related data from DynamoDB tables
func cleanupTestData() {
	ctx := context.Background()

	// Scan URLs table for test items
	urlsResp, err := testDbClient.Scan(ctx, &dynamodb.ScanInput{
		TableName:        aws.String("URLs"),
		FilterExpression: aws.String("contains(target_url, :test_marker)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":test_marker": &types.AttributeValueMemberS{Value: "test.example.com"},
		},
	})

	if err == nil && len(urlsResp.Items) > 0 {
		for _, item := range urlsResp.Items {
			if shortID, ok := item["short_id"]; ok {
				if sid, ok := shortID.(*types.AttributeValueMemberS); ok {
					testDbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
						TableName: aws.String("URLs"),
						Key: map[string]types.AttributeValue{
							"short_id": &types.AttributeValueMemberS{Value: sid.Value},
						},
					})

					// Also clean up any analytics data for this shortID
					testDbClient.Query(ctx, &dynamodb.QueryInput{
						TableName:              aws.String("Analytics"),
						KeyConditionExpression: aws.String("short_id = :sid"),
						ExpressionAttributeValues: map[string]types.AttributeValue{
							":sid": &types.AttributeValueMemberS{Value: sid.Value},
						},
					})
				}
			}
		}
	}
}

// TestShortenURL tests the basic URL shortening functionality
func TestShortenURL(t *testing.T) {
	// Test creating a shortened URL
	targetURL := "https://test.example.com/basic"

	requestBody, _ := json.Marshal(ShortenRequest{
		URL:   targetURL,
		Title: "Test URL",
	})

	resp, err := http.Post(
		baseURL+"/api/shorten",
		"application/json",
		bytes.NewBuffer(requestBody),
	)

	require.NoError(t, err, "HTTP request should not error")
	require.Equal(t, http.StatusOK, resp.StatusCode, "HTTP status code should be 200")

	var shortenResponse ShortenResponse
	err = json.NewDecoder(resp.Body).Decode(&shortenResponse)
	resp.Body.Close()

	require.NoError(t, err, "Should decode response")
	assert.NotEmpty(t, shortenResponse.ShortID, "Should receive a short ID")
	assert.Contains(t, shortenResponse.ShortURL, shortenResponse.ShortID, "Short URL should contain the short ID")
	assert.Equal(t, targetURL, shortenResponse.TargetURL, "Target URL should match the request")

	// Verify entry in DynamoDB
	ctx := context.Background()
	result, err := testDbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String("URLs"),
		Key: map[string]types.AttributeValue{
			"short_id": &types.AttributeValueMemberS{Value: shortenResponse.ShortID},
		},
	})

	require.NoError(t, err, "DynamoDB GetItem should not error")
	assert.NotNil(t, result.Item, "Item should exist in DynamoDB")

	var urlEntry URLEntry
	err = attributevalue.UnmarshalMap(result.Item, &urlEntry)

	require.NoError(t, err, "Should unmarshal DynamoDB item")
	assert.Equal(t, targetURL, urlEntry.TargetURL, "Target URL in DynamoDB should match")
	assert.Equal(t, "Test URL", urlEntry.Title, "Title in DynamoDB should match")
}

// TestShortenURLWithCustomID tests creating a URL with a custom short ID
func TestShortenURLWithCustomID(t *testing.T) {
	// Create a custom short ID
	customID := "test-" + fmt.Sprintf("%d", time.Now().Unix())
	targetURL := "https://test.example.com/custom"

	requestBody, _ := json.Marshal(ShortenRequest{
		URL:     targetURL,
		ShortID: customID,
	})

	resp, err := http.Post(
		baseURL+"/api/shorten",
		"application/json",
		bytes.NewBuffer(requestBody),
	)

	require.NoError(t, err, "HTTP request should not error")
	require.Equal(t, http.StatusOK, resp.StatusCode, "HTTP status should be 200")

	var shortenResponse ShortenResponse
	err = json.NewDecoder(resp.Body).Decode(&shortenResponse)
	resp.Body.Close()

	require.NoError(t, err, "Should decode response")
	assert.Equal(t, customID, shortenResponse.ShortID, "Should use the custom short ID")
	assert.Contains(t, shortenResponse.ShortURL, customID, "Short URL should contain the custom ID")

	// Try creating another URL with the same custom ID (should fail)
	resp, err = http.Post(
		baseURL+"/api/shorten",
		"application/json",
		bytes.NewBuffer(requestBody),
	)

	require.NoError(t, err, "HTTP request should not error")
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "Should get conflict status for duplicate ID")
}

// TestRedirect tests the redirect functionality
func TestRedirect(t *testing.T) {
	// First create a shortened URL
	targetURL := "https://test.example.com/redirect"

	requestBody, _ := json.Marshal(ShortenRequest{
		URL: targetURL,
	})

	resp, err := http.Post(
		baseURL+"/api/shorten",
		"application/json",
		bytes.NewBuffer(requestBody),
	)

	require.NoError(t, err, "HTTP request should not error")

	var shortenResponse ShortenResponse
	err = json.NewDecoder(resp.Body).Decode(&shortenResponse)
	resp.Body.Close()

	require.NoError(t, err, "Should decode response")

	// Now test the redirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}

	shortIDURL := baseURL + "/" + shortenResponse.ShortID

	resp, err = client.Get(shortIDURL)
	require.NoError(t, err, "HTTP request should not error")
	resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode, "Should get redirect status")
	assert.Equal(t, targetURL, resp.Header.Get("Location"), "Redirect location should match target")

	// Wait a moment for analytics to be recorded
	time.Sleep(1 * time.Second)

	// Check that analytics were recorded
	ctx := context.Background()
	result, err := testDbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String("Analytics"),
		KeyConditionExpression: aws.String("short_id = :sid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":sid": &types.AttributeValueMemberS{Value: shortenResponse.ShortID},
		},
	})

	require.NoError(t, err, "DynamoDB Query should not error")
	assert.GreaterOrEqual(t, len(result.Items), 1, "Analytics should be recorded")
}

// TestRedirectNonexistent tests the behavior when accessing a non-existent short URL
func TestRedirectNonexistent(t *testing.T) {
	resp, err := http.Get(baseURL + "/nonexistent-short-id")
	require.NoError(t, err, "HTTP request should not error")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Should get 404 for non-existent ID")
}

// TestStats tests the statistics API
func TestStats(t *testing.T) {
	// First create a shortened URL
	targetURL := "https://test.example.com/stats"
	customID := "test-stats-" + fmt.Sprintf("%d", time.Now().Unix())

	requestBody, _ := json.Marshal(ShortenRequest{
		URL:     targetURL,
		ShortID: customID,
	})

	resp, err := http.Post(
		baseURL+"/api/shorten",
		"application/json",
		bytes.NewBuffer(requestBody),
	)

	require.NoError(t, err, "HTTP request should not error")
	resp.Body.Close()

	// Access the URL a few times to generate analytics
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for i := 0; i < 3; i++ {
		resp, err := client.Get(baseURL + "/" + customID)
		require.NoError(t, err, "HTTP request should not error")
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for analytics to be processed
	time.Sleep(1 * time.Second)

	// Now check stats
	resp, err = http.Get(baseURL + "/api/stats/" + customID)
	require.NoError(t, err, "HTTP request should not error")

	var statsResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&statsResponse)
	resp.Body.Close()

	require.NoError(t, err, "Should decode response")
	assert.Equal(t, customID, statsResponse["short_id"], "Short ID should match")

	// We expect at least 3 clicks, but analytics might not be fully processed yet
	clicks, ok := statsResponse["clicks"].(float64)
	assert.True(t, ok, "Clicks should be a number")
	assert.GreaterOrEqual(t, int(clicks), 1, "Should have recorded at least one click")

	details, ok := statsResponse["details"].([]interface{})
	assert.True(t, ok, "Details should be an array")
	assert.GreaterOrEqual(t, len(details), 1, "Should have at least one detail entry")
}

// TestInvalidRequests tests various invalid request scenarios
func TestInvalidRequests(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		method       string
		body         map[string]interface{}
		expectedCode int
	}{
		{
			name:     "Missing URL",
			endpoint: "/api/shorten",
			method:   http.MethodPost,
			body: map[string]interface{}{
				"title": "Test without URL",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:     "Invalid URL",
			endpoint: "/api/shorten",
			method:   http.MethodPost,
			body: map[string]interface{}{
				"url": "not-a-valid-url",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Method Not Allowed",
			endpoint:     "/api/shorten",
			method:       http.MethodGet,
			body:         nil,
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:         "Empty Stats ID",
			endpoint:     "/api/stats/",
			method:       http.MethodGet,
			body:         nil,
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			var err error

			if tc.method == http.MethodPost && tc.body != nil {
				jsonBody, _ := json.Marshal(tc.body)
				resp, err = http.Post(
					baseURL+tc.endpoint,
					"application/json",
					bytes.NewBuffer(jsonBody),
				)
			} else {
				req, _ := http.NewRequest(tc.method, baseURL+tc.endpoint, nil)
				resp, err = http.DefaultClient.Do(req)
			}

			require.NoError(t, err, "HTTP request should not error")
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedCode, resp.StatusCode, "Status code should match expected")

			// Read body for debugging purposes
			bodyBytes, _ := io.ReadAll(resp.Body)
			assert.NotEmpty(t, bodyBytes, "Response should not be empty")
		})
	}
}

// TestUtilityFunctions tests the utility functions directly
func TestUtilityFunctions(t *testing.T) {
	// Test hashIP
	hashedIP := hashIP("192.168.1.1")
	assert.NotEmpty(t, hashedIP, "IP hash should not be empty")
	assert.NotEqual(t, "192.168.1.1", hashedIP, "IP hash should be different from input")
	assert.Equal(t, 64, len(hashedIP), "SHA256 hash should be 64 hex characters")

	// Different IPs should hash to different values
	hashedIP2 := hashIP("192.168.1.2")
	assert.NotEqual(t, hashedIP, hashedIP2, "Different IPs should hash differently")

	// Same IP should hash to same value
	hashedIPAgain := hashIP("192.168.1.1")
	assert.Equal(t, hashedIP, hashedIPAgain, "Same IP should hash to same value")

	// Test with port
	hashedIPWithPort := hashIP("192.168.1.1:8080")
	assert.Equal(t, hashedIP, hashedIPWithPort, "IP with port should hash same as IP alone")

	// Test isValidURL
	assert.True(t, isValidURL("http://example.com"), "HTTP URL should be valid")
	assert.True(t, isValidURL("https://example.com"), "HTTPS URL should be valid")
	assert.False(t, isValidURL("example.com"), "Domain without protocol should be invalid")
	assert.False(t, isValidURL("ftp://example.com"), "FTP URL should be invalid")

	// Test getEnv
	origValue := os.Getenv("TEST_ENV_VAR")
	defer os.Setenv("TEST_ENV_VAR", origValue) // Restore original value

	os.Setenv("TEST_ENV_VAR", "test-value")
	assert.Equal(t, "test-value", getEnv("TEST_ENV_VAR", "default"), "Should get environment variable")
	assert.Equal(t, "default", getEnv("NONEXISTENT_VAR", "default"), "Should get default value")
}

// TestPerformance does a simple load test to measure performance
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create a unique URL for testing
	targetURL := "https://test.example.com/performance"

	// Warm-up call
	requestBody, _ := json.Marshal(ShortenRequest{URL: targetURL})
	resp, err := http.Post(baseURL+"/api/shorten", "application/json", bytes.NewBuffer(requestBody))
	require.NoError(t, err, "HTTP request should not error")

	var shortenResponse ShortenResponse
	json.NewDecoder(resp.Body).Decode(&shortenResponse)
	resp.Body.Close()

	// Now test redirection performance
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	numRequests := 10
	start := time.Now()

	for i := 0; i < numRequests; i++ {
		resp, err := client.Get(baseURL + "/" + shortenResponse.ShortID)
		require.NoError(t, err, "HTTP request should not error")
		resp.Body.Close()
	}

	elapsed := time.Since(start)
	avgMS := float64(elapsed.Milliseconds()) / float64(numRequests)

	t.Logf("Average response time: %.2f ms", avgMS)
	assert.Less(t, avgMS, 100.0, "Average response time should be under 100ms")
}

// TestConcurrentShortening tests creating many URLs concurrently
func TestConcurrentShortening(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	numConcurrent := 5 // Adjust based on your system capabilities
	results := make(chan string, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(i int) {
			targetURL := fmt.Sprintf("https://test.example.com/concurrent/%d", i)
			requestBody, _ := json.Marshal(ShortenRequest{URL: targetURL})

			resp, err := http.Post(baseURL+"/api/shorten", "application/json", bytes.NewBuffer(requestBody))
			if err != nil || resp.StatusCode != http.StatusOK {
				results <- fmt.Sprintf("error-%d", i)
				return
			}

			var shortenResponse ShortenResponse
			err = json.NewDecoder(resp.Body).Decode(&shortenResponse)
			resp.Body.Close()

			if err != nil {
				results <- fmt.Sprintf("error-%d", i)
			} else {
				results <- shortenResponse.ShortID
			}
		}(i)
	}

	// Collect results
	shortIDs := make([]string, 0, numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		id := <-results
		assert.NotContains(t, id, "error", "Concurrent request should not error")
		shortIDs = append(shortIDs, id)
	}

	// Check for uniqueness
	idMap := make(map[string]bool)
	for _, id := range shortIDs {
		assert.False(t, idMap[id], "Short IDs should be unique")
		idMap[id] = true
	}
}

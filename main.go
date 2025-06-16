package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/teris-io/shortid"
)

type URLEntry struct {
	ShortID   string    `json:"short_id" dynamodbav:"short_id"`
	TargetURL string    `json:"target_url" dynamodbav:"target_url"`
	CreatedAt time.Time `json:"created_at" dynamodbav:"created_at"`
	Title     string    `json:"title,omitempty" dynamodbav:"title,omitempty"`
}

type AnalyticsEntry struct {
	ShortID   string `json:"short_id" dynamodbav:"short_id"`
	Timestamp string `json:"timestamp" dynamodbav:"timestamp"`
	UserAgent string `json:"user_agent" dynamodbav:"user_agent"`
	Referrer  string `json:"referrer" dynamodbav:"referrer"`
	IPHash    string `json:"ip_hash" dynamodbav:"ip_hash"`
}

type ShortenRequest struct {
	URL     string `json:"url"`
	Title   string `json:"title,omitempty"`
	ShortID string `json:"shortId,omitempty"`
}

type ShortenResponse struct {
	ShortID   string `json:"short_id"`
	ShortURL  string `json:"short_url"`
	TargetURL string `json:"target_url"`
}

var (
	ddbClient      *dynamodb.Client
	urlsTable      string
	analyticsTable string
)

func init() {
	// Initialize the shortid generator
	// shortid.SetDefault()

	// Set table names from environment or use defaults
	urlsTable = os.Getenv("URLS_TABLE")
	if urlsTable == "" {
		urlsTable = "URLs"
	}
	analyticsTable = os.Getenv("ANALYTICS_TABLE")
	if analyticsTable == "" {
		analyticsTable = "Analytics"
	}
}

func main() {
	// Load AWS config
	cfgOptions := []func(*config.LoadOptions) error{
		config.WithRegion(getEnv("AWS_REGION", "us-east-1")),
	}

	// Check for custom endpoint (for local development with DynamoDB Local)
	if endpoint := os.Getenv("AWS_ENDPOINT"); endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               endpoint,
				HostnameImmutable: true,
				PartitionID:       "aws",
			}, nil
		})
		cfgOptions = append(cfgOptions, config.WithEndpointResolverWithOptions(customResolver))

		// For local development, credentials can be dummy values
		cfgOptions = append(cfgOptions, config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID: "dummy", SecretAccessKey: "dummy",
					Source: "Hard-coded credentials for local development",
				}, nil
			}),
		))

		log.Printf("Using custom DynamoDB endpoint: %s", endpoint)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), cfgOptions...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create DynamoDB client
	ddbClient = dynamodb.NewFromConfig(cfg)

	// Set up HTTP handlers
	http.HandleFunc("/api/shorten", shortenHandler)
	http.HandleFunc("/api/stats/", statsHandler)
	http.HandleFunc("/", redirectHandler)

	// Get port from environment or use default
	port := getEnv("PORT", "8080")
	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func shortenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ShortenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Validate URL
	if !isValidURL(req.URL) {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Use provided ShortID or generate a new one
	sid := req.ShortID
	if sid == "" {
		// Generate short ID only if not provided
		var err error
		sid, err = shortid.Generate()
		if err != nil {
			log.Printf("Error generating shortid: %v", err)
			http.Error(w, "Failed to create short URL", http.StatusInternalServerError)
			return
		}
	} else {
		// Check if the provided ShortID is already in use
		result, err := ddbClient.GetItem(context.TODO(), &dynamodb.GetItemInput{
			TableName: aws.String(urlsTable),
			Key: map[string]types.AttributeValue{
				"short_id": &types.AttributeValueMemberS{Value: sid},
			},
		})
		if err != nil {
			log.Printf("Error checking ShortID existence: %v", err)
			http.Error(w, "Failed to verify ShortID availability", http.StatusInternalServerError)
			return
		}
		if result.Item != nil {
			http.Error(w, "The provided ShortID is already in use", http.StatusConflict)
			return
		}
	}

	// Create URL entry
	urlEntry := URLEntry{
		ShortID:   sid,
		TargetURL: req.URL,
		CreatedAt: time.Now(),
		Title:     req.Title,
	}

	// Convert to DynamoDB attribute values
	item, err := attributevalue.MarshalMap(urlEntry)
	if err != nil {
		log.Printf("Error marshaling URL entry: %v", err)
		http.Error(w, "Failed to create short URL", http.StatusInternalServerError)
		return
	}

	// Store in DynamoDB
	_, err = ddbClient.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: aws.String(urlsTable),
		Item:      item,
	})
	if err != nil {
		log.Printf("Error putting item in DynamoDB: %v", err)
		http.Error(w, "Failed to create short URL", http.StatusInternalServerError)
		return
	}

	// Create response
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	shortURL := fmt.Sprintf("%s://%s/%s", proto, r.Host, sid)

	resp := ShortenResponse{
		ShortID:   sid,
		ShortURL:  shortURL,
		TargetURL: req.URL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Extract shortID from the path
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Look up the URL in DynamoDB
	result, err := ddbClient.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(urlsTable),
		Key: map[string]types.AttributeValue{
			"short_id": &types.AttributeValueMemberS{Value: path},
		},
	})
	if err != nil {
		log.Printf("Error getting item from DynamoDB: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Check if URL was found
	if result.Item == nil {
		http.Error(w, "Short URL not found", http.StatusNotFound)
		return
	}

	var urlEntry URLEntry
	if err := attributevalue.UnmarshalMap(result.Item, &urlEntry); err != nil {
		log.Printf("Error unmarshaling URL entry: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Track analytics asynchronously
	go func() {
		analytics := AnalyticsEntry{
			ShortID:   path,
			Timestamp: time.Now().Format(time.RFC3339),
			UserAgent: r.UserAgent(),
			Referrer:  r.Referer(),
			IPHash:    hashIP(r.RemoteAddr),
		}

		item, err := attributevalue.MarshalMap(analytics)
		if err != nil {
			log.Printf("Error marshaling analytics: %v", err)
			return
		}

		_, err = ddbClient.PutItem(context.Background(), &dynamodb.PutItemInput{
			TableName: aws.String(analyticsTable),
			Item:      item,
		})
		if err != nil {
			log.Printf("Error storing analytics: %v", err)
		}
	}()

	// Redirect to the target URL
	http.Redirect(w, r, urlEntry.TargetURL, http.StatusFound)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract shortID from the path
	shortID := strings.TrimPrefix(r.URL.Path, "/api/stats/")
	if shortID == "" {
		http.Error(w, "Short ID is required", http.StatusBadRequest)
		return
	}

	// Query analytics from DynamoDB
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(analyticsTable),
		KeyConditionExpression: aws.String("short_id = :sid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":sid": &types.AttributeValueMemberS{Value: shortID},
		},
	}

	result, err := ddbClient.Query(context.TODO(), queryInput)
	if err != nil {
		log.Printf("Error querying analytics: %v", err)
		http.Error(w, "Failed to fetch stats", http.StatusInternalServerError)
		return
	}

	var analytics []AnalyticsEntry
	if err := attributevalue.UnmarshalListOfMaps(result.Items, &analytics); err != nil {
		log.Printf("Error unmarshaling analytics: %v", err)
		http.Error(w, "Failed to fetch stats", http.StatusInternalServerError)
		return
	}

	// Return analytics data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"short_id": shortID,
		"clicks":   len(analytics),
		"details":  analytics,
	})
}

func hashIP(ip string) string {
	// Remove port if present
	parts := strings.Split(ip, ":")
	ipAddress := parts[0]

	// Hash the IP address
	hash := sha256.Sum256([]byte(ipAddress))
	return hex.EncodeToString(hash[:])
}

func isValidURL(urlStr string) bool {
	// Simple validation - in production you'd want more robust validation
	return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

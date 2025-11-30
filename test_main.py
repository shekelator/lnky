"""
Tests for the Lnky URL shortener service.

These tests run against the service and DynamoDB Local running via docker-compose.
"""
import os
import time

import boto3
import pytest
from botocore.config import Config

# Base URL for the lnky service running in docker-compose
BASE_URL = "http://localhost:8080"
DYNAMODB_ENDPOINT = "http://localhost:8000"


@pytest.fixture(scope="session")
def http_client():
    """Create an HTTP client for tests."""
    import httpx

    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.fixture(scope="session")
def dynamodb_client():
    """Create a DynamoDB client for tests."""
    return boto3.client(
        "dynamodb",
        endpoint_url=DYNAMODB_ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        config=Config(region_name="us-east-1"),
    )


@pytest.fixture(scope="session", autouse=True)
def wait_for_service(http_client):
    """Wait for the lnky service to be available."""
    max_retries = 10
    for i in range(max_retries):
        try:
            # Try to connect to the service
            response = http_client.get("/nonexistent-test-check")
            # If we get any response (even 404), the service is up
            break
        except Exception as e:
            if i == max_retries - 1:
                pytest.fail(
                    f"Cannot connect to lnky service at {BASE_URL}. "
                    "Make sure docker-compose is running."
                )
            print(f"Waiting for lnky service to be available... ({i + 1}/{max_retries})")
            time.sleep(2)


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_data(dynamodb_client):
    """Clean up test data after tests complete."""
    yield

    # Scan URLs table for test items
    try:
        urls_resp = dynamodb_client.scan(
            TableName="URLs",
            FilterExpression="contains(target_url, :test_marker)",
            ExpressionAttributeValues={":test_marker": {"S": "test.example.com"}},
        )

        for item in urls_resp.get("Items", []):
            short_id = item.get("short_id", {}).get("S")
            if short_id:
                dynamodb_client.delete_item(
                    TableName="URLs",
                    Key={"short_id": {"S": short_id}},
                )

                # Clean up analytics data
                try:
                    analytics_resp = dynamodb_client.query(
                        TableName="Analytics",
                        KeyConditionExpression="short_id = :sid",
                        ExpressionAttributeValues={":sid": {"S": short_id}},
                    )
                    for analytics_item in analytics_resp.get("Items", []):
                        timestamp = analytics_item.get("timestamp", {}).get("S")
                        if timestamp:
                            dynamodb_client.delete_item(
                                TableName="Analytics",
                                Key={
                                    "short_id": {"S": short_id},
                                    "timestamp": {"S": timestamp},
                                },
                            )
                except Exception:
                    pass
    except Exception:
        pass


class TestShortenURL:
    """Tests for URL shortening functionality."""

    def test_shorten_url_basic(self, http_client, dynamodb_client):
        """Test basic URL shortening functionality."""
        target_url = "https://test.example.com/basic"

        response = http_client.post(
            "/api/shorten",
            json={"url": target_url, "title": "Test URL"},
        )

        assert response.status_code == 200
        data = response.json()

        assert "short_id" in data
        assert data["short_id"]
        assert data["short_url"].endswith(data["short_id"])
        assert data["target_url"] == target_url

        # Verify entry in DynamoDB
        result = dynamodb_client.get_item(
            TableName="URLs",
            Key={"short_id": {"S": data["short_id"]}},
        )

        assert "Item" in result
        assert result["Item"]["target_url"]["S"] == target_url
        assert result["Item"]["title"]["S"] == "Test URL"

    def test_shorten_url_with_custom_id(self, http_client):
        """Test creating a URL with a custom short ID."""
        custom_id = f"test-{int(time.time())}"
        target_url = "https://test.example.com/custom"

        response = http_client.post(
            "/api/shorten",
            json={"url": target_url, "shortId": custom_id},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["short_id"] == custom_id
        assert custom_id in data["short_url"]

    def test_duplicate_custom_id_conflict(self, http_client):
        """Test that duplicate custom IDs return conflict."""
        custom_id = f"test-dup-{int(time.time())}"
        target_url = "https://test.example.com/duplicate"

        # First request should succeed
        response1 = http_client.post(
            "/api/shorten",
            json={"url": target_url, "shortId": custom_id},
        )
        assert response1.status_code == 200

        # Second request with same ID should fail
        response2 = http_client.post(
            "/api/shorten",
            json={"url": target_url, "shortId": custom_id},
        )
        assert response2.status_code == 409

    def test_missing_url(self, http_client):
        """Test that missing URL returns bad request."""
        response = http_client.post(
            "/api/shorten",
            json={"title": "Test without URL"},
        )
        assert response.status_code == 422  # Validation error

    def test_invalid_url(self, http_client):
        """Test that invalid URL returns bad request."""
        response = http_client.post(
            "/api/shorten",
            json={"url": "not-a-valid-url"},
        )
        assert response.status_code == 400

    def test_short_id_too_long(self, http_client):
        """Test that short ID exceeding max length is rejected."""
        long_id = "a" * 51  # Exceeds SHORT_ID_MAX_LENGTH of 50
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/too-long", "shortId": long_id},
        )
        assert response.status_code == 422  # Validation error

    def test_short_id_invalid_characters(self, http_client):
        """Test that short ID with invalid characters is rejected."""
        # Test special characters
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/special", "shortId": "my@id!"},
        )
        assert response.status_code == 422

        # Test spaces
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/spaces", "shortId": "my short id"},
        )
        assert response.status_code == 422

        # Test starting with hyphen
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/hyphen", "shortId": "-startswith"},
        )
        assert response.status_code == 422

    def test_short_id_reserved_prefix(self, http_client):
        """Test that short ID starting with reserved prefix is rejected."""
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/api-prefix", "shortId": "api-endpoint"},
        )
        assert response.status_code == 422

        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/API-prefix", "shortId": "API-endpoint"},
        )
        assert response.status_code == 422

    def test_short_id_valid_characters(self, http_client):
        """Test that valid short IDs with hyphens and underscores work."""
        import time

        custom_id = f"valid-id_{int(time.time())}"
        response = http_client.post(
            "/api/shorten",
            json={"url": "https://test.example.com/valid", "shortId": custom_id},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["short_id"] == custom_id


class TestRedirect:
    """Tests for redirect functionality."""

    def test_redirect_basic(self, http_client, dynamodb_client):
        """Test basic redirect functionality."""
        target_url = "https://test.example.com/redirect"

        # First create a shortened URL
        response = http_client.post(
            "/api/shorten",
            json={"url": target_url},
        )
        assert response.status_code == 200
        short_id = response.json()["short_id"]

        # Now test the redirect (without following)
        redirect_response = http_client.get(
            f"/{short_id}",
            follow_redirects=False,
        )

        assert redirect_response.status_code == 302
        assert redirect_response.headers["location"] == target_url

        # Analytics are now written synchronously, but give a brief moment for consistency
        time.sleep(0.1)

        # Check that analytics were recorded
        result = dynamodb_client.query(
            TableName="Analytics",
            KeyConditionExpression="short_id = :sid",
            ExpressionAttributeValues={":sid": {"S": short_id}},
        )

        assert len(result.get("Items", [])) >= 1

    def test_redirect_nonexistent(self, http_client):
        """Test redirect for non-existent short URL."""
        response = http_client.get(
            "/nonexistent-short-id",
            follow_redirects=False,
        )
        assert response.status_code == 404


class TestStats:
    """Tests for stats functionality."""

    def test_stats_basic(self, http_client):
        """Test basic stats functionality."""
        custom_id = f"test-stats-{int(time.time())}"
        target_url = "https://test.example.com/stats"

        # Create a shortened URL
        response = http_client.post(
            "/api/shorten",
            json={"url": target_url, "shortId": custom_id},
        )
        assert response.status_code == 200

        # Access the URL a few times
        for _ in range(3):
            http_client.get(f"/{custom_id}", follow_redirects=False)
            time.sleep(0.1)

        # Analytics are now written synchronously
        time.sleep(0.1)

        # Check stats
        stats_response = http_client.get(f"/api/stats/{custom_id}")
        assert stats_response.status_code == 200

        data = stats_response.json()
        assert data["short_id"] == custom_id
        assert data["clicks"] >= 1
        assert isinstance(data["details"], list)
        assert len(data["details"]) >= 1


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_hash_ip(self):
        """Test IP hashing functionality."""
        from main import hash_ip

        hashed = hash_ip("192.168.1.1")
        assert hashed
        assert hashed != "192.168.1.1"
        assert len(hashed) == 64  # SHA256 hex digest

        # Different IPs should hash differently
        hashed2 = hash_ip("192.168.1.2")
        assert hashed != hashed2

        # Same IP should hash the same
        hashed_again = hash_ip("192.168.1.1")
        assert hashed == hashed_again

        # IP with port should hash same as IP alone
        hashed_with_port = hash_ip("192.168.1.1:8080")
        assert hashed == hashed_with_port

    def test_is_valid_url(self):
        """Test URL validation."""
        from main import is_valid_url

        assert is_valid_url("http://example.com") is True
        assert is_valid_url("https://example.com") is True
        assert is_valid_url("example.com") is False
        assert is_valid_url("ftp://example.com") is False

    def test_short_id_validation(self):
        """Test short ID validation in ShortenRequest model."""
        from pydantic import ValidationError

        from main import ShortenRequest

        # Valid short IDs should work
        request = ShortenRequest(url="https://example.com", shortId="valid123")
        assert request.shortId == "valid123"

        request = ShortenRequest(url="https://example.com", shortId="valid-id_123")
        assert request.shortId == "valid-id_123"

        # None should work (auto-generated)
        request = ShortenRequest(url="https://example.com")
        assert request.shortId is None

        # Too long should fail
        try:
            ShortenRequest(url="https://example.com", shortId="a" * 51)
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass

        # Invalid characters should fail
        try:
            ShortenRequest(url="https://example.com", shortId="invalid@id")
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass

        # Starting with hyphen should fail
        try:
            ShortenRequest(url="https://example.com", shortId="-invalid")
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass

        # Reserved prefix should fail
        try:
            ShortenRequest(url="https://example.com", shortId="api-test")
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass


class TestPerformance:
    """Performance tests."""

    @pytest.mark.slow
    def test_redirect_performance(self, http_client):
        """Test redirect response time."""
        target_url = "https://test.example.com/performance"

        # Create a shortened URL
        response = http_client.post(
            "/api/shorten",
            json={"url": target_url},
        )
        assert response.status_code == 200
        short_id = response.json()["short_id"]

        # Measure redirect performance
        num_requests = 10
        start = time.time()

        for _ in range(num_requests):
            http_client.get(f"/{short_id}", follow_redirects=False)

        elapsed = time.time() - start
        avg_ms = (elapsed * 1000) / num_requests

        print(f"Average response time: {avg_ms:.2f} ms")
        assert avg_ms < 100.0, "Average response time should be under 100ms"


class TestConcurrency:
    """Concurrency tests."""

    @pytest.mark.slow
    def test_concurrent_shortening(self, http_client):
        """Test creating many URLs concurrently."""
        import concurrent.futures

        import httpx

        num_concurrent = 5

        def create_url(i):
            with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
                target_url = f"https://test.example.com/concurrent/{i}"
                response = client.post(
                    "/api/shorten",
                    json={"url": target_url},
                )
                if response.status_code != 200:
                    return f"error-{i}"
                return response.json()["short_id"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = [executor.submit(create_url, i) for i in range(num_concurrent)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Check no errors
        for result in results:
            assert not result.startswith("error"), f"Concurrent request failed: {result}"

        # Check uniqueness
        assert len(set(results)) == len(results), "Short IDs should be unique"

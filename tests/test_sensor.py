"""Tests for the security sensor module."""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from security_use.sensor import (
    AttackDetector,
    AttackType,
    RequestData,
    SecurityEvent,
    MatchedPattern,
    SensorConfig,
    create_config,
    RateLimiter,
    WebhookAlerter,
    AlertResponse,
    ActionTaken,
)


class TestRequestData:
    """Tests for RequestData model."""

    def test_create_request_data(self):
        """Test creating request data."""
        request = RequestData(
            method="POST",
            path="/api/users",
            query_params={"search": "test"},
            headers={"content-type": "application/json"},
            body='{"name": "test"}',
            source_ip="192.168.1.100",
        )

        assert request.method == "POST"
        assert request.path == "/api/users"
        assert request.query_params == {"search": "test"}
        assert request.source_ip == "192.168.1.100"
        assert request.request_id  # Auto-generated

    def test_default_values(self):
        """Test default values."""
        request = RequestData(method="GET", path="/")

        assert request.query_params == {}
        assert request.headers == {}
        assert request.body is None
        assert request.source_ip == "unknown"


class TestSecurityEvent:
    """Tests for SecurityEvent model."""

    def test_to_dict(self):
        """Test converting event to dictionary."""
        event = SecurityEvent(
            event_type=AttackType.SQL_INJECTION,
            severity="HIGH",
            timestamp=datetime(2024, 1, 25, 12, 0, 0),
            source_ip="192.168.1.100",
            path="/api/users",
            method="POST",
            matched_pattern=MatchedPattern(
                pattern="' OR 1=1",
                location="body",
                field="username",
                matched_value="admin' OR 1=1--",
            ),
            description="SQL injection attempt",
        )

        result = event.to_dict()

        assert result["event_type"] == "sql_injection"
        assert result["severity"] == "HIGH"
        assert result["source_ip"] == "192.168.1.100"
        assert result["matched_pattern"]["location"] == "body"


class TestAttackDetector:
    """Tests for AttackDetector."""

    @pytest.fixture
    def detector(self):
        """Create a detector with all patterns enabled."""
        return AttackDetector()

    @pytest.fixture
    def sqli_only_detector(self):
        """Create a detector with only SQL injection detection."""
        return AttackDetector(enabled_detectors=["sqli"])

    # SQL Injection Tests
    def test_detect_basic_sqli(self, detector):
        """Test detection of basic SQL injection."""
        request = RequestData(
            method="POST",
            path="/api/login",
            body="username=admin'--&password=test",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        assert len(events) > 0
        sqli_events = [e for e in events if e.event_type == AttackType.SQL_INJECTION]
        assert len(sqli_events) > 0

    def test_detect_union_sqli(self, detector):
        """Test detection of UNION-based SQL injection."""
        request = RequestData(
            method="GET",
            path="/api/users",
            query_params={"id": "1 UNION SELECT * FROM users"},
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        sqli_events = [e for e in events if e.event_type == AttackType.SQL_INJECTION]
        assert len(sqli_events) > 0

    def test_detect_or_sqli(self, detector):
        """Test detection of OR-based SQL injection."""
        request = RequestData(
            method="POST",
            path="/api/login",
            body="username=admin' OR '1'='1",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        sqli_events = [e for e in events if e.event_type == AttackType.SQL_INJECTION]
        assert len(sqli_events) > 0

    # XSS Tests
    def test_detect_script_xss(self, detector):
        """Test detection of script tag XSS."""
        request = RequestData(
            method="POST",
            path="/api/comments",
            body='<script>alert("xss")</script>',
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        xss_events = [e for e in events if e.event_type == AttackType.XSS]
        assert len(xss_events) > 0

    def test_detect_event_handler_xss(self, detector):
        """Test detection of event handler XSS."""
        request = RequestData(
            method="POST",
            path="/api/profile",
            body='<img src="x" onerror="alert(1)">',
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        xss_events = [e for e in events if e.event_type == AttackType.XSS]
        assert len(xss_events) > 0

    def test_detect_javascript_uri_xss(self, detector):
        """Test detection of javascript: URI XSS."""
        request = RequestData(
            method="GET",
            path="/redirect",
            query_params={"url": "javascript:alert(1)"},
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        xss_events = [e for e in events if e.event_type == AttackType.XSS]
        assert len(xss_events) > 0

    # Path Traversal Tests
    def test_detect_basic_path_traversal(self, detector):
        """Test detection of basic path traversal."""
        request = RequestData(
            method="GET",
            path="/files/../../../etc/passwd",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        pt_events = [e for e in events if e.event_type == AttackType.PATH_TRAVERSAL]
        assert len(pt_events) > 0

    def test_detect_encoded_path_traversal(self, detector):
        """Test detection of URL-encoded path traversal."""
        request = RequestData(
            method="GET",
            path="/files/%2e%2e%2f%2e%2e%2fetc/passwd",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        pt_events = [e for e in events if e.event_type == AttackType.PATH_TRAVERSAL]
        assert len(pt_events) > 0

    # Command Injection Tests
    def test_detect_semicolon_command_injection(self, detector):
        """Test detection of semicolon command injection."""
        request = RequestData(
            method="POST",
            path="/api/ping",
            body="host=localhost; cat /etc/passwd",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        ci_events = [e for e in events if e.event_type == AttackType.COMMAND_INJECTION]
        assert len(ci_events) > 0

    def test_detect_pipe_command_injection(self, detector):
        """Test detection of pipe command injection."""
        request = RequestData(
            method="GET",
            path="/api/lookup",
            query_params={"domain": "example.com | ls -la"},
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        ci_events = [e for e in events if e.event_type == AttackType.COMMAND_INJECTION]
        assert len(ci_events) > 0

    def test_detect_backtick_command_injection(self, detector):
        """Test detection of backtick command injection."""
        request = RequestData(
            method="POST",
            path="/api/eval",
            body="input=`whoami`",
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        ci_events = [e for e in events if e.event_type == AttackType.COMMAND_INJECTION]
        assert len(ci_events) > 0

    # Suspicious Headers Tests
    def test_detect_sqlmap_user_agent(self, detector):
        """Test detection of sqlmap user agent."""
        request = RequestData(
            method="GET",
            path="/api/users",
            headers={"user-agent": "sqlmap/1.6"},
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        sh_events = [e for e in events if e.event_type == AttackType.SUSPICIOUS_HEADER]
        assert len(sh_events) > 0

    # Clean Request Tests
    def test_clean_request(self, detector):
        """Test that clean requests don't trigger alerts."""
        request = RequestData(
            method="GET",
            path="/api/users",
            query_params={"page": "1", "limit": "10"},
            headers={"user-agent": "Mozilla/5.0"},
            source_ip="10.0.0.1",
        )

        events = detector.analyze_request(request)

        # May have rate limit events, but no attack events
        attack_events = [
            e
            for e in events
            if e.event_type not in (AttackType.RATE_LIMIT_EXCEEDED,)
        ]
        assert len(attack_events) == 0

    # Selective Detection Tests
    def test_selective_detection(self, sqli_only_detector):
        """Test that only enabled detectors run."""
        request = RequestData(
            method="POST",
            path="/api/test",
            body="<script>alert(1)</script> AND ' OR 1=1",
            source_ip="10.0.0.1",
        )

        events = sqli_only_detector.analyze_request(request)

        # Should only detect SQL injection, not XSS
        sqli_events = [e for e in events if e.event_type == AttackType.SQL_INJECTION]
        xss_events = [e for e in events if e.event_type == AttackType.XSS]

        assert len(sqli_events) > 0
        assert len(xss_events) == 0


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_under_limit(self):
        """Test that requests under limit are allowed."""
        limiter = RateLimiter(threshold=10, window_seconds=60)

        for _ in range(9):
            assert not limiter.check("192.168.1.1")

    def test_over_limit(self):
        """Test that requests over limit are blocked."""
        limiter = RateLimiter(threshold=5, window_seconds=60)

        # First 5 requests should pass
        for _ in range(5):
            assert not limiter.check("192.168.1.1")

        # 6th request should be blocked
        assert limiter.check("192.168.1.1")

    def test_separate_ips(self):
        """Test that rate limits are per-IP."""
        limiter = RateLimiter(threshold=2, window_seconds=60)

        assert not limiter.check("192.168.1.1")
        assert not limiter.check("192.168.1.1")
        assert limiter.check("192.168.1.1")  # Blocked

        # Different IP should still be allowed
        assert not limiter.check("192.168.1.2")

    def test_reset(self):
        """Test resetting rate limits."""
        limiter = RateLimiter(threshold=2, window_seconds=60)

        limiter.check("192.168.1.1")
        limiter.check("192.168.1.1")
        assert limiter.check("192.168.1.1")  # Blocked

        limiter.reset("192.168.1.1")
        assert not limiter.check("192.168.1.1")  # Allowed again

    def test_get_request_count(self):
        """Test getting request count."""
        limiter = RateLimiter(threshold=10, window_seconds=60)

        limiter.check("192.168.1.1")
        limiter.check("192.168.1.1")
        limiter.check("192.168.1.1")

        assert limiter.get_request_count("192.168.1.1") == 3


class TestSensorConfig:
    """Tests for SensorConfig."""

    def test_create_config(self):
        """Test creating configuration."""
        config = create_config(
            webhook_url="https://example.com/webhook",
            block_on_detection=True,
            excluded_paths=["/health", "/metrics"],
        )

        assert config.webhook_url == "https://example.com/webhook"
        assert config.block_on_detection is True
        assert "/health" in config.excluded_paths

    def test_from_dict(self):
        """Test creating config from dictionary."""
        config = SensorConfig.from_dict(
            {
                "webhook_url": "https://example.com/webhook",
                "enabled_detectors": ["sqli", "xss"],
                "rate_limit_threshold": 50,
            }
        )

        assert config.webhook_url == "https://example.com/webhook"
        assert config.enabled_detectors == ["sqli", "xss"]
        assert config.rate_limit_threshold == 50

    def test_to_dict(self):
        """Test converting config to dictionary."""
        config = create_config(
            webhook_url="https://example.com/webhook",
            block_on_detection=True,
        )

        result = config.to_dict()

        assert result["webhook_url"] == "https://example.com/webhook"
        assert result["block_on_detection"] is True

    def test_is_path_excluded_exact(self):
        """Test exact path exclusion."""
        config = create_config(
            webhook_url="https://example.com/webhook",
            excluded_paths=["/health", "/metrics"],
        )

        assert config.is_path_excluded("/health") is True
        assert config.is_path_excluded("/metrics") is True
        assert config.is_path_excluded("/api/users") is False

    def test_is_path_excluded_wildcard(self):
        """Test wildcard path exclusion."""
        config = create_config(
            webhook_url="https://example.com/webhook",
            excluded_paths=["/static/*", "/public/*"],
        )

        assert config.is_path_excluded("/static/js/app.js") is True
        assert config.is_path_excluded("/static/css/style.css") is True
        assert config.is_path_excluded("/api/users") is False


class TestWebhookAlerter:
    """Tests for WebhookAlerter."""

    @pytest.fixture
    def alerter(self):
        """Create a webhook alerter."""
        return WebhookAlerter(
            webhook_url="https://example.com/webhook",
            retry_count=2,
            retry_delay=0.1,
        )

    @pytest.fixture
    def sample_event(self):
        """Create a sample security event."""
        return SecurityEvent(
            event_type=AttackType.SQL_INJECTION,
            severity="HIGH",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            path="/api/users",
            method="POST",
            matched_pattern=MatchedPattern(
                pattern="' OR 1=1",
                location="body",
                field="username",
            ),
            description="SQL injection attempt",
        )

    @pytest.mark.asyncio
    async def test_send_alert_success(self, alerter, sample_event):
        """Test successful alert sending."""
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200

            # Create async context manager mock
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response

            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client_class.return_value.__aenter__.return_value = mock_client

                response = await alerter.send_alert(sample_event)

                assert response.success is True
                assert response.webhook_status == 200
                mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_alert_failure(self, alerter, sample_event):
        """Test failed alert sending."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_client.post.return_value = mock_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = mock_client

            response = await alerter.send_alert(sample_event)

            assert response.success is False
            assert response.retry_count == 2  # Should have retried

    def test_send_alert_sync_success(self, alerter, sample_event):
        """Test synchronous alert sending."""
        with patch("httpx.Client") as mock_client_class:
            mock_response = MagicMock()
            mock_response.status_code = 200

            mock_client = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client

            response = alerter.send_alert_sync(sample_event)

            assert response.success is True
            assert response.webhook_status == 200


class TestIntegration:
    """Integration tests."""

    def test_full_detection_flow(self):
        """Test full detection flow from request to events."""
        config = create_config(
            webhook_url="https://example.com/webhook",
            block_on_detection=True,
            enabled_detectors=["sqli", "xss"],
        )

        detector = AttackDetector(
            enabled_detectors=config.enabled_detectors,
            rate_limit_threshold=config.rate_limit_threshold,
        )

        request = RequestData(
            method="POST",
            path="/api/login",
            body="username=admin' OR '1'='1&password=<script>alert(1)</script>",
            headers={"content-type": "application/x-www-form-urlencoded"},
            source_ip="192.168.1.100",
        )

        events = detector.analyze_request(request)

        # Should detect both SQL injection and XSS
        event_types = {e.event_type for e in events}
        assert AttackType.SQL_INJECTION in event_types
        assert AttackType.XSS in event_types

        # All events should have correct metadata
        for event in events:
            assert event.source_ip == "192.168.1.100"
            assert event.path == "/api/login"
            assert event.method == "POST"

"""
Tests for LiteSOC Python SDK
"""

import unittest
from unittest.mock import patch

import requests
import responses

from litesoc import (
    Actor,
    EventSeverity,
    LiteSOC,
    LiteSOCAuthError,
    LiteSOCError,
    PlanRestrictedError,
    RateLimitError,
    ResponseMetadata,
    SecurityEvents,
)


class TestLiteSOCInit(unittest.TestCase):
    """Test SDK initialization"""

    def test_init_with_api_key(self):
        """Test basic initialization"""
        sdk = LiteSOC(api_key="test-key")
        self.assertIsNotNone(sdk)
        sdk.shutdown()

    def test_init_without_api_key_raises(self):
        """Test that missing API key raises ValueError"""
        with self.assertRaises(ValueError):
            LiteSOC(api_key="")

    def test_init_with_custom_options(self):
        """Test initialization with custom options"""
        sdk = LiteSOC(
            api_key="test-key",
            endpoint="https://custom.endpoint.com",
            batching=False,
            batch_size=20,
            flush_interval=10.0,
            debug=True,
            silent=False,
            timeout=60.0,
        )
        self.assertIsNotNone(sdk)
        sdk.shutdown()


class TestLiteSOCTrack(unittest.TestCase):
    """Test event tracking"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", batching=True, debug=False)

    def tearDown(self):
        self.sdk.clear_queue()
        self.sdk.shutdown()

    def test_track_basic_event(self):
        """Test tracking a basic event"""
        self.sdk.track("auth.login_failed", actor_id="user_123")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_actor_id(self):
        """Test tracking with actor ID"""
        self.sdk.track(
            "auth.login_success",
            actor_id="user_123",
            actor_email="test@example.com",
        )
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_actor_object(self):
        """Test tracking with Actor object"""
        actor = Actor(id="user_123", email="test@example.com")
        self.sdk.track("auth.login_success", actor=actor)
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_metadata(self):
        """Test tracking with metadata"""
        self.sdk.track(
            "auth.login_failed",
            actor_id="user_123",
            metadata={"reason": "invalid_password", "attempts": 3},
        )
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_severity(self):
        """Test tracking with severity level"""
        self.sdk.track(
            "security.suspicious_activity",
            actor_id="user_123",
            severity=EventSeverity.CRITICAL,
        )
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_actor_string(self):
        """Test tracking with actor as string"""
        self.sdk.track("auth.login_success", actor="user_123")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_actor_dict(self):
        """Test tracking with actor as dict"""
        self.sdk.track(
            "auth.login_success",
            actor={"id": "user_123", "email": "test@example.com"}
        )
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_actor_email_only(self):
        """Test tracking with only actor_email (no actor_id)"""
        self.sdk.track("auth.login_success", actor_email="test@example.com")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_datetime_timestamp(self):
        """Test tracking with datetime timestamp"""
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc)
        self.sdk.track("auth.login_success", actor_id="user_123", timestamp=ts)
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_string_timestamp(self):
        """Test tracking with string timestamp"""
        self.sdk.track("auth.login_success", actor_id="user_123", timestamp="2025-01-15T12:00:00Z")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_with_string_severity(self):
        """Test tracking with string severity"""
        self.sdk.track("auth.login_success", actor_id="user_123", severity="high")
        self.assertEqual(self.sdk.get_queue_size(), 1)


class TestLiteSOCNoBatching(unittest.TestCase):
    """Test non-batching mode"""

    @responses.activate
    def test_track_without_batching(self):
        """Test tracking without batching sends immediately"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=False)
        sdk.track("auth.login_success", actor_id="user_123")
        sdk.shutdown()
        
        # Should have sent immediately
        self.assertEqual(len(responses.calls), 1)

    @responses.activate
    def test_track_without_batching_error(self):
        """Test tracking without batching handles error silently"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": False, "error": "Test error"},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=False, silent=True)
        # Should not raise even with error due to silent mode
        sdk.track("auth.login_success", actor_id="user_123")
        sdk.shutdown()

    @responses.activate
    def test_track_without_batching_error_non_silent(self):
        """Test tracking without batching raises error when non-silent"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": False, "error": "Test error"},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=False, silent=False)
        with self.assertRaises(Exception):
            sdk.track("auth.login_success", actor_id="user_123")
        sdk.shutdown()


class TestLiteSOCBatching(unittest.TestCase):
    """Test batching functionality"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", batching=True, batch_size=3)

    def tearDown(self):
        self.sdk.clear_queue()
        self.sdk.shutdown()

    @patch.object(LiteSOC, "_send_events")
    def test_auto_flush_on_batch_size(self, mock_send):
        """Test automatic flush when batch size is reached"""
        mock_send.return_value = None
        
        # Add events up to batch size
        for i in range(3):
            self.sdk.track("auth.login_failed", actor_id=f"user_{i}")
        
        # Should have triggered a flush
        mock_send.assert_called_once()

    @responses.activate
    def test_flush_sends_single_event(self):
        """Test flush sends single event correctly"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True},
            status=200,
        )
        
        self.sdk.track("auth.login_success", actor_id="user_123")
        self.sdk.flush()
        
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(self.sdk.get_queue_size(), 0)

    @responses.activate
    def test_flush_sends_batch_events(self):
        """Test flush sends batch of events"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True, "events_accepted": 2},
            status=200,
        )
        
        self.sdk.track("auth.login_success", actor_id="user_1")
        self.sdk.track("auth.login_success", actor_id="user_2")
        self.sdk.flush()
        
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(self.sdk.get_queue_size(), 0)

    @patch.object(LiteSOC, "_send_events")
    def test_flush_skipped_when_already_flushing(self, mock_send):
        """Test flush is skipped when another flush is in progress"""
        self.sdk._is_flushing = True
        self.sdk.track("auth.login_success", actor_id="user_123")
        self.sdk.flush()
        
        # Should not have called _send_events
        mock_send.assert_not_called()
        self.sdk._is_flushing = False

    def test_flush_empty_queue(self):
        """Test flush with empty queue does nothing"""
        # Should not raise
        self.sdk.flush()

    @responses.activate
    def test_flush_retries_on_error(self):
        """Test flush returns False on error and re-queues events"""
        # First call fails
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"error": "Server error"},
            status=500,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True, batch_size=10, silent=True, debug=False)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # flush() returns False on error (graceful failure)
        result = sdk.flush()
        self.assertFalse(result)
        
        # Events should be re-queued for retry (retry_count incremented)
        self.assertGreater(sdk.get_queue_size(), 0)
        sdk.clear_queue()
        sdk.shutdown()

    def test_send_events_empty_list(self):
        """Test _send_events with empty list does nothing"""
        sdk = LiteSOC(api_key="test-key", batching=True)
        # Should not raise and should not make any HTTP calls
        sdk._send_events([])
        sdk.shutdown()


class TestLiteSOCScheduledFlush(unittest.TestCase):
    """Test scheduled flush functionality"""

    @responses.activate
    def test_scheduled_flush_success(self):
        """Test scheduled flush executes correctly"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True, batch_size=10, flush_interval=0.01)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # Wait for scheduled flush
        import time
        time.sleep(0.1)
        
        # Should have flushed
        self.assertEqual(sdk.get_queue_size(), 0)
        sdk.shutdown()

    def test_scheduled_flush_handles_error(self):
        """Test scheduled flush handles error silently"""
        sdk = LiteSOC(api_key="test-key", batching=True, batch_size=10, flush_interval=0.01, silent=True)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # Wait for scheduled flush (will fail with no mock)
        import time
        time.sleep(0.1)
        
        # Should not crash, events might be re-queued
        sdk.clear_queue()
        sdk.shutdown()


class TestLiteSOCShutdown(unittest.TestCase):
    """Test shutdown functionality"""

    @responses.activate
    def test_shutdown_with_pending_timer(self):
        """Test shutdown cancels pending flush timer"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True, batch_size=10, flush_interval=10.0)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # Timer should be scheduled but not executed yet
        self.assertIsNotNone(sdk._flush_timer)
        
        # Shutdown should cancel timer
        sdk.shutdown()
        
        self.assertIsNone(sdk._flush_timer)

    def test_shutdown_without_pending_timer(self):
        """Test shutdown works with no pending timer"""
        sdk = LiteSOC(api_key="test-key", batching=True)
        # No events tracked, no timer
        self.assertIsNone(sdk._flush_timer)
        sdk.shutdown()
        self.assertIsNone(sdk._flush_timer)


class TestLiteSOCSendEvents(unittest.TestCase):
    """Test _send_events method"""

    @responses.activate
    def test_send_events_success(self):
        """Test successful event sending"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": True},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True, debug=True)
        sdk.track("auth.login_success", actor_id="user_123")
        sdk.flush()
        
        self.assertEqual(len(responses.calls), 1)
        sdk.shutdown()

    @responses.activate
    def test_send_events_http_error(self):
        """Test event sending with HTTP error returns False"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"error": "Unauthorized"},
            status=401,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # flush() returns False on HTTP errors (graceful failure)
        result = sdk.flush()
        self.assertFalse(result)
        
        sdk.clear_queue()
        sdk.shutdown()

    @responses.activate
    def test_send_events_api_error(self):
        """Test event sending with API error response returns False"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            json={"success": False, "error": "Invalid event"},
            status=200,
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # flush() returns False on API errors (graceful failure)
        result = sdk.flush()
        self.assertFalse(result)
        
        sdk.clear_queue()
        sdk.shutdown()


class TestTimeoutHandling(unittest.TestCase):
    """Test timeout handling for track and flush"""

    @responses.activate
    def test_track_timeout_returns_false(self):
        """Test track returns False on timeout when batching disabled"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            body=requests.exceptions.Timeout("Connection timed out"),
        )
        
        sdk = LiteSOC(api_key="test-key", batching=False, timeout=1.0)
        result = sdk.track("auth.login_success", actor_id="user_123")
        
        # Should return False on timeout
        self.assertFalse(result)
        sdk.shutdown()

    @responses.activate
    def test_flush_timeout_returns_false_and_requeues(self):
        """Test flush returns False on timeout and re-queues events"""
        responses.add(
            responses.POST,
            "https://api.litesoc.io/collect",
            body=requests.exceptions.Timeout("Connection timed out"),
        )
        
        sdk = LiteSOC(api_key="test-key", batching=True, batch_size=10, timeout=1.0)
        sdk.track("auth.login_success", actor_id="user_123")
        
        # Flush should return False on timeout
        result = sdk.flush()
        self.assertFalse(result)
        
        # Events should be re-queued for retry
        self.assertGreater(sdk.get_queue_size(), 0)
        
        sdk.clear_queue()
        sdk.shutdown()


class TestLiteSOCConvenienceMethods(unittest.TestCase):
    """Test convenience methods"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", batching=True)

    def tearDown(self):
        self.sdk.clear_queue()
        self.sdk.shutdown()

    def test_track_login_failed(self):
        """Test track_login_failed convenience method"""
        self.sdk.track_login_failed("user_123", user_ip="192.168.1.1")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_login_success(self):
        """Test track_login_success convenience method"""
        self.sdk.track_login_success("user_123", user_ip="192.168.1.1")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_privilege_escalation(self):
        """Test track_privilege_escalation convenience method"""
        self.sdk.track_privilege_escalation("admin_user", user_ip="192.168.1.1")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_sensitive_access(self):
        """Test track_sensitive_access convenience method"""
        self.sdk.track_sensitive_access("user_123", "pii_table", user_ip="192.168.1.1")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_bulk_delete(self):
        """Test track_bulk_delete convenience method"""
        self.sdk.track_bulk_delete("admin_user", 500, user_ip="192.168.1.1")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_role_changed(self):
        """Test track_role_changed convenience method"""
        self.sdk.track_role_changed("user_123", old_role="viewer", new_role="admin")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_track_access_denied(self):
        """Test track_access_denied convenience method"""
        self.sdk.track_access_denied("user_123", resource="/admin/settings")
        self.assertEqual(self.sdk.get_queue_size(), 1)


class TestLiteSOCQueueManagement(unittest.TestCase):
    """Test queue management"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", batching=True)

    def tearDown(self):
        self.sdk.clear_queue()
        self.sdk.shutdown()

    def test_get_queue_size(self):
        """Test getting queue size"""
        self.assertEqual(self.sdk.get_queue_size(), 0)
        self.sdk.track("auth.login_failed", actor_id="user_123")
        self.assertEqual(self.sdk.get_queue_size(), 1)

    def test_clear_queue(self):
        """Test clearing the queue"""
        for i in range(5):
            self.sdk.track("auth.login_failed", actor_id=f"user_{i}")
        self.assertEqual(self.sdk.get_queue_size(), 5)
        
        self.sdk.clear_queue()
        self.assertEqual(self.sdk.get_queue_size(), 0)


class TestLiteSOCContextManager(unittest.TestCase):
    """Test context manager support"""

    def test_context_manager(self):
        """Test using SDK as context manager"""
        with LiteSOC(api_key="test-key", batching=False) as sdk:
            # Just test that context manager works, don't actually send events
            self.assertIsNotNone(sdk)
            sdk.clear_queue()  # Clear any pending events to avoid HTTP calls
        # After exiting context, shutdown should have been called


class TestActor(unittest.TestCase):
    """Test Actor class"""

    def test_actor_to_dict(self):
        """Test Actor.to_dict()"""
        actor = Actor(id="user_123", email="test@example.com")
        result = actor.to_dict()
        self.assertEqual(result["id"], "user_123")
        self.assertEqual(result["email"], "test@example.com")

    def test_actor_without_email(self):
        """Test Actor without email"""
        actor = Actor(id="user_123")
        result = actor.to_dict()
        self.assertEqual(result["id"], "user_123")
        self.assertIsNone(result["email"])


class TestSecurityEvents(unittest.TestCase):
    """Test SecurityEvents enum"""

    def test_security_events_values(self):
        """Test that all 26 standard events exist"""
        # Auth events (8)
        self.assertEqual(SecurityEvents.AUTH_LOGIN_SUCCESS.value, "auth.login_success")
        self.assertEqual(SecurityEvents.AUTH_LOGIN_FAILED.value, "auth.login_failed")
        self.assertEqual(SecurityEvents.AUTH_LOGOUT.value, "auth.logout")
        self.assertEqual(SecurityEvents.AUTH_PASSWORD_RESET.value, "auth.password_reset")
        self.assertEqual(SecurityEvents.AUTH_MFA_ENABLED.value, "auth.mfa_enabled")
        self.assertEqual(SecurityEvents.AUTH_MFA_DISABLED.value, "auth.mfa_disabled")
        self.assertEqual(SecurityEvents.AUTH_SESSION_EXPIRED.value, "auth.session_expired")
        self.assertEqual(SecurityEvents.AUTH_TOKEN_REFRESHED.value, "auth.token_refreshed")
        
        # Authz events (4)
        self.assertEqual(SecurityEvents.AUTHZ_ROLE_CHANGED.value, "authz.role_changed")
        self.assertEqual(SecurityEvents.AUTHZ_PERMISSION_GRANTED.value, "authz.permission_granted")
        self.assertEqual(SecurityEvents.AUTHZ_PERMISSION_REVOKED.value, "authz.permission_revoked")
        self.assertEqual(SecurityEvents.AUTHZ_ACCESS_DENIED.value, "authz.access_denied")
        
        # Admin events (7)
        self.assertEqual(SecurityEvents.ADMIN_PRIVILEGE_ESCALATION.value, "admin.privilege_escalation")
        self.assertEqual(SecurityEvents.ADMIN_USER_IMPERSONATION.value, "admin.user_impersonation")
        self.assertEqual(SecurityEvents.ADMIN_SETTINGS_CHANGED.value, "admin.settings_changed")
        self.assertEqual(SecurityEvents.ADMIN_API_KEY_CREATED.value, "admin.api_key_created")
        self.assertEqual(SecurityEvents.ADMIN_API_KEY_REVOKED.value, "admin.api_key_revoked")
        self.assertEqual(SecurityEvents.ADMIN_USER_SUSPENDED.value, "admin.user_suspended")
        self.assertEqual(SecurityEvents.ADMIN_USER_DELETED.value, "admin.user_deleted")
        
        # Data events (3)
        self.assertEqual(SecurityEvents.DATA_BULK_DELETE.value, "data.bulk_delete")
        self.assertEqual(SecurityEvents.DATA_SENSITIVE_ACCESS.value, "data.sensitive_access")
        self.assertEqual(SecurityEvents.DATA_EXPORT.value, "data.export")
        
        # Security events (4)
        self.assertEqual(SecurityEvents.SECURITY_SUSPICIOUS_ACTIVITY.value, "security.suspicious_activity")
        self.assertEqual(SecurityEvents.SECURITY_RATE_LIMIT_EXCEEDED.value, "security.rate_limit_exceeded")
        self.assertEqual(SecurityEvents.SECURITY_IP_BLOCKED.value, "security.ip_blocked")
        self.assertEqual(SecurityEvents.SECURITY_BRUTE_FORCE_DETECTED.value, "security.brute_force_detected")

    def test_security_events_count(self):
        """Test that there are exactly 26 standard events"""
        self.assertEqual(len(SecurityEvents), 26)

    def test_security_events_track(self):
        """Test tracking with SecurityEvents enum"""
        sdk = LiteSOC(api_key="test-key", batching=True)
        sdk.track(SecurityEvents.AUTH_LOGIN_FAILED, actor_id="user_123")
        self.assertEqual(sdk.get_queue_size(), 1)
        sdk.clear_queue()
        sdk.shutdown()


class TestCustomExceptions(unittest.TestCase):
    """Test custom exception classes"""

    def test_litesoc_error(self):
        """Test LiteSOCError"""
        error = LiteSOCError("Test error", status_code=500, error_code="TEST_ERROR")
        self.assertEqual(error.message, "Test error")
        self.assertEqual(error.status_code, 500)
        self.assertEqual(error.error_code, "TEST_ERROR")
        self.assertEqual(str(error), "Test error")

    def test_litesoc_error_minimal(self):
        """Test LiteSOCError with minimal arguments"""
        error = LiteSOCError("Test error")
        self.assertEqual(error.message, "Test error")
        self.assertIsNone(error.status_code)
        self.assertIsNone(error.error_code)

    def test_litesoc_auth_error(self):
        """Test LiteSOCAuthError"""
        error = LiteSOCAuthError("Unauthorized", status_code=401)
        self.assertEqual(error.message, "Unauthorized")
        self.assertEqual(error.status_code, 401)
        self.assertIsInstance(error, LiteSOCError)

    def test_rate_limit_error(self):
        """Test RateLimitError"""
        error = RateLimitError("Too many requests", retry_after=60)
        self.assertEqual(error.message, "Too many requests")
        self.assertEqual(error.status_code, 429)
        self.assertEqual(error.retry_after, 60)
        self.assertIsInstance(error, LiteSOCError)

    def test_rate_limit_error_without_retry(self):
        """Test RateLimitError without retry_after"""
        error = RateLimitError("Too many requests")
        self.assertIsNone(error.retry_after)

    def test_plan_restricted_error(self):
        """Test PlanRestrictedError"""
        error = PlanRestrictedError("Feature not available", required_plan="pro")
        self.assertEqual(error.message, "Feature not available")
        self.assertEqual(error.status_code, 403)
        self.assertEqual(error.required_plan, "pro")
        self.assertIsInstance(error, LiteSOCError)

    def test_plan_restricted_error_without_plan(self):
        """Test PlanRestrictedError without required_plan"""
        error = PlanRestrictedError("Feature not available")
        self.assertIsNone(error.required_plan)


class TestLiteSOCBaseUrl(unittest.TestCase):
    """Test base_url configuration"""

    def test_default_base_url(self):
        """Test default base URL"""
        sdk = LiteSOC(api_key="test-key")
        self.assertEqual(sdk._base_url, "https://api.litesoc.io")
        sdk.shutdown()

    def test_custom_base_url(self):
        """Test custom base URL"""
        sdk = LiteSOC(api_key="test-key", base_url="https://custom.api.com")
        self.assertEqual(sdk._base_url, "https://custom.api.com")
        sdk.shutdown()

    def test_base_url_trailing_slash(self):
        """Test base URL trailing slash is stripped"""
        sdk = LiteSOC(api_key="test-key", base_url="https://custom.api.com/")
        self.assertEqual(sdk._base_url, "https://custom.api.com")
        sdk.shutdown()

    def test_legacy_endpoint_parameter(self):
        """Test legacy endpoint parameter backward compatibility"""
        sdk = LiteSOC(api_key="test-key", endpoint="https://old.api.com/collect")
        self.assertEqual(sdk._base_url, "https://old.api.com")
        sdk.shutdown()

    def test_legacy_endpoint_without_collect(self):
        """Test legacy endpoint parameter without /collect"""
        sdk = LiteSOC(api_key="test-key", endpoint="https://old.api.com/v1")
        self.assertEqual(sdk._base_url, "https://old.api.com/v1")
        sdk.shutdown()


class TestLiteSOCUserAgent(unittest.TestCase):
    """Test User-Agent header"""

    def test_user_agent_format(self):
        """Test User-Agent header format"""
        sdk = LiteSOC(api_key="test-key")
        user_agent = sdk._session.headers.get("User-Agent")
        self.assertTrue(user_agent.startswith("litesoc-python-sdk/"))
        self.assertIn("2.2.0", user_agent)
        sdk.shutdown()

    def test_api_key_header(self):
        """Test X-API-Key header is set correctly"""
        sdk = LiteSOC(api_key="test-api-key-12345")
        api_key_header = sdk._session.headers.get("X-API-Key")
        self.assertEqual(api_key_header, "test-api-key-12345")
        # Ensure Authorization header is NOT used
        self.assertIsNone(sdk._session.headers.get("Authorization"))
        sdk.shutdown()


class TestManagementAPI(unittest.TestCase):
    """Test Management API methods"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", base_url="https://api.litesoc.io")

    def tearDown(self):
        self.sdk.shutdown()

    @responses.activate
    def test_get_alerts(self):
        """Test get_alerts method"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"alerts": [{"id": "alert_1", "type": "auth.login_failed"}]},
            status=200,
        )
        
        result = self.sdk.get_alerts()
        self.assertIn("alerts", result)
        self.assertEqual(len(result["alerts"]), 1)

    @responses.activate
    def test_get_alerts_with_filters(self):
        """Test get_alerts with filters"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"alerts": []},
            status=200,
        )
        
        result = self.sdk.get_alerts(status="open", severity="high", limit=50)
        self.assertIn("alerts", result)

    @responses.activate
    def test_get_alerts_with_all_filters(self):
        """Test get_alerts with all filters including alert_type and offset"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"alerts": []},
            status=200,
        )
        
        result = self.sdk.get_alerts(
            status="open", 
            severity="critical", 
            alert_type="impossible_travel",
            limit=25,
            offset=10
        )
        self.assertIn("alerts", result)

    @responses.activate
    def test_get_alert(self):
        """Test get_alert method"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts/alert_123",
            json={"id": "alert_123", "type": "auth.login_failed"},
            status=200,
        )
        
        result = self.sdk.get_alert("alert_123")
        self.assertEqual(result["id"], "alert_123")

    @responses.activate
    def test_resolve_alert(self):
        """Test resolve_alert method"""
        responses.add(
            responses.PATCH,
            "https://api.litesoc.io/alerts/alert_123",
            json={"id": "alert_123", "status": "resolved"},
            status=200,
        )
        
        result = self.sdk.resolve_alert("alert_123", "fixed", notes="Fixed in PR #123")
        self.assertEqual(result["status"], "resolved")

    @responses.activate
    def test_resolve_alert_without_notes(self):
        """Test resolve_alert without notes"""
        responses.add(
            responses.PATCH,
            "https://api.litesoc.io/alerts/alert_123",
            json={"id": "alert_123", "status": "resolved"},
            status=200,
        )
        
        result = self.sdk.resolve_alert("alert_123", "false_positive")
        self.assertEqual(result["status"], "resolved")

    @responses.activate
    def test_mark_alert_safe(self):
        """Test mark_alert_safe method"""
        responses.add(
            responses.PATCH,
            "https://api.litesoc.io/alerts/alert_123",
            json={"id": "alert_123", "status": "safe"},
            status=200,
        )
        
        result = self.sdk.mark_alert_safe("alert_123", notes="Expected behavior")
        self.assertEqual(result["status"], "safe")

    @responses.activate
    def test_mark_alert_safe_without_notes(self):
        """Test mark_alert_safe without notes"""
        responses.add(
            responses.PATCH,
            "https://api.litesoc.io/alerts/alert_123",
            json={"id": "alert_123", "status": "safe"},
            status=200,
        )
        
        result = self.sdk.mark_alert_safe("alert_123")
        self.assertEqual(result["status"], "safe")

    @responses.activate
    def test_get_events(self):
        """Test get_events method"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/events",
            json={"events": [{"id": "event_1", "type": "auth.login_success"}]},
            status=200,
        )
        
        result = self.sdk.get_events()
        self.assertIn("events", result)
        self.assertEqual(len(result["events"]), 1)

    @responses.activate
    def test_get_events_with_limit(self):
        """Test get_events with custom limit"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/events",
            json={"events": []},
            status=200,
        )
        
        result = self.sdk.get_events(limit=50)
        self.assertIn("events", result)

    @responses.activate
    def test_get_events_with_all_filters(self):
        """Test get_events with all filters including event_name, actor_id, severity, offset"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/events",
            json={"events": []},
            status=200,
        )
        
        result = self.sdk.get_events(
            limit=25,
            event_name="auth.login_failed",
            actor_id="user_123",
            severity="critical",
            offset=10
        )
        self.assertIn("events", result)

    @responses.activate
    def test_get_event(self):
        """Test get_event method"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/events/event_123",
            json={"id": "event_123", "type": "auth.login_success"},
            status=200,
        )
        
        result = self.sdk.get_event("event_123")
        self.assertEqual(result["id"], "event_123")


class TestManagementAPIErrors(unittest.TestCase):
    """Test Management API error handling"""

    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key", base_url="https://api.litesoc.io")

    def tearDown(self):
        self.sdk.shutdown()

    @responses.activate
    def test_401_unauthorized(self):
        """Test 401 unauthorized error"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"error": "Invalid API key"},
            status=401,
        )
        
        with self.assertRaises(LiteSOCAuthError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Invalid API key", ctx.exception.message)

    @responses.activate
    def test_403_forbidden(self):
        """Test 403 forbidden error"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"error": "Access denied"},
            status=403,
        )
        
        with self.assertRaises(LiteSOCAuthError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 403)

    @responses.activate
    def test_403_plan_restricted(self):
        """Test 403 plan restricted error with upgrade hint"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/events",
            json={"error": "Feature not available", "code": "PLAN_RESTRICTED", "required_plan": "pro"},
            status=403,
        )
        
        with self.assertRaises(PlanRestrictedError) as ctx:
            self.sdk.get_events()
        
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.required_plan, "pro")
        # Verify upgrade hint is included in message
        self.assertIn("Upgrade to", str(ctx.exception))
        self.assertIn("pro", str(ctx.exception))

    @responses.activate
    def test_429_rate_limit(self):
        """Test 429 rate limit error"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"error": "Rate limit exceeded"},
            status=429,
            headers={"Retry-After": "60"},
        )
        
        with self.assertRaises(RateLimitError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.retry_after, 60)

    @responses.activate
    def test_429_rate_limit_without_retry_after(self):
        """Test 429 rate limit without Retry-After header"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"error": "Rate limit exceeded"},
            status=429,
        )
        
        with self.assertRaises(RateLimitError) as ctx:
            self.sdk.get_alerts()
        
        self.assertIsNone(ctx.exception.retry_after)

    @responses.activate
    def test_500_server_error(self):
        """Test 500 server error"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"error": "Internal server error"},
            status=500,
        )
        
        with self.assertRaises(LiteSOCError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 500)

    @responses.activate
    def test_error_without_json_body(self):
        """Test error without JSON body"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            body="Bad Gateway",
            status=502,
        )
        
        with self.assertRaises(LiteSOCError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertIn("Bad Gateway", ctx.exception.message)

    @responses.activate
    def test_timeout_error(self):
        """Test request timeout"""
        import requests.exceptions
        
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            body=requests.exceptions.Timeout("Connection timed out"),
        )
        
        with self.assertRaises(LiteSOCError) as ctx:
            self.sdk.get_alerts()
        
        self.assertEqual(ctx.exception.status_code, 408)

    @responses.activate
    def test_connection_error(self):
        """Test connection error"""
        import requests.exceptions
        
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            body=requests.exceptions.ConnectionError("Connection refused"),
        )
        
        with self.assertRaises(LiteSOCError) as ctx:
            self.sdk.get_alerts()
        
        self.assertIn("Request failed", ctx.exception.message)


class TestResponseMetadata(unittest.TestCase):
    """Test ResponseMetadata class"""
    
    def test_from_headers(self):
        """Test parsing headers"""
        headers = {
            "X-LiteSOC-Plan": "pro",
            "X-LiteSOC-Retention": "90",
            "X-LiteSOC-Cutoff": "2024-01-01T00:00:00Z",
        }
        
        metadata = ResponseMetadata.from_headers(headers)
        
        self.assertEqual(metadata.plan, "pro")
        self.assertEqual(metadata.retention_days, 90)
        self.assertEqual(metadata.cutoff_date, "2024-01-01T00:00:00Z")
    
    def test_from_headers_case_insensitive(self):
        """Test case-insensitive header parsing"""
        headers = {
            "x-litesoc-plan": "enterprise",
            "x-litesoc-retention": "365",
            "x-litesoc-cutoff": "2023-06-01T00:00:00Z",
        }
        
        metadata = ResponseMetadata.from_headers(headers)
        
        self.assertEqual(metadata.plan, "enterprise")
        self.assertEqual(metadata.retention_days, 365)
        self.assertEqual(metadata.cutoff_date, "2023-06-01T00:00:00Z")
    
    def test_from_empty_headers(self):
        """Test parsing empty headers"""
        metadata = ResponseMetadata.from_headers({})
        
        self.assertIsNone(metadata.plan)
        self.assertIsNone(metadata.retention_days)
        self.assertIsNone(metadata.cutoff_date)
        self.assertFalse(metadata.has_plan_info())
        self.assertFalse(metadata.has_retention_info())
    
    def test_has_plan_info(self):
        """Test has_plan_info helper"""
        metadata = ResponseMetadata(plan="pro")
        self.assertTrue(metadata.has_plan_info())
        
        metadata2 = ResponseMetadata()
        self.assertFalse(metadata2.has_plan_info())
    
    def test_has_retention_info(self):
        """Test has_retention_info helper"""
        metadata = ResponseMetadata(retention_days=90)
        self.assertTrue(metadata.has_retention_info())
        
        metadata2 = ResponseMetadata()
        self.assertFalse(metadata2.has_retention_info())
    
    def test_to_dict(self):
        """Test to_dict method"""
        metadata = ResponseMetadata(
            plan="pro",
            retention_days=90,
            cutoff_date="2024-01-01T00:00:00Z"
        )
        
        expected = {
            "plan": "pro",
            "retention_days": 90,
            "cutoff_date": "2024-01-01T00:00:00Z",
        }
        
        self.assertEqual(metadata.to_dict(), expected)


class TestPlanInfo(unittest.TestCase):
    """Test plan info methods"""
    
    def setUp(self):
        self.sdk = LiteSOC(api_key="test-key")
    
    def tearDown(self):
        self.sdk.shutdown()
    
    def test_get_plan_info_initially_none(self):
        """Test that plan info is None before any API calls"""
        self.assertIsNone(self.sdk.get_plan_info())
        self.assertFalse(self.sdk.has_plan_info())
    
    @responses.activate
    def test_get_plan_info_after_api_call(self):
        """Test that plan info is populated after an API call"""
        responses.add(
            responses.GET,
            "https://api.litesoc.io/alerts",
            json={"alerts": [], "total": 0},
            status=200,
            headers={
                "X-LiteSOC-Plan": "pro",
                "X-LiteSOC-Retention": "90",
                "X-LiteSOC-Cutoff": "2024-01-01T00:00:00Z",
            },
        )
        
        self.sdk.get_alerts()
        
        plan_info = self.sdk.get_plan_info()
        self.assertIsNotNone(plan_info)
        self.assertEqual(plan_info.plan, "pro")
        self.assertEqual(plan_info.retention_days, 90)
        self.assertTrue(self.sdk.has_plan_info())


class TestPlanRestrictedErrorUpgradeUrl(unittest.TestCase):
    """Test PlanRestrictedError upgrade URL"""
    
    def test_upgrade_url_constant(self):
        """Test that upgrade URL constant is set"""
        self.assertEqual(
            PlanRestrictedError.UPGRADE_URL,
            "https://www.litesoc.io/pricing"
        )
    
    def test_upgrade_url_attribute(self):
        """Test that upgrade URL is set on instance"""
        error = PlanRestrictedError("Test error")
        self.assertEqual(error.upgrade_url, "https://www.litesoc.io/pricing")


class TestNetworkForensics(unittest.TestCase):
    """Test NetworkForensics dataclass"""
    
    def test_from_dict_full(self):
        """Test creating NetworkForensics from full data"""
        from litesoc import NetworkForensics
        
        data = {
            "is_vpn": True,
            "is_tor": False,
            "is_proxy": True,
            "is_datacenter": True,
            "is_mobile": False,
            "asn": 12345,
            "asn_org": "Example Hosting Inc",
            "isp": "Example ISP",
        }
        
        network = NetworkForensics.from_dict(data)
        
        self.assertTrue(network.is_vpn)
        self.assertFalse(network.is_tor)
        self.assertTrue(network.is_proxy)
        self.assertTrue(network.is_datacenter)
        self.assertFalse(network.is_mobile)
        self.assertEqual(network.asn, 12345)
        self.assertEqual(network.asn_org, "Example Hosting Inc")
        self.assertEqual(network.isp, "Example ISP")
    
    def test_from_dict_partial(self):
        """Test creating NetworkForensics from partial data"""
        from litesoc import NetworkForensics
        
        data = {
            "is_vpn": False,
            "is_tor": True,
        }
        
        network = NetworkForensics.from_dict(data)
        
        self.assertFalse(network.is_vpn)
        self.assertTrue(network.is_tor)
        self.assertFalse(network.is_proxy)  # Default to False
        self.assertFalse(network.is_datacenter)
        self.assertFalse(network.is_mobile)
        self.assertIsNone(network.asn)
        self.assertIsNone(network.asn_org)
        self.assertIsNone(network.isp)
    
    def test_to_dict(self):
        """Test NetworkForensics to_dict method"""
        from litesoc import NetworkForensics
        
        network = NetworkForensics(
            is_vpn=True,
            is_tor=False,
            is_proxy=False,
            is_datacenter=True,
            is_mobile=False,
            asn=67890,
            asn_org="Test Org",
            isp="Test ISP",
        )
        
        result = network.to_dict()
        
        self.assertEqual(result["is_vpn"], True)
        self.assertEqual(result["is_tor"], False)
        self.assertEqual(result["asn"], 67890)
        self.assertEqual(result["asn_org"], "Test Org")


class TestLocationForensics(unittest.TestCase):
    """Test LocationForensics dataclass"""
    
    def test_from_dict_full(self):
        """Test creating LocationForensics from full data"""
        from litesoc import LocationForensics
        
        data = {
            "city": "New York",
            "region": "New York",
            "country_code": "US",
            "country_name": "United States",
            "latitude": 40.7128,
            "longitude": -74.006,
            "timezone": "America/New_York",
        }
        
        location = LocationForensics.from_dict(data)
        
        self.assertEqual(location.city, "New York")
        self.assertEqual(location.region, "New York")
        self.assertEqual(location.country_code, "US")
        self.assertEqual(location.country_name, "United States")
        self.assertEqual(location.latitude, 40.7128)
        self.assertEqual(location.longitude, -74.006)
        self.assertEqual(location.timezone, "America/New_York")
    
    def test_from_dict_partial(self):
        """Test creating LocationForensics from partial data"""
        from litesoc import LocationForensics
        
        data = {
            "country_code": "GB",
        }
        
        location = LocationForensics.from_dict(data)
        
        self.assertIsNone(location.city)
        self.assertIsNone(location.region)
        self.assertEqual(location.country_code, "GB")
        self.assertIsNone(location.country_name)
        self.assertIsNone(location.latitude)
        self.assertIsNone(location.longitude)
        self.assertIsNone(location.timezone)
    
    def test_to_dict(self):
        """Test LocationForensics to_dict method"""
        from litesoc import LocationForensics
        
        location = LocationForensics(
            city="London",
            region="England",
            country_code="GB",
            country_name="United Kingdom",
            latitude=51.5074,
            longitude=-0.1278,
            timezone="Europe/London",
        )
        
        result = location.to_dict()
        
        self.assertEqual(result["city"], "London")
        self.assertEqual(result["country_code"], "GB")
        self.assertEqual(result["latitude"], 51.5074)


class TestForensics(unittest.TestCase):
    """Test Forensics dataclass"""
    
    def test_from_dict_full(self):
        """Test creating Forensics from full data"""
        from litesoc import Forensics
        
        data = {
            "network": {
                "is_vpn": True,
                "is_tor": False,
                "is_proxy": False,
                "is_datacenter": True,
                "is_mobile": False,
                "asn": 12345,
                "asn_org": "Test Org",
                "isp": "Test ISP",
            },
            "location": {
                "city": "Berlin",
                "region": "Berlin",
                "country_code": "DE",
                "country_name": "Germany",
                "latitude": 52.52,
                "longitude": 13.405,
                "timezone": "Europe/Berlin",
            },
        }
        
        forensics = Forensics.from_dict(data)
        
        self.assertIsNotNone(forensics)
        self.assertTrue(forensics.network.is_vpn)
        self.assertEqual(forensics.network.asn, 12345)
        self.assertEqual(forensics.location.city, "Berlin")
        self.assertEqual(forensics.location.country_code, "DE")
    
    def test_from_dict_none(self):
        """Test creating Forensics from None (Free tier)"""
        from litesoc import Forensics
        
        forensics = Forensics.from_dict(None)
        
        self.assertIsNone(forensics)
    
    def test_from_dict_empty(self):
        """Test creating Forensics from empty data"""
        from litesoc import Forensics
        
        forensics = Forensics.from_dict({})
        
        self.assertIsNotNone(forensics)
        self.assertFalse(forensics.network.is_vpn)
        self.assertIsNone(forensics.location.city)
    
    def test_to_dict(self):
        """Test Forensics to_dict method"""
        from litesoc import Forensics, LocationForensics, NetworkForensics
        
        forensics = Forensics(
            network=NetworkForensics(
                is_vpn=True,
                is_tor=False,
                is_proxy=False,
                is_datacenter=False,
                is_mobile=True,
            ),
            location=LocationForensics(
                city="Tokyo",
                country_code="JP",
            ),
        )
        
        result = forensics.to_dict()
        
        self.assertTrue(result["network"]["is_vpn"])
        self.assertTrue(result["network"]["is_mobile"])
        self.assertEqual(result["location"]["city"], "Tokyo")
        self.assertEqual(result["location"]["country_code"], "JP")


class TestAlert(unittest.TestCase):
    """Test Alert dataclass"""
    
    def test_from_dict_full(self):
        """Test creating Alert from full data"""
        from litesoc import Alert
        
        data = {
            "id": "alert_abc123",
            "alert_type": "brute_force_attack",
            "severity": "high",
            "status": "open",
            "title": "Brute Force Attack Detected",
            "description": "Multiple failed login attempts from single IP",
            "source_ip": "192.168.1.100",
            "actor_id": "user_123",
            "trigger_event_id": "evt_xyz789",
            "forensics": {
                "network": {
                    "is_vpn": True,
                    "is_tor": False,
                    "is_proxy": False,
                    "is_datacenter": True,
                    "is_mobile": False,
                    "asn": 12345,
                    "asn_org": "Example Hosting",
                    "isp": "Example ISP",
                },
                "location": {
                    "city": "New York",
                    "region": "New York",
                    "country_code": "US",
                    "country_name": "United States",
                    "latitude": 40.7128,
                    "longitude": -74.006,
                    "timezone": "America/New_York",
                },
            },
            "created_at": "2026-03-01T12:00:00Z",
            "updated_at": "2026-03-01T12:30:00Z",
            "resolved_at": None,
            "resolution_notes": None,
            "metadata": {"attempts": 50},
        }
        
        alert = Alert.from_dict(data)
        
        self.assertEqual(alert.id, "alert_abc123")
        self.assertEqual(alert.alert_type, "brute_force_attack")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.status, "open")
        self.assertEqual(alert.title, "Brute Force Attack Detected")
        self.assertEqual(alert.trigger_event_id, "evt_xyz789")
        self.assertIsNotNone(alert.forensics)
        self.assertTrue(alert.forensics.network.is_vpn)
        self.assertEqual(alert.forensics.network.asn, 12345)
        self.assertEqual(alert.forensics.location.city, "New York")
        self.assertEqual(alert.forensics.location.country_code, "US")
        self.assertEqual(alert.metadata, {"attempts": 50})
    
    def test_from_dict_minimal(self):
        """Test creating Alert from minimal data"""
        from litesoc import Alert
        
        data = {
            "id": "alert_minimal",
        }
        
        alert = Alert.from_dict(data)
        
        self.assertEqual(alert.id, "alert_minimal")
        self.assertEqual(alert.alert_type, "")
        self.assertEqual(alert.severity, "")
        self.assertEqual(alert.status, "")
        self.assertEqual(alert.title, "")
        self.assertIsNone(alert.trigger_event_id)
        self.assertIsNone(alert.forensics)
        self.assertIsNone(alert.description)
    
    def test_from_dict_null_forensics_free_tier(self):
        """Test creating Alert with null forensics (Free tier)"""
        from litesoc import Alert
        
        data = {
            "id": "alert_free",
            "alert_type": "geo_anomaly",
            "severity": "medium",
            "status": "open",
            "title": "Geographic Anomaly",
            "trigger_event_id": "evt_123",
            "forensics": None,
        }
        
        alert = Alert.from_dict(data)
        
        self.assertEqual(alert.id, "alert_free")
        self.assertEqual(alert.trigger_event_id, "evt_123")
        self.assertIsNone(alert.forensics)
        # Accessing forensics properties should not throw
        if alert.forensics:
            _ = alert.forensics.network.is_vpn
    
    def test_to_dict(self):
        """Test Alert to_dict method"""
        from litesoc import Alert, Forensics, LocationForensics, NetworkForensics
        
        alert = Alert(
            id="alert_test",
            alert_type="impossible_travel",
            severity="critical",
            status="open",
            title="Impossible Travel Detected",
            trigger_event_id="evt_abc",
            forensics=Forensics(
                network=NetworkForensics(
                    is_vpn=False,
                    is_tor=True,
                    is_proxy=False,
                    is_datacenter=False,
                    is_mobile=False,
                ),
                location=LocationForensics(city="Paris", country_code="FR"),
            ),
        )
        
        result = alert.to_dict()
        
        self.assertEqual(result["id"], "alert_test")
        self.assertEqual(result["trigger_event_id"], "evt_abc")
        self.assertIsNotNone(result["forensics"])
        self.assertTrue(result["forensics"]["network"]["is_tor"])
        self.assertEqual(result["forensics"]["location"]["city"], "Paris")
    
    def test_to_dict_null_forensics(self):
        """Test Alert to_dict with null forensics"""
        from litesoc import Alert
        
        alert = Alert(
            id="alert_no_forensics",
            alert_type="suspicious_activity",
            severity="low",
            status="resolved",
            title="Suspicious Activity",
            forensics=None,
        )
        
        result = alert.to_dict()
        
        self.assertEqual(result["id"], "alert_no_forensics")
        self.assertIsNone(result["forensics"])
        self.assertIsNone(result["trigger_event_id"])


if __name__ == "__main__":
    unittest.main()

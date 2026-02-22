"""
Tests for LiteSOC Python SDK
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from litesoc import LiteSOC, Actor, EventSeverity


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
        self.sdk.track("auth.login_success", actor_id="user_123", actor_email="test@example.com")
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

    def test_track_multiple_events(self):
        """Test tracking multiple events"""
        for i in range(5):
            self.sdk.track("auth.login_failed", actor_id=f"user_{i}")
        self.assertEqual(self.sdk.get_queue_size(), 5)


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
        with LiteSOC(api_key="test-key") as sdk:
            sdk.track("auth.login_failed", actor_id="user_123")
            self.assertEqual(sdk.get_queue_size(), 1)
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


if __name__ == "__main__":
    unittest.main()

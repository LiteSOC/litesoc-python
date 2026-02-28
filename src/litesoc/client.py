"""
LiteSOC Python SDK Client
"""

import atexit
import threading
from datetime import datetime, timezone
from typing import Any, Optional, Union

import requests

from litesoc.types import (
    Actor,
    EventSeverity,
    EventType,
    LiteSOCAuthError,
    LiteSOCConfig,
    LiteSOCError,
    PlanRestrictedError,
    QueuedEvent,
    RateLimitError,
)

__version__ = "2.0.0"

# Default base URL for the API
DEFAULT_BASE_URL = "https://api.litesoc.io"


class LiteSOC:
    """
    LiteSOC SDK for tracking security events and managing alerts.
    
    Example:
        ```python
        from litesoc import LiteSOC
        
        litesoc = LiteSOC(api_key="your-api-key")
        
        # Track a login failure
        litesoc.track("auth.login_failed", 
            actor_id="user_123",
            actor_email="user@example.com",
            user_ip="192.168.1.1",
            metadata={"reason": "invalid_password"}
        )
        
        # Get alerts from the Management API
        alerts = litesoc.get_alerts(status="open", severity="high")
        
        # Flush remaining events before shutdown
        litesoc.flush()
        ```
    """
    
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        endpoint: Optional[str] = None,
        batching: bool = True,
        batch_size: int = 10,
        flush_interval: float = 5.0,
        debug: bool = False,
        silent: bool = True,
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the LiteSOC SDK.
        
        Args:
            api_key: Your LiteSOC API key (required)
            base_url: Base URL for the API (default: https://api.litesoc.io)
            endpoint: Legacy endpoint URL (deprecated, use base_url instead)
            batching: Enable event batching (default: True)
            batch_size: Number of events before auto-flush (default: 10)
            flush_interval: Seconds between auto-flushes (default: 5.0)
            debug: Enable debug logging (default: False)
            silent: Fail silently on errors (default: True)
            timeout: Request timeout in seconds (default: 30.0)
        
        Raises:
            ValueError: If api_key is not provided
        """
        if not api_key:
            raise ValueError("LiteSOC: api_key is required")
        
        # Handle legacy endpoint parameter
        if endpoint is not None:
            # If endpoint is provided, extract base_url from it
            # This maintains backward compatibility
            if endpoint.endswith("/collect"):
                base_url = endpoint[:-8]  # Remove /collect
            else:
                base_url = endpoint.rstrip("/")
        
        self._base_url = base_url.rstrip("/")
        
        self._config = LiteSOCConfig(
            api_key=api_key,
            endpoint=f"{self._base_url}/collect",
            batching=batching,
            batch_size=batch_size,
            flush_interval=flush_interval,
            debug=debug,
            silent=silent,
            timeout=timeout,
        )
        
        self._queue: list[QueuedEvent] = []
        self._queue_lock = threading.Lock()
        self._flush_timer: Optional[threading.Timer] = None
        self._is_flushing = False
        self._session = requests.Session()
        
        # Set up session headers
        self._session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": f"litesoc-python-sdk/{__version__}",
        })
        
        # Register shutdown handler
        atexit.register(self.shutdown)
        
        self._log("Initialized with base URL:", self._base_url)
    
    def track(
        self,
        event_name: EventType,
        *,
        actor_id: Optional[str] = None,
        actor_email: Optional[str] = None,
        actor: Optional[Union[Actor, str, dict[str, str]]] = None,
        user_ip: Optional[str] = None,
        severity: Optional[Union[EventSeverity, str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        timestamp: Optional[Union[datetime, str]] = None,
    ) -> None:
        """
        Track a security event.
        
        Args:
            event_name: The event type (e.g., 'auth.login_failed')
            actor_id: User/actor ID (shorthand for actor)
            actor_email: Actor's email address
            actor: Actor object, ID string, or dict with 'id' and 'email'
            user_ip: End-user's IP address
            severity: Event severity level
            metadata: Additional event metadata
            timestamp: Custom timestamp (defaults to now)
        
        Example:
            ```python
            # Track with individual parameters
            litesoc.track("auth.login_failed",
                actor_id="user_123",
                actor_email="user@example.com",
                user_ip="192.168.1.1",
                metadata={"reason": "invalid_password"}
            )
            
            # Track with Actor object
            from litesoc import Actor
            litesoc.track("auth.login_failed",
                actor=Actor(id="user_123", email="user@example.com"),
                user_ip="192.168.1.1"
            )
            ```
        """
        try:
            # Normalize actor
            actor_dict: Optional[dict[str, Optional[str]]] = None
            
            if actor is not None:
                if isinstance(actor, Actor):
                    actor_dict = actor.to_dict()
                elif isinstance(actor, str):
                    actor_dict = {"id": actor, "email": actor_email}
                elif isinstance(actor, dict):
                    actor_dict = {
                        "id": actor.get("id"),
                        "email": actor.get("email") or actor_email,
                    }
            elif actor_id is not None:
                actor_dict = {"id": actor_id, "email": actor_email}
            elif actor_email is not None:
                actor_dict = {"id": actor_email, "email": actor_email}
            
            # Normalize timestamp
            if timestamp is None:
                ts = datetime.now(timezone.utc).isoformat()
            elif isinstance(timestamp, datetime):
                ts = timestamp.isoformat()
            else:
                ts = timestamp
            
            # Normalize severity
            severity_str: Optional[str] = None
            if severity is not None:
                severity_str = (
                    severity.value if isinstance(severity, EventSeverity) else severity
                )
            
            # Build metadata
            event_metadata: dict[str, Any] = {
                **(metadata or {}),
                "_sdk": "litesoc-python",
                "_sdk_version": __version__,
            }
            if severity_str:
                event_metadata["_severity"] = severity_str
            
            # Create queued event
            queued_event = QueuedEvent(
                event=event_name,
                actor=actor_dict,
                user_ip=user_ip,
                metadata=event_metadata,
                timestamp=ts,
            )
            
            self._log("Tracking event:", event_name, queued_event)
            
            if self._config.batching:
                with self._queue_lock:
                    self._queue.append(queued_event)
                    queue_size = len(self._queue)
                
                self._log(f"Event queued. Queue size: {queue_size}")
                
                if queue_size >= self._config.batch_size:
                    self.flush()
                else:
                    self._schedule_flush()
            else:
                self._send_events([queued_event])
        
        except Exception as e:
            self._handle_error("track", e)
    
    def flush(self) -> None:
        """
        Flush all queued events to the server.
        
        Example:
            ```python
            # Flush before application shutdown
            litesoc.flush()
            ```
        """
        if self._is_flushing:
            self._log("Flush already in progress, skipping")
            return
        
        # Cancel scheduled flush
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None
        
        # Get events to send
        with self._queue_lock:
            events = self._queue.copy()
            self._queue.clear()
        
        if not events:
            self._log("No events to flush")
            return
        
        self._is_flushing = True
        self._log(f"Flushing {len(events)} events")
        
        try:
            self._send_events(events)
        finally:
            self._is_flushing = False
    
    def get_queue_size(self) -> int:
        """Get the current queue size."""
        with self._queue_lock:
            return len(self._queue)
    
    def clear_queue(self) -> None:
        """Clear all queued events without sending."""
        with self._queue_lock:
            self._queue.clear()
        
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None
        
        self._log("Queue cleared")
    
    def shutdown(self) -> None:
        """
        Shutdown the SDK gracefully.
        Flushes remaining events and cleans up resources.
        """
        self._log("Shutting down...")
        self.flush()
        
        # Defensive cleanup - timer is normally cancelled by flush()
        if self._flush_timer is not None:  # pragma: no cover
            self._flush_timer.cancel()
            self._flush_timer = None
        
        self._session.close()
        self._log("Shutdown complete")
    
    # ============================================
    # CONVENIENCE METHODS
    # ============================================
    
    def track_login_failed(
        self,
        actor_id: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a login failure event."""
        self.track(
            "auth.login_failed",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            metadata=metadata,
        )
    
    def track_login_success(
        self,
        actor_id: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a login success event."""
        self.track(
            "auth.login_success",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            metadata=metadata,
        )
    
    def track_privilege_escalation(
        self,
        actor_id: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a privilege escalation event (critical severity)."""
        self.track(
            "admin.privilege_escalation",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            severity=EventSeverity.CRITICAL,
            metadata=metadata,
        )
    
    def track_sensitive_access(
        self,
        actor_id: str,
        resource: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a sensitive data access event (high severity)."""
        self.track(
            "data.sensitive_access",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            severity=EventSeverity.HIGH,
            metadata={"resource": resource, **(metadata or {})},
        )
    
    def track_bulk_delete(
        self,
        actor_id: str,
        record_count: int,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a bulk delete event (high severity)."""
        self.track(
            "data.bulk_delete",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            severity=EventSeverity.HIGH,
            metadata={"records_deleted": record_count, **(metadata or {})},
        )
    
    def track_role_changed(
        self,
        actor_id: str,
        old_role: str,
        new_role: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track a role change event."""
        self.track(
            "authz.role_changed",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            metadata={"old_role": old_role, "new_role": new_role, **(metadata or {})},
        )
    
    def track_access_denied(
        self,
        actor_id: str,
        resource: str,
        *,
        actor_email: Optional[str] = None,
        user_ip: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Track an access denied event."""
        self.track(
            "authz.access_denied",
            actor_id=actor_id,
            actor_email=actor_email,
            user_ip=user_ip,
            metadata={"resource": resource, **(metadata or {})},
        )
    
    # ============================================
    # MANAGEMENT API METHODS
    # ============================================
    
    def get_alerts(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """
        Get alerts from the Management API.
        
        Args:
            status: Filter by status ('open', 'resolved', 'safe')
            severity: Filter by severity ('low', 'medium', 'high', 'critical')
            limit: Maximum number of alerts to return (default: 100)
        
        Returns:
            Dictionary containing alerts data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            PlanRestrictedError: If feature is not available on current plan
            LiteSOCError: For other API errors
        
        Example:
            ```python
            alerts = litesoc.get_alerts(status="open", severity="high")
            for alert in alerts.get("alerts", []):
                print(f"Alert: {alert['id']} - {alert['type']}")
            ```
        """
        params: dict[str, Any] = {"limit": limit}
        if status is not None:
            params["status"] = status
        if severity is not None:
            params["severity"] = severity
        
        return self._api_request("GET", "/alerts", params=params)
    
    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Get a single alert by ID.
        
        Args:
            alert_id: The alert ID
        
        Returns:
            Dictionary containing alert data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            LiteSOCError: For other API errors
        
        Example:
            ```python
            alert = litesoc.get_alert("alert_abc123")
            print(f"Alert type: {alert['type']}")
            ```
        """
        return self._api_request("GET", f"/alerts/{alert_id}")
    
    def resolve_alert(
        self,
        alert_id: str,
        resolution_type: str,
        *,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Resolve an alert.
        
        Args:
            alert_id: The alert ID
            resolution_type: Resolution type ('fixed', 'false_positive', 'ignored')
            notes: Optional resolution notes
        
        Returns:
            Dictionary containing updated alert data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            LiteSOCError: For other API errors
        
        Example:
            ```python
            litesoc.resolve_alert(
                "alert_abc123",
                "fixed",
                notes="Issue was addressed in PR #123"
            )
            ```
        """
        body: dict[str, Any] = {
            "status": "resolved",
            "resolution_type": resolution_type,
        }
        if notes is not None:
            body["notes"] = notes
        
        return self._api_request("PATCH", f"/alerts/{alert_id}", json=body)
    
    def mark_alert_safe(
        self,
        alert_id: str,
        *,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Mark an alert as safe/false positive.
        
        Args:
            alert_id: The alert ID
            notes: Optional notes explaining why this is safe
        
        Returns:
            Dictionary containing updated alert data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            LiteSOCError: For other API errors
        
        Example:
            ```python
            litesoc.mark_alert_safe(
                "alert_abc123",
                notes="This is expected behavior from the test suite"
            )
            ```
        """
        body: dict[str, Any] = {"status": "safe"}
        if notes is not None:
            body["notes"] = notes
        
        return self._api_request("PATCH", f"/alerts/{alert_id}", json=body)
    
    def get_events(
        self,
        *,
        limit: int = 20,
    ) -> dict[str, Any]:
        """
        Get events from the Management API.
        
        Args:
            limit: Maximum number of events to return (default: 20)
        
        Returns:
            Dictionary containing events data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            PlanRestrictedError: If feature is not available on current plan
            LiteSOCError: For other API errors
        
        Example:
            ```python
            events = litesoc.get_events(limit=50)
            for event in events.get("events", []):
                print(f"Event: {event['type']} - {event['timestamp']}")
            ```
        """
        return self._api_request("GET", "/events", params={"limit": limit})
    
    def get_event(self, event_id: str) -> dict[str, Any]:
        """
        Get a single event by ID.
        
        Args:
            event_id: The event ID
        
        Returns:
            Dictionary containing event data
        
        Raises:
            LiteSOCAuthError: If authentication fails
            RateLimitError: If rate limit is exceeded
            LiteSOCError: For other API errors
        
        Example:
            ```python
            event = litesoc.get_event("event_abc123")
            print(f"Event type: {event['type']}")
            ```
        """
        return self._api_request("GET", f"/events/{event_id}")
    
    # ============================================
    # PRIVATE METHODS
    # ============================================
    
    def _api_request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Make a request to the Management API.
        
        Args:
            method: HTTP method
            path: API path (e.g., '/alerts')
            params: Query parameters
            json: Request body
        
        Returns:
            Dictionary containing API response
        
        Raises:
            LiteSOCAuthError: If authentication fails (401/403)
            RateLimitError: If rate limit is exceeded (429)
            PlanRestrictedError: If plan restriction applies
            LiteSOCError: For other API errors
        """
        url = f"{self._base_url}{path}"
        
        try:
            response = self._session.request(
                method,
                url,
                params=params,
                json=json,
                timeout=self._config.timeout,
            )
            
            # Handle errors
            if not response.ok:
                self._handle_api_error(response)
            
            return response.json()  # type: ignore[no-any-return]
        
        except (LiteSOCError, LiteSOCAuthError, RateLimitError, PlanRestrictedError):
            raise
        except requests.exceptions.Timeout as e:
            raise LiteSOCError("Request timed out", status_code=408) from e
        except requests.exceptions.RequestException as e:
            raise LiteSOCError(f"Request failed: {e}") from e
    
    def _handle_api_error(self, response: requests.Response) -> None:
        """Handle API error responses."""
        try:
            data = response.json()
            message = data.get("error", data.get("message", "Unknown error"))
            error_code = data.get("code")
        except Exception:
            message = response.text or f"HTTP {response.status_code}"
            error_code = None
        
        status_code = response.status_code
        
        if status_code == 401:
            raise LiteSOCAuthError(
                message,
                status_code=status_code,
                error_code=error_code,
            )
        
        if status_code == 403:
            # Check if it's a plan restriction
            try:
                data = response.json()
                if data.get("code") == "PLAN_RESTRICTED":
                    raise PlanRestrictedError(
                        message,
                        status_code=status_code,
                        error_code=error_code,
                        required_plan=data.get("required_plan"),
                    )
            except (PlanRestrictedError, ValueError, KeyError):
                if isinstance(
                    response.json() if response.text else {},
                    dict
                ) and response.json().get("code") == "PLAN_RESTRICTED":
                    raise
            raise LiteSOCAuthError(
                message,
                status_code=status_code,
                error_code=error_code,
            )
        
        if status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                message,
                status_code=status_code,
                error_code=error_code,
                retry_after=int(retry_after) if retry_after else None,
            )
        
        raise LiteSOCError(
            message,
            status_code=status_code,
            error_code=error_code,
        )

    def _schedule_flush(self) -> None:
        """Schedule a flush after the flush interval."""
        if self._flush_timer is not None:
            return
        
        self._flush_timer = threading.Timer(
            self._config.flush_interval,
            self._scheduled_flush
        )
        self._flush_timer.daemon = True
        self._flush_timer.start()
    
    def _scheduled_flush(self) -> None:
        """Handle scheduled flush."""
        self._flush_timer = None
        try:
            self.flush()
        except Exception as e:
            self._handle_error("scheduled flush", e)
    
    def _send_events(self, events: list[QueuedEvent]) -> None:
        """Send events to the LiteSOC API."""
        if not events:
            return
        
        try:
            # Single event or batch
            is_batch = len(events) > 1
            if is_batch:
                payload = {"events": [e.to_dict() for e in events]}
            else:
                payload = events[0].to_dict()
            
            response = self._session.post(
                self._config.endpoint,
                json=payload,
                timeout=self._config.timeout,
            )
            
            response.raise_for_status()
            result = response.json()
            
            if result.get("success"):
                batch_info = ""
                if is_batch:
                    batch_info = f"(batch, {result.get('events_accepted')} accepted)"
                self._log(f"Successfully sent {len(events)} event(s)", batch_info)
            else:
                raise Exception(result.get("error", "Unknown API error"))
        
        except Exception:
            # Re-queue events for retry (with limit)
            retryable = [ev for ev in events if ev.retry_count < 3]
            
            if retryable and self._config.batching:
                self._log(f"Re-queuing {len(retryable)} events for retry")
                for event in retryable:
                    event.retry_count += 1
                
                with self._queue_lock:
                    self._queue = retryable + self._queue
                
                self._schedule_flush()
            
            raise
    
    def _handle_error(self, context: str, error: Exception) -> None:
        """Handle errors based on silent mode."""
        if self._config.silent:
            self._log(f"Error in {context}: {error}")
        else:
            raise error
    
    def _log(self, *args: Any) -> None:
        """Log debug messages."""
        if self._config.debug:
            print("[LiteSOC]", *args)
    
    def __enter__(self) -> "LiteSOC":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - flushes events."""
        self.shutdown()

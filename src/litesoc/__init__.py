"""
LiteSOC Python SDK
Official SDK for security event tracking and threat detection

Example:
    ```python
    from litesoc import LiteSOC, SecurityEvents
    
    litesoc = LiteSOC(api_key="your-api-key")
    
    # Track a login failure
    litesoc.track(SecurityEvents.AUTH_LOGIN_FAILED, 
        actor_id="user_123",
        actor_email="user@example.com",
        user_ip="192.168.1.1"
    )
    
    # Get alerts from Management API
    alerts = litesoc.get_alerts(status="open")
    
    # Flush remaining events before shutdown
    litesoc.flush()
    ```
"""

from litesoc.client import LiteSOC
from litesoc.types import (
    Actor,
    AdminEvent,
    ApiEvent,
    AuthEvent,
    AuthzEvent,
    BillingEvent,
    DataEvent,
    EventSeverity,
    EventType,
    LiteSOCAuthError,
    LiteSOCConfig,
    LiteSOCError,
    PlanRestrictedError,
    QueuedEvent,
    RateLimitError,
    ResponseMetadata,
    SecurityEvent,
    SecurityEvents,
    TrackOptions,
    UserEvent,
)

__version__ = "2.0.0"
__all__ = [
    # Core client
    "LiteSOC",
    # Exceptions
    "LiteSOCError",
    "LiteSOCAuthError",
    "RateLimitError",
    "PlanRestrictedError",
    # Types
    "Actor",
    "TrackOptions",
    "EventType",
    "EventSeverity",
    "LiteSOCConfig",
    "QueuedEvent",
    "ResponseMetadata",
    # 26 Standard Events Enum
    "SecurityEvents",
    # Event type literals (backward compatibility)
    "AuthEvent",
    "UserEvent",
    "AuthzEvent",
    "AdminEvent",
    "DataEvent",
    "SecurityEvent",
    "ApiEvent",
    "BillingEvent",
]

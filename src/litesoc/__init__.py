"""
LiteSOC Python SDK
Official SDK for security event tracking and threat detection

Example:
    ```python
    from litesoc import LiteSOC
    
    litesoc = LiteSOC(api_key="your-api-key")
    
    # Track a login failure
    litesoc.track("auth.login_failed", 
        actor_id="user_123",
        actor_email="user@example.com",
        user_ip="192.168.1.1"
    )
    
    # Flush remaining events before shutdown
    litesoc.flush()
    ```
"""

from litesoc.types import (
    Actor,
    TrackOptions,
    EventType,
    EventSeverity,
    LiteSOCConfig,
    QueuedEvent,
    AuthEvent,
    UserEvent,
    AuthzEvent,
    AdminEvent,
    DataEvent,
    SecurityEvent,
    ApiEvent,
    BillingEvent,
)
from litesoc.client import LiteSOC

__version__ = "1.0.0"
__all__ = [
    "LiteSOC",
    "Actor",
    "TrackOptions",
    "EventType",
    "EventSeverity",
    "LiteSOCConfig",
    "QueuedEvent",
    "AuthEvent",
    "UserEvent",
    "AuthzEvent",
    "AdminEvent",
    "DataEvent",
    "SecurityEvent",
    "ApiEvent",
    "BillingEvent",
]

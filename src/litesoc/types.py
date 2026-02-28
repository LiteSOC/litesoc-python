"""
Type definitions for LiteSOC SDK

LiteSOC defines 26 standard security events across 5 categories.
These events are automatically enriched with Security Intelligence
including GeoIP, VPN/Tor/Proxy detection, and threat scoring.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional, Union

# =============================================================================
# SECURITY EVENTS - 26 Standard Events for Security Intelligence
# =============================================================================


class SecurityEvents(str, Enum):
    """
    26 Standard Security Events optimized for Security Intelligence.
    
    These events are automatically enriched with GeoIP, VPN/Tor/Proxy
    detection, and threat scoring when user_ip is provided.
    
    Example:
        ```python
        from litesoc import LiteSOC, SecurityEvents
        
        litesoc = LiteSOC(api_key="your-api-key")
        litesoc.track(SecurityEvents.AUTH_LOGIN_FAILED, actor_id="user_123")
        ```
    """
    # Authentication events (8 events)
    AUTH_LOGIN_SUCCESS = "auth.login_success"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_PASSWORD_RESET = "auth.password_reset"
    AUTH_MFA_ENABLED = "auth.mfa_enabled"
    AUTH_MFA_DISABLED = "auth.mfa_disabled"
    AUTH_SESSION_EXPIRED = "auth.session_expired"
    AUTH_TOKEN_REFRESHED = "auth.token_refreshed"
    
    # Authorization events (4 events)
    AUTHZ_ROLE_CHANGED = "authz.role_changed"
    AUTHZ_PERMISSION_GRANTED = "authz.permission_granted"
    AUTHZ_PERMISSION_REVOKED = "authz.permission_revoked"
    AUTHZ_ACCESS_DENIED = "authz.access_denied"
    
    # Admin events (7 events)
    ADMIN_PRIVILEGE_ESCALATION = "admin.privilege_escalation"
    ADMIN_USER_IMPERSONATION = "admin.user_impersonation"
    ADMIN_SETTINGS_CHANGED = "admin.settings_changed"
    ADMIN_API_KEY_CREATED = "admin.api_key_created"
    ADMIN_API_KEY_REVOKED = "admin.api_key_revoked"
    ADMIN_USER_SUSPENDED = "admin.user_suspended"
    ADMIN_USER_DELETED = "admin.user_deleted"
    
    # Data events (3 events)
    DATA_BULK_DELETE = "data.bulk_delete"
    DATA_SENSITIVE_ACCESS = "data.sensitive_access"
    DATA_EXPORT = "data.export"
    
    # Security events (4 events)
    SECURITY_SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    SECURITY_RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    SECURITY_IP_BLOCKED = "security.ip_blocked"
    SECURITY_BRUTE_FORCE_DETECTED = "security.brute_force_detected"


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================


class LiteSOCError(Exception):
    """
    Base exception for LiteSOC SDK errors.
    
    Attributes:
        message: Human-readable error description
        status_code: HTTP status code (if applicable)
        error_code: LiteSOC error code (if applicable)
    """
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)


class LiteSOCAuthError(LiteSOCError):
    """
    Authentication/Authorization error (401/403).
    
    Raised when the API key is invalid, expired, or lacks
    required permissions.
    """
    pass


class RateLimitError(LiteSOCError):
    """
    Rate limit exceeded error (429).
    
    Raised when too many requests are made in a short period.
    
    Attributes:
        retry_after: Seconds to wait before retrying (if provided)
    """
    
    def __init__(
        self,
        message: str,
        status_code: int = 429,
        error_code: Optional[str] = None,
        retry_after: Optional[int] = None
    ) -> None:
        super().__init__(message, status_code, error_code)
        self.retry_after = retry_after


class PlanRestrictedError(LiteSOCError):
    """
    Plan restriction error (403).
    
    Raised when trying to access features not available
    on the current plan.
    
    Attributes:
        required_plan: The plan required to access this feature
    """
    
    def __init__(
        self,
        message: str,
        status_code: int = 403,
        error_code: Optional[str] = None,
        required_plan: Optional[str] = None
    ) -> None:
        super().__init__(message, status_code, error_code)
        self.required_plan = required_plan


# Event severity levels
class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# 26 STANDARD EVENTS (Primary - Security Intelligence optimized)
# =============================================================================

# Authentication events (8 events)
AuthEvent = Literal[
    "auth.login_success",
    "auth.login_failed",
    "auth.logout",
    "auth.password_reset",
    "auth.mfa_enabled",
    "auth.mfa_disabled",
    "auth.session_expired",
    "auth.token_refreshed",
]

# Authorization events (4 events)
AuthzEvent = Literal[
    "authz.role_changed",
    "authz.permission_granted",
    "authz.permission_revoked",
    "authz.access_denied",
]

# Admin events (7 events)
AdminEvent = Literal[
    "admin.privilege_escalation",
    "admin.user_impersonation",
    "admin.settings_changed",
    "admin.api_key_created",
    "admin.api_key_revoked",
    "admin.user_suspended",
    "admin.user_deleted",
]

# Data events (3 events)
DataEvent = Literal[
    "data.bulk_delete",
    "data.sensitive_access",
    "data.export",
]

# Security events (4 events)
SecurityEvent = Literal[
    "security.suspicious_activity",
    "security.rate_limit_exceeded",
    "security.ip_blocked",
    "security.brute_force_detected",
]


# =============================================================================
# LEGACY/EXTENDED EVENTS (Backward Compatibility)
# =============================================================================

# Extended authentication events
LegacyAuthEvent = Literal[
    "auth.password_changed",
    "auth.password_reset_requested",
    "auth.password_reset_completed",
    "auth.mfa_challenge_success",
    "auth.mfa_challenge_failed",
    "auth.session_created",
    "auth.session_revoked",
    "auth.failed",
]

# User events
UserEvent = Literal[
    "user.created",
    "user.updated",
    "user.deleted",
    "user.email_changed",
    "user.email_verified",
    "user.phone_changed",
    "user.phone_verified",
    "user.profile_updated",
    "user.avatar_changed",
    "user.login_failed",
    "user.login.failed",
]

# Extended authorization events
LegacyAuthzEvent = Literal[
    "authz.role_assigned",
    "authz.role_removed",
    "authz.access_granted",
]

# Extended admin events
LegacyAdminEvent = Literal[
    "admin.invite_sent",
    "admin.invite_accepted",
    "admin.member_removed",
]

# Extended data events
LegacyDataEvent = Literal[
    "data.import",
    "data.bulk_update",
    "data.download",
    "data.upload",
    "data.shared",
    "data.unshared",
]

# Extended security events
LegacySecurityEvent = Literal[
    "security.ip_unblocked",
    "security.account_locked",
    "security.account_unlocked",
    "security.impossible_travel",
    "security.geo_anomaly",
]

# API events
ApiEvent = Literal[
    "api.key_used",
    "api.rate_limited",
    "api.error",
    "api.webhook_sent",
    "api.webhook_failed",
]

# Billing events
BillingEvent = Literal[
    "billing.subscription_created",
    "billing.subscription_updated",
    "billing.subscription_cancelled",
    "billing.payment_succeeded",
    "billing.payment_failed",
    "billing.invoice_created",
    "billing.invoice_paid",
]

# All event types (26 standard + legacy/extended + custom)
EventType = Union[
    # Primary 26 standard events
    AuthEvent,
    AuthzEvent,
    AdminEvent,
    DataEvent,
    SecurityEvent,
    # Extended/Legacy events
    LegacyAuthEvent,
    UserEvent,
    LegacyAuthzEvent,
    LegacyAdminEvent,
    LegacyDataEvent,
    LegacySecurityEvent,
    ApiEvent,
    BillingEvent,
    str,  # Allow custom events
]


@dataclass
class Actor:
    """Actor (user) information"""
    
    id: str
    email: Optional[str] = None
    
    def to_dict(self) -> dict[str, Optional[str]]:
        """Convert to dictionary for API payload"""
        return {"id": self.id, "email": self.email}


@dataclass
class TrackOptions:
    """Options for tracking an event"""
    
    actor: Optional[Union[Actor, str]] = None
    actor_email: Optional[str] = None
    user_ip: Optional[str] = None
    severity: Optional[EventSeverity] = None
    metadata: Optional[dict[str, Any]] = None
    timestamp: Optional[Union[datetime, str]] = None


@dataclass
class QueuedEvent:
    """Internal event structure for the queue"""
    
    event: str
    actor: Optional[dict[str, Optional[str]]]
    user_ip: Optional[str]
    metadata: dict[str, Any]
    timestamp: str
    retry_count: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API payload"""
        return {
            "event": self.event,
            "actor": self.actor,
            "user_ip": self.user_ip,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class LiteSOCConfig:
    """SDK configuration options"""
    
    api_key: str
    endpoint: str = "https://api.litesoc.io/collect"
    batching: bool = True
    batch_size: int = 10
    flush_interval: float = 5.0  # seconds
    debug: bool = False
    silent: bool = True
    timeout: float = 5.0  # seconds (optimized for non-blocking behavior)

"""
Type definitions for LiteSOC SDK
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union


# Event severity levels
class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Authentication events
AuthEvent = Literal[
    "auth.login_success",
    "auth.login_failed",
    "auth.logout",
    "auth.password_changed",
    "auth.password_reset_requested",
    "auth.password_reset_completed",
    "auth.mfa_enabled",
    "auth.mfa_disabled",
    "auth.mfa_challenge_success",
    "auth.mfa_challenge_failed",
    "auth.session_created",
    "auth.session_revoked",
    "auth.token_refreshed",
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

# Authorization events
AuthzEvent = Literal[
    "authz.role_assigned",
    "authz.role_removed",
    "authz.role_changed",
    "authz.permission_granted",
    "authz.permission_revoked",
    "authz.access_denied",
    "authz.access_granted",
]

# Admin events
AdminEvent = Literal[
    "admin.privilege_escalation",
    "admin.user_impersonation",
    "admin.settings_changed",
    "admin.api_key_created",
    "admin.api_key_revoked",
    "admin.invite_sent",
    "admin.invite_accepted",
    "admin.member_removed",
]

# Data events
DataEvent = Literal[
    "data.export",
    "data.import",
    "data.bulk_delete",
    "data.bulk_update",
    "data.sensitive_access",
    "data.download",
    "data.upload",
    "data.shared",
    "data.unshared",
]

# Security events
SecurityEvent = Literal[
    "security.suspicious_activity",
    "security.rate_limit_exceeded",
    "security.ip_blocked",
    "security.ip_unblocked",
    "security.account_locked",
    "security.account_unlocked",
    "security.brute_force_detected",
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

# All event types
EventType = Union[
    AuthEvent,
    UserEvent,
    AuthzEvent,
    AdminEvent,
    DataEvent,
    SecurityEvent,
    ApiEvent,
    BillingEvent,
    str,  # Allow custom events
]


@dataclass
class Actor:
    """Actor (user) information"""
    
    id: str
    email: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert to dictionary for API payload"""
        return {"id": self.id, "email": self.email}


@dataclass
class TrackOptions:
    """Options for tracking an event"""
    
    actor: Optional[Union[Actor, str]] = None
    actor_email: Optional[str] = None
    user_ip: Optional[str] = None
    severity: Optional[EventSeverity] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[Union[datetime, str]] = None


@dataclass
class QueuedEvent:
    """Internal event structure for the queue"""
    
    event: str
    actor: Optional[Dict[str, Optional[str]]]
    user_ip: Optional[str]
    metadata: Dict[str, Any]
    timestamp: str
    retry_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
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
    endpoint: str = "https://www.litesoc.io/api/v1/collect"
    batching: bool = True
    batch_size: int = 10
    flush_interval: float = 5.0  # seconds
    debug: bool = False
    silent: bool = True
    timeout: float = 30.0  # seconds

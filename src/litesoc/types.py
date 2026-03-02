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
    ADMIN_USER_CREATED = "admin.user_created"
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
        upgrade_url: URL to upgrade the plan
    
    Upgrade at: https://www.litesoc.io/pricing
    """
    
    UPGRADE_URL = "https://www.litesoc.io/pricing"
    
    def __init__(
        self,
        message: str,
        status_code: int = 403,
        error_code: Optional[str] = None,
        required_plan: Optional[str] = None
    ) -> None:
        super().__init__(message, status_code, error_code)
        self.required_plan = required_plan
        self.upgrade_url = self.UPGRADE_URL


# Event severity levels (matches Events API: info, warning, critical)
class EventSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
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
    "admin.user_created",
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
    retry_count: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API payload.
        
        Note: timestamp is not sent to the API as the server
        generates its own timestamp for consistency.
        """
        return {
            "event": self.event,
            "actor": self.actor,
            "user_ip": self.user_ip,
            "metadata": self.metadata,
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


@dataclass
class ResponseMetadata:
    """
    Plan and quota information from API response headers.
    
    Parsed from response headers:
    - X-LiteSOC-Plan: Current plan name (e.g., "free", "pro", "enterprise")
    - X-LiteSOC-Retention: Data retention period in days
    - X-LiteSOC-Cutoff: Earliest accessible data timestamp (ISO 8601)
    
    Example:
        ```python
        events = litesoc.get_events()
        plan_info = litesoc.get_plan_info()
        if plan_info:
            print(f"Plan: {plan_info.plan}")
            print(f"Retention: {plan_info.retention_days} days")
        ```
    """
    
    plan: Optional[str] = None
    retention_days: Optional[int] = None
    cutoff_date: Optional[str] = None
    
    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "ResponseMetadata":
        """
        Create ResponseMetadata from HTTP response headers.
        
        Args:
            headers: Response headers dictionary
        
        Returns:
            ResponseMetadata instance with parsed values
        """
        # Normalize header names to lowercase for case-insensitive access
        normalized = {k.lower(): v for k, v in headers.items()}
        
        plan = normalized.get("x-litesoc-plan")
        retention_str = normalized.get("x-litesoc-retention")
        cutoff = normalized.get("x-litesoc-cutoff")
        
        # Parse retention days - API returns "30 days" format, extract the number
        retention_days: Optional[int] = None
        if retention_str:
            # Handle both "30 days" and "30" formats
            retention_str = retention_str.strip()
            if retention_str.endswith(" days"):
                retention_str = retention_str[:-5]  # Remove " days" suffix
            try:
                retention_days = int(retention_str)
            except ValueError:
                retention_days = None
        
        return cls(
            plan=plan,
            retention_days=retention_days,
            cutoff_date=cutoff,
        )
    
    def has_plan_info(self) -> bool:
        """Check if plan information is available."""
        return self.plan is not None
    
    def has_retention_info(self) -> bool:
        """Check if retention information is available."""
        return self.retention_days is not None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan": self.plan,
            "retention_days": self.retention_days,
            "cutoff_date": self.cutoff_date,
        }


# =============================================================================
# FORENSICS TYPES (Pro/Enterprise plans only)
# =============================================================================


@dataclass
class NetworkForensics:
    """
    Network forensics information (Pro/Enterprise plans only).
    
    Contains network intelligence data including VPN, Tor, proxy detection,
    and ISP/ASN information.
    
    Note: Returns None for Free tier users.
    """
    
    is_vpn: bool
    """Whether the IP is from a VPN provider."""
    
    is_tor: bool
    """Whether the IP is a Tor exit node."""
    
    is_proxy: bool
    """Whether the IP is from a proxy server."""
    
    is_datacenter: bool
    """Whether the IP is from a datacenter/cloud provider."""
    
    is_mobile: bool
    """Whether the IP is from a mobile carrier."""
    
    asn: Optional[int] = None
    """Autonomous System Number."""
    
    asn_org: Optional[str] = None
    """Autonomous System Organization name."""
    
    isp: Optional[str] = None
    """Internet Service Provider name."""
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkForensics":
        """Create NetworkForensics from API response dictionary."""
        return cls(
            is_vpn=data.get("is_vpn", False),
            is_tor=data.get("is_tor", False),
            is_proxy=data.get("is_proxy", False),
            is_datacenter=data.get("is_datacenter", False),
            is_mobile=data.get("is_mobile", False),
            asn=data.get("asn"),
            asn_org=data.get("asn_org"),
            isp=data.get("isp"),
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_vpn": self.is_vpn,
            "is_tor": self.is_tor,
            "is_proxy": self.is_proxy,
            "is_datacenter": self.is_datacenter,
            "is_mobile": self.is_mobile,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
        }


@dataclass
class LocationForensics:
    """
    Location forensics information (Pro/Enterprise plans only).
    
    Contains GeoIP location data including city, country, and coordinates.
    
    Note: Returns None for Free tier users.
    """
    
    city: Optional[str] = None
    """City name."""
    
    region: Optional[str] = None
    """Region/state name."""
    
    country_code: Optional[str] = None
    """ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')."""
    
    country_name: Optional[str] = None
    """Full country name."""
    
    latitude: Optional[float] = None
    """Latitude coordinate."""
    
    longitude: Optional[float] = None
    """Longitude coordinate."""
    
    timezone: Optional[str] = None
    """Timezone (e.g., 'America/New_York')."""
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LocationForensics":
        """Create LocationForensics from API response dictionary."""
        return cls(
            city=data.get("city"),
            region=data.get("region"),
            country_code=data.get("country_code"),
            country_name=data.get("country_name"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            timezone=data.get("timezone"),
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "city": self.city,
            "region": self.region,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
        }


@dataclass
class Forensics:
    """
    Forensics data attached to alerts (Pro/Enterprise plans only).
    
    Contains network intelligence and location data for threat analysis.
    
    Note: Returns None for Free tier users.
    
    Example:
        ```python
        alert = litesoc.get_alert("alert_123")
        if alert.get("forensics"):
            forensics = Forensics.from_dict(alert["forensics"])
            if forensics.network.is_vpn:
                print("Alert originated from VPN")
            print(f"Location: {forensics.location.city}, {forensics.location.country_code}")
        ```
    """
    
    network: NetworkForensics
    """Network intelligence data."""
    
    location: LocationForensics
    """Location/GeoIP data."""
    
    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> Optional["Forensics"]:
        """
        Create Forensics from API response dictionary.
        
        Args:
            data: Forensics dictionary from API response, or None
        
        Returns:
            Forensics instance, or None if data is None (Free tier)
        """
        if data is None:
            return None
        
        return cls(
            network=NetworkForensics.from_dict(data.get("network", {})),
            location=LocationForensics.from_dict(data.get("location", {})),
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "network": self.network.to_dict(),
            "location": self.location.to_dict(),
        }


@dataclass
class Alert:
    """
    Alert object returned from the Management API.
    
    Represents a security alert detected by LiteSOC's threat detection engine.
    
    Example:
        ```python
        alerts_data = litesoc.get_alerts(status="open")
        for alert_data in alerts_data.get("data", []):
            alert = Alert.from_dict(alert_data)
            print(f"{alert.title} - {alert.severity}")
            if alert.forensics:
                print(f"  VPN: {alert.forensics.network.is_vpn}")
                print(f"  Location: {alert.forensics.location.city}")
        ```
    """
    
    id: str
    """Unique alert identifier."""
    
    alert_type: str
    """Alert type (e.g., 'brute_force_attack', 'impossible_travel')."""
    
    severity: str
    """Alert severity ('low', 'medium', 'high', 'critical')."""
    
    status: str
    """Alert status ('open', 'acknowledged', 'resolved', 'dismissed')."""
    
    title: str
    """Human-readable alert title."""
    
    description: Optional[str] = None
    """Detailed alert description."""
    
    source_ip: Optional[str] = None
    """Source IP address that triggered the alert."""
    
    actor_id: Optional[str] = None
    """Actor/user ID associated with the alert."""
    
    trigger_event_id: Optional[str] = None
    """The event ID that triggered this alert."""
    
    forensics: Optional[Forensics] = None
    """
    Forensics data (network intelligence + location).
    Only available on Pro/Enterprise plans. Returns None for Free tier.
    """
    
    created_at: Optional[str] = None
    """ISO 8601 timestamp when alert was created."""
    
    updated_at: Optional[str] = None
    """ISO 8601 timestamp when alert was last updated."""
    
    resolved_at: Optional[str] = None
    """ISO 8601 timestamp when alert was resolved (if resolved)."""
    
    resolution_notes: Optional[str] = None
    """Notes explaining the resolution."""
    
    metadata: Optional[dict[str, Any]] = None
    """Additional metadata."""
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """
        Create Alert from API response dictionary.
        
        Args:
            data: Alert dictionary from API response
        
        Returns:
            Alert instance
        """
        return cls(
            id=data["id"],
            alert_type=data.get("alert_type", ""),
            severity=data.get("severity", ""),
            status=data.get("status", ""),
            title=data.get("title", ""),
            description=data.get("description"),
            source_ip=data.get("source_ip"),
            actor_id=data.get("actor_id"),
            trigger_event_id=data.get("trigger_event_id"),
            forensics=Forensics.from_dict(data.get("forensics")),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            resolved_at=data.get("resolved_at"),
            resolution_notes=data.get("resolution_notes"),
            metadata=data.get("metadata"),
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "status": self.status,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "actor_id": self.actor_id,
            "trigger_event_id": self.trigger_event_id,
            "forensics": self.forensics.to_dict() if self.forensics else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved_at": self.resolved_at,
            "resolution_notes": self.resolution_notes,
            "metadata": self.metadata,
        }

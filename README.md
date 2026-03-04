# LiteSOC Python SDK

Official Python SDK for [LiteSOC](https://www.litesoc.io) - Security event tracking and threat detection for your applications.

[![PyPI version](https://badge.fury.io/py/litesoc.svg)](https://badge.fury.io/py/litesoc)
[![Python Version](https://img.shields.io/pypi/pyversions/litesoc.svg)](https://pypi.org/project/litesoc/)
[![CI](https://github.com/LiteSOC/litesoc-python/actions/workflows/ci.yml/badge.svg)](https://github.com/LiteSOC/litesoc-python/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/LiteSOC/litesoc-python)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
pip install litesoc
```

## Quick Start

```python
from litesoc import LiteSOC, SecurityEvents

# Initialize the SDK
litesoc = LiteSOC(api_key="your-api-key")

# Track a login failure using the SecurityEvents enum
litesoc.track(SecurityEvents.AUTH_LOGIN_FAILED,
    actor_id="user_123",
    actor_email="user@example.com",
    user_ip="192.168.1.1",  # Required for Security Intelligence
    metadata={"reason": "invalid_password"}
)

# Get alerts from the Management API
alerts = litesoc.get_alerts(status="open", severity="high")

# Flush remaining events before shutdown
litesoc.flush()
```

## Features

- ✅ **Event Ingestion API** - Track security events via `/api/v1/collect`
- ✅ **Management API** - Query events and alerts via `/api/v1/events` and `/api/v1/alerts`
- ✅ **26 standard security event types** - Authentication, authorization, admin, data, and security events
- ✅ **Automatic batching** - Events are batched for efficient delivery
- ✅ **Batch ingestion helper** - `track_batch()` sends up to 100 events in a single request
- ✅ **Retry logic** - Failed events are automatically retried
- ✅ **Type hints** - Full type annotations for IDE support
- ✅ **Thread-safe** - Safe to use across multiple threads
- ✅ **Context manager support** - Use with `with` statement for automatic cleanup
- ✅ **Custom exceptions** - Typed error handling with `LiteSOCError`, `RateLimitError`, etc.
- 🗺️ **GeoIP Enrichment** - Automatic location data from IP addresses
- 🛡️ **Network Intelligence** - VPN, Tor, Proxy & Datacenter detection
- 📊 **Threat Scoring** - Auto-assigned severity (Low → Critical)

## API Endpoints

The SDK provides access to three LiteSOC API endpoints:

| Endpoint | SDK Methods | Description |
|----------|-------------|-------------|
| `POST /api/v1/collect` | `track()`, `flush()` | Ingest security events |
| `GET /api/v1/events` | `get_events()`, `get_event()` | Query events (all plans) |
| `GET/PATCH /api/v1/alerts` | `get_alerts()`, `get_alert()`, `resolve_alert()`, `mark_alert_safe()` | Manage alerts (Pro/Enterprise) |

## Security Intelligence (Automatic Enrichment)

When you provide `user_ip`, LiteSOC automatically enriches your events with:

### 🗺️ Geolocation
- Country & City resolution
- Latitude/Longitude coordinates
- Interactive map visualization in dashboard

### 🛡️ Network Intelligence
- **VPN Detection** - NordVPN, ExpressVPN, Surfshark, etc.
- **Tor Exit Nodes** - Anonymizing network detection
- **Proxy Detection** - HTTP/SOCKS proxy identification
- **Datacenter IPs** - AWS, GCP, Azure, DigitalOcean, etc.

### 📊 Threat Scoring
Events are auto-classified by severity:
- **Low** - Normal activity
- **Medium** - Unusual patterns
- **High** - Suspicious behavior
- **Critical** - Active threats (triggers instant alerts)

> **Important**: Always include `user_ip` for full Security Intelligence features.

## Configuration Options

```python
from litesoc import LiteSOC

litesoc = LiteSOC(
    api_key="your-api-key",      # Required
    endpoint="https://...",       # Custom API endpoint
    batching=True,                # Enable event batching (default: True)
    batch_size=10,                # Events before auto-flush (default: 10)
    flush_interval=5.0,           # Seconds between auto-flushes (default: 5.0)
    debug=False,                  # Enable debug logging (default: False)
    silent=True,                  # Fail silently on errors (default: True)
    timeout=5.0,                  # Request timeout in seconds (default: 5.0)
)
```

## Tracking Events

### Event Ingestion API (`/api/v1/collect`)

The `track()` method sends security events to LiteSOC for analysis and alerting.

### Basic Usage

```python
# Track any event type
litesoc.track("auth.login_failed",
    actor_id="user_123",
    actor_email="user@example.com",
    user_ip="192.168.1.1"
)
```

### Batch Ingestion with `track_batch` (v2.5.0+)

To minimize network overhead and take advantage of Redis pipelining on the
LiteSOC backend, you can send up to **100 events** in a single call using
`track_batch`:

```python
from litesoc import LiteSOC

litesoc = LiteSOC(api_key="your-api-key")

events = [
    {
        "event_name": "auth.login_success",
        "actor_id": "user_123",
        "actor_email": "user@example.com",
        "user_ip": "203.0.113.50",
        "metadata": {"method": "password"},
    },
    {
        "event_name": "data.export",
        "actor_id": "user_123",
        "user_ip": "203.0.113.50",
        "metadata": {"table": "orders", "rows": 500},
    },
]

accepted = litesoc.track_batch(events)
print(f"{accepted} events accepted")
```

### Using Actor Object

```python
from litesoc import LiteSOC, Actor

litesoc = LiteSOC(api_key="your-api-key")

actor = Actor(id="user_123", email="user@example.com")
litesoc.track("auth.login_success", actor=actor, user_ip="192.168.1.1")
```

### With Severity Level

```python
from litesoc import EventSeverity

litesoc.track("security.suspicious_activity",
    actor_id="user_123",
    user_ip="192.168.1.1",
    severity=EventSeverity.CRITICAL,
    metadata={"reason": "impossible travel detected"}
)
```

### With Metadata

```python
litesoc.track("data.export",
    actor_id="user_123",
    user_ip="192.168.1.1",
    metadata={
        "file_type": "csv",
        "record_count": 1000,
        "export_reason": "monthly_report"
    }
)
```

## Management API

The SDK provides methods to interact with the LiteSOC Management API:

### Events API (`/api/v1/events`)

Available to **all plans**. Free tier users have some forensic fields redacted.

#### Get Events

```python
from litesoc import LiteSOC

litesoc = LiteSOC(api_key="your-api-key")

# Get recent events
events = litesoc.get_events()

# Filter by event name
events = litesoc.get_events(event_name="auth.login_failed")

# Filter by actor
events = litesoc.get_events(actor_id="user_123")

# Filter by severity
events = litesoc.get_events(severity="critical")  # critical, warning, info

# Pagination
events = litesoc.get_events(limit=50, offset=100)

# Access the data
for event in events.get("data", []):
    print(f"Event: {event['event_name']} - {event['created_at']}")
    print(f"  Actor: {event.get('actor_id')}")
    print(f"  IP: {event.get('user_ip')}")
```

#### Get Single Event

```python
event = litesoc.get_event("event-uuid-here")
print(f"Event: {event['data']['event_name']}")
```

### Alerts API (`/api/v1/alerts`)

Available to **Pro and Enterprise** plans only.

#### Get Alerts

```python
from litesoc import LiteSOC, PlanRestrictedError

litesoc = LiteSOC(api_key="your-api-key")

try:
    # Get all open alerts
    alerts = litesoc.get_alerts(status="open")

    # Filter by severity
    alerts = litesoc.get_alerts(severity="critical")  # critical, high, medium, low

    # Filter by alert type
    alerts = litesoc.get_alerts(alert_type="brute_force_attack")
    # Types: impossible_travel, brute_force_attack, geo_anomaly, new_device,
    #        privilege_escalation, data_exfiltration, suspicious_activity, rate_limit_exceeded

    # Pagination
    alerts = litesoc.get_alerts(limit=100, offset=0)

    # Access the data
    for alert in alerts.get("data", []):
        print(f"Alert: {alert['id']} - {alert['alert_type']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Status: {alert['status']}")

except PlanRestrictedError as e:
    print(f"Alerts API requires {e.required_plan} plan")
```

#### Get Single Alert

```python
alert = litesoc.get_alert("alert-uuid-here")
print(f"Alert type: {alert['data']['alert_type']}")
```

#### Resolve Alert

```python
# Resolve with resolution type (required)
litesoc.resolve_alert(
    "alert-uuid-here",
    resolution_type="blocked_ip",  # blocked_ip, reset_password, contacted_user, false_positive, other
    notes="IP has been blocked in firewall",
    resolved_by="security-team"  # Optional: who/what resolved it
)

# Mark as false positive
litesoc.resolve_alert(
    "alert-uuid-here",
    resolution_type="false_positive",
    notes="This was a test from the QA team"
)
```

#### Mark Alert Safe

```python
litesoc.mark_alert_safe(
    "alert-uuid-here",
    notes="This is expected behavior from the CI/CD pipeline",
    resolved_by="automation"  # Optional: who/what marked it safe
)
```

### Plan Info

Get plan information from the last API response:

```python
# Make an API call first
alerts = litesoc.get_alerts()

# Get plan info from response headers
plan_info = litesoc.get_plan_info()
if plan_info:
    print(f"Plan: {plan_info.plan}")
    print(f"Retention: {plan_info.retention_days} days")
    print(f"Cutoff: {plan_info.cutoff_date}")
```

## SecurityEvents Enum

Use the `SecurityEvents` enum for type-safe event tracking:

```python
from litesoc import LiteSOC, SecurityEvents

litesoc = LiteSOC(api_key="your-api-key")

# Use enum for type safety and IDE autocomplete
litesoc.track(SecurityEvents.AUTH_LOGIN_FAILED, actor_id="user_123")
litesoc.track(SecurityEvents.ADMIN_PRIVILEGE_ESCALATION, actor_id="admin_user")
litesoc.track(SecurityEvents.DATA_SENSITIVE_ACCESS, actor_id="user_123")
```

All 26 standard events are available:
- `AUTH_LOGIN_SUCCESS`, `AUTH_LOGIN_FAILED`, `AUTH_LOGOUT`, etc.
- `AUTHZ_ROLE_CHANGED`, `AUTHZ_PERMISSION_GRANTED`, etc.
- `ADMIN_PRIVILEGE_ESCALATION`, `ADMIN_USER_IMPERSONATION`, etc.
- `DATA_BULK_DELETE`, `DATA_SENSITIVE_ACCESS`, `DATA_EXPORT`
- `SECURITY_SUSPICIOUS_ACTIVITY`, `SECURITY_BRUTE_FORCE_DETECTED`, etc.

## Error Handling

The SDK provides custom exception classes for proper error handling:

```python
from litesoc import (
    LiteSOC,
    LiteSOCError,
    LiteSOCAuthError,
    RateLimitError,
    PlanRestrictedError,
)

litesoc = LiteSOC(api_key="your-api-key")

try:
    alerts = litesoc.get_alerts()
except LiteSOCAuthError as e:
    print(f"Authentication failed: {e.message} (status: {e.status_code})")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
except PlanRestrictedError as e:
    print(f"Feature requires {e.required_plan} plan")
except LiteSOCError as e:
    print(f"API error: {e.message}")
```

## Convenience Methods

The SDK provides convenience methods for common security events:

```python
# Track login failures
litesoc.track_login_failed("user_123", user_ip="192.168.1.1")

# Track login successes
litesoc.track_login_success("user_123", user_ip="192.168.1.1")

# Track privilege escalation (critical severity)
litesoc.track_privilege_escalation("admin_user", user_ip="192.168.1.1")

# Track sensitive data access (high severity)
litesoc.track_sensitive_access("user_123", "customer_pii_table", user_ip="192.168.1.1")

# Track bulk deletions (high severity)
litesoc.track_bulk_delete("admin_user", record_count=500, user_ip="192.168.1.1")

# Track role changes
litesoc.track_role_changed("user_123", old_role="viewer", new_role="admin", user_ip="192.168.1.1")

# Track access denied
litesoc.track_access_denied("user_123", resource="/admin/settings", user_ip="192.168.1.1")
```

## Event Types

### 26 Standard Events (Primary)

These are the primary events for comprehensive security coverage:

| Category | Event Type | Description |
|----------|------------|-------------|
| **Auth** | `auth.login_success` | Successful user login |
| **Auth** | `auth.login_failed` | Failed login attempt |
| **Auth** | `auth.logout` | User logout |
| **Auth** | `auth.password_reset` | Password reset completed |
| **Auth** | `auth.mfa_enabled` | MFA enabled on account |
| **Auth** | `auth.mfa_disabled` | MFA disabled on account |
| **Auth** | `auth.session_expired` | Session timeout/expiry |
| **Auth** | `auth.token_refreshed` | Token refresh |
| **Authz** | `authz.role_changed` | User role modified |
| **Authz** | `authz.permission_granted` | Permission assigned |
| **Authz** | `authz.permission_revoked` | Permission removed |
| **Authz** | `authz.access_denied` | Access denied event |
| **Admin** | `admin.privilege_escalation` | Admin privilege escalation |
| **Admin** | `admin.user_impersonation` | Admin impersonating user |
| **Admin** | `admin.settings_changed` | System settings modified |
| **Admin** | `admin.api_key_created` | New API key generated |
| **Admin** | `admin.api_key_revoked` | API key revoked |
| **Admin** | `admin.user_suspended` | User account suspended |
| **Admin** | `admin.user_deleted` | User account deleted |
| **Data** | `data.bulk_delete` | Bulk data deletion |
| **Data** | `data.sensitive_access` | PII/sensitive data accessed |
| **Data** | `data.export` | Data export operation |
| **Security** | `security.suspicious_activity` | Suspicious behavior detected |
| **Security** | `security.rate_limit_exceeded` | Rate limit triggered |
| **Security** | `security.ip_blocked` | IP address blocked |
| **Security** | `security.brute_force_detected` | Brute force attack detected |

### Extended Events (Backward Compatible)

Additional events for granular tracking:

- `auth.password_changed`, `auth.password_reset_requested`, `auth.mfa_challenge_success`, `auth.mfa_challenge_failed`, `auth.session_created`
- `user.created`, `user.updated`, `user.deleted`, `user.email_changed`, `user.profile_updated`
- `authz.role_assigned`, `authz.role_removed`, `authz.access_granted`
- `admin.invite_sent`, `admin.invite_accepted`, `admin.member_removed`
- `data.import`, `data.bulk_update`, `data.download`, `data.upload`, `data.shared`
- `security.ip_unblocked`, `security.account_locked`, `security.impossible_travel`, `security.geo_anomaly`
- `api.key_used`, `api.rate_limited`, `api.error`, `api.webhook_sent`, `api.webhook_failed`
- `billing.subscription_created`, `billing.subscription_cancelled`, `billing.payment_succeeded`, `billing.payment_failed`

## Framework Integration

### Flask

```python
from flask import Flask, request, g
from litesoc import LiteSOC

app = Flask(__name__)
litesoc = LiteSOC(api_key="your-api-key")

@app.route("/login", methods=["POST"])
def login():
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # Attempt authentication
    user = authenticate(request.form["email"], request.form["password"])
    
    if user:
        litesoc.track_login_success(user.id, actor_email=user.email, user_ip=user_ip)
        return {"success": True}
    else:
        litesoc.track_login_failed(request.form["email"], user_ip=user_ip)
        return {"success": False}, 401
```

### Django

```python
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver
from litesoc import LiteSOC

litesoc = LiteSOC(api_key="your-api-key")

@receiver(user_logged_in)
def track_login_success(sender, request, user, **kwargs):
    user_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
    litesoc.track_login_success(str(user.id), actor_email=user.email, user_ip=user_ip)

@receiver(user_login_failed)
def track_login_failure(sender, credentials, request, **kwargs):
    user_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
    litesoc.track_login_failed(credentials.get("username", "unknown"), user_ip=user_ip)
```

### FastAPI

```python
from fastapi import FastAPI, Request, Depends
from litesoc import LiteSOC

app = FastAPI()
litesoc = LiteSOC(api_key="your-api-key")

@app.post("/login")
async def login(request: Request, credentials: LoginRequest):
    user_ip = request.headers.get("X-Forwarded-For", request.client.host)
    
    user = await authenticate(credentials.email, credentials.password)
    
    if user:
        litesoc.track_login_success(user.id, actor_email=user.email, user_ip=user_ip)
        return {"success": True}
    else:
        litesoc.track_login_failed(credentials.email, user_ip=user_ip)
        raise HTTPException(status_code=401)
```

## Context Manager Support

```python
from litesoc import LiteSOC

with LiteSOC(api_key="your-api-key") as litesoc:
    litesoc.track("auth.login_success", actor_id="user_123")
    # Events are automatically flushed when exiting the context
```

## Queue Management

```python
# Get current queue size
queue_size = litesoc.get_queue_size()

# Manually flush all events
litesoc.flush()

# Clear queue without sending
litesoc.clear_queue()

# Graceful shutdown
litesoc.shutdown()
```

## Error Handling

By default, the SDK fails silently (`silent=True`). To catch errors:

```python
litesoc = LiteSOC(api_key="your-api-key", silent=False)

try:
    litesoc.track("auth.login_failed", actor_id="user_123")
    litesoc.flush()
except Exception as e:
    print(f"Failed to track event: {e}")
```

## Debug Mode

Enable debug logging to troubleshoot issues:

```python
litesoc = LiteSOC(api_key="your-api-key", debug=True)
# Logs will be printed to stdout
```

## Performance Tips

### Timeout Configuration

The SDK uses a **5-second default timeout** for all API requests. This prevents slow network conditions from blocking your application:

```python
# Default: 5-second timeout
litesoc = LiteSOC(api_key="your-api-key")

# Custom timeout for the entire client
litesoc = LiteSOC(api_key="your-api-key", timeout=10.0)

# Per-request timeout override (takes precedence)
alerts = litesoc.get_alerts(timeout=2.0)  # 2-second timeout for this call
events = litesoc.get_events(timeout=3.0)  # 3-second timeout for this call
```

### Graceful Timeout Handling

The `track()` method handles timeouts gracefully, returning `False` instead of raising an exception:

```python
# track() returns True on success, False on timeout
success = litesoc.track("auth.login_success", actor_id="user_123")
if not success:
    print("Event tracking timed out, but application continues")
```

### Batching for High-Throughput

For applications with high event volume, batching reduces network overhead:

```python
litesoc = LiteSOC(
    api_key="your-api-key",
    batching=True,
    batch_size=50,          # Send after 50 events
    flush_interval=10.0,    # Or every 10 seconds
)
```

## Development

### Prerequisites

- Python 3.9+
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/LiteSOC/litesoc-python.git
cd litesoc-python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src/litesoc --cov-report=term-missing

# Run specific test file
pytest tests/test_litesoc.py -v
```

### Code Quality

```bash
# Run linter
ruff check src/ tests/

# Run type checker
mypy src/

# Format code
ruff format src/ tests/
```

### Building

```bash
# Build package
python -m build

# Install locally
pip install -e .
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [LiteSOC Website](https://www.litesoc.io)
- [Documentation](https://www.litesoc.io/docs)
- [API Reference](https://www.litesoc.io/docs/api)
- [GitHub Repository](https://github.com/LiteSOC/litesoc-python)

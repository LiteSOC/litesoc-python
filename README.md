# LiteSOC Python SDK

Official Python SDK for [LiteSOC](https://www.litesoc.io) - Security event tracking and threat detection for your applications.

[![PyPI version](https://badge.fury.io/py/litesoc.svg)](https://badge.fury.io/py/litesoc)
[![Python Version](https://img.shields.io/pypi/pyversions/litesoc.svg)](https://pypi.org/project/litesoc/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
pip install litesoc
```

## Quick Start

```python
from litesoc import LiteSOC

# Initialize the SDK
litesoc = LiteSOC(api_key="your-api-key")

# Track a login failure
litesoc.track("auth.login_failed",
    actor_id="user_123",
    actor_email="user@example.com",
    user_ip="192.168.1.1",
    metadata={"reason": "invalid_password"}
)

# Flush remaining events before shutdown
litesoc.flush()
```

## Features

- ✅ **50+ pre-defined security event types** - Authentication, authorization, data access, and more
- ✅ **Automatic batching** - Events are batched for efficient delivery
- ✅ **Retry logic** - Failed events are automatically retried
- ✅ **Type hints** - Full type annotations for IDE support
- ✅ **Thread-safe** - Safe to use across multiple threads
- ✅ **Context manager support** - Use with `with` statement for automatic cleanup

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
    timeout=30.0,                 # Request timeout in seconds (default: 30.0)
)
```

## Tracking Events

### Basic Usage

```python
# Track any event type
litesoc.track("auth.login_failed",
    actor_id="user_123",
    actor_email="user@example.com",
    user_ip="192.168.1.1"
)
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

### Authentication Events
- `auth.login_success`
- `auth.login_failed`
- `auth.logout`
- `auth.password_changed`
- `auth.password_reset_requested`
- `auth.password_reset_completed`
- `auth.mfa_enabled`
- `auth.mfa_disabled`
- `auth.mfa_challenge_success`
- `auth.mfa_challenge_failed`
- `auth.session_created`
- `auth.session_revoked`
- `auth.token_refreshed`

### User Events
- `user.created`
- `user.updated`
- `user.deleted`
- `user.email_changed`
- `user.email_verified`
- `user.profile_updated`

### Authorization Events
- `authz.role_assigned`
- `authz.role_removed`
- `authz.role_changed`
- `authz.permission_granted`
- `authz.permission_revoked`
- `authz.access_denied`
- `authz.access_granted`

### Admin Events
- `admin.privilege_escalation`
- `admin.user_impersonation`
- `admin.settings_changed`
- `admin.api_key_created`
- `admin.api_key_revoked`
- `admin.invite_sent`
- `admin.invite_accepted`
- `admin.member_removed`

### Data Events
- `data.export`
- `data.import`
- `data.bulk_delete`
- `data.bulk_update`
- `data.sensitive_access`
- `data.download`
- `data.upload`
- `data.shared`
- `data.unshared`

### Security Events
- `security.suspicious_activity`
- `security.rate_limit_exceeded`
- `security.ip_blocked`
- `security.ip_unblocked`
- `security.account_locked`
- `security.account_unlocked`
- `security.brute_force_detected`
- `security.impossible_travel`
- `security.geo_anomaly`

### API Events
- `api.key_used`
- `api.rate_limited`
- `api.error`
- `api.webhook_sent`
- `api.webhook_failed`

### Billing Events
- `billing.subscription_created`
- `billing.subscription_updated`
- `billing.subscription_cancelled`
- `billing.payment_succeeded`
- `billing.payment_failed`

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

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [LiteSOC Website](https://www.litesoc.io)
- [Documentation](https://www.litesoc.io/docs)
- [API Reference](https://www.litesoc.io/docs/api)
- [GitHub Repository](https://github.com/LiteSOC/litesoc-python)

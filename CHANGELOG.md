# Changelog

All notable changes to the LiteSOC Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-03-02

### Changed

#### Management API Enhancements
- **`get_events()`** - Added new optional parameters to match API spec:
  - `event_name` - Filter by event name
  - `actor_id` - Filter by actor ID
  - `severity` - Filter by severity level
  - `offset` - Pagination offset
- **`get_alerts()`** - Added new optional parameters to match API spec:
  - `alert_type` - Filter by alert type
  - `offset` - Pagination offset
- **`resolve_alert()`** - API body now sends `{ action: 'resolve', resolution_type, internal_notes }` to match API spec
- **`mark_alert_safe()`** - API body now sends `{ action: 'mark_safe', internal_notes }` to match API spec

### Fixed
- Aligned SDK methods with API codebase requirements for all Management API endpoints
- Updated test suite (106 tests, 99% coverage)
- Fixed docstring parameter name from `event` to `event_name` in `get_events()`

## [2.1.0] - 2026-03-01

### Added

#### Alert Model Enhancements
- **`trigger_event_id`** - New field on `Alert` dataclass linking alerts to their triggering event
- **`forensics`** - New field on `Alert` dataclass containing network intelligence and location data

#### Forensics Types (Pro/Enterprise)
- **`Forensics`** - Container dataclass for network and location forensics data
- **`NetworkForensics`** - Network intelligence dataclass including:
  - `is_vpn`, `is_tor`, `is_proxy`, `is_datacenter`, `is_mobile` - Boolean flags
  - `asn`, `asn_org`, `isp` - Autonomous System and ISP information
- **`LocationForensics`** - GeoIP location dataclass including:
  - `city`, `region`, `country_code`, `country_name` - Location strings
  - `latitude`, `longitude` - Coordinates
  - `timezone` - IANA timezone identifier

#### New Exports
- Added `Alert`, `Forensics`, `NetworkForensics`, `LocationForensics` to module exports

### Changed
- **Version** - Updated to 2.1.0

### Notes
- `forensics` returns `None` for Free tier users - ensure null-safe access in your code
- `trigger_event_id` may be `None` for alerts not triggered by a specific event
- All new dataclasses include `from_dict()` and `to_dict()` methods for easy serialization

## [2.0.0] - 2026-02-28

### Added

#### Management API
- **`get_alerts(status, severity, limit)`** - Get alerts from the Management API with optional filters
- **`get_alert(alert_id)`** - Get a single alert by ID
- **`resolve_alert(alert_id, resolution_type, notes)`** - Resolve an alert with resolution type
- **`mark_alert_safe(alert_id, notes)`** - Mark an alert as safe/false positive
- **`get_events(limit)`** - Get events from the Management API
- **`get_event(event_id)`** - Get a single event by ID

#### SecurityEvents Enum
- **`SecurityEvents`** - New enum class with all 26 standard security events
- Use `SecurityEvents.AUTH_LOGIN_FAILED` instead of `"auth.login_failed"` for type safety

#### Custom Exception Classes
- **`LiteSOCError`** - Base exception class for all SDK errors
- **`LiteSOCAuthError`** - Authentication/authorization errors (401/403)
- **`RateLimitError`** - Rate limit exceeded (429) with `retry_after` attribute
- **`PlanRestrictedError`** - Plan restriction errors with `required_plan` attribute

#### Method-level Timeout Overrides
- All Management API methods now support an optional `timeout` parameter
- `track()`, `flush()`, `get_alerts()`, `get_alert()`, `resolve_alert()`, `mark_alert_safe()`, `get_events()`, `get_event()` accept `timeout` parameter
- Per-request timeouts take precedence over the class-level default

### Changed
- **Default Timeout** - Reduced from 30 seconds to **5 seconds** for faster failure detection
- **Authentication Header** - Changed from `Authorization: Bearer` to `X-API-Key` header
- **Base URL Configuration** - New `base_url` parameter (default: `https://api.litesoc.io`)
  - The `endpoint` parameter is now deprecated but still supported for backward compatibility
- **User-Agent Format** - Updated from `litesoc-python/x.x.x` to `litesoc-python-sdk/x.x.x`
- **`track()` Return Value** - Now returns `bool` (`True` on success, `False` on timeout) for graceful timeout handling
- **403 Error Messages** - Now include upgrade hints (e.g., "Upgrade to Business plan to access this feature")

### Breaking Changes
- None - All v1.x code continues to work. The `endpoint` parameter is deprecated but fully supported.

## [1.2.0] - 2026-02-25

### Changed
- **New API Endpoint** - Updated default endpoint from `https://litesoc.io/api/v1/collect` to `https://api.litesoc.io/collect`
  - Cleaner subdomain-based API architecture
  - Improved routing and performance
  - No breaking changes - existing custom endpoints continue to work

### Notes
- If you're using a custom `endpoint` parameter, no changes needed
- The new endpoint provides the same functionality with improved infrastructure

## [1.1.0] - 2026-02-22

### Added
- **26 Standard Security Events** - Reorganized event types into 5 categories:
  - Auth (8 events): `login_success`, `login_failed`, `logout`, `password_reset`, `mfa_enabled`, `mfa_disabled`, `session_expired`, `token_refreshed`
  - Authz (4 events): `role_changed`, `permission_granted`, `permission_revoked`, `access_denied`
  - Admin (7 events): `privilege_escalation`, `user_impersonation`, `settings_changed`, `api_key_created`, `api_key_revoked`, `user_suspended`, `user_deleted`
  - Data (3 events): `bulk_delete`, `sensitive_access`, `export`
  - Security (4 events): `suspicious_activity`, `rate_limit_exceeded`, `ip_blocked`, `brute_force_detected`
- **Security Intelligence Documentation** - Added documentation for auto-enrichment features:
  - GeoIP Enrichment (country, city, coordinates)
  - Network Intelligence (VPN, Tor, Proxy, Datacenter detection)
  - Threat Scoring (Low → Critical severity auto-classification)
- New type definitions: `AuthEvent`, `AuthzEvent`, `AdminEvent`, `DataEvent`, `SecurityEvent`

### Changed
- Reorganized `types.py` with standard events as primary Literal types
- Updated README with Security Intelligence section and 26-event table
- Emphasized importance of `user_ip` parameter for full enrichment features

### Deprecated
- Legacy event types (e.g., `LegacyAuthEvent`, `LegacySecurityEvent`) still supported for backward compatibility

## [1.0.1] - Previous Release

- Initial stable release with basic event tracking

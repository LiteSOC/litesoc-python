# Changelog

All notable changes to the LiteSOC Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

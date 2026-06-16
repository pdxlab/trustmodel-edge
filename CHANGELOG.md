# Changelog

All notable changes to TrustModel Edge.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may introduce breaking changes on minor bumps.

## [0.4.0] — 2026-06-16

### Added — TRUS-1270 (Edge OAuth)

- **`POST /v1/oauth/token`** — OAuth 2.0 `client_credentials` token endpoint.
  Accepts `client_id` + `client_secret` (form-encoded), validates against the
  policy-sync'd `authorized_clients` list, returns a short-lived JWT (default
  1 h TTL, configurable via `EDGE_OAUTH_TOKEN_TTL_SECONDS`) signed with Edge's
  enrollment cert private key.
- **`POST /mcp/oauth/token`** — URL alias for `/v1/oauth/token` so the
  published TrustModel Python SDK (which hardcodes the `/mcp/` path under
  `base_url`) works against Edge without per-customer overrides.
- **Policy-sync payload** now consumes the `authorized_clients` array shipped
  by aurora-gateway (`GET /api/v1/edge/policy/current/`). Edge caches the
  client list locally and validates `client_credentials` requests fully
  offline — no round-trip to aurora-gateway on the token-mint path.
- **Pydantic model** `AuthorizedClient` on the `EdgePolicy` wire format.

### Changed — breaking

- **`POST /v1/decide` now requires an OAuth Bearer JWT** minted by this Edge
  instance's `/v1/oauth/token`. Edge verifies the JWT signature with its own
  public key and enforces the `govern:enforce` scope claim. The `agent_id`
  field on the emitted audit event is sourced from the JWT (the request
  body's `agent_id` is now a fallback used only when the token has no claim).
- Pre-0.4.0 callers without a Bearer token will receive HTTP 401.
- Customers running an older agent code path against a 0.4.0+ Edge must
  upgrade to `trustmodel>=3.2.0` (or any release containing the
  `EdgeTransport` OAuth-Bearer patch) before any agent in their cluster can
  call `decide()`.

### Unchanged

- **Edge ↔ aurora-gateway auth** stays on cert-JWT. Policy sync, heartbeat,
  rotate, telemetry — all still use the cert-JWT minted at Edge enrollment.
  TRUS-1270 adds only the agent-facing OAuth surface; the long-running
  infrastructure auth path is untouched.
- The cert-JWT private key doubles as the OAuth JWT signing key — no new key
  material to provision.

### Dependencies

- Added `python-multipart>=0.0.9,<1.0` (required by FastAPI `Form()` to parse
  the OAuth-spec form-encoded token-endpoint body).

### Documentation

- Customer onboarding walkthrough lives in aurora-gateway's
  `docs/edge-agent-onboarding-guide.md`.
- Local-process E2E recipe lives in aurora-gateway's
  `docs/edge-local-e2e-testing.md`.

## [0.3.0] and earlier

See git history (no formal changelog kept prior to 0.4.0).

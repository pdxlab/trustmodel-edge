# Changelog

All notable changes to TrustModel Edge.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may introduce breaking changes on minor bumps.

## [0.4.1] — 2026-07-22

### Fixed — telemetry-store init must not crash the sidecar

- **`TelemetryStore` now auto-recovers from a corrupt `telemetry.db`.**
  On the `database disk image is malformed` / `file is not a database` /
  `database is locked` markers, the store rotates the offending
  `telemetry.db`, `telemetry.db-wal`, `telemetry.db-shm` files aside
  (renamed with a `.corrupt-<timestamp>` suffix, preserved for
  post-mortem) and retries once with a fresh DB. See
  `src/edge/telemetry/store.py::TelemetryStore._open_or_recreate`.
- **`get_store()` degrades to a `NoopTelemetryStore` if the real store
  cannot be constructed** (unrecoverable corruption, unwritable state
  dir, transient disk I/O errors that outlast one retry). The sidecar
  lifespan continues; `/decide` keeps enforcing policy; audit events
  for the affected instance are dropped and counted via
  `dropped_count` so operators can see the degraded mode on `/metrics`.

### Context

Root cause was reported by XSpan on 2026-07-22 (RCA doc). A ~100-req
burst against a governed agent drove concurrent writes to
`telemetry.db` on a GCSFuse-mounted shared bucket; WAL's `-shm` +
locking assumptions don't hold on FUSE, so the DB corrupted. Every
subsequent container start opened the same corrupt file in the shared
bucket, propagated the exception out of the ASGI lifespan, and exited
before binding port 8080 — blocking the customer's deploy pipeline and
autoscale fleet-wide.

Governance/enforcement never depended on telemetry landing; treating
`get_store()` as fatal was the actual bug. This release makes the
storage failure a warning, not a crash. Long-term event-pipeline
replacement (Azure Service Bus + Event Hubs) is tracked in TRUS-1073.

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

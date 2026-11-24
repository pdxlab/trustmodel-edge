# TrustModel Edge

**In-VPC AGP data plane.** Customer-deployed Kubernetes workload that serves
the AGP `decide()` API locally with cached policy and forwards telemetry
outbound-only to the TrustModel control plane (`aurora-gateway`).

Pattern: Datadog Agent / Splunk Universal Forwarder / Sysdig — the agent
never accepts inbound connections from TrustModel.

## Why Edge exists

The direct SDK pattern (`agent → HTTPS → api.trustmodel.ai`) works on a
laptop but fails for any Fortune 500 with restricted egress, no public
internet, or data-residency rules. Edge lets customers run AGP **inside
their own VPC**. By default (v0.6.0+), tool arguments stay in the pod and
subject IDs are pseudonymised or withheld; decision metadata (agent, policy,
verdict, reason, tool name, matched rule, latency) is forwarded to TrustModel
over mTLS for audit. Setting `telemetry.omitPayload: false`, or running v0.5.x,
also forwards tool arguments and clear subject IDs.

Tracking: [TRUS-984](https://predixtions.atlassian.net/browse/TRUS-984)
(EPIC) · [TRUS-986](https://predixtions.atlassian.net/browse/TRUS-986)
(this scaffold).

## Status — v0.6.0

| Surface | Status | Implementing ticket |
|---|---|---|
| Helm chart + container (amd64 + arm64) | shipped | TRUS-986 |
| `GET /health/live`, `/health/ready` | shipped | TRUS-986 |
| Outbound-only enrollment + bootstrap token, heartbeat | shipped | TRUS-987 |
| Policy cache + offline-tolerant `POST /v1/decide` | shipped | TRUS-988 |
| On-disk telemetry queue + outbound sync | shipped | TRUS-989 |
| Raw payloads + subject IDs kept in-pod by default | shipped | TRUS-1725, TRUS-2002 |
| `POST /v1/enroll-callback` | **501 stub** (Edge never accepts inbound calls) | — |

See [CHANGELOG.md](CHANGELOG.md) for per-release detail.

## Quickstart with Docker (no Kubernetes)

The image is public on GHCR — no registry login needed.

```bash
# 1. Put the one-time bootstrap token from the TrustModel console in an env
#    file (keeps it out of shell history). It is spent on first enrollment.
cat > edge.env <<'ENV'
EDGE_TENANT_ID=<your-tenant>
EDGE_BOOTSTRAP_TOKEN=<tm-bs-...>
ENV

# 2. Run. The named volume holds the mTLS cert, policy cache and telemetry
#    queue — without it a restart has to re-enroll with a spent token.
docker run -d --name trustmodel-edge \
  --env-file edge.env \
  -v trustmodel-edge-state:/var/lib/trustmodel \
  -p 8080:8080 \
  --restart unless-stopped \
  ghcr.io/pdxlab/trustmodel-edge:0.6.0

# 3. Check it
curl -s localhost:8080/health/live    # {"status":"ok"}
curl -s localhost:8080/health/ready   # 200 once enrolled and policies synced
docker logs trustmodel-edge
```

Notes:

* Instead of `EDGE_BOOTSTRAP_TOKEN` you can mount the token as a file:
  `-v "$PWD/bootstrap-token:/etc/trustmodel/bootstrap-token:ro"` (the file
  must be readable by uid 10001, e.g. `chmod 0644`).
* `/health/ready` returns 503 until enrollment and the first policy sync
  succeed. With no token, or if the control plane is unreachable, the
  container exits non-zero so `--restart` retries it.
* `EDGE_CONTROL_PLANE_URL` defaults to `https://api.trustmodel.ai`; override
  it only for QA or self-hosted control planes.
* Pin a version tag in production. `:latest` follows semver releases;
  `:<branch>` tags are QA builds from `release-branch.yml`.

## Quickstart on kind (5 min)

```bash
# 1. Create cluster
kind create cluster --name trustmodel-edge

# 2. Build + load the image (multi-arch build covered by release.yml)
docker build -t trustmodel-edge:dev .
kind load docker-image trustmodel-edge:dev --name trustmodel-edge

# 3. Install with CI fixture values (no PVC, no NetworkPolicy, no HPA)
helm install trustmodel-edge ./chart/trustmodel-edge \
  -f chart/trustmodel-edge/ci/values-ci.yaml \
  --set image.repository=trustmodel-edge \
  --set image.tag=dev \
  --set image.pullPolicy=Never \
  --wait --timeout 90s

# 4. Smoke test
kubectl wait --for=condition=Ready --timeout=60s \
  pod -l app.kubernetes.io/instance=trustmodel-edge
helm test trustmodel-edge
```

## Production install (EKS / GKE / AKS)

```bash
helm install trustmodel-edge oci://ghcr.io/pdxlab/charts/trustmodel-edge \
  --version 0.1.0 \
  --namespace trustmodel-edge --create-namespace \
  --set tenant=acme \
  --set bootstrapToken=tm-bs-...
```

**Required values:**

* `tenant` — your tenant slug (issued by TrustModel)
* `bootstrapToken` — one-time enrollment token from the cosmic-vector
  Add Agent wizard (24h TTL, single-use)

**Common overrides:** see [`chart/trustmodel-edge/README.md`](chart/trustmodel-edge/README.md).

### Cloud-specific notes

| Cloud | StorageClass | Notes |
|---|---|---|
| EKS  | `gp3` (set `--set persistence.storageClass=gp3`) | NetworkPolicy needs the VPC CNI's policy enforcement enabled |
| GKE  | `standard-rwo` or `premium-rwo` | Autopilot supports the chart as-is |
| AKS  | `managed-csi` | Calico must be enabled for NetworkPolicy enforcement |

## Acceptance criteria (TRUS-986)

* `helm install` succeeds on fresh EKS / GKE / AKS clusters
* Pod reaches Ready in **<60s** (startup probe budget enforced)
* Container image **<200MB** (verified in `ci.yml` build step)
* `helm test trustmodel-edge` passes health-check probe

## Repo layout

```
.
├── src/edge/                  Python package (FastAPI app, routes, config)
├── tests/                     pytest — health + stub-route contract tests
├── Dockerfile                 multi-stage, amd64+arm64 via buildx
├── chart/trustmodel-edge/     Helm chart v0.1.0
│   ├── Chart.yaml
│   ├── values.yaml            7 user-tunable keys
│   ├── values.schema.json     fail-fast install validation
│   └── templates/             Deployment · Service · ConfigMap · Secret
│                              ServiceAccount · HPA · PDB · NetworkPolicy
│                              PVC · helm-test · NOTES
└── .github/workflows/
    ├── ci.yml                 lint · test · helm-lint · kubeconform · image-size
    └── release.yml            tag v* → push GHCR multi-arch + OCI chart
```

## Development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest -q
ruff check .

# Run locally (binds 8080)
EDGE_TENANT_ID=local edge
```

## Architecture references

* [TRUS-984 EPIC](https://predixtions.atlassian.net/browse/TRUS-984) — AGP Agent Connectivity / Edge MVP
* Edge architecture plan — `aurora-gateway/var/agp-docs/TRUS-984-edge-architecture-plan.md`
  * §2 Pod internals (3-loop runtime: decide / policy syncer / telemetry syncer)
  * §3 Request flows (enrollment, decide, policy sync, telemetry, heartbeat)
  * §6 New aurora-gateway endpoints (`/api/v1/edge/*`)

## License

Apache-2.0

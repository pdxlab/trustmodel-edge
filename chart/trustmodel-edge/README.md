# trustmodel-edge Helm chart

Installs TrustModel Edge into a Kubernetes cluster. See the
[repo README](../../README.md) for the full architecture overview.

## TL;DR

```bash
helm install trustmodel-edge oci://ghcr.io/pdxlab/charts/trustmodel-edge \
  --version 0.1.0 \
  --set tenant=acme \
  --set bootstrapToken=tm-bs-...
```

## Required values

| Key | Type | Description |
|---|---|---|
| `tenant` | string | Tenant slug this Edge instance serves |
| `bootstrapToken` | string | One-time enrollment token from cosmic-vector wizard |

## Common overrides

| Key | Default | Notes |
|---|---|---|
| `controlPlaneUrl` | `https://api.trustmodel.ai` | Override for QA / staging |
| `image.tag` | `.Chart.AppVersion` | Pin a specific image version |
| `autoscaling.enabled` | `true` | HPA needs metrics-server in-cluster |
| `replicaCount` | `2` | Used only when autoscaling disabled |
| `persistence.size` | `10Gi` | mTLS cert + policy cache + telemetry queue |
| `persistence.storageClass` | (cluster default) | Set explicitly on EKS/GKE/AKS for predictable provisioner |
| `logLevel` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `telemetry.queueSize` | `10000` | In-memory event cap before back-pressure |
| `networkPolicy.enabled` | `true` | Restricts egress to control plane + DNS only |

## Acceptance gates (TRUS-986)

After install:

```bash
# Pod Ready in <60s
kubectl wait --for=condition=Ready --timeout=60s \
  pod -l app.kubernetes.io/instance=trustmodel-edge

# helm test passes
helm test trustmodel-edge
```

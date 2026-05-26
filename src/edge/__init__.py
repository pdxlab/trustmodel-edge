"""TrustModel Edge — in-VPC AGP data plane.

This package is the runtime that customers deploy into their K8s cluster via
the Helm chart in ``chart/trustmodel-edge``. It serves the AGP ``decide()``
API locally with cached policy and forwards telemetry outbound-only to
TrustModel's control plane (aurora-gateway).

TRUS-986 ships the chart + container scaffold with stub routes only. The
real decide / enroll / telemetry logic lands via TRUS-987, TRUS-988, TRUS-989.
"""

__version__ = "0.1.0"

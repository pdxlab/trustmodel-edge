"""TrustModel Edge — in-VPC AGP data plane.

This package is the runtime that customers deploy into their K8s cluster via
the Helm chart in ``chart/trustmodel-edge``. It serves the AGP ``decide()``
API locally with cached policy and forwards telemetry outbound-only to
TrustModel's control plane (aurora-gateway).

TRUS-986 ships the chart + container scaffold with stub routes only. The
real decide / enroll / telemetry logic lands via TRUS-987, TRUS-988, TRUS-989.
"""

# Single source of truth for the package version: pyproject.toml reads it via
# [tool.hatch.version]. Keep it equal to appVersion in
# chart/trustmodel-edge/Chart.yaml (tests/test_version.py fails otherwise).
__version__ = "0.6.0"

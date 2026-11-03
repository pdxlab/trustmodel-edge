"""The runtime version must match the Helm chart's appVersion.

``/health/ready`` and the startup log report ``edge.__version__``. Releases
bump Chart.yaml; if ``__version__`` is not bumped with it, a 0.6.0 image
reports itself as 0.1.0 and support cannot tell which build a customer runs.
"""

from __future__ import annotations

import re
from pathlib import Path

from edge import __version__

CHART = Path(__file__).resolve().parents[1] / "chart" / "trustmodel-edge" / "Chart.yaml"


def _chart_field(name: str) -> str:
    match = re.search(rf'^{name}:\s*"?([^"\s]+)"?\s*$', CHART.read_text(), re.MULTILINE)
    assert match, f"{name} not found in {CHART}"
    return match.group(1)


def test_version_matches_chart_app_version() -> None:
    assert __version__ == _chart_field("appVersion")

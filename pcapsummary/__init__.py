"""pcapsummary — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from pcapsummary.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from pcapsummary.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "pcapsummary"
    TOOL_VERSION = "0.5.0"
try:  # detectors are part of the public API too (additive, non-breaking)
    from pcapsummary.detectors import (  # noqa: F401
        detect_beaconing,
        detect_dns_tunnel,
        detect_exfil,
        detect_port_scan,
        run_all as detect_all,
        DETECTORS,
    )
except Exception:  # pragma: no cover
    pass
__version__ = TOOL_VERSION

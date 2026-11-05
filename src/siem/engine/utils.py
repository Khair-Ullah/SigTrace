"""Small engine helpers."""
from __future__ import annotations

import re
from typing import Optional

_DURATION_RE = re.compile(r"^(\d+)\s*([smhd]?)$", re.I)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value) -> Optional[int]:
    """Parse '60s', '5m', '1h', '300' into seconds. Returns None if invalid."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    if s.isdigit():
        return int(s)
    m = _DURATION_RE.match(s)
    if not m:
        return None
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()]

"""JSON log parser (FR-05)."""
from __future__ import annotations

import json
from typing import Optional


def parse(raw: str) -> Optional[dict]:
    """Parse a single JSON object/array line into a flat field mapping.

    Nested objects are flattened with underscore-joined keys. If the top level
    is a list, only the first object element is used.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None

    if isinstance(data, list):
        data = next((x for x in data if isinstance(x, dict)), None)
        if data is None:
            return None
    if not isinstance(data, dict):
        return None

    flat: dict = {}
    _flatten(data, "", flat)
    return flat


def _flatten(obj: dict, prefix: str, out: dict) -> None:
    for key, value in obj.items():
        name = f"{prefix}_{key}" if prefix else str(key)
        if isinstance(value, dict):
            _flatten(value, name, out)
        elif isinstance(value, list):
            out[name] = json.dumps(value)
        else:
            out[name] = value

"""Helpers for parsing query-string parameters."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from flask import request


def get_int(name: str, default: Optional[int] = None,
            minimum: Optional[int] = None, maximum: Optional[int] = None) -> Optional[int]:
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def get_bool(name: str, default: Optional[bool] = None) -> Optional[bool]:
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def get_str(name: str, default: Optional[str] = None) -> Optional[str]:
    raw = request.args.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip()


def get_dt(name: str) -> Optional[datetime]:
    raw = request.args.get(name)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def pagination(default_per_page: int = 25, max_per_page: int = 200) -> tuple[int, int, int]:
    """Return ``(limit, offset, page)`` derived from ``page``/``per_page``."""
    page = get_int("page", 1, minimum=1) or 1
    per_page = get_int("per_page", default_per_page, minimum=1, maximum=max_per_page) or default_per_page
    return per_page, (page - 1) * per_page, page


def page_meta(total: int, limit: int, page: int) -> dict:
    pages = (total + limit - 1) // limit if limit else 1
    return {
        "total": total,
        "page": page,
        "per_page": limit,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
    }

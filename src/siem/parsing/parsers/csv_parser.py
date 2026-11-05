"""CSV log parser (FR-05) with per-source header caching.

Since the pipeline is line-oriented, the first non-numeric row seen for a
source is treated as the header and cached; subsequent rows map onto it. If no
header is available, columns are mapped to generic keys (col_0, col_1, ...).
"""
from __future__ import annotations

import csv
import io
from typing import Optional


class CSVParser:
    def __init__(self) -> None:
        self._headers: dict[str, list[str]] = {}

    def set_columns(self, source_id: str, columns: list[str]) -> None:
        """Explicitly provide column names for a source (from config)."""
        self._headers[source_id] = [c.strip() for c in columns]

    def parse(self, raw: str, source_id: str = "__default__") -> tuple[dict, bool]:
        """Parse one CSV row.

        Returns (fields, is_header). If the row was consumed as a header, the
        returned fields dict is empty and is_header is True.
        """
        try:
            row = next(csv.reader(io.StringIO(raw)))
        except (csv.Error, StopIteration):
            return {}, False

        headers = self._headers.get(source_id)

        if headers is None and self._is_header_row(row):
            self._headers[source_id] = [c.strip() for c in row]
            return {}, True

        if headers is None:
            headers = [f"col_{i}" for i in range(len(row))]

        fields = {}
        for i, value in enumerate(row):
            key = headers[i] if i < len(headers) else f"col_{i}"
            if key:
                fields[key] = value
        return fields, False

    @staticmethod
    def _is_header_row(row: list[str]) -> bool:
        if not row:
            return False
        tokens = [c.strip() for c in row if c.strip()]
        if not tokens:
            return False
        # A header row: every field is an identifier-like token (no digits-only)
        for tok in tokens:
            if tok.replace("_", "").replace("-", "").isalpha():
                continue
            return False
        return True


def parse(raw: str, source_id: str = "__default__", parser: Optional[CSVParser] = None) -> dict:
    """Stateless convenience wrapper (no header caching)."""
    p = parser or CSVParser()
    fields, _ = p.parse(raw, source_id)
    return fields

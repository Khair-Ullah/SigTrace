"""Import of SigmaHQ-style detection rules (Phase 2).

Converts Sigma rules to the engine's native YAML dialect:

* top-level metadata passes through (title, id, description, author, date,
  logsource, tags, falsepositives, level, status, references, modified)
* selection / group-by field names are translated through
  :data:`FIELD_MAP`, so rules written against raw Windows Event Log field
  names (``EventID``, ``TargetUserName``, ...) match this engine's
  normalized schema (``windows_event_id``, ``user_name``, ...) - the same
  names the agent's Windows collector emits into event extras
* old-style ``aggregation: count() > N by field`` becomes
  ``threshold`` / ``timeframe`` / ``group-by``; unsupported aggregations
  (sum/avg/min/max, ``<`` operators) cause the rule to be skipped rather
  than silently changing its meaning
* ``type: correlation|metric`` and deprecated/unsupported rules are skipped
* every converted rule is validated with the engine's rule validator
  before it is written to disk

Unmapped fields (``Image``, ``CommandLine``, ...) pass through verbatim:
they match only sources that emit those exact field names (e.g. raw JSON
logs), never silently point at a different field.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

import yaml

from siem.core.logger import get_logger
from siem.engine.rule_validator import (
    RESERVED_DETECTION_KEYS,
    validate_rule,
)

log = get_logger("engine.sigma_import")

# Sigma raw field name -> engine flat-schema field name.
# Keys are matched against the base name (before any '|modifier').
FIELD_MAP: dict[str, str] = {
    # Windows Event Log -> agent Windows collector payload / normalized schema
    "EventID": "windows_event_id",
    "Channel": "channel",
    "Computer": "computer",
    "ProviderName": "provider",
    "SubjectUserName": "user_name",
    "TargetUserName": "user_name",
    "AccountName": "user_name",
    "IpAddress": "src_ip",
    "SourceNetworkAddress": "src_ip",
    "ClientAddress": "src_ip",
    "SourceAddress": "src_ip",
    "SourceIp": "src_ip",
    # Winlogbeat ECS-style keys
    "winlog.event_id": "windows_event_id",
    "winlog.channel": "channel",
    "winlog.computer_name": "computer",
}

SKIPPED_STATUSES = {"deprecated", "unsupported"}
SKIPPED_TYPES = {"correlation", "metric"}

# Legacy aggregation default window (Sigma's old aggregation rules rarely
# carried an explicit timeframe; the engine requires one).
DEFAULT_AGGREGATION_TIMEFRAME = "5m"

_RULE_EXTENSIONS = {".yml", ".yaml"}

_AGGREGATION_RE = re.compile(
    r"^\s*count\s*\(\s*\)\s*(?P<op>>=|>|==)\s*(?P<n>\d+)" r"(?:\s+by\s+(?P<by>.+))?\s*$",
    re.IGNORECASE,
)


@dataclass
class ConversionResult:
    ok: bool
    rule: Optional[dict] = None
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class ImportReport:
    imported: list[str] = field(default_factory=list)  # written (or planned) paths
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (source, reason)
    warnings: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def import_count(self) -> int:
        return len(self.imported)

    @property
    def skip_count(self) -> int:
        return len(self.skipped)


# -- field translation ------------------------------------------------------


def map_field(name: str, field_map: Optional[dict[str, str]] = None) -> str:
    """Translate a base field name (modifiers are re-attached by the caller)."""
    mapping = FIELD_MAP if field_map is None else field_map
    return mapping.get(name, name)


def _translate_key(key: str, field_map: Optional[dict[str, str]]) -> str:
    if not field_map:
        return key
    base, sep, modifiers = key.partition("|")
    translated = map_field(base, field_map)
    return f"{translated}{sep}{modifiers}" if sep else translated


def _translate_dict_fields(obj: object, field_map: Optional[dict[str, str]]) -> object:
    if not isinstance(obj, dict):
        return obj
    out: dict = {}
    for k, v in obj.items():
        new_k = _translate_key(k, field_map)
        out[new_k] = _translate_dict_fields(v, field_map)
    return out


def _translate_selection_values(
    detection: dict, field_map: Optional[dict[str, str]], warnings: list[str]
) -> dict:
    """Translate field keys inside selection* mappings."""
    out: dict = {}
    for key, value in detection.items():
        if key in RESERVED_DETECTION_KEYS:
            out[key] = value
            continue
        # selection name (or any other non-reserved top-level detection key that
        # points to selection content) - traverse its contents
        translated = _translate_dict_fields(value, field_map)
        out[key] = translated
        # collect warnings for translated keys at top level of this selection
        if isinstance(value, dict) and isinstance(translated, dict):
            for old_k, new_k in zip(value.keys(), translated.keys()):
                if old_k != new_k:
                    warnings.append(f"field '{old_k}' translated to '{new_k}'")
    return out


# -- legacy aggregation -----------------------------------------------------


def _convert_aggregation(
    detection: dict, warnings: list[str], field_map: Optional[dict[str, str]]
) -> Optional[str]:
    """Convert ``detection.aggregation`` in place.

    Returns a skip reason on failure, None on success (including when no
    aggregation is present).
    """
    agg = detection.pop("aggregation", None)
    if agg is None:
        return None

    if "threshold" in detection:
        warnings.append(
            "rule has both 'threshold' and 'aggregation'; "
            "keeping explicit threshold, dropping aggregation"
        )
        return None

    text = str(agg).strip()
    match = _AGGREGATION_RE.match(text)
    if not match:
        lowered = text.lower()
        if re.match(r"^(sum|avg|min|max)\s*\(", lowered):
            return f"unsupported aggregation function: {text!r}"
        if re.search(r"count\s*\(\s*\)\s*(<|<=|!=)", lowered):
            return f"unsupported aggregation operator: {text!r}"
        return f"unparseable aggregation: {text!r}"

    op = match.group("op")
    count = int(match.group("n"))
    if op == ">":
        threshold = count + 1  # engine alerts at count >= threshold
    else:
        threshold = count

    detection["threshold"] = threshold
    detection["timeframe"] = detection.get("timeframe") or DEFAULT_AGGREGATION_TIMEFRAME

    by = match.group("by")
    if by:
        fields = [f.strip() for f in re.split(r"[,\s]+", by) if f.strip()]
        detection["group-by"] = [map_field(f, field_map) for f in fields]

    warnings.append(
        f"aggregation {text!r} -> threshold={threshold}, "
        f"timeframe={detection.get('timeframe')}"
        + (f", group-by={detection['group-by']}" if by else "")
    )
    return None


# -- rule conversion --------------------------------------------------------


def convert_rule(
    data: object,
    field_map: Optional[dict[str, str]] = FIELD_MAP,
    include_deprecated: bool = False,
) -> ConversionResult:
    """Convert one parsed Sigma rule mapping into the engine dialect."""
    if not isinstance(data, dict):
        return ConversionResult(ok=False, reason="not a YAML mapping")

    rule_type = str(data.get("type") or "").lower()
    if rule_type in SKIPPED_TYPES:
        return ConversionResult(ok=False, reason=f"unsupported type: {rule_type}")

    status = str(data.get("status") or "").lower()
    if status in SKIPPED_STATUSES and not include_deprecated:
        return ConversionResult(ok=False, reason=f"status: {status}")

    detection = data.get("detection")
    if not isinstance(detection, dict) or not detection.get("condition"):
        return ConversionResult(ok=False, reason="no detection/condition (not a " "detection rule)")

    warnings: list[str] = []
    converted = {k: v for k, v in data.items() if k != "detection"}
    new_detection = copy.deepcopy(detection)

    reason = _convert_aggregation(new_detection, warnings, field_map)
    if reason is not None:
        return ConversionResult(ok=False, reason=reason, warnings=warnings)

    new_detection = _translate_selection_values(new_detection, field_map, warnings)

    # Normalize list-ish metadata that sloppy Sigma rules write as scalars
    # (the rule loader does ``list(...)`` which would split strings into chars).
    for list_key in ("tags", "falsepositives", "references"):
        value = converted.get(list_key)
        if isinstance(value, str):
            converted[list_key] = [value]

    if not converted.get("level"):
        converted["level"] = "medium"

    converted["detection"] = new_detection
    converted.pop("type", None)

    errors = validate_rule(converted)
    if errors:
        return ConversionResult(
            ok=False, reason=f"invalid after conversion: {errors[0]}", warnings=warnings
        )

    return ConversionResult(ok=True, rule=converted, warnings=warnings)


# -- file/directory import --------------------------------------------------


def iter_sigma_files(path: Path) -> Iterator[tuple[Path, Path]]:
    """Yield (file, relative_path) pairs for a file or directory tree."""
    if path.is_file():
        yield path, Path(path.name)
        return
    for file in sorted(path.rglob("*")):
        if file.is_file() and file.suffix.lower() in _RULE_EXTENSIONS:
            yield file, file.relative_to(path)


def import_sigma(
    source: Path,
    out_dir: Path,
    field_map: Optional[dict[str, str]] = FIELD_MAP,
    include_deprecated: bool = False,
    overwrite: bool = False,
    dry_run: bool = False,
    limit: Optional[int] = None,
) -> ImportReport:
    """Convert Sigma rule files under ``source`` into ``out_dir``."""
    report = ImportReport(dry_run=dry_run)
    if not source.exists():
        report.skipped.append((str(source), "source path does not exist"))
        return report

    count = 0
    for file, rel in iter_sigma_files(source):
        if limit is not None and count >= limit:
            break
        count += 1

        try:
            raw = file.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            report.skipped.append((str(file), f"yaml/reading error: {e}"))
            continue

        result = convert_rule(data, field_map=field_map, include_deprecated=include_deprecated)
        for warning in result.warnings:
            report.warnings.append(f"{file}: {warning}")

        if not result.ok or result.rule is None:
            report.skipped.append((str(file), result.reason))
            continue

        target = out_dir / rel
        if target.exists() and not overwrite:
            report.skipped.append((str(file), f"output exists: {target}"))
            continue

        report.imported.append(str(target))
        if dry_run:
            continue

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            dumped = yaml.safe_dump(result.rule, sort_keys=False, allow_unicode=True, width=100)
            target.write_text(dumped, encoding="utf-8")
        except OSError as e:
            report.imported.pop()
            report.skipped.append((str(file), f"write failed: {e}"))

    log.info(
        "Sigma import %s: %d imported, %d skipped, %d warning(s)",
        "(dry-run)" if dry_run else "complete",
        report.import_count,
        report.skip_count,
        len(report.warnings),
    )
    return report

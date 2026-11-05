"""CLI commands for inspecting, validating and importing rules (Phase 9, Phase 2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from siem.core.config import Config, get_config
from siem.engine.rule_loader import RuleLoader

_LIST_CAP = 10
_SKIP_CAP = 20
_WARNING_CAP = 30


def cmd_rules_list(args, config: Optional[Config] = None) -> int:
    config = config or get_config()
    loader = RuleLoader(config)
    rules = loader.load()

    print(f"Loaded {len(rules)} rule(s) from " f"{', '.join(str(d) for d in loader.directories)}\n")
    header = f"{'EN':<3} {'LEVEL':<9} {'ID':<38} TITLE"
    print(header)
    print("-" * len(header))
    for rule in sorted(rules, key=lambda r: (r.level, r.title)):
        print(
            f"{'Y' if rule.enabled else 'n':<3} {rule.level:<9} " f"{rule.rule_id:<38} {rule.title}"
        )

    if loader.last_errors:
        print(f"\n{len(loader.last_errors)} rule file(s) had errors:")
        for err in loader.last_errors:
            print(f"  - {err}")
    return 0


def cmd_rules_validate(args, config: Optional[Config] = None) -> int:
    config = config or get_config()
    loader = RuleLoader(config)
    rules = loader.load()

    if loader.last_errors:
        print(f"FAILED: {len(loader.last_errors)} error(s) while loading rules:")
        for err in loader.last_errors:
            print(f"  - {err}")
        return 1

    print(f"OK: {len(rules)} rule(s) valid")
    return 0


def _default_out_dir(config: Config) -> Path:
    custom = config.get("rules.custom_path") or "rules/custom"
    return config.project_root / custom / "sigma"


def _print_capped(title: str, lines: list[str], cap: int) -> None:
    if not lines:
        return
    print(f"\n{title} ({len(lines)}):")
    for line in lines[:cap]:
        print(f"  - {line}")
    if len(lines) > cap:
        print(f"  ... and {len(lines) - cap} more")


def cmd_rules_import_sigma(args, config: Optional[Config] = None) -> int:
    config = config or get_config()
    from siem.engine.sigma_import import FIELD_MAP, import_sigma

    source = Path(args.path).expanduser()
    if not source.exists():
        print(f"ERROR: source path not found: {source}")
        return 1

    out_dir = Path(args.out).expanduser() if args.out else _default_out_dir(config)
    report = import_sigma(
        source,
        out_dir,
        field_map={} if args.no_field_map else FIELD_MAP,
        include_deprecated=args.include_deprecated,
        overwrite=args.overwrite,
        dry_run=args.dry_run,
        limit=args.limit,
    )

    mode = "Sigma import (dry-run)" if report.dry_run else "Sigma import"
    print(
        f"{mode}: {report.import_count} imported, "
        f"{report.skip_count} skipped, {len(report.warnings)} warning(s)"
    )
    print(f"  source: {source}")
    print(f"  output: {out_dir}")

    _print_capped("Imported", report.imported, _LIST_CAP)
    _print_capped(
        "Skipped",
        [f"{path} - {reason}" for path, reason in report.skipped],
        _SKIP_CAP,
    )
    _print_capped("Warnings", report.warnings, _WARNING_CAP)

    if report.import_count and not report.dry_run:
        print(
            "\nNext: siem rules validate   (hot-reload applies automatically "
            "when the engine is running)"
        )
    return 0

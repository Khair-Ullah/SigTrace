"""Unit tests for Sigma rule import (Phase 2)."""
from __future__ import annotations

import yaml

from siem.engine import sigma_import
from siem.engine.rule_loader import RuleLoader
from siem.core.config import load_config


def _make_sigma(minimal: dict) -> dict:
    base = {
        "title": "Test Rule",
        "id": "00000000-0000-0000-0000-000000000001",
        "description": "test",
        "level": "medium",
        "status": "stable",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4624},
            "condition": "selection",
        },
    }
    base.update(minimal)
    return base


def test_convert_basic_field_mapping():
    res = sigma_import.convert_rule(_make_sigma({}))
    assert res.ok
    assert res.rule is not None
    sel = res.rule["detection"]["selection"]
    assert "windows_event_id" in sel and sel["windows_event_id"] == 4624


def test_convert_preserves_modifiers_and_translates_base():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {
                    "EventID": 1,
                    "TargetUserName|contains": "admin",
                    "Image|endswith": "\\cmd.exe",
                },
                "condition": "selection",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert res.ok
    sel = res.rule["detection"]["selection"]
    assert sel["windows_event_id"] == 1
    assert "user_name|contains" in sel
    assert sel["Image|endswith"] == "\\cmd.exe"  # unmapped stays


def test_convert_aggregation_gt_to_threshold():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 4625},
                "condition": "selection",
                "timeframe": "10m",
                "aggregation": "count() > 5 by SourceIp",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert res.ok
    det = res.rule["detection"]
    assert det["threshold"] == 6  # > 5 -> >=6
    assert det["timeframe"] == "10m"
    assert det["group-by"] == ["src_ip"]


def test_convert_aggregation_ge():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 4625},
                "condition": "selection",
                "aggregation": "count() >= 10 by src_ip, computer",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert res.ok
    det = res.rule["detection"]
    assert det["threshold"] == 10
    assert det["group-by"] == ["src_ip", "computer"]


def test_convert_aggregation_default_timeframe_and_maps():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 4634},
                "condition": "selection",
                "aggregation": "count() > 2 by IpAddress",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert res.ok
    det = res.rule["detection"]
    assert det["timeframe"] == "5m"
    assert det["group-by"] == ["src_ip"]


def test_convert_skips_deprecated():
    sigma = _make_sigma({"status": "deprecated"})
    res = sigma_import.convert_rule(sigma)
    assert not res.ok
    assert "deprecated" in res.reason


def test_convert_skips_unsupported_type():
    sigma = _make_sigma({"type": "correlation"})
    res = sigma_import.convert_rule(sigma)
    assert not res.ok
    assert "correlation" in res.reason or "type" in res.reason


def test_convert_skips_unsupported_aggregation_sum():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 1},
                "condition": "selection",
                "aggregation": "sum(bytes) > 1000 by src_ip",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert not res.ok
    assert "unsupported aggregation" in res.reason


def test_convert_skips_unsupported_aggregation_op():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 1},
                "condition": "selection",
                "aggregation": "count() < 5",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert not res.ok
    assert "unsupported aggregation" in res.reason


def test_convert_skips_unparseable_aggregation():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 1},
                "condition": "selection",
                "aggregation": "count by ip",
            }
        }
    )
    res = sigma_import.convert_rule(sigma)
    assert not res.ok
    assert "unparseable aggregation" in res.reason


def test_convert_skips_when_no_detection():
    res = sigma_import.convert_rule({"title": "x"})
    assert not res.ok


def test_convert_with_no_field_map():
    sigma = _make_sigma(
        {
            "detection": {
                "selection": {"EventID": 4624, "TargetUserName|contains": "admin"},
                "condition": "selection",
            }
        }
    )
    res = sigma_import.convert_rule(sigma, field_map={})
    assert res.ok
    sel = res.rule["detection"]["selection"]
    assert "EventID" in sel
    assert "TargetUserName|contains" in sel


def test_convert_level_defaulted():
    sigma = _make_sigma({"level": None})
    res = sigma_import.convert_rule(sigma)
    assert res.ok
    assert res.rule["level"] == "medium"


def test_import_writes_and_validate(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    rule = _make_sigma(
        {
            "title": "Login Success",
            "id": "11111111-1111-1111-1111-111111111111",
            "detection": {
                "selection": {"EventID": 4624, "LogonType": 2},
                "condition": "selection",
            },
        }
    )
    (src / "login.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")

    out = tmp_path / "out"
    report = sigma_import.import_sigma(src, out)
    assert report.import_count == 1
    assert report.skip_count == 0
    written = out / "login.yml"
    assert written.exists()

    # validate loaded rule is clean
    cfg = load_config()
    # handle cross-drive tmp paths
    try:
        rel = str(out.relative_to(cfg.project_root)).replace("\\", "/")
        cfg.set("rules.custom_path", rel)
    except Exception:
        # tmp_path can live on another drive (C:) than the project root (F:);
        # os.path.relpath cannot cross mounts on Windows, so use the absolute
        # path instead.
        cfg.set("rules.custom_path", str(out))
    cfg.set("rules.builtin_path", "rules/builtin")  # doesn't need to exist
    loader = RuleLoader(cfg)
    rules = loader.load()
    assert len(rules) >= 1
    assert not loader.last_errors


def test_import_dry_run_does_not_write(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "r.yml").write_text(yaml.safe_dump(_make_sigma({})), encoding="utf-8")
    out = tmp_path / "out"
    report = sigma_import.import_sigma(src, out, dry_run=True)
    assert report.import_count == 1
    assert report.skip_count == 0
    assert not out.exists()


def test_import_overwrite_guard(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "r.yml").write_text(yaml.safe_dump(_make_sigma({})), encoding="utf-8")
    out = tmp_path / "out"
    sigma_import.import_sigma(src, out)
    # second import without overwrite
    report = sigma_import.import_sigma(src, out, overwrite=False)
    assert report.skip_count == 1
    assert "output exists" in report.skipped[0][1]


def test_import_overwrite_ok(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "r.yml").write_text(yaml.safe_dump(_make_sigma({})), encoding="utf-8")
    out = tmp_path / "out"
    sigma_import.import_sigma(src, out)
    report = sigma_import.import_sigma(src, out, overwrite=True)
    assert report.import_count == 1
    assert report.skip_count == 0


def test_import_skips_bad_yaml_and_missing_source(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "bad.yml").write_text("not: valid\n- broken", encoding="utf-8")
    out = tmp_path / "out"
    report = sigma_import.import_sigma(src, out)
    assert report.import_count == 0
    assert report.skip_count >= 1

    report2 = sigma_import.import_sigma(tmp_path / "nope", out)
    assert report2.skip_count == 1
    assert "does not exist" in report2.skipped[0][1]


def test_import_include_deprecated(tmp_path):
    src = tmp_path / "sigma"
    src.mkdir()
    (src / "dep.yml").write_text(yaml.safe_dump(_make_sigma({"status": "deprecated"})),
                                 encoding="utf-8")
    out = tmp_path / "out"
    report = sigma_import.import_sigma(src, out, include_deprecated=True)
    assert report.import_count == 1

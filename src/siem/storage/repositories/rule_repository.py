"""Rule metadata persistence (FR-43, FR-55)."""
from __future__ import annotations

import json
from typing import Optional

from sqlalchemy import func, select, update

from siem.engine.models import Rule
from siem.storage.models import Rule as OrmRule
from siem.storage.repositories.base import BaseRepository


class RuleRepository(BaseRepository):
    """Persist the currently loaded detection rules for the dashboard."""

    def sync(self, rules: list[Rule]) -> int:
        """Insert/update all provided rules. Returns the number synced."""
        with self.session_scope() as session:
            for rule in rules:
                existing = session.get(OrmRule, rule.rule_id)
                logsource = json.dumps(rule.logsource or {})
                if existing is None:
                    session.add(OrmRule(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        level=rule.level,
                        logsource=logsource,
                        yaml_content=rule.raw_yaml,
                        file_path=rule.file_path,
                        is_enabled=1 if rule.enabled else 0,
                    ))
                else:
                    existing.title = rule.title
                    existing.description = rule.description
                    existing.level = rule.level
                    existing.logsource = logsource
                    existing.yaml_content = rule.raw_yaml
                    existing.file_path = rule.file_path
                    existing.is_enabled = 1 if rule.enabled else 0
        return len(rules)

    def list(self) -> list[dict]:
        with self.session_scope() as session:
            rows = session.execute(
                select(OrmRule).order_by(OrmRule.title)
            ).scalars().all()
            return [self._to_dict(r) for r in rows]

    def get(self, rule_id: str) -> Optional[dict]:
        with self.session_scope() as session:
            row = session.get(OrmRule, rule_id)
            return self._to_dict(row) if row else None

    def set_enabled(self, rule_id: str, enabled: bool) -> int:
        with self.session_scope() as session:
            result = session.execute(
                update(OrmRule)
                .where(OrmRule.rule_id == rule_id)
                .values(is_enabled=1 if enabled else 0)
            )
            return int(result.rowcount or 0)

    def count(self) -> int:
        with self.session_scope() as session:
            return int(session.execute(
                select(func.count()).select_from(OrmRule)
            ).scalar_one())

    @staticmethod
    def _to_dict(row: OrmRule) -> dict:
        try:
            logsource = json.loads(row.logsource) if row.logsource else {}
        except (ValueError, TypeError):
            logsource = {}
        return {
            "rule_id": row.rule_id,
            "title": row.title,
            "description": row.description,
            "level": row.level,
            "logsource": logsource,
            "file_path": row.file_path,
            "is_enabled": bool(row.is_enabled),
            "yaml_content": row.yaml_content,
            "loaded_at": row.loaded_at,
        }

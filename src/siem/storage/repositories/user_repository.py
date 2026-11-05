"""User account persistence and authentication lookups (FR-56, FR-57)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select, update

from siem.core.constants import ROLE_ANALYST, VALID_ROLES
from siem.core.security import hash_password, verify_password
from siem.core.utils import utcnow
from siem.storage.models import User as OrmUser
from siem.storage.repositories.base import BaseRepository


class UserRepository(BaseRepository):
    """CRUD + credential checks for dashboard accounts."""

    def create(
        self,
        username: str,
        password: str,
        role: str = ROLE_ANALYST,
        password_hash: Optional[str] = None,
    ) -> int:
        """Create a user. Returns the new ``user_id``.

        Either ``password`` or a pre-computed ``password_hash`` may be given.
        """
        if role not in VALID_ROLES:
            raise ValueError(f"invalid role: {role}")
        oph = password_hash or hash_password(password)
        with self.session_scope() as session:
            row = OrmUser(username=username, password_hash=oph, role=role)
            session.add(row)
            session.flush()
            return int(row.user_id)

    def get(self, user_id: int) -> Optional[dict]:
        with self.session_scope() as session:
            row = session.get(OrmUser, user_id)
            return self._to_dict(row) if row else None

    def get_by_username(self, username: str) -> Optional[dict]:
        with self.session_scope() as session:
            row = session.execute(
                select(OrmUser).where(OrmUser.username == username)
            ).scalar_one_or_none()
            return self._to_dict(row) if row else None

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Return the user dict on valid credentials, else ``None``."""
        with self.session_scope() as session:
            row = session.execute(
                select(OrmUser).where(OrmUser.username == username)
            ).scalar_one_or_none()
            if row is None or not verify_password(password, row.password_hash):
                return None
            row.last_login = utcnow()
            return self._to_dict(row)

    def list(self) -> list[dict]:
        with self.session_scope() as session:
            rows = session.execute(
                select(OrmUser).order_by(OrmUser.username)
            ).scalars().all()
            return [self._to_dict(r) for r in rows]

    def set_role(self, user_id: int, role: str) -> int:
        if role not in VALID_ROLES:
            raise ValueError(f"invalid role: {role}")
        with self.session_scope() as session:
            result = session.execute(
                update(OrmUser).where(OrmUser.user_id == user_id).values(role=role)
            )
            return int(result.rowcount or 0)

    def set_password(self, user_id: int, password: str) -> int:
        oph = hash_password(password)
        with self.session_scope() as session:
            result = session.execute(
                update(OrmUser).where(OrmUser.user_id == user_id)
                .values(password_hash=oph)
            )
            return int(result.rowcount or 0)

    def delete(self, user_id: int) -> int:
        with self.session_scope() as session:
            result = session.execute(delete(OrmUser).where(OrmUser.user_id == user_id))
            return int(result.rowcount or 0)

    def count(self) -> int:
        with self.session_scope() as session:
            return int(session.execute(
                select(func.count()).select_from(OrmUser)
            ).scalar_one())

    @staticmethod
    def _to_dict(row: OrmUser) -> dict:
        return {
            "user_id": row.user_id,
            "username": row.username,
            "role": row.role,
            "created_at": row.created_at,
            "last_login": row.last_login,
        }

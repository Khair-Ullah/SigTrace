"""Dashboard user management (FR-56, FR-57).

Lives inside the package so it works from a frozen executable, where
``scripts/create_user.py`` is not bundled. The script remains as a thin
wrapper for backwards compatibility.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from siem.core.constants import VALID_ROLES


def _repo():
    from siem.storage import database
    from siem.storage.repositories import UserRepository

    database.init_engine()
    return UserRepository()


def has_users() -> bool:
    return bool(_repo().list())


def create_user(username: str, password: str, role: str = "analyst") -> int:
    """Create a user; returns 0 on success, 1 if it already exists."""
    repo = _repo()
    if repo.get_by_username(username):
        return 1
    repo.create(username, password, role=role)
    return 0


def _get_password(args) -> str:
    if args.password:
        return args.password
    if not sys.stdin or not sys.stdin.isatty():
        raise SystemExit(
            "No console available for a password prompt; pass --password."
        )
    pw = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        print("Passwords do not match.", file=sys.stderr)
        raise SystemExit(2)
    return pw


def cmd_create(args) -> int:
    repo = _repo()
    if repo.get_by_username(args.username):
        print(f"User '{args.username}' already exists.", file=sys.stderr)
        return 1
    uid = repo.create(args.username, _get_password(args), role=args.role)
    print(f"Created user '{args.username}' (#{uid}) with role '{args.role}'.")
    return 0


def cmd_list(args) -> int:
    repo = _repo()
    users = repo.list()
    if not users:
        print("No users. Create one with: siem user create --username admin --password ...")
        return 0
    print(f"{'ID':<4} {'USERNAME':<24} {'ROLE':<12} LAST LOGIN")
    for u in users:
        print(f"{u['user_id']:<4} {u['username']:<24} {u['role']:<12} "
              f"{u['last_login'] or 'never'}")
    return 0


def cmd_passwd(args) -> int:
    repo = _repo()
    user = repo.get_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.", file=sys.stderr)
        return 1
    repo.set_password(user["user_id"], _get_password(args))
    print(f"Password updated for '{args.username}'.")
    return 0


def cmd_role(args) -> int:
    repo = _repo()
    user = repo.get_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.", file=sys.stderr)
        return 1
    repo.set_role(user["user_id"], args.role)
    print(f"Role for '{args.username}' set to '{args.role}'.")
    return 0


def cmd_delete(args) -> int:
    repo = _repo()
    user = repo.get_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.", file=sys.stderr)
        return 1
    repo.delete(user["user_id"])
    print(f"Deleted user '{args.username}'.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage SIEM dashboard users.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a user")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--password", help="Password (prompted if omitted)")
    p_create.add_argument("--role", default="analyst", choices=sorted(VALID_ROLES))
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list", help="List users")
    p_list.set_defaults(func=cmd_list)

    p_pass = sub.add_parser("passwd", help="Reset a user's password")
    p_pass.add_argument("--username", required=True)
    p_pass.add_argument("--password", help="Password (prompted if omitted)")
    p_pass.set_defaults(func=cmd_passwd)

    p_role = sub.add_parser("role", help="Change a user's role")
    p_role.add_argument("--username", required=True)
    p_role.add_argument("--role", required=True, choices=sorted(VALID_ROLES))
    p_role.set_defaults(func=cmd_role)

    p_del = sub.add_parser("delete", help="Delete a user")
    p_del.add_argument("--username", required=True)
    p_del.set_defaults(func=cmd_delete)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

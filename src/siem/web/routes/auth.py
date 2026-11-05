"""Authentication routes: login / logout (FR-56)."""
from __future__ import annotations

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from siem.web.auth import AuthUser
from siem.web.deps import get_storage

bp = Blueprint("auth", __name__)


def _safe_next(target: str | None) -> str | None:
    """Only allow same-site relative redirect targets."""
    if not target:
        return None
    if target.startswith("/") and not target.startswith("//"):
        return target
    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        storage = get_storage()
        user = storage.users.authenticate(username, password)
        if user is not None:
            auth_user = AuthUser(user["user_id"], user["username"], user["role"])
            login_user(auth_user, remember=bool(request.form.get("remember")))
            storage.audit.record(
                "login", details=f"user={username}",
                user_id=user["user_id"], ip_address=request.remote_addr,
            )
            return redirect(_safe_next(request.args.get("next"))
                            or url_for("dashboard.index"))
        error = "Invalid username or password."
        storage.audit.record(
            "login_failed", details=f"user={username}", ip_address=request.remote_addr,
        )

    return render_template("login.html", error=error,
                           next=request.args.get("next", ""))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    storage = get_storage()
    storage.audit.record(
        "logout", details=f"user={current_user.username}",
        user_id=current_user.user_id, ip_address=request.remote_addr,
    )
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))

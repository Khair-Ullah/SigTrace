"""Native desktop shell: pipeline + dashboard server + pywebview window."""
from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path

from siem.core import paths

log = logging.getLogger("siem.desktop.app")

_mutex_handle = None
_instance_lock = None
_show_event = None
_show_callback = None
_MUTEX_NAME = "Local\\SIEMDesktop"
_EVENT_NAME = "Local\\SIEMDesktopShow"


# -- single instance -------------------------------------------------------

def _kernel32():
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CreateEventW.restype = ctypes.c_void_p
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    ]
    kernel32.OpenEventW.restype = ctypes.c_void_p
    kernel32.OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.SetEvent.argtypes = [ctypes.c_void_p]
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    return kernel32


def _signal_running_instance() -> None:
    """Ask an existing instance to bring its window to the front."""
    try:
        kernel32 = _kernel32()
        handle = kernel32.OpenEventW(0x0002, False, _EVENT_NAME)  # EVENT_MODIFY_STATE
        if handle:
            kernel32.SetEvent(handle)
            kernel32.CloseHandle(handle)
    except Exception:
        log.exception("Could not signal the running SIEM instance")


def _watch_show_requests(handle) -> None:
    kernel32 = _kernel32()
    while True:
        result = kernel32.WaitForSingleObject(handle, 1000)
        if result == 0:  # WAIT_OBJECT_0
            callback = _show_callback
            if callback is not None:
                try:
                    callback()
                except Exception:
                    log.exception("Could not show the dashboard window")
        elif result != 258:  # WAIT_TIMEOUT
            return


def _acquire_single_instance() -> bool:
    """Prevent two app processes from writing the same SQLite database."""
    global _mutex_handle, _instance_lock, _show_event
    if os.name == "nt":
        import ctypes

        kernel32 = _kernel32()
        handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
        if not handle:
            return False
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            _signal_running_instance()
            return False
        _mutex_handle = handle
        _show_event = kernel32.CreateEventW(None, False, False, _EVENT_NAME)
        if _show_event:
            threading.Thread(
                target=_watch_show_requests,
                args=(_show_event,),
                name="siem-show-window",
                daemon=True,
            ).start()
        return True

    import fcntl

    lock_path = paths.data_dir() / ".siem.lock"
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_file.close()
        return False
    _instance_lock = lock_file
    return True


# -- dialogs ---------------------------------------------------------------

def _show_message(title: str, message: str, *, error: bool = False) -> None:
    if os.name == "nt":
        try:
            import ctypes

            flags = 0x10 if error else 0x40  # MB_ICONERROR / MB_ICONINFORMATION
            ctypes.windll.user32.MessageBoxW(0, message, title, flags)
            return
        except Exception:
            pass
    stream = sys.stderr or sys.stdout
    if stream is not None:
        print(f"[{title}] {message}", file=stream)


def _admin_message(username: str, password: str, note: Path) -> str:
    return (
        "A first-run administrator account has been created.\n\n"
        f"Username: {username}\n"
        f"Password: {password}\n\n"
        f"These credentials are also saved to:\n{note}\n\n"
        "Change the password after signing in, then delete that file."
    )


# -- runtime ---------------------------------------------------------------

def _build_runtime():
    """Create storage, pipeline and Flask app bound to localhost."""
    from siem.cli.commands.engine import build_storage
    from siem.core.config import get_config
    from siem.pipeline import Pipeline
    from siem.storage import database
    from siem.web import realtime
    from siem.web.app import create_app, find_free_port

    config = get_config()
    config.set("web.host", "127.0.0.1")
    config.set("web.debug", False)
    config.set("web.cookie_secure", False)

    port = find_free_port("127.0.0.1")
    config.set("web.port", port)
    origin = f"http://127.0.0.1:{port}"
    config.set("web.socketio_cors", origin)

    database.dispose_engine()
    storage = build_storage(config)
    pipeline = Pipeline(config, storage)

    app = create_app(config, storage=storage)
    app.extensions["siem_pipeline"] = pipeline
    pipeline.on_alert = realtime.make_socketio_callback()

    return config, storage, pipeline, app, port


def run_desktop() -> int:
    """Launch the desktop application. Returns a process exit code."""
    paths.bootstrap_env()

    # Configure logging early; the formal config is seeded just below.
    try:
        from siem.core.logger import setup_logging

        setup_logging()
    except Exception:  # logging must never prevent startup
        pass

    if not _acquire_single_instance():
        # On Windows the existing instance has been asked to show its window.
        if os.name != "nt":
            _show_message(
                "SIEM",
                "SIEM is already running. Use the system tray icon to open the "
                "dashboard, or quit the existing instance first.",
            )
        return 0

    from siem.desktop.bootstrap import prepare_runtime

    selftest = os.environ.get("SIEM_DESKTOP_SELFTEST") == "1"

    first_run = prepare_runtime()
    log.info("Desktop runtime prepared at %s", first_run.data_root)

    if first_run.admin_created and not selftest:
        note = first_run.data_root / "FIRST_RUN_ADMIN.txt"
        _show_message(
            "SIEM - First run",
            _admin_message(
                first_run.admin_username or "admin",
                first_run.admin_password or "",
                note,
            ),
        )

    server = None
    pipeline = None
    state = {"quitting": False}

    try:
        config, _storage, pipeline, app, port = _build_runtime()
        dashboard_url = f"http://127.0.0.1:{port}"

        pipeline.run(block=False)

        from siem.desktop import server as server_mod

        server = server_mod.start(app, host="127.0.0.1", port=port, threads=8)
        if not server_mod.wait_until_ready(dashboard_url):
            _show_message(
                "SIEM - Startup failed",
                "The local dashboard did not start in time. Check the log file "
                f"under {paths.logs_dir()} for details.",
                error=True,
            )
            return 1

        if selftest:
            return _selftest(first_run, dashboard_url, pipeline)

        return _run_window(
            dashboard_url=dashboard_url,
            data_root=first_run.data_root,
            state=state,
        )
    except Exception as exc:
        log.exception("Desktop startup failed")
        _show_message("SIEM - Startup failed", f"{exc}\n\nSee {paths.logs_dir()}", error=True)
        return 1
    finally:
        state["quitting"] = True
        if server is not None:
            server.stop()
        if pipeline is not None:
            pipeline.stop()
        try:
            from siem.storage import database

            database.dispose_engine()
        except Exception:
            pass


def _selftest(first_run, dashboard_url: str, pipeline) -> int:
    """Headless smoke test used by packaging/CI (SIEM_DESKTOP_SELFTEST=1)."""
    import json

    from siem import version

    result = {
        "ok": True,
        "version": version.__version__,
        "frozen": paths.is_frozen(),
        "data_root": str(first_run.data_root),
        "bundle_dir": str(paths.bundle_dir()),
        "config": str(paths.default_config_path()),
        "logs": str(paths.logs_dir()),
        "dashboard": dashboard_url,
        "rules_loaded": len(getattr(pipeline, "rules", [])),
        "admin_created": first_run.admin_created,
    }
    target = first_run.data_root / "selftest.json"
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    log.info("Desktop self-test passed: %s", result)
    return 0


def _run_window(*, dashboard_url: str, data_root: Path, state: dict) -> int:
    global _show_callback
    try:
        import webview
    except Exception:
        _show_message(
            "SIEM - Missing dependency",
            "pywebview is not installed.\n\n"
            "Install the desktop extras with:\n"
            "    pip install -e \".[desktop]\"",
            error=True,
        )
        return 1

    from siem.desktop.tray import DesktopTray

    window_holder: dict[str, object] = {}

    def open_window() -> None:
        window = window_holder.get("window")
        if window is None:
            return
        try:
            window.show()
            restore = getattr(window, "restore", None)
            if callable(restore):
                restore()
        except Exception:
            log.exception("Could not show dashboard window")

    def quit_app() -> None:
        state["quitting"] = True
        window = window_holder.get("window")
        if window is not None:
            try:
                window.destroy()
            except Exception:
                log.exception("Could not destroy dashboard window")

    _show_callback = open_window

    tray = DesktopTray(on_open=open_window, on_quit=quit_app, data_dir=data_root)
    tray_running = tray.start()

    window = webview.create_window(
        "SIEM Dashboard",
        dashboard_url,
        width=1360,
        height=900,
        min_size=(960, 600),
    )
    window_holder["window"] = window

    def on_closing():
        if state["quitting"]:
            return None
        if tray_running:
            try:
                window.hide()
                return False  # cancel close: keep monitoring in the tray
            except Exception:
                log.exception("Could not hide window; closing instead")
        state["quitting"] = True
        return None

    try:
        window.events.closing += on_closing
    except Exception:
        log.debug("closing event is not available; window close will exit")

    start_kwargs = {
        "gui": "edgechromium",
        "debug": False,
        "private_mode": False,
    }
    icon = Path(__file__).resolve().parent.parent / "web" / "static" / "img" / "siem.ico"
    if icon.is_file():
        start_kwargs["icon"] = str(icon)
    log.info("Starting native window at %s", dashboard_url)
    try:
        webview.start(storage_path=str(data_root / "webview"), **start_kwargs)
        return 0
    except TypeError:
        # Older pywebview releases do not accept storage_path.
        try:
            webview.start(gui="edgechromium", debug=False)
            return 0
        except Exception as exc:
            return _webview_failure(exc)
    except Exception as exc:
        return _webview_failure(exc)
    finally:
        _show_callback = None
        try:
            tray.stop()
        except Exception:
            pass


def _webview_failure(exc: Exception) -> int:
    log.exception("pywebview failed to start")
    _show_message(
        "SIEM - WebView2 required",
        "The native dashboard window could not be created.\n\n"
        "Windows requires the Microsoft Edge WebView2 Runtime:\n"
        "https://developer.microsoft.com/microsoft-edge/webview2/\n\n"
        f"Details: {exc}",
        error=True,
    )
    return 1

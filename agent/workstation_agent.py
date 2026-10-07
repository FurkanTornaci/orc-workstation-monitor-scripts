"""Availability/resource monitor. No application, content or input-event collection."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import logging
import math
import os
import plistlib
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from logging.handlers import RotatingFileHandler
from pathlib import Path

import psutil

VERSION = "1.2.0"
LOG = logging.getLogger("workstation-monitor")
STOP = threading.Event()


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object")
    url = urllib.parse.urlsplit(config.get("api_url", ""))
    local = url.hostname in {"127.0.0.1", "localhost", "::1"}
    if (
        not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
    ):
        raise ValueError("api_url must be a server origin")
    if url.scheme != "https" and not (
        url.scheme == "http" and local and config.get("allow_local_http") is True
    ):
        raise ValueError(
            "HTTPS required; HTTP allowed only for explicitly enabled localhost development"
        )
    token = config.get("api_token", "")
    if (
        not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token)
        or token.startswith("REPLACE")
    ):
        raise ValueError("A provisioned per-machine API token is required")
    hostname = config.get("hostname") or socket.gethostname()
    if not isinstance(hostname, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", hostname
    ):
        raise ValueError("Invalid hostname")
    interval = config.get("heartbeat_seconds", 60)
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or not 30 <= interval <= 120
    ):
        raise ValueError("heartbeat_seconds must be between 30 and 120")
    if not isinstance(config.get("collect_username", True), bool):
        raise ValueError("collect_username must be a boolean")
    return {
        **config,
        "hostname": hostname.upper(),
        "heartbeat_seconds": interval,
        "api_url": config["api_url"].rstrip("/"),
    }


def select_session(sessions: list[dict], detection_ok: bool = True) -> dict:
    """Consider desktop/remote sessions, including users switched into the background.

    Report the least-idle session. Unknown idle data takes priority so a failed
    measurement never turns a potentially active user into an idle user.
    """
    users = [session for session in sessions if session.get("username")]
    if not users:
        return {
            "logged_in": False,
            "username": None,
            "idle_seconds": None,
            "session_detection_ok": detection_ok,
        }
    session = min(
        users, key=lambda item: -1 if item.get("idle_seconds") is None else item["idle_seconds"]
    )
    return {
        "logged_in": True,
        "username": session["username"],
        "idle_seconds": session.get("idle_seconds"),
        "session_detection_ok": detection_ok,
    }


def windows_sessions() -> dict:
    # WTS APIs inspect other interactive sessions from the SYSTEM task. The
    # current process's GetLastInputInfo would incorrectly measure session 0.
    from ctypes import wintypes

    class Session(ctypes.Structure):
        _fields_ = [("id", wintypes.DWORD), ("station", wintypes.LPWSTR), ("state", ctypes.c_int)]

    class Info(ctypes.Structure):
        _fields_ = (
            [("state", ctypes.c_int), ("id", wintypes.DWORD)]
            + [
                (name, wintypes.DWORD)
                for name in (
                    "incoming_bytes",
                    "outgoing_bytes",
                    "incoming_frames",
                    "outgoing_frames",
                    "incoming_compressed",
                    "outgoing_compressed",
                )
            ]
            + [
                ("station", wintypes.WCHAR * 32),
                ("domain", wintypes.WCHAR * 17),
                ("user", wintypes.WCHAR * 21),
            ]
            + [
                (name, ctypes.c_longlong)
                for name in ("connect", "disconnect", "last_input", "logon", "current")
            ]
        )

    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    wts.WTSEnumerateSessionsW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    wts.WTSEnumerateSessionsW.restype = wintypes.BOOL
    wts.WTSQuerySessionInformationW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    wts.WTSFreeMemory.restype = None
    pointer = ctypes.c_void_p()
    count = wintypes.DWORD()
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(pointer), ctypes.byref(count)):
        return select_session([], False)
    sessions = []
    detection_ok = True
    try:
        entries = ctypes.cast(pointer, ctypes.POINTER(Session))
        for index in range(count.value):
            entry = entries[index]
            if entry.id == 0 or entry.state in {6, 7, 8, 9}:  # Listener/reset/down/init sessions.
                continue
            buffer = ctypes.c_void_p()
            size = wintypes.DWORD()
            # WTSUserName = 5. Failure to query any candidate is conservative.
            if not wts.WTSQuerySessionInformationW(
                None, entry.id, 5, ctypes.byref(buffer), ctypes.byref(size)
            ):
                detection_ok = False
                continue
            try:
                username = ctypes.wstring_at(buffer) if buffer.value and size.value > 2 else ""
            finally:
                if buffer.value:
                    wts.WTSFreeMemory(buffer)
            if not username:
                continue
            idle = None
            buffer = ctypes.c_void_p()
            # WTSSessionInfo = 24: timestamps are Windows FILETIME 100 ns units.
            if wts.WTSQuerySessionInformationW(
                None, entry.id, 24, ctypes.byref(buffer), ctypes.byref(size)
            ):
                try:
                    if buffer.value and size.value >= ctypes.sizeof(Info):
                        info = ctypes.cast(buffer, ctypes.POINTER(Info)).contents
                        if info.last_input > 0 and info.current >= info.last_input:
                            idle = min(315360000, (info.current - info.last_input) // 10_000_000)
                finally:
                    if buffer.value:
                        wts.WTSFreeMemory(buffer)
            sessions.append({"username": username, "idle_seconds": idle})
    finally:
        wts.WTSFreeMemory(pointer)
    return select_session(sessions, detection_ok)


def read_macos_registry(*selection: str) -> list:
    result = subprocess.run(
        ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", *selection],
        capture_output=True,
        timeout=5,
        check=True,
    )
    if len(result.stdout) > 1_048_576:
        raise ValueError("Session registry response is too large")
    data = plistlib.loads(result.stdout)
    if not isinstance(data, list):
        raise ValueError("Session registry response is not an array")
    return data


def parse_macos_sessions(entries: list, idle_seconds: int | None) -> list[dict]:
    sessions = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid macOS session")
        username = entry.get("kCGSSessionUserNameKey")
        uid = entry.get("kCGSSessionUserIDKey")
        if not isinstance(username, str) or type(uid) is not int or uid < 0:
            raise ValueError("macOS session identity unavailable")
        if uid == 0 and username in {"", "loginwindow"}:
            continue
        if not username:
            raise ValueError("macOS session username unavailable")
        # HID idle time belongs to the foreground console. Background/unfinished
        # sessions stay occupied with unknown activity, including Fast User Switching.
        foreground = (
            entry.get("kCGSSessionOnConsoleKey") is True
            and entry.get("kCGSessionLoginDoneKey") is True
        )
        sessions.append(
            {
                "username": username,
                "idle_seconds": idle_seconds if foreground else None,
                "foreground": foreground,
            }
        )
    return sessions


def macos_sessions() -> dict:
    roots = read_macos_registry("-n", "Root")
    if len(roots) != 1 or not isinstance(roots[0], dict):
        raise ValueError("macOS session registry unavailable")
    entries = roots[0].get("IOConsoleUsers")
    if not isinstance(entries, list):
        raise ValueError("macOS session inventory unavailable")
    idle = None
    if entries:
        try:
            devices = read_macos_registry("-c", "IOHIDSystem")
            values = [
                entry["HIDIdleTime"]
                for entry in devices
                if isinstance(entry, dict)
                and type(entry.get("HIDIdleTime")) is int
                and entry["HIDIdleTime"] >= 0
            ]
            if values:
                idle = min(315360000, min(values) // 1_000_000_000)
        except (OSError, ValueError, subprocess.SubprocessError, plistlib.InvalidFileException):
            pass  # Occupancy is still known; activity remains unknown.
    sessions = parse_macos_sessions(entries, idle)
    # Include SSH/terminal sessions. Their activity is unknown, so they must not
    # become Available merely because the GUI user signed out.
    known = {entry["username"] for entry in sessions}
    for user in psutil.users():
        if user.name and (user.name not in known or (user.host and user.terminal != "console")):
            sessions.append({"username": user.name, "idle_seconds": None})
    result = select_session(sessions)
    # Display the foreground desktop user while retaining conservative activity
    # when other signed-in sessions have unknown idle time.
    foreground = next((session for session in sessions if session.get("foreground")), None)
    if foreground:
        result["username"] = foreground["username"]
    return result


def collect_session() -> dict:
    try:
        if os.name == "nt":
            return windows_sessions()
        if sys.platform == "darwin":
            return macos_sessions()
        return select_session([], False)
    except (
        OSError,
        ValueError,
        AttributeError,
        subprocess.SubprocessError,
        psutil.Error,
        plistlib.InvalidFileException,
    ):
        LOG.warning("Session detection unavailable; machine will not be advertised as available")
        return select_session([], False)


def parse_gpu_output(output: str) -> dict:
    empty = {"gpu_percent": None, "gpu_memory_used_mb": None, "gpu_memory_total_mb": None}
    rows = []
    for line in output.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 3:
            continue

        def value(field):
            try:
                number = float(field)
                return number if math.isfinite(number) and number >= 0 else None
            except ValueError:
                return None

        rows.append(tuple(value(field) for field in fields))
    if not rows:
        return empty
    usage = [row[0] for row in rows if row[0] is not None and row[0] <= 100]
    memory = all(
        row[1] is not None and row[2] is not None and row[2] > 0 and row[1] <= row[2]
        for row in rows
    )
    return {
        "gpu_percent": max(usage) if usage else None,
        "gpu_memory_used_mb": sum(row[1] for row in rows) if memory else None,
        "gpu_memory_total_mb": sum(row[2] for row in rows) if memory else None,
    }


def collect_gpu() -> dict:
    executable = shutil.which("nvidia-smi")
    if not executable and os.name == "nt":
        for candidate in (
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/nvidia-smi.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "NVIDIA Corporation/NVSMI/nvidia-smi.exe",
        ):
            if candidate.is_file():
                executable = str(candidate)
                break
    if not executable:
        return parse_gpu_output("")
    try:
        result = subprocess.run(
            [
                executable,
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return parse_gpu_output(result.stdout)
    except (OSError, subprocess.SubprocessError):
        return parse_gpu_output("")


def collect_system_name() -> str | None:
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/scutil", "--get", "LocalHostName"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            name = result.stdout.strip()
            if name:
                return name[:255]
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        return socket.gethostname().strip()[:255] or None
    except OSError:
        return None


def collect_heartbeat(config: dict) -> dict:
    session = collect_session()
    if not config.get("collect_username", True):
        session["username"] = None
    return {
        "hostname": config["hostname"],
        "system_name": collect_system_name(),
        **session,
        "cpu_percent": round(psutil.cpu_percent(interval=1), 1),
        "ram_percent": round(psutil.virtual_memory().percent, 1),
        "uptime_seconds": min(315360000, max(0, int(time.time() - psutil.boot_time()))),
        **collect_gpu(),
        "agent_version": VERSION,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a workstation credential to an Access login or other host.
        return None


def send_heartbeat(config: dict, payload: dict) -> dict:
    request = urllib.request.Request(
        f"{config['api_url']}/api/heartbeat",
        data=json.dumps(payload, allow_nan=False).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {config['api_token']}",
            "Content-Type": "application/json",
            "User-Agent": f"workstation-monitor/{VERSION}",
        },
    )
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        receipt = json.loads(response.read(8192))
    if receipt.get("ok") is not True or not receipt.get("last_seen"):
        raise ValueError("Invalid server heartbeat receipt")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument(
        "--once", action="store_true", help="Send one heartbeat and verify its receipt"
    )
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--validate-config", action="store_true", help="Validate without reporting")
    options = parser.parse_args()
    handlers = [logging.StreamHandler()]
    if options.log_file:
        options.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                options.log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
            )
        )
    logging.basicConfig(
        level=logging.INFO, handlers=handlers, format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        config = load_config(options.config)
    except (OSError, ValueError, TypeError):
        LOG.error("Invalid or unreadable configuration; check the protected config file")
        return 2
    if options.validate_config:
        return 0
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: STOP.set())
    failures = 0
    while not STOP.is_set():
        started = time.monotonic()
        try:
            receipt = send_heartbeat(config, collect_heartbeat(config))
            LOG.info("Heartbeat accepted at %s", receipt["last_seen"])
            failures = 0
            if options.once:
                return 0
        except urllib.error.HTTPError as error:
            failures += 1
            LOG.warning(
                "Heartbeat rejected (HTTP %s); check credentials, Access bypass and system clock",
                error.code,
            )
            if options.once:
                return 1
        except (urllib.error.URLError, OSError, ValueError, psutil.Error):
            failures += 1
            LOG.warning("Heartbeat failed; retrying without retaining a payload history")
            if options.once:
                return 1
        interval = (
            min(300, 10 * 2 ** min(failures - 1, 5)) if failures else config["heartbeat_seconds"]
        )
        STOP.wait(max(1, interval - (time.monotonic() - started) + random.uniform(-2, 2)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

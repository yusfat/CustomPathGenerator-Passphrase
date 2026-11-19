# ============================================================
# FILE: custompath/security.py
# Strengthened version – improved detection, lower false positives
# ============================================================

import sys
import gc
import os
import time
import threading
import subprocess
import ctypes
from typing import Any

def is_debugger_present() -> bool:
    if sys.gettrace() is not None:
        return True

    try:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                return True
            is_debugged = ctypes.c_int(0)
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(), ctypes.byref(is_debugged)
            )
            if is_debugged.value:
                return True

        elif sys.platform.startswith("linux"):
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            if int(line.split()[1]) != 0:
                                return True
            except Exception:
                pass

            try:
                with open("/proc/self/wchan", "r") as f:
                    if "ptrace" in f.read().lower():
                        return True
            except Exception:
                pass

        elif sys.platform == "darwin":
            try:
                libc = ctypes.CDLL(None)
                if libc.ptrace(31, 0, 0, 0) == -1:
                    return True
            except Exception:
                pass
    except Exception:
        pass

    return False

def is_terminal_recorder_present(strict: bool = False) -> bool:
    """
    Improved detection.
    - Still blocks in strict mode when something real is found.
    - Much lower false-positive rate.
    """
    high_confidence = {
        "asciinema", "ttyrec", "script", "peek",
        "obs", "obs-studio", "wf-recorder", "kooha",
        "recordmydesktop", "simplescreenrecorder", "vokoscreen",
        "ffmpeg", "x11vnc", "wayvnc", "vnc",
        "keylogger", "logkeys", "screenkey",
    }

    low_confidence = {
        "discord", "zoom", "teams", "flameshot",
        "spectacle", "gnome-screenshot", "scrot", "maim",
    }

    found_high = False
    found_low = False

    # psutil path
    try:
        import psutil
        for proc in psutil.process_iter(["name", "cmdline", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmd  = " ".join(proc.info.get("cmdline") or []).lower()
                exe  = (proc.info.get("exe") or "").lower()

                for s in high_confidence:
                    if s in name or s in cmd or s in exe:
                        found_high = True
                        break
                if found_high:
                    break

                for s in low_confidence:
                    if s in name or s in cmd or s in exe:
                        found_low = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except ImportError:
        pass
    except Exception:
        pass

    # Linux /proc fallback
    if not found_high and sys.platform.startswith("linux"):
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip().lower()
                    for s in high_confidence:
                        if s in comm:
                            found_high = True
                            break
                    if found_high:
                        break
                except Exception:
                    continue
        except Exception:
            pass

    if found_high:
        return True

    if strict:
        return found_high   # only high-confidence in strict mode

    return found_high or found_low

def clear_clipboard_after(seconds: int = 45) -> None:
    def _clear():
        time.sleep(seconds)
        commands = [
            ["xsel", "-bc"],
            ["xclip", "-selection", "clipboard", "/dev/null"],
            ["pbcopy"],
            ["wl-copy", "--clear"],
            ["cmd", "/c", "echo off | clip"],
            ["termux-clipboard-set", ""],
        ]
        for cmd in commands:
            try:
                if cmd[0] == "pbcopy":
                    subprocess.run(cmd, input=b"", check=False, capture_output=True, timeout=2)
                else:
                    subprocess.run(cmd, check=False, capture_output=True, timeout=2)
            except Exception:
                continue
    t = threading.Thread(target=_clear, daemon=True)
    t.start()

def clear_terminal_scrollback() -> None:
    try:
        sys.stdout.write("\033[3J\033[H\033[2J")
        sys.stdout.flush()
    except Exception:
        pass

def secure_cleanup(*secrets: Any) -> None:
    """Best-effort only. Pure Python cannot fully wipe strings."""
    for s in secrets:
        if isinstance(s, str) and s:
            try:
                buf = (ctypes.c_char * len(s)).from_address(
                    id(s) + sys.getsizeof("") - 1
                )
                for _ in range(3):
                    ctypes.memset(buf, 0x00, len(s))
                    ctypes.memset(buf, 0xFF, len(s))
                    ctypes.memset(buf, 0x00, len(s))
            except Exception:
                pass
            s = "\0" * len(s)
        elif isinstance(s, bytearray):
            for i in range(len(s)):
                s[i] = 0
        elif isinstance(s, bytes):
            try:
                ba = bytearray(s)
                for i in range(len(ba)):
                    ba[i] = 0
            except Exception:
                pass
    del secrets
    for _ in range(5):
        gc.collect()
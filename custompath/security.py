# custompath/security.py

import sys
import gc
import time
import threading
import subprocess
import ctypes
from typing import Any

def is_debugger_present() -> bool:
    # Original check
    if sys.gettrace() is not None:
        return True

    # Additional lightweight platform checks
    try:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
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
    except Exception:
        pass
    return False


def is_terminal_recorder_present() -> bool:
    suspicious = {
        "script", "ttyrec", "asciinema", "tmate", "peek",
        "obs", "obs-studio", "ffmpeg", "recordmydesktop",
        "simplescreenrecorder", "vokoscreen", "kazam",
        "gnome-screenshot", "spectacle", "flameshot",
        "screenkey", "keylogger", "logkeys", "xwd",
        "import", "scrot", "maim"
    }
    try:
        import psutil
        for proc in psutil.process_iter(["name", "cmdline", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmd = " ".join(proc.info.get("cmdline") or []).lower()
                exe = (proc.info.get("exe") or "").lower()
                for s in suspicious:
                    if s in name or s in cmd or s in exe:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except ImportError:
        pass
    return False


def clear_clipboard_after(seconds: int = 90) -> None:
    def _clear():
        time.sleep(seconds)
        commands = [
            ["xsel", "-bc"],
            ["xclip", "-selection", "clipboard", "/dev/null"],
            ["pbcopy"],                          # macOS
            ["wl-copy", "--clear"],              # Wayland
            ["cmd", "/c", "echo off | clip"],    # Windows
            ["termux-clipboard-set", ""],        # Termux
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


def secure_cleanup(*secrets: Any) -> None:
    """Improved best-effort memory cleanup (still limited by Python GC)."""
    for s in secrets:
        if isinstance(s, str) and s:
            try:
                # Attempt to zero the underlying buffer on CPython
                buf = (ctypes.c_char * len(s)).from_address(
                    id(s) + sys.getsizeof("") - 1
                )
                ctypes.memset(buf, 0, len(s))
            except Exception:
                pass
            # Force replacement
            s = "\0" * len(s)
        elif isinstance(s, bytearray):
            for i in range(len(s)):
                s[i] = 0
        elif isinstance(s, bytes):
            ba = bytearray(s)
            for i in range(len(ba)):
                ba[i] = 0
    del secrets
    gc.collect()
    gc.collect()
# ============================================================
# FILE: custompath/security.py
# Strengthened version – psutil kept & improved, better fallbacks
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
    Keep psutil path, make it stronger, add Linux fallback.
    strict=True → treat inability to check as potentially unsafe.
    """
    suspicious = {
        "script", "ttyrec", "asciinema", "tmate", "peek",
        "obs", "obs-studio", "ffmpeg", "recordmydesktop",
        "simplescreenrecorder", "vokoscreen", "kazam",
        "gnome-screenshot", "spectacle", "flameshot",
        "screenkey", "keylogger", "logkeys", "xwd",
        "import", "scrot", "maim", "byzanz", "vnc",
        "x11vnc", "wayvnc", "wf-recorder", "kooha",
        "screenrec", "bandicam", "fraps", "nvidia share",
        "discord", "zoom", "teams",
        "wireshark", "tcpdump", "tshark",
    }

    found = False

    # Preferred path: psutil
    try:
        import psutil
        for proc in psutil.process_iter(["name", "cmdline", "exe", "ppid"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmd  = " ".join(proc.info.get("cmdline") or []).lower()
                exe  = (proc.info.get("exe") or "").lower()

                for s in suspicious:
                    if s in name or s in cmd or s in exe:
                        found = True
                        break
                if found:
                    break

                try:
                    parent = psutil.Process(proc.info.get("ppid") or 0)
                    pname = (parent.name() or "").lower()
                    for s in suspicious:
                        if s in pname:
                            found = True
                            break
                except Exception:
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if found:
            return True

    except ImportError:
        pass
    except Exception:
        pass

    # Linux fallback without psutil
    if sys.platform.startswith("linux"):
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip().lower()
                    cmdline = ""
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "ignore").lower()
                    except Exception:
                        pass

                    for s in suspicious:
                        if s in comm or s in cmdline:
                            return True
                except Exception:
                    continue
        except Exception:
            pass

    if strict and not found:
        return True

    return found

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
    """
    Best-effort only. Python strings cannot be reliably wiped.
    """
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
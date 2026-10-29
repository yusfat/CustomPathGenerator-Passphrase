# custompath/security.py

import sys
import gc
import time
import threading
import subprocess

def is_debugger_present():
    return sys.gettrace() is not None

def is_terminal_recorder_present():
    suspicious = {
        "script", "ttyrec", "asciinema", "tmate", "peek",
        "obs", "obs-studio", "ffmpeg", "recordmydesktop",
        "simplescreenrecorder", "vokoscreen"
    }
    try:
        import psutil
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmd = " ".join(proc.info.get("cmdline") or []).lower()
                for s in suspicious:
                    if s in name or s in cmd:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        pass
    return False

def clear_clipboard_after(seconds=90):
    def _clear():
        time.sleep(seconds)
        try:
            subprocess.run(["xsel", "-bc"], check=False, capture_output=True)
            subprocess.run(["xclip", "-selection", "clipboard", "/dev/null"],
                           check=False, capture_output=True)
            subprocess.run(["pbcopy"], input=b" ", check=False, capture_output=True)
            subprocess.run(["cmd", "/c", "echo off | clip"],
                           check=False, capture_output=True)
        except Exception:
            pass
    t = threading.Thread(target=_clear, daemon=True)
    t.start()

def secure_cleanup(*secrets):
    for s in secrets:
        if isinstance(s, str):
            s = "\0" * len(s)
    del secrets
    gc.collect()
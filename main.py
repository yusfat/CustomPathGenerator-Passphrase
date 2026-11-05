#!/usr/bin/env python3

import socket
import sys
import time
import threading
import os

_REAL_SOCKET = socket.socket
_REAL_INET = socket.AF_INET
_REAL_INET6 = socket.AF_INET6
_REAL_STREAM = socket.SOCK_STREAM

def has_network():
    test_targets = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("8.8.8.8", 80),
        ("1.1.1.1", 80),
    ]
    test_targets_v6 = [
        ("2001:4860:4860::8888", 53, 0, 0),
        ("2606:4700:4700::1111", 53, 0, 0),
    ]
    for ip, port in test_targets:
        try:
            s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
            s.settimeout(1.5)
            s.connect((ip, port))
            s.close()
            return True
        except:
            pass
    for target in test_targets_v6:
        try:
            s = _REAL_SOCKET(_REAL_INET6, _REAL_STREAM)
            s.settimeout(1.5)
            s.connect(target)
            s.close()
            return True
        except:
            pass
    return False

def network_guard():
    while True:
        time.sleep(3)
        if has_network():
            print("\n[!] NETWORK TURNED ON MID-EXECUTION - ABORTING!")
            try:
                sys.stdout.write("\033[3J\033[H\033[2J")
                sys.stdout.flush()
            except:
                pass
            os._exit(1)

print("=" * 70)
print("  CustomPathGenerator-Passphrase")
print("  High-entropy path & password generator")
print("=" * 70)
print("[*] Checking offline status... (security measure)")

if has_network():
    print("\n" + "="*50)
    print("[!] SECURITY LOCK: NETWORK DETECTED")
    print("="*50)
    print("This tool will NEVER run while online.")
    print("This is NOT an error. This is protection.")
    print("\nYour secrets are safe because we refused to run.")
    print("\nTo continue:")
    print("  1. Turn ON Airplane Mode / Flight Mode")
    print("  2. Turn OFF WiFi & Data / Unplug Ethernet")
    print("  3. Restart the app/phone/system, or wait 2-3 minutes")
    print("     (Android keeps old network routes for a while)")
    print("="*50)
    sys.exit(1)

print("[OK] Offline verified. Vault is isolated.")
print("[OK] Starting continuous network guard...")
threading.Thread(target=network_guard, daemon=True).start()

import ssl
import urllib.request
import http.client

def _blocked(*args, **kwargs):
    raise RuntimeError("Network blocked by policy (offline enforcement)")

socket.socket = _blocked
socket.create_connection = _blocked
socket.socketpair = _blocked

ssl.SSLContext = _blocked
ssl.create_default_context = _blocked
if hasattr(ssl, "_create_unverified_context"):
    ssl._create_unverified_context = _blocked

urllib.request.urlopen = _blocked
urllib.request.Request = _blocked

http.client.HTTPConnection = _blocked
http.client.HTTPSConnection = _blocked

def _audit_block_network(event, args):
    if event == "socket.connect":
        sock = args[0]
        if getattr(sock, "family", None) != getattr(socket, "AF_UNIX", -1):
            raise RuntimeError("Network connection blocked by audit policy")

sys.addaudithook(_audit_block_network)

print("[OK] Hardened network stack disabled for this session (name + audit).\n")

from custompath.crypto import make_system_salt, make_random_salt, make_password, load_secret_noise, _n
from custompath.generator import make_path
from custompath.security import (
    is_debugger_present,
    is_terminal_recorder_present,
    clear_clipboard_after,
    secure_cleanup
)
import hashlib
import shutil
import subprocess

def copy_to_clipboard(text):
    cmds = []
    termux_candidates = [
        "/data/data/com.termux/files/usr/bin/termux-clipboard-set",
        "termux-clipboard-set",
    ]
    for t in termux_candidates:
        if t == "termux-clipboard-set" or os.path.exists(t):
            cmds.append([t])
    if shutil.which("xclip"):
        cmds.append(["xclip", "-selection", "clipboard"])
    if shutil.which("xsel"):
        cmds.append(["xsel", "--clipboard", "--input"])
    if shutil.which("pbcopy"):
        cmds.append(["pbcopy"])
    if os.name == "nt":
        cmds.append(["cmd", "/c", "clip"])
    for cmd in cmds:
        try:
            subprocess.run(cmd, input=text.encode("utf-8"), check=True, capture_output=True, timeout=3)
            return True
        except Exception:
            continue
    return False

def clear_terminal_after(seconds: int = 45):
    def _clear():
        time.sleep(seconds)
        try:
            sys.stdout.write("\033[3J\033[H\033[2J")
            sys.stdout.flush()
            print("Terminal cleared for security.")
            print("You can now generate another one or restart the script.")
            print("Type y for yes to generate another, or n for no.")
        except Exception:
            pass
    t = threading.Thread(target=_clear, daemon=True)
    t.start()

def print_header():
    print("WARNING: Use at your own risk. Always test recovery with a small amount.")
    print()

def get_target_length():
    while True:
        try:
            value = int(input("Path length (2000-2100): ").strip())
            if 2000 <= value <= 2100:
                return value
            print("Must be between 2000 and 2100.")
        except ValueError:
            print("Enter a number.")

def get_advanced_salt():
    print("\nAdvanced mode")
    print("1. Pure random")
    print("2. One personal salt")
    print("3. Salt chaining")
    choice = input("Choice (1/2/3): ").strip()
    if choice == "3":
        print("\nSalt chaining (3-5 layers recommended)")
        final_salt = ""
        layers = 0
        while layers < 5:
            print(f"\nLayer {layers + 1}")
            gen = input("Generate random salt for this layer? (y/n): ").strip().lower()
            if gen == "y":
                current = make_random_salt()
                print("Random salt applied (not shown).")
            else:
                current = input("Paste salt (at least 50 chars): ").strip()
                if len(current) < 50:
                    print("Too short, skipping.")
                    continue
            if layers == 0:
                final_salt = current
            else:
                final_salt = hashlib.sha3_512((final_salt + current).encode()).hexdigest()
            layers += 1
            if input("Add another layer? (y/n): ").strip().lower() != "y":
                break
        print(f"\nDone. {layers} layers used.")
        return final_salt
    if choice == "2":
        personal = input("Personal salt (at least 50 chars): ").strip()
        if len(personal) < 50:
            print("Too short, using pure random instead.")
            return ""
        return personal
    return ""

def security_gate():
    if is_debugger_present():
        print("Debugger detected. Refusing to generate secrets.")
        return False
    if is_terminal_recorder_present():
        print("Terminal recorder or screen-capture tool detected.")
        print("Refusing to generate secrets for safety.")
        return False
    return True

def generate_path(paranoid: bool = False):
    if not security_gate():
        return
    mode = input("Beginner or Advanced? (b/a): ").strip().lower()
    target_len = get_target_length()
    _, system_salt_hex = make_system_salt()
    if mode == "a":
        final_salt = get_advanced_salt()
    else:
        print("\nBeginner mode – pure random")
        final_salt = ""
    combined = final_salt + system_salt_hex if final_salt else system_salt_hex
    print("\nGenerating path...")
    result, levels = make_path(combined, target_len)
    print("\n" + "=" * 70)
    print("DERIVATION PATH")
    print("=" * 70)
    print(result)
    print(".")
    print(f"Length: {len(result)} characters")
    print(f"Levels: {levels} (excluding the final /0/0)")
    if paranoid:
        print("\n[Paranoid mode] Result printed only. Clipboard disabled.")
    else:
        if copy_to_clipboard(result):
            print("Path also copied to clipboard.")
            print("Clipboard will be cleared automatically in 45 seconds.")
            clear_clipboard_after(45)
        else:
            print("Could not copy to clipboard.")
    print("⚠️  Terminal will be cleared in 45 seconds for security...")
    clear_terminal_after(45)
    secure_cleanup(result)

def generate_password(paranoid: bool = False):
    if not security_gate():
        return
    print("\nSelect service / limit:")
    print("1. SafePal          (max 128 chars, full noise allowed)")
    print("2. Gmail            (max 100 chars, letters/digits/standard specials only)")
    print("3. Coursera          (max 71 chars)")
    print("4. GitHub / General (emojis & noise ok, longer)")
    print("5. Custom length")
    choice = input("Choice (1-5): ").strip()
    if choice == "1":
        value = 1110
        while True:
            raw = input(f"Enter length [{75}-{value}] [default 75]: ").strip()
            if raw == "":
                max_len = 75
                break
            if not raw.isdigit():
                print(f"Invalid! Must be a number between 75 and {value}.")
                continue
            max_len = int(raw)
            if not 75 <= max_len <= value:
                print(f"Invalid! Must be between 75 and {value}.")
                continue
            break
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
    elif choice == "2":
        max_len = 100
        print("\nGmail rules: no emoji, no invisible characters.")
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=False, allow_invisible=False, allow_space=allow_space, standard_only=True)
    elif choice == "3":
        max_len = 71
        use_full = input("Use full noise (emoji + invisible)? (y/n): ").strip().lower() == "y"
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        if use_full:
            result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
        else:
            result = make_password(max_len, allow_emoji=False, allow_invisible=False, allow_space=allow_space, standard_only=True)
    elif choice == "4":
        max_len = 200
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
    else:
        while True:
            try:
                max_len = int(input("Maximum length: ").strip())
                if max_len >= 16:
                    break
                print("Minimum 16 characters recommended.")
            except ValueError:
                print("Enter a number.")
        allow_emoji = input("Allow emojis & scripts? (y/n): ").strip().lower() == "y"
        allow_invisible = input("Allow invisible characters? (y/n): ").strip().lower() == "y"
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=allow_emoji, allow_invisible=allow_invisible, allow_space=allow_space)
    print("\n" + "=" * 70)
    print("GENERATED PASSWORD / PASSPHRASE")
    print("=" * 70)
    print(result)
    print(".")
    print(f"Length: {len(result)} characters")
    if paranoid:
        print("\n[Paranoid mode] Result printed only. Clipboard disabled.")
    else:
        if copy_to_clipboard(result):
            print("Password also copied to clipboard.")
            print("Clipboard will be cleared automatically in 45 seconds.")
            clear_clipboard_after(45)
        else:
            print("Could not copy to clipboard.")
    print("⚠️  Terminal will be cleared in 45 seconds for security...")
    clear_terminal_after(45)
    secure_cleanup(result)

def main():
    try:
        sys.stdout.write("\033[3J\033[H\033[2J")
        sys.stdout.flush()
    except Exception:
        pass
    print_header()
    default_name = _n()
    encrypted_noise = input("Path to encrypted secret noise file (or press Enter to skip): ").strip() or default_name
    loaded = load_secret_noise(encrypted_noise)
    if loaded:
        print(f"✅ Secret noise pool loaded ({len(loaded)} unique characters). Will be used more frequently.")
    else:
        print("ℹ️  No secret noise pool loaded (file missing, wrong password, or skipped). Using original pools only.")
    paranoid = input("Enable paranoid mode? (y/n): ").strip().lower() == "y"
    while True:
        print("What do you want to generate?")
        print("1. Long custom derivation path (for advanced wallets)")
        print("2. Password / passphrase for SafePal, Gmail, Coursera, GitHub, etc.")
        choice = input("Choice (1/2): ").strip()
        if choice == "1":
            generate_path(paranoid=paranoid)
        else:
            generate_password(paranoid=paranoid)
        print("\nChecklist:")
        print("  - Save the final result in a password manager")
        print("  - Never store it together with your seed phrase")
        print()
        if input("Generate another one? (y/n): ").strip().lower() != "y":
            print("\nStay safe.")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
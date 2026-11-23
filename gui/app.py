# gui/app.py
# Yusfat Window – fully additive GUI that re-uses existing core security & generation

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sys
import os
import threading
import time

# Ensure project root is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from .styles import DARK_THEME
from .widgets.security_status import SecurityStatusBar

# Real core imports
try:
    from custompath.crypto import make_system_salt, make_random_salt, make_password, load_secret_noise, _n
    from custompath.generator import make_path
    from custompath.security import (
        is_debugger_present,
        is_terminal_recorder_present,
        clear_clipboard_after,
        secure_cleanup,
    )
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"[Yusfat Window] Core import warning: {e}")
    CORE_AVAILABLE = False


class YusfatWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Yusfat Window — CustomPathGenerator-Passphrase")
        self.geometry("860x680")
        self.configure(bg=DARK_THEME["bg"])
        self.resizable(True, True)

        self.paranoid = False
        self.noise_loaded = False

        self._setup_styles()
        self._build_ui()
        self._run_startup_security_checks()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=DARK_THEME["bg"], foreground=DARK_THEME["fg"])
        style.configure("TFrame", background=DARK_THEME["frame_bg"])
        style.configure("TLabel", background=DARK_THEME["frame_bg"], foreground=DARK_THEME["fg"])
        style.configure("TButton", background=DARK_THEME["button_bg"], foreground=DARK_THEME["button_fg"])
        style.configure("TNotebook", background=DARK_THEME["bg"])
        style.configure("TNotebook.Tab", background=DARK_THEME["button_bg"], foreground=DARK_THEME["fg"])
        style.configure("TCheckbutton", background=DARK_THEME["frame_bg"], foreground=DARK_THEME["fg"])
        style.configure("TSpinbox", fieldbackground=DARK_THEME["entry_bg"], foreground=DARK_THEME["entry_fg"])

    def _build_ui(self):
        # Security Status Bar
        self.status_bar = SecurityStatusBar(self)
        self.status_bar.pack(fill="x", padx=10, pady=(8, 0))

        # Top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=6)

        self.paranoid_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top,
            text="Paranoid mode (recommended)",
            variable=self.paranoid_var,
            command=self._on_paranoid_toggle
        ).pack(side="left", padx=4)

        ttk.Button(top, text="Load Secret Noise…", command=self._load_noise).pack(side="left", padx=8)

        # Notebook
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=8)

        # Path Tab
        path_frame = ttk.Frame(notebook)
        notebook.add(path_frame, text="  Custom Path  ")
        self._build_path_tab(path_frame)

        # Password Tab
        password_frame = ttk.Frame(notebook)
        notebook.add(password_frame, text="  Password / Passphrase  ")
        self._build_password_tab(password_frame)

        # Bottom
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=8)
        ttk.Button(bottom, text="Close Yusfat Window", command=self.destroy).pack(side="right")

    def _build_path_tab(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        ttk.Label(frame, text="Target length (2000-2100):").grid(row=0, column=0, sticky="w")
        self.path_len_var = tk.IntVar(value=2050)
        ttk.Spinbox(frame, from_=2000, to=2100, textvariable=self.path_len_var, width=10).grid(
            row=0, column=1, sticky="w", padx=8
        )

        ttk.Label(frame, text="Mode:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.path_mode_var = tk.StringVar(value="b")
        mode_frame = ttk.Frame(frame)
        mode_frame.grid(row=1, column=1, sticky="w", pady=(10, 0))
        ttk.Radiobutton(mode_frame, text="Beginner (pure random)", variable=self.path_mode_var, value="b").pack(side="left")
        ttk.Radiobutton(mode_frame, text="Advanced", variable=self.path_mode_var, value="a").pack(side="left", padx=12)

        self.path_result_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.path_result_var, font=("Consolas", 10), width=90)
        entry.grid(row=3, column=0, columnspan=3, pady=18, sticky="ew")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=8)

        ttk.Button(btn_frame, text="Generate Path", command=self.on_generate_path).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Copy", command=self.copy_path).pack(side="left", padx=6)

        frame.columnconfigure(2, weight=1)

    def _build_password_tab(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        ttk.Label(frame, text="Service / Profile:").grid(row=0, column=0, sticky="w")
        self.pw_profile_var = tk.StringVar(value="4")
        profiles = [
            ("1 – SafePal (max 128)", "1"),
            ("2 – Gmail (max 100, no emoji)", "2"),
            ("3 – Coursera (max 71)", "3"),
            ("4 – GitHub / General (noise OK)", "4"),
            ("5 – Custom length", "5"),
        ]
        profile_box = ttk.Combobox(frame, textvariable=self.pw_profile_var, values=[p[0] for p in profiles], state="readonly", width=40)
        profile_box.grid(row=0, column=1, sticky="w", padx=8)
        profile_box.current(3)

        ttk.Label(frame, text="Length:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.pw_len_var = tk.IntVar(value=80)
        ttk.Spinbox(frame, from_=16, to=256, textvariable=self.pw_len_var, width=10).grid(
            row=1, column=1, sticky="w", padx=8, pady=(10, 0)
        )

        self.allow_space_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Allow spaces", variable=self.allow_space_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=6
        )

        self.password_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.password_var, font=("Consolas", 11), width=90)
        entry.grid(row=4, column=0, columnspan=3, pady=18, sticky="ew")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=8)

        ttk.Button(btn_frame, text="Generate Password / Passphrase", command=self.on_generate_password).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Copy", command=self.copy_password).pack(side="left", padx=6)

        frame.columnconfigure(2, weight=1)

    def _on_paranoid_toggle(self):
        self.paranoid = self.paranoid_var.get()
        self.status_bar.update_status(
            f"Paranoid mode: {'ON' if self.paranoid else 'OFF'}",
            is_safe=True
        )

    def _load_noise(self):
        if not CORE_AVAILABLE:
            messagebox.showerror("Error", "Core modules not available")
            return
        path = simpledialog.askstring("Secret Noise", "Path to encrypted secret noise file (leave empty for default):")
        if path is None:
            return
        default_name = _n()
        encrypted = path.strip() or default_name
        loaded = load_secret_noise(encrypted)
        if loaded:
            self.noise_loaded = True
            self.status_bar.update_status(f"Secret noise loaded ({len(loaded)} chars)", True)
            messagebox.showinfo("Noise", f"Loaded {len(loaded)} unique characters.")
        else:
            self.noise_loaded = False
            self.status_bar.update_status("No secret noise loaded", True)
            messagebox.showinfo("Noise", "No valid noise pool loaded (using default pools).")

    def _run_startup_security_checks(self):
        if not CORE_AVAILABLE:
            self.status_bar.update_status("Core modules not found – limited mode", False)
            return

        issues = []
        if is_debugger_present():
            issues.append("Debugger detected")
        if is_terminal_recorder_present(strict=True):
            issues.append("Recorder / capture tool detected")

        if issues:
            self.status_bar.update_status(" + ".join(issues), False)
            messagebox.showwarning("Security", "\n".join(issues) + "\n\nGeneration will be blocked while these conditions exist.")
        else:
            self.status_bar.update_status("All security checks passed • Ready", True)

    def _security_gate(self) -> bool:
        if not CORE_AVAILABLE:
            messagebox.showerror("Error", "Core security modules not available")
            return False
        if is_debugger_present():
            messagebox.showerror("Security Gate", "Debugger detected – generation blocked.")
            self.status_bar.update_status("Blocked: debugger", False)
            return False
        if is_terminal_recorder_present(strict=self.paranoid):
            messagebox.showerror("Security Gate", "Terminal recorder / screen-capture tool detected – generation blocked.")
            self.status_bar.update_status("Blocked: recorder", False)
            return False
        return True

    def on_generate_path(self):
        if not self._security_gate():
            return

        try:
            target_len = self.path_len_var.get()
            if not (2000 <= target_len <= 2100):
                messagebox.showerror("Length", "Path length must be between 2000 and 2100.")
                return

            mode = self.path_mode_var.get()
            _, system_salt_hex = make_system_salt()

            final_salt = ""
            if mode == "a":
                # Simple advanced: ask once for personal salt (full chaining can be added later)
                personal = simpledialog.askstring(
                    "Advanced Salt",
                    "Personal salt (≥50 chars) or leave empty for pure random:",
                    show="*"
                )
                if personal and len(personal.strip()) >= 50:
                    final_salt = personal.strip()
                else:
                    messagebox.showinfo("Salt", "Using pure random (no personal salt).")

            combined = final_salt + system_salt_hex if final_salt else system_salt_hex
            self.status_bar.update_status("Generating path…", True)
            self.update_idletasks()

            result, levels = make_path(combined, target_len)

            self.path_result_var.set(result)
            self.status_bar.update_status(f"Path generated ({len(result)} chars, {levels} levels)", True)

            if not self.paranoid:
                # Clipboard handled by copy button + auto-clear on demand
                pass

            # Best-effort cleanup later
            self.after(100, lambda: secure_cleanup(result))

        except Exception as e:
            messagebox.showerror("Generation Error", str(e))
            self.status_bar.update_status("Generation failed", False)

    def on_generate_password(self):
        if not self._security_gate():
            return

        try:
            profile = self.pw_profile_var.get()
            # Extract the number
            choice = profile.split("–")[0].strip() if "–" in profile else "4"

            max_len = self.pw_len_var.get()
            allow_space = self.allow_space_var.get()

            if choice.startswith("1"):
                max_len = min(max(max_len, 75), 128)
                result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
            elif choice.startswith("2"):
                max_len = min(max_len, 100)
                result = make_password(max_len, allow_emoji=False, allow_invisible=False, allow_space=allow_space, standard_only=True)
            elif choice.startswith("3"):
                max_len = min(max_len, 71)
                result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
            elif choice.startswith("5"):
                if max_len < 16:
                    messagebox.showerror("Length", "Minimum recommended length is 16.")
                    return
                result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
            else:  # 4 or default
                result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)

            self.password_var.set(result)
            self.status_bar.update_status(f"Password generated ({len(result)} chars)", True)

            self.after(100, lambda: secure_cleanup(result))

        except Exception as e:
            messagebox.showerror("Generation Error", str(e))
            self.status_bar.update_status("Generation failed", False)

    def copy_path(self):
        value = self.path_result_var.get()
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_bar.update_status("Path copied – will clear in 45 s", True)
            clear_clipboard_after(45)

    def copy_password(self):
        value = self.password_var.get()
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_bar.update_status("Password copied – will clear in 45 s", True)
            clear_clipboard_after(45)


def run_yusfat_window():
    app = YusfatWindow()
    app.mainloop()
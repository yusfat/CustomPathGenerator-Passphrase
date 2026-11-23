# gui/widgets/security_status.py

import tkinter as tk
from tkinter import ttk

class SecurityStatusBar(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.status_label = ttk.Label(
            self,
            text="Security: Initializing...",
            font=("Consolas", 10)
        )
        self.status_label.pack(side="left", padx=8, pady=4)

    def update_status(self, message: str, is_safe: bool = True):
        color = "#00ff66" if is_safe else "#ff4444"
        self.status_label.configure(text=message, foreground=color)
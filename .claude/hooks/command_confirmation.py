"""A one-command desktop approval gate for hosts without an ask response."""
from __future__ import annotations

import contextlib
from typing import Optional


def confirm_command(command: str, cwd: str, reason: str,
                    title: str = "AI Command Review - Cascade / Windsurf",
                    timeout_seconds: Optional[int] = None) -> bool:
    """Wait for an explicit Allow once; closing the window rejects the command.

    Import Tk only on the ask path: allow/deny also work on headless machines.
    Missing Tk, an unavailable display, and UI errors propagate to the adapter's
    blocking error handler. This function never executes the proposed command.
    """
    import tkinter as tk
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    approved = False
    callback_error: Optional[BaseException] = None
    try:
        root.withdraw()
        root.title(title)
        root.geometry("820x560")
        root.minsize(600, 360)

        def reject() -> None:
            root.quit()

        def approve() -> None:
            nonlocal approved
            approved = True
            root.quit()

        def callback_failed(kind: type, error: BaseException, traceback: object) -> None:
            nonlocal callback_error
            callback_error = error
            root.quit()

        # Tk otherwise prints callback exceptions and leaves mainloop running.
        root.report_callback_exception = callback_failed
        root.protocol("WM_DELETE_WINDOW", reject)
        root.bind("<Escape>", lambda event: reject())
        root.bind("<Return>", lambda event: reject())

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Allow this command once?",
                  font=("TkDefaultFont", 14, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Execution is waiting for your decision.").pack(anchor="w", pady=8)
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise ValueError("Confirmation timeout must be positive")
            ttk.Label(frame, text=f"This request cancels after {timeout_seconds} seconds.").pack(
                anchor="w", pady=(0, 8))
            root.after(timeout_seconds * 1000, reject)
        details = ScrolledText(frame, wrap="word", width=90, height=20)
        details.pack(fill="both", expand=True)
        details.insert("1.0", f"Working directory:\n{cwd}\n\nCommand:\n{command}"
                       f"\n\nWhy approval is needed:\n{reason}")
        details.configure(state="disabled")

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, name="allow_once", text="Allow once",
                   command=approve).pack(side="right")
        cancel = ttk.Button(buttons, name="cancel", text="Cancel", command=reject)
        cancel.pack(side="right", padx=8)
        root.deiconify()
        root.lift()
        root.attributes("-topmost", True)
        cancel.focus_set()
        root.mainloop()
        if callback_error is not None:
            raise RuntimeError("Confirmation dialog failed") from callback_error
        return approved
    finally:
        with contextlib.suppress(tk.TclError):
            root.destroy()

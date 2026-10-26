from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from analyzer import analyze_password, MIN_LENGTH
from generator import generate_password, generate_passphrase


BG = "#F5F0E8"
PANEL = "#FFFCF7"
PANEL_2 = "#EAE0D2"
TEXT = "#3D3329"
MUTED = "#827363"
ACCENT = "#B79A78"
RED = "#C65D55"
ORANGE = "#C78A4A"
YELLOW = "#D5B45B"
GREEN = "#65866A"
BLUE = "#728DA6"

class PasswordLabApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Lab")
        self.root.geometry("1020x790")
        self.root.minsize(800, 680)
        self.root.configure(bg=BG)
        self.analysis_queue = queue.Queue()
        self.pending_analysis = False
        self.personal_info_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.generated_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.length_var = tk.IntVar(value=20)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=False)
        self.count_var = tk.IntVar(value=3)
        self.passphrase_words_var = tk.IntVar(value=5)
        self.passphrase_number_var = tk.BooleanVar(value=True)
        self.passphrase_caps_var = tk.BooleanVar(value=False)
        self._configure_styles()
        self._build_ui()
        self.password_var.trace_add("write", self._schedule_analysis)
        self.root.after(100, self._poll_analysis_queue)

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "TNotebook.Tab",
            background="#E8F4F0",
            foreground="#8A6716",
            padding=(16, 9),
            font=("Segoe UI", 10, "bold")
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#FFFFFF")],
            foreground=[("selected", "#8A6716")]
        )
        style.configure(
            "TProgressbar",
            troughcolor="#DCEAE5",
            background=ACCENT,
            bordercolor="#DCEAE5",
            lightcolor=ACCENT,
            darkcolor=ACCENT
        )

    def _label(self, parent, text, *, color=TEXT, size=10, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"),
                        **kwargs)

    def _button(self, parent, text, command, primary=False):
        return tk.Button(
        parent,
        text=text,
        command=command,
        bg=ACCENT if primary else PANEL_2,
        fg="#FFFFFF" if primary else TEXT,
        activebackground="#A58868" if primary else "#E3D5C3",
        activeforeground="#FFFFFF" if primary else TEXT,
        relief="flat",
        bd=0,
        padx=14,
        pady=9,
        font=("Segoe UI", 9, "bold"),
        cursor="hand2"
    )

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG, padx=24, pady=18)
        header.pack(fill="x")
        self._label(header, "PASSWORD LAB", color=ACCENT, size=10, bold=True, bg=BG).pack(anchor="w")
        self._label(header, "Strength Checker & Secure Generator", color=TEXT, size=22,
                    bold=True, bg=BG).pack(anchor="w", pady=(4, 2))
        self._label(header, "Local-first password ",
                    color=MUTED, size=10, bg=BG).pack(anchor="w")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=22, pady=(0, 12))
        self.check_tab = tk.Frame(self.notebook, bg=BG)
        self.generate_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.check_tab, text="  Strength checker  ")
        self.notebook.add(self.generate_tab, text="  Password generator  ")
        self._build_checker()
        self._build_generator()

        footer = self._label(self.root,
            "Privacy: password analysis runs locally. Passwords are not logged, saved, or sent to a server.",
            color=MUTED, size=9, bg=BG)
        footer.pack(pady=(0, 10))

    def _card(self, parent, padx=16, pady=14):
        frame = tk.Frame(parent, bg=PANEL, padx=padx, pady=pady)
        return frame

    def _build_checker(self):
        top = self._card(self.check_tab)
        top.pack(fill="x", padx=8, pady=(8, 6))
        self._label(top, "Check a password", size=12, bold=True).pack(anchor="w")
        row = tk.Frame(top, bg=PANEL)
        row.pack(fill="x", pady=(10, 6))
        self.password_entry = tk.Entry(row, textvariable=self.password_var,
            show="•", bg="#d4cdae", fg=TEXT, insertbackground=TEXT,
            relief="flat", font=("Consolas", 13))
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 8))
        self._button(row, "Show / hide", self._toggle_visibility).pack(side="left", padx=(0, 7))
        self._button(row, "Clear", self.clear_checker).pack(side="left")
        self._label(top, "Optional personal details (comma-separated; processed only in memory):",
                    color=MUTED, size=9).pack(anchor="w", pady=(6, 3))
        tk.Entry(top, textvariable=self.personal_info_var, bg="#d4cdae", fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=("Segoe UI", 10)).pack(fill="x", ipady=7)
        self._label(top, "Examples: nickname, username, pet name, birth year. Do not enter sensitive data you do not want checked.",
                    color=MUTED, size=8, wraplength=900, justify="left").pack(anchor="w", pady=(4, 0))

        summary = self._card(self.check_tab)
        summary.pack(fill="x", padx=8, pady=6)
        score_row = tk.Frame(summary, bg=PANEL)
        score_row.pack(fill="x")
        self.score_label = self._label(score_row, "0 / 100", size=22, bold=True, color=RED)
        self.score_label.pack(side="left")
        self.strength_label = self._label(score_row, "Very Weak", size=12, bold=True, color=RED)
        self.strength_label.pack(side="left", padx=16)
        self.entropy_label = self._label(score_row, "Estimated entropy: 0 bits", color=MUTED, size=9)
        self.entropy_label.pack(side="right")
        self.progress = ttk.Progressbar(summary, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(8, 6))
        self.groups_label = self._label(summary, "Character groups: none detected", color=MUTED, size=9)
        self.groups_label.pack(anchor="w")

        body = tk.Frame(self.check_tab, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=(6, 8))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        checks = self._card(body, pady=10)
        checks.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        findings = self._card(body, pady=10)
        findings.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self._label(checks, "Checklist", size=11, bold=True).pack(anchor="w", pady=(0, 7))
        self.checklist = tk.Text(checks, height=12, wrap="word", bg=PANEL, fg=TEXT,
            relief="flat", font=("Segoe UI", 9), padx=2, pady=2, state="disabled")
        self.checklist.pack(fill="both", expand=True)
        self._label(findings, "Detected issues & suggestions", size=11, bold=True).pack(anchor="w", pady=(0, 7))
        self.findings_text = tk.Text(findings, height=12, wrap="word", bg=PANEL, fg=TEXT,
            relief="flat", font=("Segoe UI", 9), padx=2, pady=2, state="disabled")
        self.findings_text.pack(fill="both", expand=True)

    def _build_generator(self):
        outer = tk.Frame(self.generate_tab, bg=BG)
        outer.pack(fill="both", expand=True, padx=8, pady=8)
        settings = self._card(outer)
        settings.pack(fill="x", pady=(0, 8))
        self._label(settings, "Random password settings", size=12, bold=True).pack(anchor="w")
        row = tk.Frame(settings, bg=PANEL)
        row.pack(fill="x", pady=(10, 7))
        self._label(row, "Length (8–128)", color=MUTED).pack(side="left")
        tk.Spinbox(row, from_=8, to=128, textvariable=self.length_var, width=6,
                   bg="#d4cdae", fg=TEXT, buttonbackground=PANEL_2, relief="flat").pack(side="left", padx=(10, 20))
        self._label(row, "Suggestions", color=MUTED).pack(side="left")
        tk.Spinbox(row, from_=1, to=8, textvariable=self.count_var, width=4,
                   bg="#d4cdae", fg=TEXT, buttonbackground=PANEL_2, relief="flat").pack(side="left", padx=10)
        options = tk.Frame(settings, bg=PANEL)
        options.pack(fill="x")
        for label, var in [
            ("Uppercase", self.upper_var), ("Lowercase", self.lower_var),
            ("Digits", self.digits_var), ("Symbols", self.symbols_var),
            ("Exclude ambiguous characters", self.ambiguous_var),
        ]:
            tk.Checkbutton(options, text=label, variable=var, bg=PANEL, fg=TEXT,
                selectcolor="#d4cdae", activebackground=PANEL, activeforeground=TEXT,
                font=("Segoe UI", 9)).pack(side="left", padx=(0, 10), pady=4)

        actions = tk.Frame(settings, bg=PANEL)
        actions.pack(fill="x", pady=(10, 0))
        self._button(actions, "Generate suggestions", self.generate_suggestions, primary=True).pack(side="left")
        self._button(actions, "Clear results", self.clear_generated).pack(side="left", padx=8)

        results = self._card(outer)
        results.pack(fill="both", expand=True, pady=(0, 8))
        self._label(results, "Generated passwords", size=11, bold=True).pack(anchor="w")
        self.results_frame = tk.Frame(results, bg=PANEL)
        self.results_frame.pack(fill="both", expand=True, pady=(8, 0))

        phrase = self._card(outer)
        phrase.pack(fill="x")
        self._label(phrase, "Memorable passphrase", size=11, bold=True).pack(anchor="w")
        prow = tk.Frame(phrase, bg=PANEL)
        prow.pack(fill="x", pady=(8, 6))
        self._label(prow, "Words", color=MUTED).pack(side="left")
        tk.Spinbox(prow, from_=3, to=10, textvariable=self.passphrase_words_var, width=4,
                   bg="#d4cdae", fg=TEXT, buttonbackground=PANEL_2, relief="flat").pack(side="left", padx=8)
        tk.Checkbutton(prow, text="Add number", variable=self.passphrase_number_var, bg=PANEL,
            fg=TEXT, selectcolor="#d4cdae", activebackground=PANEL, activeforeground=TEXT).pack(side="left", padx=8)
        tk.Checkbutton(prow, text="Capitalize words", variable=self.passphrase_caps_var, bg=PANEL,
            fg=TEXT, selectcolor="#d4cdae", activebackground=PANEL, activeforeground=TEXT).pack(side="left", padx=8)
        self._button(phrase, "Generate passphrase", self.make_passphrase, primary=True).pack(anchor="w")
        self.passphrase_var = tk.StringVar()
        tk.Entry(phrase, textvariable=self.passphrase_var, bg="#d4cdae", fg=ACCENT,
                 insertbackground=TEXT, relief="flat", font=("Consolas", 12)).pack(fill="x", ipady=9, pady=(8, 6))
        self._button(phrase, "Copy passphrase", lambda: self.copy_to_clipboard(self.passphrase_var.get())).pack(anchor="w")

    def _toggle_visibility(self):
        self.show_password_var.set(not self.show_password_var.get())
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")

    def _schedule_analysis(self, *_):
        if self.pending_analysis:
            return
        self.pending_analysis = True
        # Debounce analysis so typing remains responsive.
        self.root.after(180, self._start_analysis)

    def _start_analysis(self):
        self.pending_analysis = False
        password = self.password_var.get()
        personal = [item.strip() for item in self.personal_info_var.get().split(",") if item.strip()]
        # The analysis is quick, but worker execution prevents UI stalls if extended later.
        def worker():
            result = analyze_password(password, personal_info=personal)
            self.analysis_queue.put((password, result))
        threading.Thread(target=worker, daemon=True).start()

    def _poll_analysis_queue(self):
        try:
            while True:
                password, result = self.analysis_queue.get_nowait()
                # Don't show stale results if the user typed while a worker was running.
                if password == self.password_var.get():
                    self._render_analysis(result)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_analysis_queue)

    def _render_analysis(self, result):
        colors = {"Very Weak": RED, "Weak": ORANGE, "Fair": YELLOW,
                  "Strong": GREEN, "Very Strong": ACCENT}
        color = colors[result.label]
        self.score_label.configure(text=f"{result.score} / 100", fg=color)
        self.strength_label.configure(text=result.label, fg=color)
        self.progress.configure(value=result.score)
        self.entropy_label.configure(text=f"Estimated entropy: {result.entropy_bits_estimate} bits")
        groups = result.character_groups
        present = [name for name in ("uppercase", "lowercase", "digits", "special", "whitespace", "unicode")
                   if groups[name]]
        self.groups_label.configure(text="Detected groups: " + (", ".join(present) if present else "none"))

        checklist_lines = [
            f"{'✓' if result.length >= MIN_LENGTH else '✗'} Recommended length (12+ characters)",
            f"{'✓' if groups['uppercase'] else '–'} Uppercase letters",
            f"{'✓' if groups['lowercase'] else '–'} Lowercase letters",
            f"{'✓' if groups['digits'] else '–'} Digits",
            f"{'✓' if groups['special'] else '–'} Special characters",
            f"{'⚠' if groups['whitespace'] else '✓'} Whitespace handling",
            f"{'⚠' if groups['unicode'] else '✓'} Unicode handling",
            f"{'✗' if any(f.category == 'blocklist' for f in result.findings) else '✓'} Local common-password blocklist",
            f"{'✗' if any(f.category in {'sequence','keyboard'} for f in result.findings) else '✓'} Sequence / keyboard patterns",
            f"{'✗' if any(f.category == 'repetition' for f in result.findings) else '✓'} Repeated characters / substrings",
            f"{'✗' if any(f.category == 'dictionary' for f in result.findings) else '✓'} Common words / phrases",
            f"Length reported exactly as entered: {result.length}",
        ]
        self._set_text(self.checklist, "\n".join(checklist_lines))
        if result.findings:
            lines = []
            for item in result.findings:
                marker = "●" if item.severity == "critical" else "◆" if item.severity == "warning" else "ℹ"
                lines.append(f"{marker} {item.message}")
                if item.suggestion:
                    lines.append(f"   Suggestion: {item.suggestion}")
                lines.append("")
            if result.warnings:
                lines.append("Notes:")
                lines.extend(f"• {warning}" for warning in result.warnings[:6])
            content = "\n".join(lines)
        elif self.password_var.get():
            content = "No obvious weaknesses were found by this local heuristic checker.\n\nThis does not prove the password is safe or unique. Use a unique password for every account."
        else:
            content = "Type a password to see detected weaknesses and tailored suggestions."
        self._set_text(self.findings_text, content)

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def clear_checker(self):
        self.password_var.set("")
        self.personal_info_var.set("")
        self.password_entry.focus_set()

    def generate_suggestions(self):
        try:
            length = int(self.length_var.get())
            count = int(self.count_var.get())
            if not 1 <= count <= 8:
                raise ValueError("Choose between 1 and 8 suggestions.")
            generated = []
            for _ in range(count):
                password = generate_password(
                    length, self.upper_var.get(), self.lower_var.get(),
                    self.digits_var.get(), self.symbols_var.get(), self.ambiguous_var.get()
                )
                analysis = analyze_password(password)
                generated.append((password, analysis))
            for child in self.results_frame.winfo_children():
                child.destroy()
            for password, analysis in generated:
                row = tk.Frame(self.results_frame, bg="#0b121b", padx=10, pady=8)
                row.pack(fill="x", pady=4)
                tk.Label(row, text=password, bg="#0b121b", fg=ACCENT,
                         font=("Consolas", 11), anchor="w").pack(side="left", fill="x", expand=True)
                tk.Label(row, text=f"{analysis.score}/100 • {analysis.label}", bg="#0b121b",
                         fg=GREEN if analysis.score >= 60 else ORANGE,
                         font=("Segoe UI", 8, "bold")).pack(side="left", padx=8)
                self._button(row, "Copy", lambda value=password: self.copy_to_clipboard(value)).pack(side="right")
            self.notebook.select(self.generate_tab)
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid generator settings", str(exc))

    def clear_generated(self):
        for child in self.results_frame.winfo_children():
            child.destroy()
        self.generated_var.set("")
        self.passphrase_var.set("")

    def make_passphrase(self):
        try:
            phrase = generate_passphrase(
                int(self.passphrase_words_var.get()), separator="-",
                add_number=self.passphrase_number_var.get(),
                capitalize=self.passphrase_caps_var.get()
            )
            self.passphrase_var.set(phrase)
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid passphrase settings", str(exc))

    def copy_to_clipboard(self, value: str):
        if not value:
            messagebox.showinfo("Nothing to copy", "Generate a password or passphrase first.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.root.update_idletasks()
            messagebox.showinfo("Copied", "Copied to clipboard. Remember that other apps may read the clipboard; clear it after use on shared devices.")
        except tk.TclError as exc:
            messagebox.showerror("Clipboard error", f"Could not access the clipboard: {exc}")


def main():
    root = tk.Tk()
    PasswordLabApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

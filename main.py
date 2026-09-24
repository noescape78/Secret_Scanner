"""
main.py - Secret Scanner Desktop GUI

Lightweight, clean Tkinter desktop application for scanning directories
for accidentally exposed API keys, passwords, private keys, and tokens.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Dict, Any

from scanner import scan_directory, export_to_csv
from patterns import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW


class SecretScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secret Scanner")
        self.root.geometry("960x620")
        self.root.minsize(800, 500)

        self.selected_folder_var = tk.StringVar()
        self.current_findings: List[Dict[str, Any]] = []
        self.current_summary: Dict[str, Any] = {}

        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        """Configure clean ttk styling."""
        self.style = ttk.Style(self.root)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        self.root.configure(bg="#f8fafc")

        self.colors = {
            "bg": "#f8fafc",
            "card_bg": "#ffffff",
            "primary": "#0f172a",       # Slate 900
            "primary_btn": "#2563eb",   # Royal Blue
            "danger_btn": "#dc2626",    # Crimson
            "text": "#0f172a",
            "text_muted": "#64748b",
            "border": "#e2e8f0",
            "high": "#b91c1c",          # Red
            "medium": "#d97706",        # Amber
            "low": "#2563eb"            # Blue
        }

        self.style.configure(".", background=self.colors["bg"], foreground=self.colors["text"])
        self.style.configure("Treeview", rowheight=26, font=("Consolas", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        """Build the GUI layout components."""
        # Top Header Banner
        header = tk.Frame(self.root, bg="#0f172a", padx=16, pady=12)
        header.pack(fill="x", side="top")

        tk.Label(
            header,
            text="SECRET SCANNER",
            font=("Segoe UI", 14, "bold"),
            fg="#f8fafc",
            bg="#0f172a"
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Scan source code and configuration files for exposed API keys, passwords, and private tokens",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a"
        ).pack(anchor="w")

        # Container Frame
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        # 1. Folder Selection Group
        select_group = tk.LabelFrame(
            container,
            text=" Target Folder ",
            font=("Segoe UI", 9, "bold"),
            bg="#ffffff",
            fg="#0f172a",
            padx=10,
            pady=10
        )
        select_group.pack(fill="x", pady=(0, 8))

        select_row = tk.Frame(select_group, bg="#ffffff")
        select_row.pack(fill="x")

        tk.Label(select_row, text="Folder:", font=("Segoe UI", 9), bg="#ffffff").pack(side="left", padx=(0, 8))

        self.folder_entry = ttk.Entry(select_row, textvariable=self.selected_folder_var, font=("Segoe UI", 9))
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_browse = tk.Button(
            select_row,
            text="Select Folder",
            command=self._on_browse_folder,
            bg="#e2e8f0",
            activebackground="#cbd5e1",
            font=("Segoe UI", 8),
            relief="flat",
            padx=12,
            pady=3,
            cursor="hand2"
        )
        btn_browse.pack(side="left")

        # 2. Action Controls
        action_frame = tk.Frame(container, bg=self.colors["bg"])
        action_frame.pack(fill="x", pady=(0, 8))

        self.btn_scan = tk.Button(
            action_frame,
            text="Start Scan",
            command=self._on_start_scan,
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2"
        )
        self.btn_scan.pack(side="left", padx=(0, 8))

        self.btn_export = tk.Button(
            action_frame,
            text="Export Report",
            command=self._on_export_report,
            bg="#475569",
            fg="#ffffff",
            activebackground="#334155",
            activeforeground="#ffffff",
            font=("Segoe UI", 9),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2"
        )
        self.btn_export.pack(side="left", padx=8)

        self.btn_clear = tk.Button(
            action_frame,
            text="Clear Results",
            command=self._clear_results,
            bg="#e2e8f0",
            activebackground="#cbd5e1",
            font=("Segoe UI", 9),
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2"
        )
        self.btn_clear.pack(side="right")

        # 3. Summary Panel
        summary_group = tk.LabelFrame(
            container,
            text=" Scan Summary ",
            font=("Segoe UI", 9, "bold"),
            bg="#ffffff",
            fg=self.colors["text_muted"],
            padx=10,
            pady=6
        )
        summary_group.pack(fill="x", pady=(0, 8))

        summary_inner = tk.Frame(summary_group, bg="#ffffff")
        summary_inner.pack(fill="x")

        self.summary_labels = {}
        metrics = [
            ("files_scanned", "Files Scanned:", "#0f172a"),
            ("potential_secrets", "Potential Secrets:", "#dc2626"),
            ("high", "High:", "#b91c1c"),
            ("medium", "Medium:", "#d97706"),
            ("low", "Low:", "#2563eb"),
        ]

        for key, title, color in metrics:
            m_box = tk.Frame(summary_inner, bg="#ffffff")
            m_box.pack(side="left", padx=12)

            tk.Label(m_box, text=title, font=("Segoe UI", 9), fg="#64748b", bg="#ffffff").pack(side="left")
            val_lbl = tk.Label(m_box, text="0", font=("Segoe UI", 9, "bold"), fg=color, bg="#ffffff")
            val_lbl.pack(side="left", padx=(4, 0))
            self.summary_labels[key] = val_lbl

        self.summary_message_lbl = tk.Label(
            summary_inner,
            text="",
            font=("Segoe UI", 9, "italic"),
            fg="#64748b",
            bg="#ffffff"
        )
        self.summary_message_lbl.pack(side="right", padx=10)

        # 4. Results Table (Treeview)
        table_frame = tk.Frame(container, bg="#ffffff", relief="solid", borderwidth=1)
        table_frame.pack(fill="both", expand=True)

        columns = ("file", "line", "type", "severity", "masked_value")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading("file", text="File", anchor="w")
        self.tree.heading("line", text="Line", anchor="center")
        self.tree.heading("type", text="Type", anchor="w")
        self.tree.heading("severity", text="Severity", anchor="center")
        self.tree.heading("masked_value", text="Detected Value (Masked)", anchor="w")

        self.tree.column("file", width=280, minwidth=180, anchor="w")
        self.tree.column("line", width=65, minwidth=50, anchor="center")
        self.tree.column("type", width=160, minwidth=120, anchor="w")
        self.tree.column("severity", width=90, minwidth=70, anchor="center")
        self.tree.column("masked_value", width=320, minwidth=200, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Tag colors for severity rows
        self.tree.tag_configure(SEVERITY_HIGH, foreground="#991b1b", background="#fef2f2")
        self.tree.tag_configure(SEVERITY_MEDIUM, foreground="#92400e", background="#fffbeb")
        self.tree.tag_configure(SEVERITY_LOW, foreground="#1d4ed8", background="#eff6ff")

        # Double click to view details popup
        self.tree.bind("<Double-1>", self._on_row_double_click)

        # 5. Bottom Status Bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready. Select a project folder to scan.",
            bd=1,
            relief="sunken",
            anchor="w",
            font=("Segoe UI", 8),
            bg="#f1f5f9",
            fg="#475569",
            padx=8,
            pady=3
        )
        self.status_bar.pack(side="bottom", fill="x")

    # --- Event Handlers ---

    def _on_browse_folder(self):
        """Open directory chooser dialog."""
        folder = filedialog.askdirectory(title="Select Folder to Scan for Secrets")
        if folder:
            self.selected_folder_var.set(os.path.abspath(folder))
            self._set_status(f"Selected: {folder}")

    def _set_status(self, message: str):
        """Update status bar."""
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def _on_start_scan(self):
        """Execute secret scanning."""
        folder = self.selected_folder_var.get().strip()
        if not folder:
            messagebox.showwarning("Folder Required", "Please select a folder to scan.")
            return

        if not os.path.exists(folder) or not os.path.isdir(folder):
            messagebox.showerror("Invalid Path", f"The directory does not exist:\n{folder}")
            return

        self._set_status("Scanning files for potential secrets...")

        try:
            findings, summary, errors = scan_directory(folder)
            self.current_findings = findings
            self.current_summary = summary

            self._display_findings(findings, summary)

            if summary["potential_secrets"] > 0:
                self.summary_message_lbl.config(
                    text=f"⚠️ {summary['potential_secrets']} potential secret(s) found!",
                    fg="#dc2626"
                )
                messagebox.showwarning(
                    "Potential Secrets Detected",
                    f"Warning: Found {summary['potential_secrets']} potential secret(s)!\n"
                    f"- High Severity: {summary['high']}\n"
                    f"- Medium Severity: {summary['medium']}\n\n"
                    "Inspect the results table for details."
                )
            else:
                self.summary_message_lbl.config(
                    text="No potential secrets detected.",
                    fg="#16a34a"
                )
                messagebox.showinfo(
                    "Scan Complete",
                    "No potential secrets detected.\n\n"
                    "Note: Pattern matching cannot guarantee a project is 100% secret-free."
                )

            self._set_status(f"Scan completed: {summary['files_scanned']} file(s) evaluated.")

        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred while scanning:\n{e}")
            self._set_status("Scan failed.")

    def _display_findings(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Populate the Treeview table with findings."""
        self.tree.delete(*self.tree.get_children())

        for item in findings:
            self.tree.insert(
                "",
                "end",
                values=(
                    item["filename"],
                    item["line"],
                    item["type"],
                    item["severity"],
                    item["masked_value"]
                ),
                tags=(item["severity"],)
            )

        # Update summary labels
        for key in ["files_scanned", "potential_secrets", "high", "medium", "low"]:
            if key in self.summary_labels:
                self.summary_labels[key].config(text=str(summary.get(key, 0)))

    def _on_export_report(self):
        """Export findings to CSV."""
        if not self.current_findings:
            messagebox.showwarning("No Data", "There are no findings to export. Run a scan first.")
            return

        export_path = filedialog.asksaveasfilename(
            title="Export Secrets Report",
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet (*.csv)", "*.csv"), ("All Files", "*.*")],
            initialfile="secrets_report.csv"
        )
        if not export_path:
            return

        try:
            export_to_csv(self.current_findings, export_path)
            messagebox.showinfo("Export Successful", f"Report safely exported (with masked values) to:\n{export_path}")
            self._set_status(f"Report exported: {os.path.basename(export_path)}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to save CSV report:\n{e}")

    def _clear_results(self):
        """Clear table and reset counters."""
        self.tree.delete(*self.tree.get_children())
        self.current_findings = []
        self.current_summary = {}

        for key in ["files_scanned", "potential_secrets", "high", "medium", "low"]:
            if key in self.summary_labels:
                self.summary_labels[key].config(text="0")

        self.summary_message_lbl.config(text="")
        self._set_status("Results cleared.")

    def _on_row_double_click(self, event):
        """Open detailed finding modal on row double-click."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        vals = self.tree.item(selected_item[0], "values")
        if not vals or len(vals) < 5:
            return

        filename, line, stype, severity, masked_val = vals

        # Find matching item in current_findings for full file path
        full_path = filename
        description = ""
        for f in self.current_findings:
            if f["filename"] == filename and str(f["line"]) == str(line) and f["type"] == stype:
                full_path = f["file"]
                description = f.get("description", "")
                break

        dlg = tk.Toplevel(self.root)
        dlg.title(f"Finding Details: {filename} (Line {line})")
        dlg.geometry("560x320")
        dlg.minsize(450, 260)
        dlg.transient(self.root)

        p = ttk.Frame(dlg, padding=14)
        p.pack(fill="both", expand=True)

        tk.Label(p, text=f"Secret Type: {stype} [{severity}]", font=("Segoe UI", 11, "bold"), fg="#b91c1c" if severity == SEVERITY_HIGH else "#d97706").pack(anchor="w", pady=(0, 4))
        if description:
            tk.Label(p, text=description, font=("Segoe UI", 9, "italic"), fg="#64748b").pack(anchor="w", pady=(0, 6))

        tk.Label(p, text="File Path:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        t1 = tk.Text(p, height=2, wrap="char", font=("Consolas", 9))
        t1.insert("1.0", full_path)
        t1.config(state="disabled")
        t1.pack(fill="x", pady=(0, 6))

        tk.Label(p, text=f"Line Number: {line}", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 6))

        tk.Label(p, text="Masked Value (Protected):", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        t2 = tk.Text(p, height=2, wrap="char", font=("Consolas", 9))
        t2.insert("1.0", masked_val)
        t2.config(state="disabled")
        t2.pack(fill="x", pady=(0, 10))

        ttk.Button(p, text="Close", command=dlg.destroy).pack(anchor="e")


def main():
    root = tk.Tk()
    app = SecretScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

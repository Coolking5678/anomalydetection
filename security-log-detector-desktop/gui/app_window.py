"""
gui/app_window.py
-----------------
Main Tkinter / ttk application window for the AI-Based Security Log
Anomaly Detector.

Layout overview
---------------
┌──────────────────────────────────────────────────────────┐
│  [Header Banner]                                         │
├──────────────────────────────────────────────────────────┤
│  [Control Bar]  Browse | Contamination Slider | Run      │
├──────────────────────────────────────────────────────────┤
│  [KPI Frame]    Total Logs | Anomalies | Flagged IPs     │
├──────────────────────────────────────────────────────────┤
│  [Status Bar]   Progress / info messages                 │
├──────────────────────────────────────────────────────────┤
│  [Treeview]     Scrollable results table                 │
├──────────────────────────────────────────────────────────┤
│  [Footer]       Export button                            │
└──────────────────────────────────────────────────────────┘
"""

import logging
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import pandas as pd
import tkinter as tk
from tkinter import ttk

# Internal modules
from src.ingestion import download_log, parse_log_file, DEFAULT_LOG_PATH
from src.features import build_features
from src.model import AnomalyDetector
from src.explainer import explain_anomalies

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------

PALETTE = {
    "bg_dark": "#0d1117",
    "bg_panel": "#161b22",
    "bg_card": "#1c2128",
    "accent": "#58a6ff",
    "accent_hover": "#79c0ff",
    "danger": "#f85149",
    "danger_soft": "#3d1a1a",
    "success": "#3fb950",
    "warning": "#d29922",
    "text_primary": "#e6edf3",
    "text_secondary": "#8b949e",
    "border": "#30363d",
    "row_threat_bg": "#2d1217",
    "row_threat_fg": "#ff7b72",
    "row_normal_fg": "#e6edf3",
    "header_bg": "#1f2937",
}

FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"


# ---------------------------------------------------------------------------
# Helper: rounded button factory
# ---------------------------------------------------------------------------

def _make_btn(
    parent,
    text: str,
    command,
    bg: str = PALETTE["accent"],
    fg: str = PALETTE["bg_dark"],
    padx: int = 18,
    pady: int = 8,
    font_size: int = 10,
) -> tk.Button:
    """Return a styled flat Button widget."""
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=PALETTE["accent_hover"],
        activeforeground=PALETTE["bg_dark"],
        relief="flat",
        cursor="hand2",
        padx=padx,
        pady=pady,
        font=(FONT_FAMILY, font_size, "bold"),
        bd=0,
    )
    # Hover effect
    btn.bind("<Enter>", lambda _e: btn.config(bg=PALETTE["accent_hover"]))
    btn.bind("<Leave>", lambda _e: btn.config(bg=bg))
    return btn


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------

class AnomalyDetectorApp(tk.Tk):
    """
    Top-level Tkinter window for the Security Log Anomaly Detector.

    All UI state is managed here; heavy ML work is delegated to a background
    daemon thread so the main event loop remains responsive.
    """

    def __init__(self) -> None:
        super().__init__()

        # ── Window chrome ────────────────────────────────────────────────────
        self.title("AI Security Log Anomaly Detector")
        self.geometry("1300x780")
        self.minsize(1000, 650)
        self.configure(bg=PALETTE["bg_dark"])

        # Try to set a window icon (silently skip if unavailable)
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        # ── Internal state ───────────────────────────────────────────────────
        self._log_path: Optional[str] = None
        self._result_df: Optional[pd.DataFrame] = None
        self._is_running: bool = False

        # ── Build UI ─────────────────────────────────────────────────────────
        self._apply_ttk_theme()
        self._build_header()
        self._build_control_bar()
        self._build_kpi_frame()
        self._build_status_bar()
        self._build_table()
        self._build_footer()

        # Kick off with the default sample log pre-filled
        self._log_path_var.set(str(DEFAULT_LOG_PATH))

    # ========================================================================
    # TTK Theme Configuration
    # ========================================================================

    def _apply_ttk_theme(self) -> None:
        """Configure a dark custom ttk style throughout the application."""
        style = ttk.Style(self)
        style.theme_use("clam")

        # --- General ---
        style.configure(
            ".",
            background=PALETTE["bg_dark"],
            foreground=PALETTE["text_primary"],
            fieldbackground=PALETTE["bg_panel"],
            troughcolor=PALETTE["bg_panel"],
            selectbackground=PALETTE["accent"],
            selectforeground=PALETTE["bg_dark"],
            font=(FONT_FAMILY, 10),
        )

        # --- TFrame ---
        style.configure("TFrame", background=PALETTE["bg_dark"])
        style.configure("Card.TFrame", background=PALETTE["bg_card"])
        style.configure("Panel.TFrame", background=PALETTE["bg_panel"])

        # --- TLabel ---
        style.configure(
            "TLabel",
            background=PALETTE["bg_dark"],
            foreground=PALETTE["text_primary"],
        )
        style.configure(
            "Header.TLabel",
            background=PALETTE["bg_dark"],
            foreground=PALETTE["accent"],
            font=(FONT_FAMILY, 22, "bold"),
        )
        style.configure(
            "Sub.TLabel",
            background=PALETTE["bg_dark"],
            foreground=PALETTE["text_secondary"],
            font=(FONT_FAMILY, 10),
        )
        style.configure(
            "KPI.TLabel",
            background=PALETTE["bg_card"],
            foreground=PALETTE["text_primary"],
            font=(FONT_FAMILY, 10),
        )
        style.configure(
            "KPIValue.TLabel",
            background=PALETTE["bg_card"],
            foreground=PALETTE["accent"],
            font=(FONT_FAMILY, 26, "bold"),
        )
        style.configure(
            "KPIDanger.TLabel",
            background=PALETTE["bg_card"],
            foreground=PALETTE["danger"],
            font=(FONT_FAMILY, 26, "bold"),
        )
        style.configure(
            "KPISuccess.TLabel",
            background=PALETTE["bg_card"],
            foreground=PALETTE["success"],
            font=(FONT_FAMILY, 26, "bold"),
        )

        # --- TEntry ---
        style.configure(
            "TEntry",
            fieldbackground=PALETTE["bg_panel"],
            foreground=PALETTE["text_primary"],
            insertcolor=PALETTE["text_primary"],
            bordercolor=PALETTE["border"],
            lightcolor=PALETTE["border"],
            darkcolor=PALETTE["border"],
        )

        # --- TScale ---
        style.configure(
            "TScale",
            troughcolor=PALETTE["border"],
            sliderthickness=16,
            sliderrelief="flat",
        )
        style.map("TScale", background=[("active", PALETTE["accent"])])

        # --- Treeview ---
        style.configure(
            "Treeview",
            background=PALETTE["bg_panel"],
            foreground=PALETTE["text_primary"],
            rowheight=30,
            fieldbackground=PALETTE["bg_panel"],
            bordercolor=PALETTE["border"],
            font=(FONT_MONO, 9),
        )
        style.configure(
            "Treeview.Heading",
            background=PALETTE["header_bg"],
            foreground=PALETTE["accent"],
            relief="flat",
            font=(FONT_FAMILY, 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", PALETTE["accent"])],
            foreground=[("selected", PALETTE["bg_dark"])],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", PALETTE["bg_card"])],
        )

        # --- Scrollbar ---
        style.configure(
            "Vertical.TScrollbar",
            background=PALETTE["bg_panel"],
            troughcolor=PALETTE["bg_dark"],
            arrowcolor=PALETTE["text_secondary"],
        )

        # --- Progressbar ---
        style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor=PALETTE["bg_panel"],
            background=PALETTE["accent"],
        )

    # ========================================================================
    # UI Builders
    # ========================================================================

    def _build_header(self) -> None:
        """Banner at the top of the window."""
        frame = ttk.Frame(self, style="Panel.TFrame")
        frame.pack(fill="x", padx=0, pady=0)

        inner = ttk.Frame(frame, style="Panel.TFrame")
        inner.pack(padx=30, pady=(18, 14))

        ttk.Label(
            inner,
            text="AI Security Log Anomaly Detector",
            style="Header.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            inner,
            text=(
                "Unsupervised Isolation Forest · SSH Log Analysis · "
                "Brute-Force & Off-Hours Detection"
            ),
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        ttk.Separator(self, orient="horizontal").pack(fill="x")

    def _build_control_bar(self) -> None:
        """Control row: file picker, contamination slider, run button."""
        bar = ttk.Frame(self, style="Panel.TFrame")
        bar.pack(fill="x", padx=0, pady=0)

        inner = ttk.Frame(bar, style="Panel.TFrame")
        inner.pack(padx=30, pady=16, anchor="w")

        # --- File path entry + browse button ---
        ttk.Label(inner, text="Log File:", style="Sub.TLabel").grid(
            row=0, column=0, padx=(0, 8), sticky="w"
        )

        self._log_path_var = tk.StringVar()
        path_entry = ttk.Entry(
            inner, textvariable=self._log_path_var, width=52
        )
        path_entry.grid(row=0, column=1, padx=(0, 8))

        browse_btn = _make_btn(
            inner, "  Browse…  ", self._browse_file,
            bg=PALETTE["bg_card"], fg=PALETTE["text_primary"],
            padx=12, pady=6, font_size=9,
        )
        browse_btn.grid(row=0, column=2, padx=(0, 28))
        browse_btn.bind("<Enter>", lambda _e: browse_btn.config(bg=PALETTE["border"]))
        browse_btn.bind("<Leave>", lambda _e: browse_btn.config(bg=PALETTE["bg_card"]))

        # --- Download sample button ---
        dl_btn = _make_btn(
            inner, "Download Sample", self._download_sample,
            bg=PALETTE["bg_card"], fg=PALETTE["text_secondary"],
            padx=12, pady=6, font_size=9,
        )
        dl_btn.grid(row=0, column=3, padx=(0, 28))
        dl_btn.bind("<Enter>", lambda _e: dl_btn.config(bg=PALETTE["border"]))
        dl_btn.bind("<Leave>", lambda _e: dl_btn.config(bg=PALETTE["bg_card"]))

        # --- Contamination slider ---
        ttk.Label(inner, text="Contamination:", style="Sub.TLabel").grid(
            row=0, column=4, padx=(0, 8), sticky="w"
        )

        self._contamination_var = tk.DoubleVar(value=0.03)

        slider = ttk.Scale(
            inner,
            from_=0.01,
            to=0.15,
            orient="horizontal",
            variable=self._contamination_var,
            command=self._update_contamination_label,
            length=180,
        )
        slider.grid(row=0, column=5, padx=(0, 6))

        self._contamination_label = ttk.Label(
            inner,
            text="3.0%",
            style="Sub.TLabel",
            width=5,
        )
        self._contamination_label.grid(row=0, column=6, padx=(0, 24))

        # --- Run button ---
        self._run_btn = _make_btn(
            inner, "Run Detection", self._start_detection,
            bg=PALETTE["accent"], fg=PALETTE["bg_dark"],
            padx=20, pady=8,
        )
        self._run_btn.grid(row=0, column=7)

        ttk.Separator(self, orient="horizontal").pack(fill="x")

    def _build_kpi_frame(self) -> None:
        """Three metric cards showing key statistics."""
        frame = ttk.Frame(self, style="TFrame")
        frame.pack(fill="x", padx=30, pady=18)

        kpi_data = [
            ("Total Logs", "0", "KPIValue.TLabel", "total"),
            ("Anomalies Detected", "0", "KPIDanger.TLabel", "anomalies"),
            ("Flagged IPs", "0", "KPISuccess.TLabel", "ips"),
        ]

        self._kpi_vars: dict[str, tk.StringVar] = {}

        for col_idx, (title, default_val, value_style, key) in enumerate(kpi_data):
            card = ttk.Frame(frame, style="Card.TFrame", padding=20)
            card.grid(row=0, column=col_idx, padx=(0, 16), sticky="nsew")
            frame.columnconfigure(col_idx, weight=1)

            # Decorative left border using a 1-px label
            accent_colors = [
                PALETTE["accent"],
                PALETTE["danger"],
                PALETTE["success"],
            ]
            border = tk.Label(
                card,
                bg=accent_colors[col_idx],
                width=1,
            )
            border.pack(side="left", fill="y", padx=(0, 12))

            text_frame = ttk.Frame(card, style="Card.TFrame")
            text_frame.pack(side="left", fill="both", expand=True)

            ttk.Label(
                text_frame, text=title, style="KPI.TLabel"
            ).pack(anchor="w")

            var = tk.StringVar(value=default_val)
            self._kpi_vars[key] = var

            ttk.Label(
                text_frame,
                textvariable=var,
                style=value_style,
            ).pack(anchor="w", pady=(4, 0))

    def _build_status_bar(self) -> None:
        """Thin status / progress bar below KPIs."""
        frame = ttk.Frame(self)
        frame.pack(fill="x", padx=30, pady=(0, 8))

        self._status_var = tk.StringVar(value="Ready — load a log file and run detection.")
        ttk.Label(
            frame,
            textvariable=self._status_var,
            style="Sub.TLabel",
        ).pack(side="left")

        self._progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
            length=200,
            style="Accent.Horizontal.TProgressbar",
        )
        self._progress.pack(side="right")

    def _build_table(self) -> None:
        """Results Treeview with scrollbar."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=30, pady=(0, 8))

        columns = (
            "timestamp",
            "source_ip",
            "username",
            "event_type",
            "fail_5m",
            "status",
            "reason",
        )
        headers = (
            "Timestamp",
            "Source IP",
            "Target User",
            "Event Type",
            "Failures (5m)",
            "Status",
            "Anomaly Reason",
        )
        widths = (155, 130, 110, 120, 90, 80, 380)

        self._tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        for col, header, width in zip(columns, headers, widths):
            self._tree.heading(col, text=header, anchor="w")
            self._tree.column(col, width=width, anchor="w", stretch=False)

        # Row tags for threat highlighting
        self._tree.tag_configure(
            "threat",
            background=PALETTE["row_threat_bg"],
            foreground=PALETTE["row_threat_fg"],
            font=(FONT_MONO, 9, "bold"),
        )
        self._tree.tag_configure(
            "normal",
            background=PALETTE["bg_panel"],
            foreground=PALETTE["row_normal_fg"],
        )
        self._tree.tag_configure(
            "threat_alt",
            background="#361a1a",
            foreground=PALETTE["row_threat_fg"],
            font=(FONT_MONO, 9, "bold"),
        )
        self._tree.tag_configure(
            "normal_alt",
            background="#1a1f28",
            foreground=PALETTE["row_normal_fg"],
        )

        # Scrollbars
        vsb = ttk.Scrollbar(
            container, orient="vertical", command=self._tree.yview
        )
        hsb = ttk.Scrollbar(
            container, orient="horizontal", command=self._tree.xview
        )
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

    def _build_footer(self) -> None:
        """Bottom footer with export button."""
        ttk.Separator(self, orient="horizontal").pack(fill="x")
        footer = ttk.Frame(self, style="Panel.TFrame")
        footer.pack(fill="x", padx=30, pady=12)

        ttk.Label(
            footer,
            text="Powered by scikit-learn Isolation Forest  •  SSH Log Analysis",
            style="Sub.TLabel",
        ).pack(side="left")

        export_btn = _make_btn(
            footer,
            "Export Flagged Threats",
            self._export_threats,
            bg=PALETTE["danger"],
            fg="#ffffff",
            padx=16,
            pady=7,
        )
        export_btn.pack(side="right")
        export_btn.bind(
            "<Enter>", lambda _e: export_btn.config(bg="#c0392b")
        )
        export_btn.bind(
            "<Leave>", lambda _e: export_btn.config(bg=PALETTE["danger"])
        )

    # ========================================================================
    # Event Handlers
    # ========================================================================

    def _browse_file(self) -> None:
        """Open a file-chooser dialog to select a .log file."""
        path = filedialog.askopenfilename(
            title="Select SSH Log File",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._log_path_var.set(path)
            self._set_status(f"Log file selected: {Path(path).name}")

    def _download_sample(self) -> None:
        """Download the Loghub SSH_2k.log sample in a background thread."""
        if self._is_running:
            return

        self._set_status("Downloading SSH_2k.log from Loghub …")
        self._progress.start(12)
        self._run_btn.config(state="disabled")

        def _task():
            try:
                dest = download_log()
                self._log_path_var.set(str(dest))
                self.after(
                    0,
                    lambda: self._set_status(
                        f"Sample downloaded → {dest.name}  (ready to run)"
                    ),
                )
            except Exception as exc:
                self.after(
                    0,
                    lambda: messagebox.showerror("Download Error", str(exc)),
                )
                self.after(
                    0,
                    lambda: self._set_status("Download failed. Check your internet connection."),
                )
            finally:
                self.after(0, self._progress.stop)
                self.after(0, lambda: self._run_btn.config(state="normal"))

        threading.Thread(target=_task, daemon=True).start()

    def _update_contamination_label(self, _val: str = "") -> None:
        """Keep the contamination percentage label in sync with the slider."""
        pct = self._contamination_var.get() * 100
        self._contamination_label.config(text=f"{pct:.1f}%")

    def _start_detection(self) -> None:
        """Validate inputs and launch the ML pipeline in a background thread."""
        if self._is_running:
            return

        log_path = self._log_path_var.get().strip()
        if not log_path:
            messagebox.showwarning(
                "No File Selected",
                "Please browse to a .log file or download the sample first.",
            )
            return

        if not Path(log_path).exists():
            messagebox.showerror(
                "File Not Found",
                f"Could not find:\n{log_path}\n\nPlease verify the path.",
            )
            return

        contamination = round(self._contamination_var.get(), 4)

        # Disable controls while running
        self._is_running = True
        self._run_btn.config(state="disabled", text="Running...")
        self._progress.start(10)
        self._clear_table()
        self._reset_kpis()

        thread = threading.Thread(
            target=self._run_pipeline,
            args=(log_path, contamination),
            daemon=True,
        )
        thread.start()

    def _run_pipeline(self, log_path: str, contamination: float) -> None:
        """
        Full ML pipeline executed on a worker thread.
        Posts results back to the main thread via ``self.after``.
        """
        try:
            # 1. Parse
            self.after(0, lambda: self._set_status("Parsing log file…"))
            raw_df = parse_log_file(log_path)

            # 2. Features
            self.after(0, lambda: self._set_status("Engineering features…"))
            enriched_df, X = build_features(raw_df)

            # 3. Model
            self.after(
                0,
                lambda: self._set_status(
                    f"Training Isolation Forest (contamination={contamination:.1%}) …"
                ),
            )
            detector = AnomalyDetector(contamination=contamination)
            is_anomaly = detector.train_and_predict(X)

            # 4. Explain
            self.after(0, lambda: self._set_status("Generating anomaly explanations…"))
            explanations = explain_anomalies(enriched_df, is_anomaly)

            # Attach results to the DataFrame
            enriched_df["is_anomaly"] = is_anomaly.values
            enriched_df["reason"] = explanations.values

            # 5. Post to UI
            self.after(0, lambda: self._populate_results(enriched_df))

        except Exception as exc:
            logger.exception("Pipeline error.")
            self.after(
                0,
                lambda: messagebox.showerror(
                    "Pipeline Error",
                    f"An error occurred during analysis:\n\n{exc}",
                ),
            )
            self.after(
                0,
                lambda: self._set_status(f"Error: {exc}"),
            )
        finally:
            self.after(0, self._pipeline_done)

    def _pipeline_done(self) -> None:
        """Restore UI state after pipeline completes."""
        self._is_running = False
        self._run_btn.config(state="normal", text="Run Detection")
        self._progress.stop()

    # ========================================================================
    # Results population
    # ========================================================================

    def _populate_results(self, df: pd.DataFrame) -> None:
        """Fill the Treeview and KPI cards from the results DataFrame."""
        self._result_df = df
        self._clear_table()

        n_total = len(df)
        n_anomalies = int(df["is_anomaly"].sum())
        n_ips = int(df.loc[df["is_anomaly"], "source_ip"].nunique())

        # KPIs
        self._kpi_vars["total"].set(f"{n_total:,}")
        self._kpi_vars["anomalies"].set(f"{n_anomalies:,}")
        self._kpi_vars["ips"].set(f"{n_ips:,}")

        # Populate table (alternating row colours)
        threat_idx = 0
        normal_idx = 0

        for i, row in df.iterrows():
            is_threat = bool(row["is_anomaly"])
            status_text = "THREAT" if is_threat else "Normal"

            values = (
                str(row["timestamp"])[:19],
                row["source_ip"] or "—",
                row["username"] or "—",
                row["event_type"],
                f"{int(row['rolling_fail_5m'])}",
                status_text,
                row.get("reason", "") or "",
            )

            if is_threat:
                tag = "threat" if threat_idx % 2 == 0 else "threat_alt"
                threat_idx += 1
            else:
                tag = "normal" if normal_idx % 2 == 0 else "normal_alt"
                normal_idx += 1

            self._tree.insert("", "end", values=values, tags=(tag,))

        self._set_status(
            f"Analysis complete — {n_total:,} entries scanned, "
            f"{n_anomalies:,} anomalies detected across {n_ips:,} unique IPs."
        )

    # ========================================================================
    # Export
    # ========================================================================

    def _export_threats(self) -> None:
        """Save only anomalous rows to a user-specified CSV file."""
        if self._result_df is None:
            messagebox.showinfo(
                "No Results",
                "Please run detection first before exporting.",
            )
            return

        threats_df = self._result_df[self._result_df["is_anomaly"]]
        if threats_df.empty:
            messagebox.showinfo(
                "No Threats",
                "No anomalies were detected in the last run. Nothing to export.",
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Export Flagged Threats",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="anomaly_threats.csv",
        )
        if not save_path:
            return

        export_cols = [
            "timestamp",
            "event_type",
            "source_ip",
            "username",
            "hour",
            "is_night_access",
            "rolling_fail_5m",
            "is_admin_target",
            "ip_freq",
            "reason",
        ]
        # Keep only columns that exist in the DataFrame
        export_cols = [c for c in export_cols if c in threats_df.columns]

        try:
            threats_df[export_cols].to_csv(save_path, index=False)
            messagebox.showinfo(
                "Export Successful",
                f"Exported {len(threats_df):,} threat records to:\n{save_path}",
            )
            self._set_status(f"Threats exported → {Path(save_path).name}")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))

    # ========================================================================
    # Utility helpers
    # ========================================================================

    def _set_status(self, message: str) -> None:
        """Update the status bar label text."""
        self._status_var.set(message)
        logger.info("[STATUS] %s", message)

    def _clear_table(self) -> None:
        """Remove all rows from the Treeview."""
        for item in self._tree.get_children():
            self._tree.delete(item)

    def _reset_kpis(self) -> None:
        """Reset all KPI counters to zero."""
        for var in self._kpi_vars.values():
            var.set("0")

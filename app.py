"""Python Project 002: Windows ESTABLISHED TCP connection investigator (Tkinter)."""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from netstat_monitor import (
    Connection, annotate, export_csv, get_live_connections,
    is_public_ip, parse_netstat,
)
from reputation import lookup_ip, summarize_reputation

SAMPLE_NETSTAT = """Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.10:50100     8.8.8.8:443            ESTABLISHED     4200
  TCP    192.168.1.10:50102     1.1.1.1:4444           ESTABLISHED     4400
  TCP    127.0.0.1:50704       127.0.0.1:50705       ESTABLISHED     5100
  TCP    [::1]:50705           [::1]:50704           ESTABLISHED     5100
"""


def get_sample_connections():
    return annotate(parse_netstat(SAMPLE_NETSTAT), {4200: "browser.exe", 4400: "demo-tool.exe", 5100: "python.exe"})


class InvestigatorApp:
    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.demo = demo
        self.root.title("Python Project 002 | Netstat IP Investigator" + (" — DEMO DATA" if demo else ""))
        self.root.geometry("1280x760")
        self.root.minsize(930, 590)
        self.queue = queue.Queue()
        self.connections: list[Connection] = []
        self.reputation: dict[str, dict] = {}
        self.busy = False
        self.rep_busy = False
        self.review_only = tk.BooleanVar(value=False)
        self.auto_refresh = tk.BooleanVar(value=False)
        self.search_text = tk.StringVar()
        self.status = tk.StringVar(value="Ready. Refresh to collect current TCP connections.")
        self.overview = tk.StringVar(value="No snapshot yet")
        self.detail = tk.StringVar(value="Select a row to inspect its IP, PID, process and review notes.")
        self.api_key = tk.StringVar()
        self._build_ui()
        self.root.after(150, self._poll)
        self.root.after(250, self.refresh)

    def _build_ui(self):
        self.root.configure(background="#f4f7fb")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Treeview", rowheight=29, font=("Segoe UI", 10), background="white", fieldbackground="white")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), padding=(5, 9))
        style.configure("TButton", font=("Segoe UI", 10), padding=(9, 6))
        style.configure("TCheckbutton", font=("Segoe UI", 10), background="#f4f7fb")
        style.configure("TLabel", background="#f4f7fb", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 21, "bold"), foreground="#133358")
        style.configure("Subtitle.TLabel", foreground="#52667d", font=("Segoe UI", 10))

        frame = ttk.Frame(self.root, padding=(22, 18))
        frame.pack(fill="both", expand=True)
        frame.configure(style="TFrame")
        header = ttk.Frame(frame)
        header.pack(fill="x")
        ttk.Label(header, text="Netstat IP Investigator", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Established TCP connections  •  PID / process correlation  •  Context-based review flags", style="Subtitle.TLabel").pack(anchor="w", pady=(1, 12))

        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=(2, 9))
        self.refresh_btn = ttk.Button(controls, text="Refresh connections", command=self.refresh)
        self.refresh_btn.pack(side="left", padx=(0, 7))
        ttk.Checkbutton(controls, text="Auto-refresh (5s)", variable=self.auto_refresh).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(controls, text="Review only", variable=self.review_only, command=self._render).pack(side="left", padx=(0, 12))
        ttk.Label(controls, text="Find IP / process:").pack(side="left", padx=(0, 5))
        search = ttk.Entry(controls, textvariable=self.search_text, width=23)
        search.pack(side="left")
        self.search_text.trace_add("write", lambda *_: self._render())
        ttk.Button(controls, text="Export CSV", command=self.save_csv).pack(side="right")

        ttk.Label(frame, textvariable=self.overview, style="Subtitle.TLabel").pack(anchor="w", pady=(0, 6))

        results = ttk.Frame(frame)
        results.pack(fill="both", expand=True)
        columns = ("risk", "remote", "rport", "local", "pid", "process", "reason")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", selectmode="browse")
        names = ("Flag", "Remote IP", "R. Port", "Local endpoint", "PID", "Process", "Why review?")
        widths = (82, 163, 78, 192, 72, 145, 425)
        for name, title, width in zip(columns, names, widths):
            self.tree.heading(name, text=title, anchor="w")
            self.tree.column(name, width=width, anchor="w", minwidth=65, stretch=name == "reason")
        self.tree.tag_configure("Review", background="#fff1dc", foreground="#754400")
        self.tree.tag_configure("Routine", background="white", foreground="#20324b")
        self.tree.tag_configure("Local", background="#eaf1fa", foreground="#24446c")
        self.tree.bind("<<TreeviewSelect>>", self._select)
        vs = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(results, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        results.grid_rowconfigure(0, weight=1)
        results.grid_columnconfigure(0, weight=1)

        pane = ttk.LabelFrame(frame, text="Selected connection / investigation", padding=10)
        pane.pack(fill="x", pady=(13, 8))
        detail_label = ttk.Label(pane, textvariable=self.detail, wraplength=1180, justify="left")
        detail_label.pack(fill="x", anchor="w", pady=(0, 9))
        lookup_row = ttk.Frame(pane)
        lookup_row.pack(fill="x")
        ttk.Label(lookup_row, text="AbuseIPDB API key (optional):").pack(side="left")
        ttk.Entry(lookup_row, width=37, textvariable=self.api_key, show="•").pack(side="left", padx=7)
        self.rep_button = ttk.Button(lookup_row, text="Check selected IP reputation", command=self.lookup_selected)
        self.rep_button.pack(side="left", padx=(3, 7))
        ttk.Button(lookup_row, text="Copy IP", command=self.copy_ip).pack(side="left")

        ttk.Label(frame, textvariable=self.status, style="Subtitle.TLabel", wraplength=1100).pack(anchor="w", pady=(3, 0))

    def refresh(self):
        if self.busy:
            return
        self.busy = True
        self.refresh_btn.configure(state="disabled")
        self.status.set("Collecting netstat connections and process names...")

        def work():
            try:
                snapshot = get_sample_connections() if self.demo else get_live_connections()
                self.queue.put(("scan_ok", snapshot))
            except Exception as exc:
                self.queue.put(("scan_error", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                kind, data = self.queue.get_nowait()
                if kind == "scan_ok":
                    self.busy = False
                    self.refresh_btn.configure(state="normal")
                    self.connections = data
                    self._render()
                    self.status.set(("DEMO snapshot loaded — fabricated examples, not your computer. " if self.demo else "Snapshot updated. ") +
                                    "Flags are triage hints, not malware verdicts.")
                    if self.auto_refresh.get():
                        self.root.after(5000, self._auto_tick)
                elif kind == "scan_error":
                    self.busy = False
                    self.refresh_btn.configure(state="normal")
                    self.status.set("Scan failed: " + data)
                    messagebox.showerror("Could not collect connections", data)
                elif kind == "reputation_ok":
                    ip, result = data
                    self.rep_busy = False
                    self.rep_button.configure(state="normal")
                    self.reputation[ip] = result
                    self.status.set(f"Reputation lookup completed for {ip}.")
                    self._select()
                elif kind == "reputation_error":
                    self.rep_busy = False
                    self.rep_button.configure(state="normal")
                    self.status.set("Reputation lookup failed: " + data)
                    messagebox.showerror("Reputation lookup failed", data)
        except queue.Empty:
            pass
        self.root.after(150, self._poll)

    def _auto_tick(self):
        if self.auto_refresh.get() and not self.busy:
            self.refresh()

    def _render(self):
        if not hasattr(self, "tree"):
            return
        self.tree.delete(*self.tree.get_children())
        needle = self.search_text.get().strip().lower()
        for i, conn in enumerate(self.connections):
            if self.review_only.get() and conn.risk != "Review":
                continue
            if needle and needle not in (conn.remote_ip + " " + conn.process + " " + str(conn.pid) + " " + conn.reason).lower():
                continue
            self.tree.insert("", "end", iid=str(i), values=(conn.risk, conn.remote_ip, conn.remote_port,
                                  conn.local_endpoint, conn.pid, conn.process, conn.reason), tags=(conn.risk,))
        count_review = sum(c.risk == "Review" for c in self.connections)
        count_public = sum(c.public for c in self.connections)
        self.overview.set(f"{len(self.connections)} ESTABLISHED TCP connections  |  {count_public} public peers  |  "
                          f"{count_review} need context review  |  {len(self.tree.get_children())} rows displayed")
        self.detail.set("Select a row to inspect the process, connection and reasons for its flag.")

    def _selected_conn(self):
        selection = self.tree.selection()
        return self.connections[int(selection[0])] if selection else None

    def _select(self, event=None):
        conn = self._selected_conn()
        if conn is None:
            return
        rep = self.reputation.get(conn.remote_ip)
        extra = "\n" + summarize_reputation(rep) if rep else "\nReputation: not checked (optional, manual lookup only)."
        self.detail.set(f"{conn.remote_endpoint}  |  PID {conn.pid} ({conn.process})  |  local {conn.local_endpoint}  |  Flag: {conn.risk}\n"
                        f"Assessment: {conn.reason}{extra}\n"
                        "Netstat does not determine which side initiated a connection; verify direction and process legitimacy separately.")

    def copy_ip(self):
        conn = self._selected_conn()
        if conn is None:
            messagebox.showinfo("Select a row", "Choose a connection to copy its remote IP.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(conn.remote_ip)
        self.status.set(f"Copied {conn.remote_ip} to clipboard.")

    def lookup_selected(self):
        conn = self._selected_conn()
        if conn is None:
            messagebox.showinfo("Select a row", "Choose a connection first.")
            return
        if not is_public_ip(conn.remote_ip):
            messagebox.showinfo("Private or special IP", "Reputation lookup is intended for public IP addresses only.")
            return
        if self.rep_busy:
            return
        key = self.api_key.get().strip()
        if not key:
            messagebox.showinfo("API key required", "Enter your own AbuseIPDB API key; it is not stored on disk.")
            return
        ip = conn.remote_ip
        if not messagebox.askyesno("Share IP with AbuseIPDB?", f"Submit {ip} to AbuseIPDB for a reputation check?\n\nOnly this IP and your API key will be sent to the provider."):
            return
        self.rep_busy = True
        self.rep_button.configure(state="disabled")
        self.status.set(f"Checking AbuseIPDB reputation for {ip}...")

        def work():
            try:
                result = lookup_ip(ip, key)
                self.queue.put(("reputation_ok", (ip, result)))
            except Exception as exc:
                self.queue.put(("reputation_error", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def save_csv(self):
        if not self.connections:
            messagebox.showinfo("Nothing to export", "Collect a snapshot before exporting.")
            return
        path = filedialog.asksaveasfilename(title="Save connection snapshot", defaultextension=".csv",
                                            initialfile="netstat_connections.csv", filetypes=[("CSV Files", "*.csv")])
        if not path:
            return
        try:
            export_csv(path, self.connections, self.reputation)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.status.set(f"Saved {len(self.connections)} connections to {path}")


def main():
    demo = "--demo" in sys.argv
    root = tk.Tk()
    InvestigatorApp(root, demo=demo)
    root.mainloop()


if __name__ == "__main__":
    main()

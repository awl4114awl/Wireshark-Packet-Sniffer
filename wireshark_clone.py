import subprocess
import threading
import queue
import sys
import signal
import os
import shutil
import datetime
from collections import Counter


import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog


###############################################################
#   Tshark Capture Thread (summary output)
###############################################################
class TsharkCaptureThread(threading.Thread):
    """
    Runs `tshark -T fields ...` in a background thread and pushes
    parsed packets into a queue for the GUI.
    """
    def __init__(self, tshark_path, interface, bpf_filter, packet_queue, stop_event):
        super().__init__(daemon=True)
        self.tshark_path = tshark_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.process = None

        # store last line for debugging if needed
        self._last_line = None

    def run(self):
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-l",
            "-n",
            "-T", "fields",
            "-E", "separator=|",
            "-E", "quote=d",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "_ws.col.Info",
        ]

        if self.bpf_filter:
            cmd.extend(["-f", self.bpf_filter])

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except FileNotFoundError:
            self.packet_queue.put({
                "type": "error",
                "message": "tshark not found. Install Wireshark / tshark."
            })
            return
        except Exception as e:
            self.packet_queue.put({
                "type": "error",
                "message": f"Failed to start tshark: {e}"
            })
            return

        try:
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    break

                line = line.strip()
                if not line:
                    continue

                self._last_line = line

                parts = [p.strip('"') for p in line.split("|")]
                if len(parts) < 7:
                    continue

                packet = {
                    "type": "packet",
                    "frame": parts[0],
                    "time": parts[1],
                    "src": parts[2],
                    "dst": parts[3],
                    "protocol": parts[4],
                    "length": parts[5],
                    "info": parts[6],
                }
                self.packet_queue.put(packet)

        finally:
            if self.process and self.process.poll() is None:
                try:
                    if sys.platform.startswith("win"):
                        self.process.terminate()
                    else:
                        self.process.send_signal(signal.SIGINT)
                except Exception:
                    pass
                try:
                    self.process.wait(timeout=2)
                except Exception:
                    pass


###############################################################
#   Main Application (Wireshark-style dark theme)
###############################################################
class WiresharkCloneApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # App icon
        try:
            self.iconbitmap("screenshots/icon.ico")
        except Exception:
            pass

        # --- Force Windows taskbar icon (Tkinter bug workaround) ---
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "WiresharkClone.PythonApp"
            )
        except Exception:
            pass

        # Re-apply icon for both title bar + taskbar
        try:
            self.iconbitmap("screenshots/icon.ico")
        except Exception:
            pass

        # Window basics
        self.title("Wireshark Clone (Python + tshark)")
        self.geometry("1000x650")

        # Wireshark-ish dark theme base
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color="#181a1b")  # main background

        # Capture / state
        self.capture_thread = None
        self.capture_stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.capturing = False
        self.paused = False
        self.paused_buffer = []

        self.current_pcap_path = None
        self.pcap_process = None

        # Stats
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.talker_counts = Counter()
        self.last_packet_count = 0

        # tshark path
        self.tshark_path = self._find_tshark()

        # UI
        self._build_style()
        self._build_layout()

        if self.tshark_path:
            self._load_interfaces()
        else:
            messagebox.showerror(
                "Error",
                "tshark not found.\n\nInstall Wireshark / tshark and ensure it is in your PATH."
            )
            self.status_var.set("tshark not found.")

        # Loops
        self.after(100, self._process_packet_queue)
        self.after(1000, self._update_stats)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    ###########################################################
    #   Helper: locate tshark
    ###########################################################
    def _find_tshark(self):
        from shutil import which

        path = which("tshark")
        if path:
            return path

        # Typical Wireshark paths on Windows
        for p in (
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ):
            if os.path.exists(p):
                return p

        return None

    ###########################################################
    #   ttk Style to mimic Wireshark dark theme
    ###########################################################
    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Wireshark dark palette
        list_bg = "#1e1f22"  # packet pane background
        list_fg = "#ffffff"
        header_bg = "#2b2b2b"
        header_fg = "#f0f0f0"
        select_bg = "#4c6b8a"  # Wireshark selection blue
        select_fg = "#000000"

        style.configure(
            "Dark.Treeview",
            background=list_bg,
            foreground=list_fg,
            fieldbackground=list_bg,
            rowheight=22,
            borderwidth=0,
            relief="flat",
            font=("Consolas", 10)
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", select_bg)],
            foreground=[("selected", select_fg)]
        )

        style.configure(
            "Dark.Treeview.Heading",
            background=header_bg,
            foreground=header_fg,
            relief="flat",
            borderwidth=1,
            font=("Inter UI", 10)
        )

        style.map(
            "Dark.Treeview.Heading",
            background=[
                ("active", "#3a3a3a"),
                ("pressed", "#3a3a3a")
            ],
            foreground=[
                ("active", "#f0f0f0"),
                ("pressed", "#f0f0f0")
            ]
        )

        style.layout("Dark.Treeview", [
            ("Treeview.treearea", {"sticky": "nswe"})
        ])

        # --- Dark scrollbars (thin, inside table area) ---
        style.configure(
            "Dark.Vertical.TScrollbar",
            gripcount=0,
            background="#2b2b2b",
            troughcolor="#181a1b",
            bordercolor="#181a1b",
            arrowcolor="#d1d5db",
            relief="flat",
            width=11
        )
        style.map(
            "Dark.Vertical.TScrollbar",
            background=[
                ("active", "#3a3a3a"),
                ("pressed", "#444444")
            ],
            arrowcolor=[
                ("active", "#ffffff"),
                ("pressed", "#ffffff")
            ]
        )

        style.configure(
            "Dark.Horizontal.TScrollbar",
            gripcount=0,
            background="#2b2b2b",
            troughcolor="#181a1b",
            bordercolor="#181a1b",
            arrowcolor="#d1d5db",
            relief="flat",
            width=11
        )
        style.map(
            "Dark.Horizontal.TScrollbar",
            background=[
                ("active", "#3a3a3a"),
                ("pressed", "#444444")
            ],
            arrowcolor=[
                ("active", "#ffffff"),
                ("pressed", "#ffffff")
            ]
        )

        style.configure(
            "Dark.TPanedwindow",
            background="#181a1b",
            bordercolor="#181a1b"
        )
        style.configure(
            "Dark.TPanedwindow.Sash",
            background="#2b2b2b",
            bordercolor="#1e1e1e"
        )

    ###########################################################
    #   Layout (Wireshark-style)
    ###########################################################
    def _build_layout(self):
        # ---------- Top toolbar ----------
        toolbar_bg = "#2b2b2b"

        top_frame = ctk.CTkFrame(self, fg_color=toolbar_bg, corner_radius=0)
        top_frame.pack(side="top", fill="x", padx=0, pady=0)

        # Row 0 – Interface + filter
        row0 = ctk.CTkFrame(top_frame, fg_color=toolbar_bg)
        row0.pack(side="top", anchor="w", padx=10, pady=(8, 2))

        label_font = ("Inter UI", 12)

        ctk.CTkLabel(row0, text="Interface:", font=label_font, text_color="#ffffff").pack(side="left", padx=(0, 5))
        self.interface_var = ctk.StringVar()
        self.interface_combo = ctk.CTkComboBox(
            row0,
            variable=self.interface_var,
            width=260,
            font=label_font,
            fg_color="#3c3f41",
            border_color="#1e1f22",
            button_color="#3c3f41",
            text_color="#ffffff",
            state="readonly"
        )
        self.interface_combo.pack(side="left", padx=(0, 15))

        ctk.CTkLabel(row0, text="Capture Filter (BPF):", font=label_font, text_color="#ffffff").pack(side="left", padx=(0, 5))
        self.filter_entry = ctk.CTkEntry(
            row0,
            width=260,
            placeholder_text="e.g. tcp port 80",
            font=label_font,
            fg_color="#3c3f41",
            border_color="#1e1f22",
            text_color="#ffffff",
            placeholder_text_color="#9ca3af"
        )
        self.filter_entry.pack(side="left", padx=(0, 15))

        # Row 1 – controls
        row1 = ctk.CTkFrame(top_frame, fg_color=toolbar_bg)
        row1.pack(side="top", anchor="w", padx=10, pady=(0, 8))

        button_width = 120
        button_font = ("Inter UI", 12)
        button_fg = "#3c3f41"
        button_hover = "#4b4f53"
        button_text = "#ffffff"

        self.start_button = ctk.CTkButton(
            row1, text="Start Capture", width=button_width,
            command=self.start_capture, font=button_font, corner_radius=4,
            fg_color=button_fg, hover_color=button_hover, text_color=button_text
        )
        self.start_button.pack(side="left", padx=4, pady=2)

        self.pause_button = ctk.CTkButton(
            row1, text="Pause", width=button_width,
            state="disabled", command=self.toggle_pause,
            font=button_font, corner_radius=4,
            fg_color=button_fg, hover_color=button_hover, text_color=button_text
        )
        self.pause_button.pack(side="left", padx=4, pady=2)

        self.stop_button = ctk.CTkButton(
            row1, text="Stop", width=button_width,
            state="disabled", command=self.stop_capture,
            font=button_font, corner_radius=4,
            fg_color=button_fg, hover_color=button_hover, text_color=button_text
        )
        self.stop_button.pack(side="left", padx=4, pady=2)

        self.clear_button = ctk.CTkButton(
            row1, text="Clear", width=button_width,
            command=self.clear_packets, font=button_font, corner_radius=4,
            fg_color=button_fg, hover_color=button_hover, text_color=button_text
        )
        self.clear_button.pack(side="left", padx=4, pady=2)

        self.save_button = ctk.CTkButton(
            row1, text="Save PCAP", width=button_width,
            state="disabled", command=self.save_pcap,
            font=button_font, corner_radius=4,
            fg_color=button_fg, hover_color=button_hover, text_color=button_text
        )
        self.save_button.pack(side="left", padx=4, pady=2)

        # ---------- Split Pane ----------
        self.split = ttk.Panedwindow(self, orient="vertical", style="Dark.TPanedwindow")
        self.split.pack(fill="both", expand=True)

        middle_frame = ctk.CTkFrame(self, fg_color="#181a1b", corner_radius=0)
        bottom_frame = ctk.CTkFrame(self, fg_color="#181a1b", corner_radius=0)

        self.split.add(middle_frame, weight=3)
        self.split.add(bottom_frame, weight=1)

        # ---------- PACKET LIST ----------
        table_container = ctk.CTkFrame(middle_frame, fg_color="#181a1b", corner_radius=0)
        table_container.grid(row=0, column=0, sticky="nsew", padx=6, pady=4)

        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        columns = ("frame", "time", "src", "dst", "protocol", "length", "info")
        self.packet_tree = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            style="Dark.Treeview"
        )

        self.packet_tree.heading("frame", text="No.")
        self.packet_tree.heading("time", text="Time")
        self.packet_tree.heading("src", text="Source")
        self.packet_tree.heading("dst", text="Destination")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("length", text="Length")
        self.packet_tree.heading("info", text="Info")

        self.packet_tree.column("frame", width=60, anchor="e")
        self.packet_tree.column("time", width=180, anchor="w")
        self.packet_tree.column("src", width=140, anchor="w")
        self.packet_tree.column("dst", width=140, anchor="w")
        self.packet_tree.column("protocol", width=80, anchor="center")
        self.packet_tree.column("length", width=80, anchor="e")
        self.packet_tree.column("info", width=450, anchor="w")

        vsb = ttk.Scrollbar(
            table_container,
            orient="vertical",
            style="Dark.Vertical.TScrollbar",
            command=self.packet_tree.yview
        )
        hsb = ttk.Scrollbar(
            table_container,
            orient="horizontal",
            style="Dark.Horizontal.TScrollbar",
            command=self.packet_tree.xview
        )

        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        middle_frame.grid_rowconfigure(0, weight=1)
        middle_frame.grid_columnconfigure(0, weight=1)

        # Row colors
        self.packet_tree.tag_configure("DNS", background="#25283a")
        self.packet_tree.tag_configure("TCP", background="#20242a")
        self.packet_tree.tag_configure("UDP", background="#1d2227")
        self.packet_tree.tag_configure("HTTP", background="#23272e")
        self.packet_tree.tag_configure("TLS", background="#1f2626")
        self.packet_tree.tag_configure("OTHER", background="#1e1f22")

        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # ---------- Tabs ----------
        bottom_tabs = ctk.CTkTabview(
            bottom_frame,
            fg_color="#181a1b",
            segmented_button_selected_color="#4c6b8a",
            segmented_button_unselected_color="#2b2b2b",
            segmented_button_unselected_hover_color="#3c3f41"
        )
        bottom_tabs.pack(fill="both", expand=True, padx=6, pady=6)

        overview_tab = bottom_tabs.add("Overview")
        proto_tab = bottom_tabs.add("Protocol Tree")
        hex_tab = bottom_tabs.add("Hex Dump")
        stats_tab = bottom_tabs.add("Stats")

        text_bg = "#1e1f22"
        text_fg = "#e5e7eb"

        # Overview
        ctk.CTkLabel(overview_tab, text="Selected Packet Details:", anchor="w", text_color="#ffffff").pack(anchor="w", padx=4, pady=(4, 0))
        self.details_text = ctk.CTkTextbox(
            overview_tab, height=110,
            fg_color=text_bg, text_color=text_fg,
            font=("Consolas", 12)
        )
        self.details_text.pack(fill="both", expand=True, padx=4, pady=4)
        self.details_text.configure(state="disabled")

        # Protocol tree
        ctk.CTkLabel(proto_tab, text="Protocol Details (tshark -V):", anchor="w", text_color="#ffffff").pack(anchor="w", padx=4, pady=(4, 0))
        self.proto_text = ctk.CTkTextbox(
            proto_tab, height=110,
            fg_color=text_bg, text_color=text_fg,
            font=("Consolas", 12)
        )
        self.proto_text.pack(fill="both", expand=True, padx=4, pady=4)
        self.proto_text.configure(state="disabled")

        # Hex dump
        ctk.CTkLabel(hex_tab, text="Hex Dump (tshark -x):", anchor="w", text_color="#ffffff").pack(anchor="w", padx=4, pady=(4, 0))
        self.hex_text = ctk.CTkTextbox(
            hex_tab, height=110,
            fg_color=text_bg, text_color=text_fg,
            font=("Consolas", 12)
        )
        self.hex_text.pack(fill="both", expand=True, padx=4, pady=4)
        self.hex_text.configure(state="disabled")

        # Stats
        self.stat_total = ctk.StringVar(value="Total packets: 0")
        self.stat_pps = ctk.StringVar(value="Packets/sec: 0")
        self.stat_bytes = ctk.StringVar(value="Total bytes: 0")
        self.stat_proto = ctk.StringVar(value="Top protocol: n/a")
        self.stat_talkers = ctk.StringVar(value="Top talkers: n/a")

        for var in (self.stat_total, self.stat_pps, self.stat_bytes, self.stat_proto, self.stat_talkers):
            ctk.CTkLabel(stats_tab, textvariable=var, anchor="w", text_color="#ffffff").pack(anchor="w", padx=4, pady=2)

        # Status bar
        self.status_var = ctk.StringVar(value="Ready.")
        status_bar = ctk.CTkLabel(
            self,
            textvariable=self.status_var,
            anchor="w",
            fg_color="#2b2b2b",
            text_color="#e5e7eb"
        )
        status_bar.pack(side="bottom", fill="x")

    ###########################################################
    #   Load interfaces from tshark -D
    ###########################################################
    def _load_interfaces(self):
        try:
            result = subprocess.run(
                [self.tshark_path, "-D"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
        except Exception:
            return

        friendly_names = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if "." not in line:
                continue

            idx_str, rest = line.split(".", 1)
            idx = idx_str.strip()

            # default pretty name is the whole remainder
            pretty = rest.strip()

            # if there's a (...) part, just grab the label inside
            if "(" in rest and ")" in rest:
                pretty = rest.split("(", 1)[1].rsplit(")", 1)[0].strip()

            pretty = pretty.replace("*", "").strip()
            pretty = pretty.replace("USBPcap1", "USB Capture 1")
            pretty = pretty.replace("USBPcap2", "USB Capture 2")

            if "Loopback" in pretty:
                pretty = "Loopback"

            friendly_names.append(f"{idx}. {pretty}")

        if friendly_names:
            self.interface_combo.configure(values=friendly_names)
            self.interface_combo.set(friendly_names[0])
            self.status_var.set("Interfaces loaded.")

    def _get_selected_interface_number(self):
        """
        Returns the numeric interface index as a string, e.g. '1', '2', etc.
        This is passed directly to tshark's -i parameter.
        """
        selected = self.interface_var.get()
        if not selected:
            return ""

        parts = selected.split(".", 1)
        if parts and parts[0].strip().isdigit():
            return parts[0].strip()

        return selected.strip()

    ###########################################################
    #   Capture control
    ###########################################################
    def start_capture(self):
        if self.capturing:
            return
        if not self.tshark_path:
            messagebox.showerror("Error", "tshark is not available.")
            return

        iface = self._get_selected_interface_number()
        if not iface:
            messagebox.showwarning("No Interface", "Please select an interface first.")
            return

        bpf = self.filter_entry.get().strip()

        # Reset stats
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts.clear()
        self.talker_counts.clear()
        self.last_packet_count = 0
        self.paused = False
        self.paused_buffer.clear()

        # Create PCAP filename
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_pcap_path = os.path.join(os.getcwd(), f"capture_{ts}.pcap")

        # PCAP writer
        pcap_cmd = [self.tshark_path, "-i", iface, "-w", self.current_pcap_path]
        if bpf:
            pcap_cmd.extend(["-f", bpf])

        try:
            self.pcap_process = subprocess.Popen(
                pcap_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception as e:
            self.pcap_process = None
            messagebox.showwarning(
                "PCAP Warning",
                f"Could not start PCAP writer:\n{e}\n\n"
                "Packet list will still work, but deep details may be unavailable."
            )

        # Summary capture thread
        self.capture_stop_event.clear()
        self.capture_thread = TsharkCaptureThread(
            tshark_path=self.tshark_path,
            interface=iface,
            bpf_filter=bpf,
            packet_queue=self.packet_queue,
            stop_event=self.capture_stop_event
        )
        self.capture_thread.start()

        self.capturing = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.pause_button.configure(state="normal", text="Pause")
        self.save_button.configure(state="disabled")
        self.status_var.set(f"Capturing on interface {iface}...")

    def stop_capture(self):
        if not self.capturing:
            return

        # Stop summary
        self.capture_stop_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            try:
                self.capture_thread.join(timeout=3)
            except Exception:
                pass

        # Stop PCAP writer
        if self.pcap_process and self.pcap_process.poll() is None:
            try:
                if sys.platform.startswith("win"):
                    self.pcap_process.terminate()
                else:
                    self.pcap_process.send_signal(signal.SIGINT)
            except Exception:
                pass
            try:
                self.pcap_process.wait(timeout=3)
            except Exception:
                pass

        self.capturing = False
        self.paused = False
        self.paused_buffer.clear()

        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.pause_button.configure(state="disabled", text="Pause")

        if self.current_pcap_path and os.path.exists(self.current_pcap_path):
            self.save_button.configure(state="normal")

        self.status_var.set("Capture stopped.")

    def toggle_pause(self):
        if not self.capturing:
            return

        if not self.paused:
            self.paused = True
            self.pause_button.configure(text="Resume")
            self.status_var.set("Capture paused.")
        else:
            self.paused = False
            self.pause_button.configure(text="Pause")
            for pkt in self.paused_buffer:
                self._add_packet_to_table(pkt)
            self.paused_buffer.clear()
            self.status_var.set("Capture resumed.")

    def save_pcap(self):
        if not self.current_pcap_path or not os.path.exists(self.current_pcap_path):
            messagebox.showwarning("No PCAP", "No PCAP file is available to save.")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
        )
        if not dest:
            return

        try:
            shutil.copy2(self.current_pcap_path, dest)
            messagebox.showinfo("Saved", f"PCAP saved to:\n{dest}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PCAP:\n{e}")

    def clear_packets(self):
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # Clear text areas safely
        for txt in (self.details_text, self.proto_text, self.hex_text):
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.configure(state="disabled")

        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts.clear()
        self.talker_counts.clear()
        self.last_packet_count = 0

        self.stat_total.set("Total packets: 0")
        self.stat_pps.set("Packets/sec: 0")
        self.stat_bytes.set("Total bytes: 0")
        self.stat_proto.set("Top protocol: n/a")
        self.stat_talkers.set("Top talkers: n/a")

        self.status_var.set("Packet list cleared.")

    ###########################################################
    #   Queue processing and stats
    ###########################################################
    def _process_packet_queue(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if item["type"] == "packet":
                    if self.paused:
                        self.paused_buffer.append(item)
                    else:
                        self._add_packet_to_table(item)
                elif item["type"] == "error":
                    messagebox.showerror("Error", item["message"])
                    self.status_var.set(item["message"])
        except queue.Empty:
            pass

        self.after(100, self._process_packet_queue)

    def _add_packet_to_table(self, packet):
        proto = (packet["protocol"] or "").upper()

        if "DNS" in proto or "MDNS" in proto:
            tag = "DNS"
        elif "TCP" in proto:
            tag = "TCP"
        elif "UDP" in proto:
            tag = "UDP"
        elif "HTTP" in proto:
            tag = "HTTP"
        elif "TLS" in proto or "SSL" in proto:
            tag = "TLS"
        else:
            tag = "OTHER"

        self.packet_tree.insert(
            "",
            "end",
            values=(
                packet["frame"],
                packet["time"],
                packet["src"],
                packet["dst"],
                proto,
                packet["length"],
                packet["info"],
            ),
            tags=(tag,)
        )

        self.total_packets += 1
        try:
            self.total_bytes += int(packet["length"])
        except ValueError:
            pass

        if packet["src"]:
            self.talker_counts[packet["src"]] += 1
        if packet["dst"]:
            self.talker_counts[packet["dst"]] += 1
        if proto:
            self.protocol_counts[proto] += 1

        if self.capturing and not self.paused:
            self.status_var.set(f"Capturing... {self.total_packets} packets seen.")

    def _update_stats(self):
        pps = self.total_packets - self.last_packet_count
        self.last_packet_count = self.total_packets

        self.stat_total.set(f"Total packets: {self.total_packets}")
        self.stat_pps.set(f"Packets/sec: {pps}")
        self.stat_bytes.set(f"Total bytes: {self.total_bytes}")

        if self.protocol_counts:
            top_proto, count = self.protocol_counts.most_common(1)[0]
            self.stat_proto.set(f"Top protocol: {top_proto} ({count})")
        else:
            self.stat_proto.set("Top protocol: n/a")

        if self.talker_counts:
            top_talkers = self.talker_counts.most_common(3)
            formatted = ", ".join(f"{ip} ({c})" for ip, c in top_talkers)
            self.stat_talkers.set(f"Top talkers: {formatted}")
        else:
            self.stat_talkers.set("Top talkers: n/a")

        self.after(1000, self._update_stats)

    ###########################################################
    #   Packet selection → details / proto / hex
    ###########################################################
    def on_packet_select(self, event):
        selected = self.packet_tree.selection()
        if not selected:
            return

        item_id = selected[0]
        values = self.packet_tree.item(item_id, "values")
        if not values:
            return

        frame, time_str, src, dst, proto, length, info = values

        details = (
            f"Frame:       {frame}\n"
            f"Time:        {time_str}\n"
            f"Source:      {src}\n"
            f"Destination: {dst}\n"
            f"Protocol:    {proto}\n"
            f"Length:      {length}\n"
            f"Info:        {info}\n"
        )

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", details)
        self.details_text.configure(state="disabled")

        self._load_packet_deep_details(frame)

    def _load_packet_deep_details(self, frame_number):
        # Prepare text widgets
        self.proto_text.configure(state="normal")
        self.proto_text.delete("1.0", "end")
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")

        if not self.current_pcap_path or not os.path.exists(self.current_pcap_path):
            self.proto_text.insert("1.0", "Protocol details unavailable (no PCAP).")
            self.hex_text.insert("1.0", "Hex dump unavailable (no PCAP).")
            self.proto_text.configure(state="disabled")
            self.hex_text.configure(state="disabled")
            return

        if not self.tshark_path:
            self.proto_text.insert("1.0", "tshark not available.")
            self.hex_text.insert("1.0", "tshark not available.")
            self.proto_text.configure(state="disabled")
            self.hex_text.configure(state="disabled")
            return

        base_cmd = [
            self.tshark_path,
            "-r", self.current_pcap_path,
            "-Y", f"frame.number=={frame_number}"
        ]

        try:
            proto_proc = subprocess.run(
                base_cmd + ["-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            hex_proc = subprocess.run(
                base_cmd + ["-x"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
        except subprocess.TimeoutExpired:
            self.proto_text.insert("1.0", "Timed out while loading protocol details.")
            self.hex_text.insert("1.0", "Timed out while loading hex dump.")
            self.proto_text.configure(state="disabled")
            self.hex_text.configure(state="disabled")
            return
        except Exception as e:
            self.proto_text.insert("1.0", f"Error loading protocol details:\n{e}")
            self.hex_text.insert("1.0", f"Error loading hex dump:\n{e}")
            self.proto_text.configure(state="disabled")
            self.hex_text.configure(state="disabled")
            return

        proto_output = proto_proc.stdout or proto_proc.stderr or "No protocol details."
        hex_output = hex_proc.stdout or hex_proc.stderr or "No hex dump."

        self.proto_text.insert("1.0", proto_output)
        self.hex_text.insert("1.0", hex_output)
        self.proto_text.configure(state="disabled")
        self.hex_text.configure(state="disabled")

    ###########################################################
    #   App lifecycle
    ###########################################################
    def on_close(self):
        if self.capturing:
            self.stop_capture()
        self.destroy()


def main():
    app = WiresharkCloneApp()
    app.mainloop()


if __name__ == "__main__":
    main()
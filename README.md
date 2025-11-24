# ⌨️ Wireshark-Style Packet Sniffer (Python + Tshark)

![Python](https://img.shields.io/badge/Python-3.14-blue?style=for-the-badge\&logo=python\&logoColor=white)
![Wireshark](https://img.shields.io/badge/Backend-TShark-1679A7?style=for-the-badge\&logo=wireshark)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-0A84FF?style=for-the-badge)
![Windows](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows11)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 🪟 Overview

The Wireshark-Style Packet Sniffer is a modern, dark-themed Windows desktop application built using Python and CustomTkinter. It provides a clean and intuitive interface for capturing, inspecting, and analyzing live network traffic using **Tshark** as the backend engine. This tool is part of my cybersecurity & Python development portfolio — demonstrating GUI design, network analysis fundamentals, and the integration of Python with real packet-capture tools.

---

## 🖼 GUI Preview

<p align="left">
  <img src="screenshots/Screenshot 2025-11-18 133713.png" width="650">
</p>

---

## 🖥️ App Icon

<p align="left">
  <img src="screenshots/icon.ico" width="50">
  <img src="screenshots/icon.png" width="200">
</p>

---

## ☰ Features

* Live capture via Tshark
* BPF filter support (`tcp port 80`, `udp`, `icmp`, etc.)
* Start / Pause / Resume / Stop controls
* Fully dark-themed `ttk.Treeview`
* Colored rows per protocol (DNS, TCP, UDP, HTTP, TLS, Other)
* **Protocol Tree** (`tshark -V`)
* **Hex Dump** (`tshark -x`)
* Auto-loads details when a packet is selected
* Automatically saves every capture session
* Export to custom location
* Fully compatible with Wireshark

---

## 📁 Project Structure

```
packet-sniffer/
│
├── wireshark_clone.py         # Main application
├── README.md                  # Documentation
├── requirements.txt           # Python dependencies
├── screenshots/
│   ├── screenshot.png         # App preview
│   ├── icon.png               # PNG app icon (README)
│   └── icon.ico               # Transparent .ico for window
├── .gitignore                 # Ignore venv, cache, PCAPs
└── LICENSE                    # MIT License
```

---

## ⬇️ Installation

**1. Install Python Dependencies**

```bash
pip install -r requirements.txt
```

_> Note: Tkinter is built into Python on Windows/macOS._

---

**2. Install Tshark**

Download Wireshark or standalone Tshark:

[https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

_Make sure `tshark` is available in PATH._

---

## ▶️ Running the Application

```bash
python wireshark_clone.py
```

_The GUI will launch immediately._

---

## ❓ How the Sniffer Works

The sniffer operates by combining **Python**, **CustomTkinter**, and **Tshark** (Wireshark’s command-line engine) into a real-time capture and analysis pipeline.

**1. Background Capture Thread**

When you click **Start Capture**, the app launches a dedicated Python thread (`TsharkCaptureThread`).
This thread runs the command:

```
tshark -i <interface> -T fields -e frame.number -e frame.time ...
```

It outputs **one line per packet**, which is parsed and pushed into a thread-safe queue.

This ensures the GUI stays **responsive**, even during heavy traffic.

---

**2. Main UI Packet Processing Loop**

Every 100 ms, the GUI checks the queue:

* New packets are added to the table
* Stats are updated
* Color-coding is applied based on protocol
* If paused, packets are buffered but not displayed

This creates smooth, Wireshark-style scrolling without freezing the interface.

---

**3. Live Stats Aggregation**

For each packet, the sniffer updates:

* Packet count
* Bytes observed
* Packets per second
* Protocol histogram
* Talkers (top source/destination IPs)

These stats refresh every second.

---

**4. Deep Packet Inspection (tshark -V / -x)**

When you click a row:

* The sniffer looks up that packet number
* It re-invokes tshark against the generated PCAP file
* Two commands are executed:

**Protocol tree:**

```
tshark -r capture.pcap -Y "frame.number==X" -V
```

**Hex dump:**

```
tshark -r capture.pcap -Y "frame.number==X" -x
```

This yields the same multi-layer breakdown and raw hex Wireshark shows.

---

**5. Optional PCAP Writing**

During capture, Tshark also runs in a **separate process** writing directly to:

```
capture_YYYYMMDD_HHMMSS.pcap
```

This allows:

* Deep inspection
* Later analysis in Wireshark
* Exporting the file anywhere

---

## 📤 Output Overview — What You Can Expect to See

The sniffer produces several types of output while running.
This table summarizes each one, what it looks like, and where it appears.

| Output Type           | Where It Appears                  | Example Contents                                      | Notes                                                          |
| --------------------- | --------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------- |
| **Live Packet Table** | Main UI (top pane)                | Frame No., Time, Src, Dst, Protocol, Length, Info     | Color-coded by protocol (DNS / TCP / UDP / TLS / HTTP / Other) |
| **Overview Details**  | Bottom pane → *Overview* tab      | Human-readable summary of selected packet             | Updates instantly when clicking a row                          |
| **Protocol Tree**     | Bottom pane → *Protocol Tree* tab | Layer-by-layer decode (`tshark -V`)                   | Similar to Wireshark's “Frame / Ethernet / IP / TCP” breakdown |
| **Hex Dump**          | Bottom pane → *Hex Dump* tab      | Raw bytes + ASCII view (`tshark -x`)                  | Useful for malware analysis and payload inspection             |
| **Live Statistics**   | Bottom pane → *Stats* tab         | Packet count, PPS, bytes, top protocol, top talkers   | Refreshes every second                                         |
| **Status Messages**   | Bottom status bar                 | “Capturing…”, “Paused”, “Interfaces loaded”, warnings | Real-time feedback on capture state                            |
| **PCAP File Output**  | Saved to project directory        | `capture_YYYYMMDD_HHMMSS.pcap`                        | Full raw capture ready for Wireshark import                    |
| **Errors / Warnings** | Modal popups (messagebox)         | “tshark not found”, “No interface selected”, etc.     | Covers all runtime issues                                      |

---

## Example Output (Sample Entry)

Here’s a typical packet row you’d see during capture:

| No. | Time            | Source       | Destination   | Protocol | Length | Info         |
| --- | --------------- | ------------ | ------------- | -------- | ------ | ------------ |
| 87  | 18:41:22.912345 | 192.168.1.22 | 142.250.72.46 | TLS      | 1514   | Client Hello |

And the Overview panel would display:

```
Frame:       87
Time:        2025-03-15 18:41:22.912345
Source:      192.168.1.22
Destination: 142.250.72.46
Protocol:    TLS
Length:      1514
Info:        Client Hello
```

---

## 🪪 License
This project is released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

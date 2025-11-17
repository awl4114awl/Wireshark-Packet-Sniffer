# 🐍 Wireshark-Style Packet Sniffer (Python + Tshark)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge\&logo=python)
![Wireshark](https://img.shields.io/badge/Backend-TShark-1679A7?style=for-the-badge\&logo=wireshark)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-0A84FF?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

---

## 🧠 Overview

This project is a **Wireshark-style packet sniffer** built with:

* **Tshark** (Wireshark’s CLI backend)
* **CustomTkinter** for a modern dark-theme GUI
* A layout intentionally styled after Wireshark

It supports:

* **Real-time packet capture**
* **Protocol-based color coding**
* **Detailed packet inspection**
* **Hex dump & protocol tree views**
* **PCAP auto-saving + export**
* **Live capture statistics**

All inside a fully custom, modern Python GUI.

---

## 🖼 GUI Preview

> Replace this screenshot with your latest UI capture.

```
screenshots/screenshot.png
```

---

## 🧩 App Icon

Your custom dark-mode, transparent icon used in the title bar:

```
screenshots/icon.ico
screenshots/icon.png
```

Add it to your app with:

```python
self.iconbitmap("screenshots/icon.ico")
```

---

## ✨ Features

### 🔹 Real-Time Packet Capture

* Live capture via Tshark
* BPF filter support (`tcp port 80`, `udp`, `icmp`, etc.)
* Start / Pause / Resume / Stop controls

### 🔹 Live Statistics

* Total packets
* Packets per second
* Total bytes
* Top protocol
* Top talkers

### 🔹 Wireshark-Style Packet Table

* Fully dark-themed `ttk.Treeview`
* Colored rows per protocol (DNS, TCP, UDP, HTTP, TLS, Other)
* Smooth vertical + horizontal scrollbars
* Resizable columns

### 🔹 Deep Packet Inspection

* **Protocol Tree** (`tshark -V`)
* **Hex Dump** (`tshark -x`)
* Auto-loads details when a packet is selected

### 🔹 PCAP Support

* Automatically saves every capture session
* Export to custom location
* Fully compatible with Wireshark

---

## 📦 Installation

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

> Note: Tkinter is built into Python on Windows/macOS.

---

### 2. Install Tshark

Download Wireshark or standalone Tshark:

[https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

Make sure `tshark` is available in PATH.

---

## ▶️ Running the Application

```bash
python wireshark_clone.py
```

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

## 📘 Resume-Style Project Summary

> **Wireshark-Style Packet Sniffer (Python, Tshark, CustomTkinter)**
> Designed and developed a GUI-based packet capture and inspection tool using Python and Tshark.
> Implemented multi-threaded live packet parsing, BPF filtering, PCAP generation, and protocol-based visual tagging.
> Built deep packet inspection features (protocol tree + hex dump) and real-time statistics dashboards.
> Created a Wireshark-inspired dark UI using CustomTkinter, ttk theming, and custom scrollbars.

---

## 📝 License

This project is licensed under the **MIT License**.

---
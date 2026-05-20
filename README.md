<h1 align="center">KRAKEN</h1>

<p align="center">
  <em>wpa/wpa2 audit toolkit</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-on_hold-2B2B2B?style=flat"/>
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-3DA639?style=flat"/>
</p>

---

## > Overview

**Kraken** is a wireless security auditing framework focused on WPA/WPA2 networks.  
The project is designed for protocol research, wireless security studies, and controlled offensive security testing.

Kraken operates by:

* Capturing WPA/WPA2 4-way handshakes
* Extracting authentication material for offline analysis
* Performing dictionary-based password recovery
* Assisting wireless auditing workflows in Linux environments

---

## > Features

* WPA/WPA2 handshake capture
* Offline password auditing using wordlists
* Wireless interface management
* Deauthentication attack support

---

## > Installation

```bash
git clone https://github.com/0xf0xy/Kraken.git
cd Kraken
sudo pip install .
```

Verify installation:

```bash
kraken -h
```

---

## > Requirements

* Python 3.10+
* Linux system
* Wireless adapter with monitor mode support

---

## > Project Status

Kraken is currently on hold and remains in an experimental stage.  
The project is intended for research and educational purposes, and features may change during development.

---

## > Warning

This project is provided for **educational and research purposes only**.  
Only test networks and devices you own or are explicitly authorized to audit.  
You are responsible for any misuse of this software.

---

<p align="center">
  <a href="https://github.com/0xf0xy"><b>0xf0xy</b></a> • 
  <a href="./LICENSE"><b>MIT License</b></a>
</p>

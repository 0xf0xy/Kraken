<h1 align="center">KRAKEN</h1>

<p align="center">
  <em>wpa/wpa2 audit toolkit</em>
</p>

<p align="center">
  <img src="https://img.shields.io/github/release/0xf0xy/Kraken?color=AAAAAA&style=for-the-badge&labelColor=111111"/>
  <img src="https://img.shields.io/badge/python-3.10+-AAAAAA?style=for-the-badge&logo=python&logoColor=FFFFFF&labelColor=111111"/>
  <img src="https://img.shields.io/github/license/0xf0xy/Kraken?color=AAAAAA&style=for-the-badge&labelColor=111111"/>
</p>

<br>

> [!WARNING]
>
> Kraken is intended for educational, research, and authorized security testing purposes only.

<br>

## > About

Kraken is a tool for wireless network discovery, handshake capture and offline handshake testing.

It handles wireless network discovery, monitor mode management, handshake capture, deauthentication and offline handshake testing with wordlists.

<br>

## > Installation

```bash
git clone https://github.com/0xf0xy/Kraken.git
cd Kraken
pip install .
```

Check the installation:

```bash
kraken -h
```

Maybe you need to install as root.

<br>

## Usage

Start monitor mode:

```bash
sudo kraken start -i wlan0
```

Discover networks:

```bash
sudo kraken dump -i mon0
```

Capture a handshake:

```bash
sudo kraken dump -i mon0 -b AA:BB:CC:DD:EE:FF -c 6
```

Send deauthentication frames:

```bash
sudo kraken deauth -i mon0 -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -p 10
```

Test a captured handshake:

```bash
sudo kraken crack -f handshake.json -w wordlist.txt
```

For all available commands:

```bash
kraken -h
```

For command-specific options:

```bash
kraken <command> -h
```

---

<p align="center">
  <a href="https://github.com/0xf0xy"><b>0xf0xy</b></a> •
  <a href="./LICENSE"><b>MIT License</b></a>
</p>
